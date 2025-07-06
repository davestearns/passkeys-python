from dataclasses import fields
from datetime import datetime, timezone
from typing import Any, Sequence, Type

from psycopg.errors import UniqueViolation
from psycopg.rows import class_row
from psycopg.types.enum import EnumInfo, register_enum
from psycopg_pool import AsyncConnectionPool

from src.lib.sql import SqlGenerator
from src.services.identity.stores.identity_store import (
    AccountID,
    AccountRecord,
    ChallengeID,
    ChallengeRecord,
    CreateAccountOutcome,
    CredentialRecord,
    CredentialType,
    EmailAlreadyExistsError,
    NewAccountRecord,
    NewChallengeRecord,
    NewCredentialRecord,
)

SCHEMA_NAME = "identity"
ACCOUNTS_TABLE = f"{SCHEMA_NAME}.accounts"
CHALLENGES_TABLE = f"{SCHEMA_NAME}.challenges"
CREDENTIALS_TABLE = f"{SCHEMA_NAME}.credentials"
CREDENTIAL_TYPE_ENUM = f"{SCHEMA_NAME}.credential_type"


class PostgresIdentityStore:
    @classmethod
    async def create(cls, pool: AsyncConnectionPool) -> "PostgresIdentityStore":
        """
        Creates a new instance: use this instead of the normal constructor.

        This is necessary for registering the :class:`CredentialType` enum
        with the parallel enum defined in the database. This teaches psycopg
        how to serialize and deserialize columns of that type.
        """
        # Register the CredentialType enum
        async with pool.connection() as conn:
            enum_info = await EnumInfo.fetch(conn, CREDENTIAL_TYPE_ENUM)
            if enum_info is None:
                raise RuntimeError(f"Could not fetch {CREDENTIAL_TYPE_ENUM} info")
            register_enum(info=enum_info, enum=CredentialType)

        return cls(pool)

    def __init__(self, pool: AsyncConnectionPool):
        self._pool = pool
        self._accounts_sql = SqlGenerator(ACCOUNTS_TABLE, AccountRecord)
        self._challenges_sql = SqlGenerator(CHALLENGES_TABLE, ChallengeRecord)
        self._credentials_sql = SqlGenerator(CREDENTIALS_TABLE, CredentialRecord)

    async def create_account(
        self,
        new_account: NewAccountRecord,
        new_challenge: NewChallengeRecord | None = None,
    ) -> CreateAccountOutcome:
        account = AccountRecord(
            id=new_account.id,
            email=new_account.email,
            display_name=new_account.display_name,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            version=0,
        )

        challenge = (
            None
            if new_challenge is None
            else ChallengeRecord(
                id=new_challenge.id,
                value=new_challenge.value,
                account_id=new_challenge.account_id,
                expires_at=new_challenge.expires_at,
                created_at=datetime.now(timezone.utc),
            )
        )

        async with self._pool.connection() as conn:
            # Unfortunately, Postgres doesn't support executing
            # multiple statements with parameters in the
            # the same batch query. So we have to insert the
            # account and challenges separately. The psycopg library
            # will automatically do these under the same database transaction.
            # https://www.psycopg.org/psycopg3/docs/basic/transactions.html
            account_params = [getattr(account, f.name) for f in fields(account)]
            try:
                await conn.execute(self._accounts_sql.insert_sql, account_params)
            except UniqueViolation as e:
                if e.diag.constraint_name == "email_must_be_unique":
                    raise EmailAlreadyExistsError()
                else:
                    raise

            if challenge is not None:
                challenge_params = [
                    getattr(challenge, f.name) for f in fields(challenge)
                ]
                await conn.execute(self._challenges_sql.insert_sql, challenge_params)

        return CreateAccountOutcome(account=account, challenge=challenge)

    async def get_account_by_id(self, id: AccountID) -> AccountRecord | None:
        return await self._fetch_one(
            self._accounts_sql.select_by_id_sql, [id], AccountRecord
        )

    async def get_account_by_email(self, email: str) -> AccountRecord | None:
        return await self._fetch_one(
            self._accounts_sql.select_by_column("email"), [email], AccountRecord
        )

    async def create_challenge(
        self, new_challenge: NewChallengeRecord
    ) -> ChallengeRecord:
        challenge = ChallengeRecord(
            id=new_challenge.id,
            value=new_challenge.value,
            account_id=new_challenge.account_id,
            expires_at=new_challenge.expires_at,
            created_at=datetime.now(timezone.utc),
        )
        params = [getattr(challenge, f.name) for f in fields(challenge)]
        async with self._pool.connection() as conn:
            await conn.execute(self._challenges_sql.insert_sql, params)

        return challenge

    async def delete_challenge(self, challenge: bytes) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(self._challenges_sql.delete_by_id_sql, [challenge])

    async def get_challenge(
        self, id: ChallengeID, include_expired: bool = False
    ) -> ChallengeRecord | None:
        sql = (
            self._challenges_sql.select_by_id_sql
            if include_expired
            else self._challenges_sql.select_by_id_sql + " and expires_at >= now()"
        )
        return await self._fetch_one(sql, [id], ChallengeRecord)

    async def create_credential(
        self,
        new_credential: NewCredentialRecord,
        source_challenge_id: ChallengeID | None = None,
    ) -> CredentialRecord:
        credential = CredentialRecord(
            id=new_credential.id,
            account_id=new_credential.account_id,
            type=new_credential.type,
            value=new_credential.value,
            use_count=0,
            created_at=datetime.now(timezone.utc),
            revoked_at=None,
        )
        params = [getattr(credential, f.name) for f in fields(credential)]
        async with self._pool.connection() as conn:
            await conn.execute(self._credentials_sql.insert_sql, params)
            # If a source_challenge was provided, delete it
            if source_challenge_id is not None:
                await conn.execute(
                    self._challenges_sql.delete_by_id_sql, [source_challenge_id]
                )

        return credential

    async def get_credential(self, id: bytes) -> CredentialRecord | None:
        return await self._fetch_one(
            self._credentials_sql.select_by_id_sql, [id], CredentialRecord
        )

    async def get_account_credentials(
        self, account_id: AccountID
    ) -> Sequence[CredentialRecord]:
        return await self._fetch_many(
            self._credentials_sql.select_by_column("account_id"),
            [account_id],
            CredentialRecord,
        )

    async def update_credential_use_count(self, id: bytes, new_count: int) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                f"update {CREDENTIALS_TABLE} set use_count=%s where id=%s",
                [new_count, id],
            )

    async def _fetch_one[T](
        self, sql: str, params: Sequence[Any], cls: Type[T]
    ) -> T | None:
        async with self._pool.connection() as conn:
            async with conn.cursor(row_factory=class_row(cls)) as cur:
                result = await cur.execute(sql, params)
                return await result.fetchone()

    async def _fetch_many[T](
        self, sql: str, params: Sequence[Any], cls: Type[T]
    ) -> Sequence[T]:
        async with self._pool.connection() as conn:
            async with conn.cursor(row_factory=class_row(cls)) as cur:
                result = await cur.execute(sql, params)
                return await result.fetchmany()
