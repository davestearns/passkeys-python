import secrets
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator, Generator

import pytest
import pytest_asyncio
from psycopg_pool import AsyncConnectionPool
from pydantic import PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict
from uuid_utils import uuid7

from src.services.identity.stores.identity_store import (
    AccountID,
    ChallengeID,
    CredentialType,
    NewAccountRecord,
    NewChallengeRecord,
    NewCredentialRecord,
)
from src.services.identity.stores.pg_identity_store import PostgresIdentityStore


class DbSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    postgres_dsn: PostgresDsn


@pytest.fixture
def email() -> Generator[str]:
    yield f"T{uuid7().hex}@test.com"


@pytest_asyncio.fixture
async def store() -> AsyncGenerator[PostgresIdentityStore]:
    db_settings = DbSettings()
    async with AsyncConnectionPool(str(db_settings.postgres_dsn)) as p:
        store = await PostgresIdentityStore.create(p)
        yield store


async def test_create_account_with_challenge(
    email: str, store: PostgresIdentityStore
) -> None:
    new_account = NewAccountRecord(id=AccountID(), email=email, display_name="Tester")
    new_challenge = NewChallengeRecord(
        id=ChallengeID(),
        value=secrets.token_bytes(64),
        account_id=new_account.id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    outcome = await store.create_account(new_account, new_challenge)
    assert outcome.account.id == new_account.id
    assert outcome.account.email == new_account.email
    assert outcome.account.display_name == new_account.display_name
    assert outcome.account.version == 0
    assert outcome.challenge is not None
    assert outcome.challenge.id == new_challenge.id
    assert outcome.challenge.value == new_challenge.value
    assert outcome.challenge.account_id == new_account.id
    assert outcome.challenge.expires_at == new_challenge.expires_at

    account = await store.get_account_by_id(new_account.id)
    assert account is not None
    assert account.email == new_account.email

    challenge = await store.get_challenge(new_challenge.id)
    assert challenge is not None
    assert challenge.value == new_challenge.value


async def test_create_credential(email: str, store: PostgresIdentityStore) -> None:
    new_account = NewAccountRecord(id=AccountID(), email=email, display_name="Tester")
    await store.create_account(new_account)

    id = uuid7().bytes  # passkeys have their own IDs assigned by the Authenticator
    new_credential = NewCredentialRecord(
        id=id, account_id=new_account.id, type=CredentialType.PASSKEY, value=b"abc"
    )
    credential = await store.create_credential(new_credential)
    assert credential.id == new_credential.id
    assert credential.value == new_credential.value
    assert credential.type == new_credential.type

    reloaded = await store.get_credential(id)
    assert reloaded is not None
    assert reloaded.id == new_credential.id
    assert reloaded.value == new_credential.value
    assert reloaded.type == new_credential.type

    credentials = await store.get_account_credentials(new_account.id)
    assert len(credentials) == 1
