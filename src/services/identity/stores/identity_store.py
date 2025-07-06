from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto
from typing import Protocol, Sequence

from src.lib.ids import BaseID


class AccountID(BaseID):
    PREFIX = "ac"


class ChallengeID(BaseID):
    PREFIX = "ch"


class SessionID(BaseID):
    PREFIX = "sn"
    ORDERED = False


@dataclass(frozen=True)
class NewAccountRecord:
    id: AccountID
    email: str
    display_name: str


@dataclass(frozen=True)
class AccountRecord:
    id: AccountID
    email: str
    display_name: str
    created_at: datetime
    updated_at: datetime
    version: int


@dataclass(frozen=True)
class NewChallengeRecord:
    id: ChallengeID
    value: bytes
    account_id: AccountID
    expires_at: datetime


@dataclass(frozen=True)
class ChallengeRecord:
    id: ChallengeID
    value: bytes
    account_id: AccountID
    expires_at: datetime
    created_at: datetime


class CredentialType(Enum):
    PASSKEY = auto()


@dataclass(frozen=True)
class NewCredentialRecord:
    # Passkeys have their own bytes ID, created by the Authenticator.
    id: bytes
    account_id: AccountID
    type: CredentialType
    value: bytes


@dataclass(frozen=True)
class CredentialRecord:
    # Passkeys have their own bytes ID, created by the Authenticator.
    id: bytes
    account_id: AccountID
    type: CredentialType
    value: bytes
    use_count: int
    created_at: datetime
    revoked_at: datetime | None


@dataclass(frozen=True)
class CreateAccountOutcome:
    account: AccountRecord
    challenge: ChallengeRecord | None


@dataclass(frozen=True)
class NewSessionRecord:
    id: SessionID
    account_id: AccountID
    expires_at: datetime


@dataclass(frozen=True)
class SessionRecord:
    id: SessionID
    account_id: AccountID
    expires_at: datetime
    created_at: datetime


@dataclass(frozen=True)
class SessionWithAccountRecord:
    id: SessionID
    account_id: AccountID
    created_at: datetime
    expires_at: datetime
    account_email: str
    account_display_name: str
    account_created_at: datetime
    account_updated_at: datetime
    account_version: int


class EmailAlreadyExistsError(Exception):
    """
    Raised when the email for a NewAccountRecord already exists in the database.
    """


class IdentityStore(Protocol):
    """
    Common interface that all identity store implementations must support.
    """

    async def create_account(
        self,
        new_account: NewAccountRecord,
        new_challenge: NewChallengeRecord | None = None,
    ) -> CreateAccountOutcome:
        """
        Creates a new account in the system.

        Parameters:
            `new_account`: the account to create.
            `new_challenge`: if specified, a challenge will also be inserted and returned.

        Raises:
            :class:`EmailAlreadyExistsError` when the email address already exists.
        """

    async def get_account_by_id(self, id: AccountID) -> AccountRecord | None:
        """
        Gets an AccountRecord by ID.
        """

    async def get_account_by_email(self, email: str) -> AccountRecord | None:
        """
        Gets an AccountRecord by email.
        """

    async def create_challenge(
        self, new_challenge: NewChallengeRecord
    ) -> ChallengeRecord:
        """
        Creates a new challenge associated with the new_challenge.account_id
        """

    async def delete_challenge(self, challenge: bytes) -> None:
        """
        Deletes an existing challenge in the database.
        """

    async def get_challenge(
        self, id: ChallengeID, include_expired: bool = False
    ) -> ChallengeRecord | None:
        """
        Gets a ChallengeRecord by challenge value.
        """

    async def create_credential(
        self,
        new_credential: NewCredentialRecord,
        source_challenge_id: ChallengeID | None = None,
    ) -> CredentialRecord:
        """
        Creates a new credential.
        """

    async def get_credential(self, id: bytes) -> CredentialRecord | None:
        """
        Gets an existing credential by ID.
        """

    async def get_account_credentials(
        self, account_id: AccountID
    ) -> Sequence[CredentialRecord]:
        """
        Returns all credentials for a given account.
        """

    async def update_credential_use_count(self, id: bytes, new_count: int) -> None:
        """
        Updates the use count for a credential, to help detect replay attacks.
        """

    async def create_session(self, new_session: NewSessionRecord) -> SessionRecord:
        """
        Creates a new session.
        """

    async def get_session(
        self, session_id: SessionID, included_expired: bool = False
    ) -> SessionWithAccountRecord | None:
        """
        Gets the specified session with related account details.
        """
