import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticationCredential,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
    RegistrationCredential,
)

from src.services.identity.stores.identity_store import (
    AccountID,
    AccountRecord,
    ChallengeID,
    CredentialType,
    IdentityStore,
    NewAccountRecord,
    NewChallengeRecord,
    NewCredentialRecord,
)


@dataclass(frozen=True)
class NewAccount:
    email: str
    display_name: str


@dataclass(frozen=True)
class Account:
    id: AccountID
    email: str
    display_name: str
    created_at: datetime
    updated_at: datetime

    @staticmethod
    def from_record(record: AccountRecord) -> "Account":
        return Account(
            id=record.id,
            email=record.email,
            display_name=record.display_name,
            created_at=record.created_at,
            updated_at=record.updated_at,
        )


@dataclass
class CreateAccountOutcome:
    account: Account
    challenge_id: ChallengeID
    passkey_creation_options: PublicKeyCredentialCreationOptions


@dataclass
class RegistrationChallenge:
    account_id: AccountID
    challenge_id: ChallengeID
    passkey_creation_options: PublicKeyCredentialCreationOptions


@dataclass
class AuthenticateChallenge:
    account_id: AccountID
    challenge_id: ChallengeID
    passkey_authentication_options: PublicKeyCredentialRequestOptions


class ChallengeExpiredError(Exception):
    """
    Raised when the challenge being verified has already expired.
    """


class InvalidAccountError(Exception):
    """
    Raised during authentication when the requested account does not exist.
    """


class InvalidCredentialError(Exception):
    """
    Raised during authentication when the specified credential ID
    does not exist for the specified account.
    """


class IdentityService:
    _store: IdentityStore
    _challenge_duration: timedelta
    _relying_party_id: str
    _relying_party_name: str
    _origins: list[str]

    def __init__(
        self,
        store: IdentityStore,
        relying_party_id: str,
        relying_party_name: str,
        origins: list[str],
        challenge_duration: timedelta = timedelta(minutes=2),
    ):
        """
        Creates a new instance of the service.

        Parameters:
            store: The IdentityStore to use.
            relying_party_id: Must be the base domain for the server
                (e.g., 'localhost' or 'myservice.com').
            relying_party_name: A descriptive name that will show up in the
                operating system passkey prompts.
            origins: A list of allowed web client origins
                (e.g., 'http://localhost:8000').
            challenge_duration: How long before challenges expire
                (defaults to 2 minutes).
        """
        self._store = store
        self._challenge_duration = challenge_duration
        self._relying_party_id = relying_party_id
        self._relying_party_name = relying_party_name
        self._origins = origins

    async def create_account(self, new_account: NewAccount) -> CreateAccountOutcome:
        """
        Creates a new Account and new passkey registration options.

        Serialize the registration options to the client as JSON using the
        `options_to_json_dict()` helper method from the webauthn library.
        Use the add_passkey_credential() method to add the passkey when
        the client posts the response from the authenticator.
        """
        new_account_record = NewAccountRecord(
            id=AccountID(),
            email=new_account.email,
            display_name=new_account.display_name,
        )
        new_challenge_record = NewChallengeRecord(
            id=ChallengeID(),
            value=secrets.token_bytes(64),
            account_id=new_account_record.id,
            expires_at=datetime.now(timezone.utc) + self._challenge_duration,
        )
        outcome = await self._store.create_account(
            new_account=new_account_record, new_challenge=new_challenge_record
        )

        # Just needed to appease the type-checker
        assert outcome.challenge is not None
        account_record = outcome.account
        challenge_record = outcome.challenge

        passkey_creation_options = generate_registration_options(
            rp_id=self._relying_party_id,
            rp_name=self._relying_party_name,
            user_name=account_record.email,
            user_id=account_record.id.encode("ascii"),
            user_display_name=account_record.display_name,
            challenge=challenge_record.value,
        )

        return CreateAccountOutcome(
            account=Account.from_record(outcome.account),
            challenge_id=new_challenge_record.id,
            passkey_creation_options=passkey_creation_options,
        )

    async def create_registration_challenge(
        self, account_id: AccountID
    ) -> RegistrationChallenge:
        """
        Creates new passkey registration options for an existing account.

        Use this when adding another passkey to an existing account.
        """
        account_record = await self._store.get_account_by_id(account_id)
        if account_record is None:
            raise InvalidAccountError(f"Account ID '{account_id}' not found.")

        new_challenge_record = NewChallengeRecord(
            id=ChallengeID(),
            value=secrets.token_bytes(64),
            account_id=account_id,
            expires_at=datetime.now(timezone.utc) + self._challenge_duration,
        )
        challenge_record = await self._store.create_challenge(new_challenge_record)
        passkey_creation_options = generate_registration_options(
            rp_id=self._relying_party_id,
            rp_name=self._relying_party_name,
            user_name=account_record.email,
            user_id=account_record.id.encode("ascii"),
            user_display_name=account_record.display_name,
            challenge=challenge_record.value,
        )
        return RegistrationChallenge(
            account_id=account_id,
            challenge_id=challenge_record.id,
            passkey_creation_options=passkey_creation_options,
        )

    async def add_passkey_credential(
        self,
        account_id: AccountID,
        challenge_id: ChallengeID,
        credential: RegistrationCredential,
    ) -> None:
        """
        Verifies the provided `RegistrationCredential` against the
        specified challenge and adds the passkey to the specified account.
        """
        # Ensure the challenge was connected to the account
        # and not yet expired.
        challenge = await self._store.get_challenge(challenge_id)
        if challenge is None or challenge.account_id != account_id:
            raise ChallengeExpiredError()

        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge.value,
            expected_rp_id=self._relying_party_id,
            expected_origin=self._origins,
        )
        new_credential = NewCredentialRecord(
            id=verified.credential_id,
            account_id=account_id,
            type=CredentialType.PASSKEY,
            value=verified.credential_public_key,
        )
        await self._store.create_credential(new_credential, challenge_id)

    async def create_authentication_challenge(
        self, email: str
    ) -> AuthenticateChallenge:
        """
        Creates a new authentication challenge for the specified account.

        When you want to authenticate an account holder, start by calling
        this method passing the account email address. This returns passkey
        authentication options to send to the client. When the client sends
        the authenticator's response, call the `authenticate()` method to
        complete authentication.
        """
        account = await self._store.get_account_by_email(email)
        if account is None:
            raise InvalidAccountError(f"No account with email `{email}`")
        new_challenge = NewChallengeRecord(
            id=ChallengeID(),
            value=secrets.token_bytes(64),
            account_id=account.id,
            expires_at=datetime.now(timezone.utc) + self._challenge_duration,
        )
        await self._store.create_challenge(new_challenge)
        existing_credentials = await self._store.get_account_credentials(account.id)
        allow_credentials = [
            PublicKeyCredentialDescriptor(c.id) for c in existing_credentials
        ]
        passkey_authentication_options = generate_authentication_options(
            challenge=new_challenge.value,
            rp_id=self._relying_party_id,
            allow_credentials=allow_credentials,
        )
        return AuthenticateChallenge(
            account_id=account.id,
            challenge_id=new_challenge.id,
            passkey_authentication_options=passkey_authentication_options,
        )

    async def authenticate(
        self,
        account_id: AccountID,
        challenge_id: ChallengeID,
        credential: AuthenticationCredential,
    ) -> Account:
        """
        Verifies the `AuthenticationCredential` against the specified challenge
        for the specified account, and completes authentication.
        """
        account_record = await self._store.get_account_by_id(account_id)
        if account_record is None:
            raise InvalidAccountError(f"No account with id `{account_id}`")

        credential_record = await self._store.get_credential(credential.raw_id)
        if (
            credential_record is None
            or credential_record.account_id != account_record.id
        ):
            raise InvalidCredentialError(
                f"The credential {credential.id} does not exist for the specified account."
            )

        challenge_record = await self._store.get_challenge(challenge_id)
        if challenge_record is None or challenge_record.account_id != account_record.id:
            raise ChallengeExpiredError()

        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge_record.value,
            expected_rp_id=self._relying_party_id,
            expected_origin=self._origins,
            credential_public_key=credential_record.value,
            credential_current_sign_count=credential_record.use_count,
        )
        await self._store.update_credential_use_count(
            credential_record.id, verified.new_sign_count
        )
        return Account.from_record(account_record)
