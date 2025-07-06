from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, EmailStr, Field
from webauthn.helpers import (
    options_to_json_dict,
    parse_authentication_credential_json,
    parse_registration_credential_json,
)

from src.dependencies import identity_service, session, SESSION_COOKIE_NAME
from src.services.identity.identity_service import (
    IdentityService,
    InvalidAccountError,
    InvalidCredentialError,
    NewAccount,
    Session,
)
from src.services.identity.stores.identity_store import (
    AccountID,
    ChallengeID,
    EmailAlreadyExistsError,
)


class CreateAccountRequest(BaseModel):
    email: EmailStr
    display_name: str = Field(min_length=1)


class AccountResponse(BaseModel):
    id: str
    email: str
    display_name: str
    created_at: datetime


class CreateAccountResponse(BaseModel):
    account: AccountResponse
    challenge_id: str
    passkey_creation_options: dict[str, Any]


class CreateRegistrationChallengeResponse(BaseModel):
    account_id: str
    challenge_id: str
    passkey_creation_options: dict[str, Any]


class AddCredentialRequest(BaseModel):
    challenge_id: str
    credential_json: dict[str, Any]


class CreateAuthenticationChallengeRequest(BaseModel):
    email: EmailStr


class CreateAuthenticationChallengeResponse(BaseModel):
    account_id: str
    challenge_id: str
    passkey_authentication_options: dict[str, Any]


class CreateSessionRequest(BaseModel):
    account_id: str
    challenge_id: str
    credential_json: dict[str, Any]


class CreateSessionResponse(BaseModel):
    account: AccountResponse
    session_expires_at: datetime


router = APIRouter()


@router.post(
    "/accounts",
    status_code=201,
    description=(
        "Creates a new account and returns passkey registration options."
        " POST to /accounts/{account_id}/credentials to complete registration."
    ),
)
async def create_account(
    request: CreateAccountRequest,
    identity_service: IdentityService = Depends(identity_service),
) -> CreateAccountResponse:
    new_account = NewAccount(email=request.email, display_name=request.display_name)
    try:
        outcome = await identity_service.create_account(new_account)
        account = outcome.account
        return CreateAccountResponse(
            account=AccountResponse(
                id=account.id,
                email=account.email,
                display_name=account.display_name,
                created_at=account.created_at,
            ),
            challenge_id=outcome.challenge_id,
            passkey_creation_options=options_to_json_dict(
                outcome.passkey_creation_options
            ),
        )
    except EmailAlreadyExistsError:
        raise HTTPException(
            409, f"Email address '{request.email}' is already registered."
        )


@router.post(
    "/accounts/{account_id}/challenges",
    status_code=201,
    description=(
        "Returns registration options for a new passkey on an existing account."
        " POST to /accounts/{account_id}/credentials to complete registration."
    ),
)
async def create_registration_challenge(
    account_id: str,
    identity_service: IdentityService = Depends(identity_service),
) -> CreateRegistrationChallengeResponse:
    challenge = await identity_service.create_registration_challenge(
        AccountID(account_id)
    )
    return CreateRegistrationChallengeResponse(
        account_id=challenge.account_id,
        challenge_id=challenge.challenge_id,
        passkey_creation_options=options_to_json_dict(
            challenge.passkey_creation_options
        ),
    )


@router.post(
    "/accounts/{account_id}/credentials",
    status_code=201,
    description="Adds a new passkey to an account.",
)
async def add_credential(
    account_id: str,
    request: AddCredentialRequest,
    identity_service: IdentityService = Depends(identity_service),
) -> None:
    registration_credential = parse_registration_credential_json(
        request.credential_json
    )
    try:
        await identity_service.add_passkey_credential(
            account_id=AccountID(account_id),
            challenge_id=ChallengeID(request.challenge_id),
            credential=registration_credential,
        )
    except InvalidAccountError:
        raise HTTPException(400, f"Account ID {account_id} was not found.")
    except InvalidCredentialError as e:
        raise HTTPException(400, f"Invalid credential: {str(e)}")


@router.post(
    "/sessions/challenges",
    status_code=201,
    description="Returns passkey authentication options for starting a new session.",
)
async def create_authentication_challenge(
    request: CreateAuthenticationChallengeRequest,
    identity_service: IdentityService = Depends(identity_service),
) -> CreateAuthenticationChallengeResponse:
    outcome = await identity_service.create_authentication_challenge(
        email=request.email
    )
    return CreateAuthenticationChallengeResponse(
        account_id=outcome.account_id,
        challenge_id=outcome.challenge_id,
        passkey_authentication_options=options_to_json_dict(
            outcome.passkey_authentication_options
        ),
    )


@router.post(
    "/sessions", status_code=201, description="Starts a new authenticated session."
)
async def create_session(
    request: CreateSessionRequest,
    response: Response,
    identity_service: IdentityService = Depends(identity_service),
) -> CreateSessionResponse:
    credential = parse_authentication_credential_json(request.credential_json)
    session = await identity_service.authenticate(
        AccountID(request.account_id), ChallengeID(request.challenge_id), credential
    )
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session.token,
        httponly=True,
        secure=True,  # Setting this requires you to run https even on localhost!
        max_age=(session.expires_at - datetime.now(timezone.utc)).seconds,
    )
    account = session.account
    return CreateSessionResponse(
        account=AccountResponse(
            id=account.id,
            email=account.email,
            display_name=account.display_name,
            created_at=account.created_at,
        ),
        session_expires_at=session.expires_at,
    )


@router.get("/accounts/me", description="Returns the currently signed-in account.")
async def get_accounts_me(session: Session = Depends(session)) -> AccountResponse:
    account = session.account
    return AccountResponse(
        id=account.id,
        email=account.email,
        display_name=account.display_name,
        created_at=account.created_at,
    )
