from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Depends, HTTPException
from psycopg_pool import AsyncConnectionPool
from pydantic import PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.lib.tokens import (
    Token,
    InvalidSignatureError,
    InvalidTokenError,
)
from src.services.identity.identity_service import (
    IdentityService,
    Session,
    SessionExpiredError,
)
from src.services.identity.stores.pg_identity_store import PostgresIdentityStore

SESSION_COOKIE_NAME = "session_token"


class ServerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    postgres_dsn: PostgresDsn
    session_signing_keys: list[bytes]


@asynccontextmanager
async def lifespan(app: FastAPI):
    server_settings = ServerSettings()
    async with AsyncConnectionPool(str(server_settings.postgres_dsn)) as pool:
        store = await PostgresIdentityStore.create(pool)
        app.state.identity_service = IdentityService(
            store=store,
            relying_party_id="localhost",
            relying_party_name="Local Passkey Demo",
            origins=["https://localhost:8000"],
            session_signing_keys=server_settings.session_signing_keys,
        )
        yield


def identity_service(request: Request) -> IdentityService:
    return request.app.state.identity_service


async def session(
    request: Request, identity_service: IdentityService = Depends(identity_service)
) -> Session:
    session_cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if session_cookie is None:
        raise HTTPException(
            403,
            f"This API requires a valid session token cookie named {SESSION_COOKIE_NAME}",
        )

    try:
        return await identity_service.verify_session(Token(session_cookie))
    except (InvalidSignatureError, InvalidTokenError):
        raise HTTPException(403, "Invalid session token.")
    except SessionExpiredError:
        raise HTTPException(403, "Session expired.")
