from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from psycopg_pool import AsyncConnectionPool
from pydantic import PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.services.identity.identity_service import IdentityService
from src.services.identity.stores.pg_identity_store import PostgresIdentityStore


class ServerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    postgres_dsn: PostgresDsn
    session_signing_keys: list[str]


@asynccontextmanager
async def lifespan(app: FastAPI):
    server_settings = ServerSettings()
    async with AsyncConnectionPool(str(server_settings.postgres_dsn)) as pool:
        store = await PostgresIdentityStore.create(pool)
        app.state.identity_service = IdentityService(
            store=store,
            relying_party_id="localhost",
            relying_party_name="Local Passkey Demo",
            origins=["http://localhost:8000"],
        )
        yield


def identity_service(request: Request) -> IdentityService:
    return request.app.state.identity_service
