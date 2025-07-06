create schema identity;

-- System accounts. The emil and display_name fields
-- may be updated, so the version column is used for
-- optimistic concurrency.
create table identity.accounts (
    id text not null primary key,
    email varchar(320) not null constraint email_must_be_unique unique,
    display_name varchar(256) not null,
    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now(),
    version bigint not null default 0
);

-- Passkey or other challenges sent to the client,
-- or embedded in verification links.
-- These are immutable, and will typically be deleted
-- after they are confirmed. They may also expire.
create table identity.challenges (
    id text not null primary key,
    value bytea not null,
    account_id text not null references identity.accounts(id),
    expires_at timestamp with time zone not null,
    created_at timestamp with time zone not null default now()
);

-- Types of credentials currently supported
create type identity.credential_type as enum ('PASSKEY');

-- Credentials for accounts. The use_count and revoked_at
-- fields may be updated but are done so idempotently.
create table identity.credentials (
    id bytea not null primary key,
    account_id text not null references identity.accounts(id),
    type identity.credential_type not null,
    value bytea not null,
    use_count bigint not null default 0,
    created_at timestamp with time zone not null default now(),
    revoked_at timestamp with time zone
);

-- For fast selection of an account's existing credentials.
create index account_credentials_idx on identity.credentials(account_id, created_at);
