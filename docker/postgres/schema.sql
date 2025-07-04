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
    challenge bytea not null primary key,
    account_id text not null references identity.accounts(id),
    expires_at timestamp with time zone not null,
    created_at timestamp with time zone not null default now()
);

-- Types of credentials currently supported
create type identity.credential_type as enum ('passkey');

-- Credentials for accounts. These are immutable, but
-- may be revoked, and later deleted.
create table identity.credentials (
    id text not null primary key,
    account_id text not null references identity.accounts(id),
    type identity.credential_type not null,
    value bytea not null,
    created_at timestamp with time zone not null default now(),
    revoked_at timestamp with time zone
);
