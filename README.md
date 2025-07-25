# Passkey Authentication in Python

This repo contains example code for how to do
[passkey authentication](https://fidoalliance.org/passkeys/) in a Python API
server. To learn more about Passkeys, see my
[Authenticated Sessions](https://davestearns.github.io/tutorials/authentication.html)
tutorial.

## Running the Demo Locally

The server is written in [Python](https://realpython.com/installing-python/), so
make sure you have a moderately recent Python interpreter installed on your
machine.

Dependencies are managed using the wonderful
[`uv` utility](https://docs.astral.sh/uv/#installation). Make sure you have that
installed as well.

Clone the repo to your local development machine, and in the repo directory, run
`uv sync` to install all the dependencies.

Run the following command within the repo directory to create a self-signed
HTTPS certificate and private key for the domain `localhost`. This is necessary
to run the server with HTTPS support, which is required for Secure cookies _even
when running on localhost_.

```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=localhost"
```

Create a `.env` file in the repo directory with the following content, changing
the `POSTGRES_PASSWORD` to something you want to use as your local Postgres
server password, and `SESSION_SIGNING_KEYS` to keys you want to use when HMAC
signing session tokens:

```env
POSTGRES_PASSWORD=local-password
POSTGRES_DSN=postgresql://postgres:${POSTGRES_PASSWORD}@localhost:5432
SESSION_SIGNING_KEYS=["secret_key_1","secret_key_2","secret_key_3"]
```

The Postgres database is run via Docker, so install and run
[Docker Desktop](https://www.docker.com/) if you don't already have it. Then
start the Postgres database using `docker compose up`. This will take over that
terminal window, but also allow you to see log output while it runs.

In a different terminal window, start the server using this command:

```bash
uv run uvicorn src.main:app --ssl-keyfile key.pem --ssl-certfile cert.pem
```

In your browser, navigate to <https://localhost:8000>. The page that is returned
should show a random email address with `Sign Up`, `Sign In`, and `Who Am I?`
buttons.

- Click `Sign Up` to create an account for the displayed email and register a
  new passkey for it. Currently this doesn't start a new session, so you need to
  sign-in next.
- Click `Sign In` to authenticate using that new passkey and start an
  authenticated session, dropping a Secure HttpOnly session token cookie.
- Click `Who Am I?` to `GET /accounts/me`, which requires the session token
  cookie, and will send back details about the current account if the token is
  valid.

The client-side JavaScript has limited error handling, so you might want to open
the developer tools console so you can see any errors. The script also logs the
various responses it gets back from the APIs.

Use `ctrl+c` to shut down both the API server and the docker container. Then use
these commands to delete the docker container and clean up temporary volumes
used by it:

```bash
docker compose down
docker system prune --volumes
```

## Code Organization

```
.
├── compose.yaml # Docker compose file for running Postgres
├── docker
│   └── postgres
│       ├── Dockerfile # Dockerfile for custom Postgres container
│       └── schema.sql # Schema created within that Postgres container
├── pyproject.toml # Project settings
├── README.md # This file
├── src # All source code
│   ├── __init__.py # Required by FastAPI
│   ├── api # API routes
│   │   └── susi.py # Sign-Up and Sign-In Routes
│   ├── dependencies.py # FastAPI server dependencies
│   ├── lib # reusable code I haven't put into a library yet
│   │   ├── ids.py    # Application-assigned typed IDs
│   │   ├── sql.py    # Simple and optimized SQL generation
│   │   └── tokens.py # Digitally-signed tokens
│   ├── main.py # Main server entrypoint.
│   ├── services # All internal services
│   │   └── identity # Identity service and Stores
│   │       ├── identity_service.py # IdentityService
│   │       └── stores # IdentityStore definition and implementations
│   │           ├── identity_store.py    # IdentityStore Protocol definition
│   │           └── pg_identity_store.py # PostgresIdentityStore
│   └── static
│       └── susi.html # The client-side test page
└── uv.lock # UV lock file
```

## WebAuthn Libraries

The Python server uses the official
[webauthn library for Python](https://github.com/duo-labs/py_webauthn) to
generate passkey registration/authentication options, and verify passkey
credentials. Sadly, this library isn't well documented, so hopefully this
example will provide some working code you can use as a reference.

The client page uses the
[simplewebauthn/browser](https://simplewebauthn.dev/docs/packages/browser)
library to handle the passkey options generated by the server library.
Apparently webauthn requires (suggests?) that binary data be encoded in
[Base64URL](https://base64.guru/standards/base64url), not normal Base64, when
returned from the server. Client-side JavaScript has built-in support for
decoding normal Base64 (the `atob()` function), but not Base64URL, so this
client library handles that for you.
