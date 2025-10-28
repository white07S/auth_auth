# FastAPI BFF Boilerplate

This backend implements a production-ready FastAPI Backend-For-Frontend that wires up Azure Entra ID authentication, secure session cookies, RBAC, and Microsoft Graph integration. All behaviour is driven from a single `config.yaml` file so you can bootstrap new projects without touching application code.

## Features

- Authorization Code + PKCE with MSAL (tokens stay on the server).
- HttpOnly, Secure, SameSite session cookies with HMAC signing.
- SQLite (WAL) persistence for users, sessions, token cache, and audit data.
- Configurable RBAC via Entra groups and route policy mapping.
- Server-only Microsoft Graph proxy endpoints using cached tokens.
- CSRF protection for state-changing API calls (double submit token).

## Quick start

1. Copy `config.yaml` and set the Azure / Graph / cookie secrets for your tenant.
2. Create a virtual environment and install dependencies:

   ```bash
   cd backend
   python -m venv .venv
   source .venv/bin/activate
   pip install -U pip
   pip install -e .
   ```

3. Run the API with Uvicorn:

   ```bash
   uvicorn main:app --reload
   ```

The app reads configuration from `APP_CONFIG_PATH` (if provided) or falls back to `backend/config.yaml`.

## Configuration reference

```yaml
azure:
  tenant_id: "<tenant-guid>"
  client_id: "<app-client-id>"
  authority_url: "https://login.microsoftonline.com/<tenant-guid>"
  client_secret: "<client-secret>" # or point at a certificate below
  client_certificate_path: null
  client_certificate_thumbprint: null
  redirect_uri: "http://localhost:8000/auth/callback"
  graph_scopes:
    - "User.Read"
    - "GroupMember.Read.All"
rbac:
  group_role_map: { "<group-guid>": ["admin"] }
  route_policies: { "/#/admin": ["admin"] }
  evaluation_mode: any_of # or all_of
  group_refresh_ttl_minutes: 60
session:
  cookie_name: auth_session
  same_site: strict
  secure: true
  http_only: true
  signing_secret: "long-random-string"
  max_age_minutes: 60
csrf:
  enabled: true
  secret: "long-random-string"
security:
  require_pkce: true
  validate_state_nonce: true
  enforce_issuer_aud: true
  token_at_rest_encryption: true
  token_encryption_secret: "long-random-string"
sqlite:
  db_path: ./data/app.db
  pragmas:
    journal_mode: WAL
    synchronous: NORMAL
server:
  base_url: http://localhost:8000
  cors_allowed_origins:
    - http://localhost:3000
ui:
  default_authenticated_route: "/#/home"
  default_logged_out_route: "/#/login"
```

## Project structure

- `app/config.py` – Pydantic models for `config.yaml`.
- `app/container.py` – Dependency container used to initialise services.
- `app/db/models.py` – SQLAlchemy ORM models for users, sessions, token caches, audits.
- `app/routers` – FastAPI routers for auth, Graph proxy, and secured API routes.
- `app/services` – OIDC, session, RBAC, Graph, and token cache services.

## Next steps

- Configure Azure redirect and logout URLs for your application registration.
- Replace the example `group_role_map` and `route_policies` with project specific values.
- Swap SQLite for a shared backing store (Postgres/Redis) when you scale beyond a single instance.
