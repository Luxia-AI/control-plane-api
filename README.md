# Control Plane API

Production foundation service for Luxia platform governance.

## What it provides

- Client registration + admin approval workflow
- Client/room lifecycle APIs and credential rotation
- Socket authorization endpoint for room ownership and RBAC checks
- Admin system overview, config allowlist updates, domain trust actions
- Immutable audit log trail

## Dev auth tokens

For local dev, bearer tokens are static and configured in `app/core/config.py`:

- `admin-token` => `platform_admin`
- `client-admin-token` => `client_admin` (`client_demo`)
- `client-operator-token` => `client_operator` (`client_demo`)

## Run

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8010
```

## Key endpoints

- `POST /v1/client-registrations`
- `POST /v1/client-registrations/{id}/approve`
- `GET /v1/admin/client-registrations/pending`
- `GET /v1/admin/system-overview`
- `GET /v1/admin/config`
- `PATCH /v1/admin/config`
- `POST /v1/admin/domain-trust/{domain}/approve`
- `POST /v1/admin/domain-trust/{domain}/reject`
- `GET /v1/admin/audit-logs`
- `GET /v1/client/rooms`
- `POST /v1/client/rooms`
- `POST /v1/client/rooms/{room_id}/credentials/rotate`
- `POST /v1/socket/authorize`
