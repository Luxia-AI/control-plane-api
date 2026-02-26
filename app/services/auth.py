from dataclasses import dataclass
from typing import Any

from fastapi import Header, HTTPException

from app.core.config import DEV_STATIC_TOKENS


@dataclass
class Principal:
    sub: str
    email: str
    roles: list[str]
    client_id: str | None = None


def _from_dev_token(token: str) -> Principal | None:
    payload = DEV_STATIC_TOKENS.get(token)
    if not payload:
        return None
    return Principal(
        sub=str(payload["sub"]),
        email=str(payload["email"]),
        roles=[str(r) for r in payload.get("roles", [])],
        client_id=payload.get("client_id"),
    )


def get_principal(authorization: str | None = Header(default=None)) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    principal = _from_dev_token(token)
    if principal is None:
        raise HTTPException(status_code=401, detail="invalid token")
    return principal


def require_role(principal: Principal, allowed: set[str]) -> None:
    if not any(role in allowed for role in principal.roles):
        raise HTTPException(status_code=403, detail="forbidden")


def ensure_client_scope(principal: Principal, client_id: str) -> None:
    if "platform_admin" in principal.roles:
        return
    if principal.client_id != client_id:
        raise HTTPException(status_code=403, detail="client scope violation")


def principal_to_dict(principal: Principal) -> dict[str, Any]:
    return {
        "sub": principal.sub,
        "email": principal.email,
        "roles": principal.roles,
        "client_id": principal.client_id,
    }
