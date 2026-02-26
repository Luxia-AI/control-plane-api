import json
import uuid
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field

from app.services.audit import write_audit
from app.services.auth import Principal, ensure_client_scope, get_principal, require_role
from app.services.db import get_conn, hash_secret, issue_room_secret, utc_now

router = APIRouter(prefix="/v1", tags=["control-plane"])


class ClientRegistrationRequest(BaseModel):
    org_name: str = Field(min_length=2)
    contact_email: EmailStr
    room_id: str = Field(pattern=r"^[a-z0-9-]{3,64}$")
    room_password: str = Field(min_length=8, max_length=256)


class ApproveRegistrationRequest(BaseModel):
    client_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{3,64}$")


class ConfigPatchRequest(BaseModel):
    key: str
    value: str
    reason: str = Field(min_length=3)


class DomainTrustRequest(BaseModel):
    note: str | None = None


class CreateRoomRequest(BaseModel):
    room_id: str = Field(pattern=r"^[a-z0-9-]{3,64}$")


class SocketAuthorizeRequest(BaseModel):
    client_id: str
    room_id: str
    action: str = Field(pattern=r"^(join|post)$")


ALLOWED_CONFIG_KEYS = {
    "DISPATCH_TIMEOUT_SECONDS",
    "WORKER_TIMEOUT_SECONDS",
    "SOCKETHUB_USE_KAFKA",
    "STRICTNESS_MIN_EVIDENCE_COUNT",
}


@router.post("/client-registrations")
def create_registration(payload: ClientRegistrationRequest) -> dict[str, Any]:
    reg_id = str(uuid.uuid4())
    now = utc_now()
    normalized_room_id = payload.room_id.strip().lower()
    salt = uuid.uuid4().hex[:32]
    room_secret_hash = hash_secret(payload.room_password, salt)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO client_registrations (id, org_name, contact_email, requested_room_id, requested_room_salt, requested_room_secret_hash, status, requested_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                reg_id,
                payload.org_name,
                str(payload.contact_email),
                normalized_room_id,
                salt,
                room_secret_hash,
                "pending",
                "self_service",
                now,
                now,
            ),
        )
    write_audit(
        None,
        "client_registration_created",
        "client_registration",
        reg_id,
        {
            "org_name": payload.org_name,
            "contact_email": str(payload.contact_email),
            "room_id": normalized_room_id,
        },
    )
    return {"id": reg_id, "status": "pending", "room_id": normalized_room_id}


@router.post("/client-registrations/{registration_id}/approve")
def approve_registration(registration_id: str, payload: ApproveRegistrationRequest, principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    require_role(principal, {"platform_admin"})
    now = utc_now()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, status, org_name, requested_room_id, requested_room_salt, requested_room_secret_hash FROM client_registrations WHERE id=?",
            (registration_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="registration not found")
        if row["status"] != "pending":
            raise HTTPException(status_code=409, detail="registration already processed")
        requested_room_id = str(row["requested_room_id"] or "").strip()
        requested_room_salt = str(row["requested_room_salt"] or "").strip()
        requested_room_secret_hash = str(row["requested_room_secret_hash"] or "").strip()
        if not requested_room_id or not requested_room_salt or not requested_room_secret_hash:
            raise HTTPException(status_code=400, detail="registration missing room credentials")

        conn.execute(
            "INSERT INTO client_orgs (client_id, org_name, status, created_at) VALUES (?, ?, ?, ?)",
            (payload.client_id, row["org_name"], "active", now),
        )
        conn.execute(
            "INSERT INTO rooms (room_id, client_id, created_at) VALUES (?, ?, ?)",
            (requested_room_id, payload.client_id, now),
        )
        conn.execute(
            "INSERT INTO room_credentials (id, room_id, salt, secret_hash, active, rotated_at) VALUES (?, ?, ?, ?, 1, ?)",
            (
                str(uuid.uuid4()),
                requested_room_id,
                requested_room_salt,
                requested_room_secret_hash,
                now,
            ),
        )
        conn.execute("UPDATE client_registrations SET status='approved', updated_at=? WHERE id=?", (now, registration_id))

    write_audit(principal, "client_registration_approved", "client_registration", registration_id, payload.model_dump())
    return {
        "registration_id": registration_id,
        "client_id": payload.client_id,
        "room_id": requested_room_id,
        "status": "approved",
        "message": "Registration approved. Client can now join this room using the submitted room password.",
    }


@router.get("/admin/system-overview")
async def admin_system_overview(principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    require_role(principal, {"platform_admin"})
    services = {
        "socket_hub": "http://socket-hub:8000/healthz",
        "dispatcher": "http://dispatcher:9110/healthz",
        "worker": "http://worker:9000/healthz",
    }
    health: dict[str, Any] = {}
    async with httpx.AsyncClient(timeout=httpx.Timeout(2.5)) as client:
        for name, url in services.items():
            try:
                r = await client.get(url)
                health[name] = {"ok": r.status_code == 200, "status_code": r.status_code, "body": r.json()}
            except Exception as exc:
                health[name] = {"ok": False, "error": str(exc)}

    with get_conn() as conn:
        clients = conn.execute("SELECT COUNT(*) AS n FROM client_orgs WHERE status='active'").fetchone()["n"]
        rooms = conn.execute("SELECT COUNT(*) AS n FROM rooms").fetchone()["n"]
        pending_regs = conn.execute("SELECT COUNT(*) AS n FROM client_registrations WHERE status='pending'").fetchone()["n"]

    return {"health": health, "counts": {"active_clients": clients, "rooms": rooms, "pending_registrations": pending_regs}}


@router.get("/admin/config")
def admin_get_config(principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    require_role(principal, {"platform_admin"})
    with get_conn() as conn:
        rows = conn.execute("SELECT key, value, updated_by, updated_at, reason FROM config_store ORDER BY key ASC").fetchall()
    return {"items": [dict(r) for r in rows], "allowed_keys": sorted(ALLOWED_CONFIG_KEYS)}


@router.patch("/admin/config")
def admin_patch_config(payload: ConfigPatchRequest, principal: Principal = Depends(get_principal)) -> dict[str, str]:
    require_role(principal, {"platform_admin"})
    if payload.key not in ALLOWED_CONFIG_KEYS:
        raise HTTPException(status_code=400, detail="key not allowlisted")
    now = utc_now()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO config_store (key, value, updated_by, updated_at, reason) VALUES (?, ?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_by=excluded.updated_by, updated_at=excluded.updated_at, reason=excluded.reason",
            (payload.key, payload.value, principal.sub, now, payload.reason),
        )
    write_audit(principal, "config_updated", "config_key", payload.key, payload.model_dump())
    return {"status": "ok"}


@router.post("/admin/domain-trust/{domain}/approve")
def approve_domain(domain: str, payload: DomainTrustRequest, principal: Principal = Depends(get_principal)) -> dict[str, str]:
    require_role(principal, {"platform_admin"})
    now = utc_now()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO domain_trust (domain, status, note, updated_by, updated_at) VALUES (?, 'approved', ?, ?, ?) ON CONFLICT(domain) DO UPDATE SET status='approved', note=excluded.note, updated_by=excluded.updated_by, updated_at=excluded.updated_at",
            (domain, payload.note, principal.sub, now),
        )
    write_audit(principal, "domain_approved", "domain", domain, payload.model_dump())
    return {"status": "approved"}


@router.post("/admin/domain-trust/{domain}/reject")
def reject_domain(domain: str, payload: DomainTrustRequest, principal: Principal = Depends(get_principal)) -> dict[str, str]:
    require_role(principal, {"platform_admin"})
    now = utc_now()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO domain_trust (domain, status, note, updated_by, updated_at) VALUES (?, 'rejected', ?, ?, ?) ON CONFLICT(domain) DO UPDATE SET status='rejected', note=excluded.note, updated_by=excluded.updated_by, updated_at=excluded.updated_at",
            (domain, payload.note, principal.sub, now),
        )
    write_audit(principal, "domain_rejected", "domain", domain, payload.model_dump())
    return {"status": "rejected"}


@router.get("/admin/audit-logs")
def get_audit_logs(limit: int = 100, principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    require_role(principal, {"platform_admin"})
    limit = max(1, min(limit, 500))
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, actor_sub, actor_email, action, target_type, target_id, payload_json, created_at FROM audit_logs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return {"items": [dict(r) for r in rows]}


@router.get("/admin/client-registrations/pending")
def list_pending_registrations(principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    require_role(principal, {"platform_admin"})
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, org_name, contact_email, requested_room_id, requested_by, created_at, updated_at
            FROM client_registrations
            WHERE status='pending'
            ORDER BY created_at DESC
            """
        ).fetchall()
    return {"items": [dict(r) for r in rows]}


@router.get("/client/rooms")
def list_client_rooms(principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    require_role(principal, {"platform_admin", "client_admin", "client_operator", "client_viewer"})
    if not principal.client_id and "platform_admin" not in principal.roles:
        raise HTTPException(status_code=400, detail="client_id missing in token")

    with get_conn() as conn:
        if "platform_admin" in principal.roles:
            rows = conn.execute("SELECT room_id, client_id, created_at FROM rooms ORDER BY created_at DESC").fetchall()
        else:
            rows = conn.execute("SELECT room_id, client_id, created_at FROM rooms WHERE client_id=? ORDER BY created_at DESC", (principal.client_id,)).fetchall()

    return {"items": [dict(r) for r in rows]}


@router.post("/client/rooms")
def create_client_room(payload: CreateRoomRequest, principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    require_role(principal, {"platform_admin", "client_admin"})
    client_id = principal.client_id
    if "platform_admin" in principal.roles and not client_id:
        raise HTTPException(status_code=400, detail="platform_admin requires scoped token with client_id for this endpoint")
    if not client_id:
        raise HTTPException(status_code=400, detail="client_id missing")

    normalized_room_id = payload.room_id.strip().lower()
    now = utc_now()
    secret, salt, secret_hash = issue_room_secret()
    with get_conn() as conn:
        conn.execute("INSERT INTO rooms (room_id, client_id, created_at) VALUES (?, ?, ?)", (normalized_room_id, client_id, now))
        conn.execute(
            "INSERT INTO room_credentials (id, room_id, salt, secret_hash, active, rotated_at) VALUES (?, ?, ?, ?, 1, ?)",
            (str(uuid.uuid4()), normalized_room_id, salt, secret_hash, now),
        )

    write_audit(
        principal,
        "room_created",
        "room",
        normalized_room_id,
        {"room_id": normalized_room_id},
    )
    return {"room_id": normalized_room_id, "client_id": client_id, "room_secret": secret}


@router.post("/client/rooms/{room_id}/credentials/rotate")
def rotate_room_credentials(room_id: str, principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    require_role(principal, {"platform_admin", "client_admin"})
    with get_conn() as conn:
        room = conn.execute("SELECT room_id, client_id FROM rooms WHERE room_id=?", (room_id,)).fetchone()
        if not room:
            raise HTTPException(status_code=404, detail="room not found")
        ensure_client_scope(principal, str(room["client_id"]))

        now = utc_now()
        secret, salt, secret_hash = issue_room_secret()
        conn.execute("UPDATE room_credentials SET active=0 WHERE room_id=?", (room_id,))
        conn.execute(
            "INSERT INTO room_credentials (id, room_id, salt, secret_hash, active, rotated_at) VALUES (?, ?, ?, ?, 1, ?)",
            (str(uuid.uuid4()), room_id, salt, secret_hash, now),
        )

    write_audit(principal, "room_secret_rotated", "room", room_id)
    return {"room_id": room_id, "room_secret": secret}


@router.post("/socket/authorize")
def socket_authorize(payload: SocketAuthorizeRequest, principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    require_role(principal, {"platform_admin", "client_admin", "client_operator", "client_viewer"})
    with get_conn() as conn:
        room = conn.execute("SELECT room_id, client_id FROM rooms WHERE room_id=?", (payload.room_id,)).fetchone()
        if not room:
            raise HTTPException(status_code=404, detail="room not found")
        room_client_id = str(room["client_id"])
    if room_client_id != payload.client_id:
        raise HTTPException(status_code=403, detail="room ownership mismatch")
    ensure_client_scope(principal, payload.client_id)
    if payload.action == "post" and not any(r in {"platform_admin", "client_admin", "client_operator"} for r in principal.roles):
        raise HTTPException(status_code=403, detail="insufficient role to post")
    return {"authorized": True, "principal": {"sub": principal.sub, "roles": principal.roles, "client_id": principal.client_id}}


@router.post("/socket/verify-room-secret")
def verify_room_secret(client_id: str, room_id: str, room_secret: str, principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    # Optional helper endpoint for non-token room secret checks.
    ensure_client_scope(principal, client_id)
    with get_conn() as conn:
        room = conn.execute("SELECT client_id FROM rooms WHERE room_id=?", (room_id,)).fetchone()
        if not room or str(room["client_id"]) != client_id:
            raise HTTPException(status_code=403, detail="room ownership mismatch")
        cred = conn.execute("SELECT salt, secret_hash FROM room_credentials WHERE room_id=? AND active=1", (room_id,)).fetchone()
        if not cred:
            raise HTTPException(status_code=404, detail="active credential missing")
    ok = hash_secret(room_secret, str(cred["salt"])) == str(cred["secret_hash"])
    return {"authorized": ok}
