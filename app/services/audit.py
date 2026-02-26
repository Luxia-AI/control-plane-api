import json
import uuid

from app.services.auth import Principal
from app.services.db import get_conn, utc_now


def write_audit(
    principal: Principal | None,
    action: str,
    target_type: str,
    target_id: str,
    payload: dict | None = None,
) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (id, actor_sub, actor_email, action, target_type, target_id, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                principal.sub if principal else None,
                principal.email if principal else None,
                action,
                target_type,
                target_id,
                json.dumps(payload or {}),
                utc_now(),
            ),
        )
