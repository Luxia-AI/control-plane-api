import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app
from app.services import db as db_service


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_registration_and_approval_flow(monkeypatch, tmp_path):
    monkeypatch.setattr(db_service, "DB_PATH", str(tmp_path / "cp.db"))
    db_service.init_db()
    client = TestClient(app)

    reg = client.post(
        "/v1/client-registrations",
        json={
            "org_name": "Demo Org",
            "contact_email": "demo@example.com",
            "room_id": "room_demo",
            "room_password": "ChangeMe123!",
        },
        headers=_headers("admin-token"),
    )
    assert reg.status_code == 200
    reg_id = reg.json()["id"]

    approved = client.post(
        f"/v1/client-registrations/{reg_id}/approve",
        json={"client_id": "client_demo"},
        headers=_headers("admin-token"),
    )
    assert approved.status_code == 200
    assert approved.json()["client_id"] == "client_demo"


def test_socket_authorization(monkeypatch, tmp_path):
    monkeypatch.setattr(db_service, "DB_PATH", str(tmp_path / "cp2.db"))
    db_service.init_db()
    client = TestClient(app)
    reg = client.post(
        "/v1/client-registrations",
        json={
            "org_name": "Demo Org",
            "contact_email": "demo@example.com",
            "room_id": "room_demo",
            "room_password": "ChangeMe123!",
        },
        headers=_headers("admin-token"),
    )
    reg_id = reg.json()["id"]
    client.post(
        f"/v1/client-registrations/{reg_id}/approve",
        json={"client_id": "client_demo"},
        headers=_headers("admin-token"),
    )
    out = client.post(
        "/v1/socket/authorize",
        json={"client_id": "client_demo", "room_id": "room_demo", "action": "join"},
        headers=_headers("client-operator-token"),
    )
    assert out.status_code == 200
    verify = client.post(
        "/v1/socket/verify-room-secret",
        params={
            "client_id": "client_demo",
            "room_id": "room_demo",
            "room_secret": "ChangeMe123!",
        },
        headers=_headers("client-operator-token"),
    )
    assert verify.status_code == 200
    assert verify.json()["authorized"] is True
