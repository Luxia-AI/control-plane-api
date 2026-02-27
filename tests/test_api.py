import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app
from app.services import db as db_service


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_public_registration_and_approval_flow(monkeypatch, tmp_path):
    monkeypatch.setattr(db_service, "DB_PATH", str(tmp_path / "cp.db"))
    db_service.init_db()
    client = TestClient(app)

    reg = client.post(
        "/v1/client-registrations",
        json={
            "org_name": "Demo Org",
            "contact_email": "demo@example.com",
            "room_id": "room-demo",
            "room_password": "ChangeMe123!",
        },
    )
    assert reg.status_code == 200
    reg_id = reg.json()["id"]
    assert reg.json()["status"] == "pending"

    approved = client.post(
        f"/v1/client-registrations/{reg_id}/approve",
        json={"client_id": "client_demo"},
        headers=_headers("admin-token"),
    )
    assert approved.status_code == 200
    assert approved.json()["client_id"] == "client_demo"


def test_registration_rejects_non_universal_room_names(monkeypatch, tmp_path):
    monkeypatch.setattr(db_service, "DB_PATH", str(tmp_path / "cp_invalid_room.db"))
    db_service.init_db()
    client = TestClient(app)

    uppercase_room = client.post(
        "/v1/client-registrations",
        json={
            "org_name": "Demo Org",
            "contact_email": "demo@example.com",
            "room_id": "Room_Demo",
            "room_password": "ChangeMe123!",
        },
    )
    assert uppercase_room.status_code == 422


def test_socket_authorization_before_and_after_approval(monkeypatch, tmp_path):
    monkeypatch.setattr(db_service, "DB_PATH", str(tmp_path / "cp2.db"))
    db_service.init_db()
    client = TestClient(app)

    reg = client.post(
        "/v1/client-registrations",
        json={
            "org_name": "Demo Org",
            "contact_email": "demo@example.com",
            "room_id": "room-demo",
            "room_password": "ChangeMe123!",
        },
    )
    reg_id = reg.json()["id"]

    before_auth = client.post(
        "/v1/socket/authorize",
        json={"client_id": "client_demo", "room_id": "room-demo", "action": "join"},
        headers=_headers("client-operator-token"),
    )
    assert before_auth.status_code == 404

    before_verify = client.post(
        "/v1/socket/verify-room-secret",
        params={
            "client_id": "client_demo",
            "room_id": "room-demo",
            "room_secret": "ChangeMe123!",
        },
        headers=_headers("client-operator-token"),
    )
    assert before_verify.status_code == 403

    client.post(
        f"/v1/client-registrations/{reg_id}/approve",
        json={"client_id": "client_demo"},
        headers=_headers("admin-token"),
    )

    out = client.post(
        "/v1/socket/authorize",
        json={"client_id": "client_demo", "room_id": "room-demo", "action": "join"},
        headers=_headers("client-operator-token"),
    )
    assert out.status_code == 200
    verify = client.post(
        "/v1/socket/verify-room-secret",
        params={
            "client_id": "client_demo",
            "room_id": "room-demo",
            "room_secret": "ChangeMe123!",
        },
        headers=_headers("client-operator-token"),
    )
    assert verify.status_code == 200
    assert verify.json()["authorized"] is True


def test_admin_can_list_pending_registrations(monkeypatch, tmp_path):
    monkeypatch.setattr(db_service, "DB_PATH", str(tmp_path / "cp_pending.db"))
    db_service.init_db()
    client = TestClient(app)

    client.post(
        "/v1/client-registrations",
        json={
            "org_name": "Pending Org",
            "contact_email": "pending@example.com",
            "room_id": "pending-room",
            "room_password": "ChangeMe123!",
        },
    )

    out = client.get(
        "/v1/admin/client-registrations/pending",
        headers=_headers("admin-token"),
    )
    assert out.status_code == 200
    items = out.json()["items"]
    assert len(items) == 1
    assert items[0]["requested_room_id"] == "pending-room"
    assert items[0]["requested_by"] == "self_service"


def test_approve_second_room_for_same_client_succeeds(monkeypatch, tmp_path):
    monkeypatch.setattr(db_service, "DB_PATH", str(tmp_path / "cp_second_room.db"))
    db_service.init_db()
    client = TestClient(app)

    reg_one = client.post(
        "/v1/client-registrations",
        json={
            "org_name": "Demo Org",
            "contact_email": "demo1@example.com",
            "room_id": "room-one",
            "room_password": "ChangeMe123!",
        },
    )
    reg_two = client.post(
        "/v1/client-registrations",
        json={
            "org_name": "Demo Org",
            "contact_email": "demo2@example.com",
            "room_id": "room-two",
            "room_password": "ChangeMe123!",
        },
    )

    out_one = client.post(
        f"/v1/client-registrations/{reg_one.json()['id']}/approve",
        json={"client_id": "client_demo"},
        headers=_headers("admin-token"),
    )
    out_two = client.post(
        f"/v1/client-registrations/{reg_two.json()['id']}/approve",
        json={"client_id": "client_demo"},
        headers=_headers("admin-token"),
    )

    assert out_one.status_code == 200
    assert out_two.status_code == 200
    assert out_two.json()["room_id"] == "room-two"


def test_approve_registration_rejects_duplicate_room_id(monkeypatch, tmp_path):
    monkeypatch.setattr(db_service, "DB_PATH", str(tmp_path / "cp_dup_room.db"))
    db_service.init_db()
    client = TestClient(app)

    reg_one = client.post(
        "/v1/client-registrations",
        json={
            "org_name": "Demo Org",
            "contact_email": "demo1@example.com",
            "room_id": "room-same",
            "room_password": "ChangeMe123!",
        },
    )
    reg_two = client.post(
        "/v1/client-registrations",
        json={
            "org_name": "Demo Org",
            "contact_email": "demo2@example.com",
            "room_id": "room-same",
            "room_password": "ChangeMe123!",
        },
    )

    out_one = client.post(
        f"/v1/client-registrations/{reg_one.json()['id']}/approve",
        json={"client_id": "client_demo"},
        headers=_headers("admin-token"),
    )
    out_two = client.post(
        f"/v1/client-registrations/{reg_two.json()['id']}/approve",
        json={"client_id": "client_demo"},
        headers=_headers("admin-token"),
    )

    assert out_one.status_code == 200
    assert out_two.status_code == 409
    assert out_two.json()["detail"] == "room already exists"


def test_approve_different_clients_and_rooms_succeeds(monkeypatch, tmp_path):
    monkeypatch.setattr(db_service, "DB_PATH", str(tmp_path / "cp_multi_client.db"))
    db_service.init_db()
    client = TestClient(app)

    reg_a = client.post(
        "/v1/client-registrations",
        json={
            "org_name": "Org A",
            "contact_email": "a@example.com",
            "room_id": "room-a",
            "room_password": "ChangeMe123!",
        },
    )
    reg_b = client.post(
        "/v1/client-registrations",
        json={
            "org_name": "Org B",
            "contact_email": "b@example.com",
            "room_id": "room-b",
            "room_password": "ChangeMe123!",
        },
    )

    out_a = client.post(
        f"/v1/client-registrations/{reg_a.json()['id']}/approve",
        json={"client_id": "client_a"},
        headers=_headers("admin-token"),
    )
    out_b = client.post(
        f"/v1/client-registrations/{reg_b.json()['id']}/approve",
        json={"client_id": "client_b"},
        headers=_headers("admin-token"),
    )

    assert out_a.status_code == 200
    assert out_b.status_code == 200
    assert out_a.json()["client_id"] == "client_a"
    assert out_b.json()["client_id"] == "client_b"
