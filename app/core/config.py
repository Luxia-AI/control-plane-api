import os

SERVICE_NAME = "control-plane-api"
SERVICE_VERSION = os.getenv("SERVICE_VERSION", "1.0.0")
SERVICE_ENV = os.getenv("APP_ENV", "prod")
DB_PATH = os.getenv("CONTROL_PLANE_DB_PATH", "./control_plane.db")

DEV_STATIC_TOKENS = {
    "admin-token": {
        "sub": "admin-1",
        "email": "admin@luxia.local",
        "roles": ["platform_admin"],
        "client_id": None,
    },
    "client-admin-token": {
        "sub": "client-admin-1",
        "email": "client-admin@luxia.local",
        "roles": ["client_admin"],
        "client_id": "client_demo",
    },
    "client-operator-token": {
        "sub": "client-op-1",
        "email": "client-op@luxia.local",
        "roles": ["client_operator"],
        "client_id": "client_demo",
    },
}
