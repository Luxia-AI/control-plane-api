import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import SERVICE_NAME, SERVICE_VERSION
from app.routers.v1 import router as v1_router
from app.services.db import init_db

app = FastAPI(title="Luxia Control Plane", version=SERVICE_VERSION)

cors_origins_raw = os.getenv("CONTROL_PLANE_CORS_ORIGINS", "*").strip()
if cors_origins_raw == "*":
    cors_origins = ["*"]
else:
    cors_origins = [o.strip() for o in cors_origins_raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(v1_router)


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/")
def root() -> dict[str, str]:
    return {"service": SERVICE_NAME, "status": "running"}


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE_NAME}
