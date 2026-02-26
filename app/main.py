from fastapi import FastAPI

from app.core.config import SERVICE_NAME, SERVICE_VERSION
from app.routers.v1 import router as v1_router
from app.services.db import init_db

app = FastAPI(title="Luxia Control Plane", version=SERVICE_VERSION)
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
