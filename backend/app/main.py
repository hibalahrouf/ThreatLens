"""
MASVS Audit Copilot - FastAPI Application Entry Point
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.health import router as health_router
from app.api.auth import router as auth_router
from app.api.scans import router as scans_router
from app.api.projects import router as projects_router
from app.api.findings import router as findings_router
from app.api.diff import router as diff_router
from app.api.reports import router as reports_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown events."""
    print(f"{settings.APP_NAME} starting...")
    print("Database schema is managed by Alembic migrations.")
    yield
    print(f"{settings.APP_NAME} shutting down...")


app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Automated OWASP MASVS/MASTG security audit copilot for mobile applications. "
        "Upload an APK or IPA, get a full security report with MASVS mapping, "
        "CVSS scoring, AI-powered triage, and auto-remediation code."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(scans_router)
app.include_router(projects_router)
app.include_router(findings_router)
app.include_router(diff_router)
app.include_router(reports_router)
