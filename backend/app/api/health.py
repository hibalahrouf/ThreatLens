"""
MASVS Audit Copilot — Health Check API
"""

from fastapi import APIRouter

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health")
async def health_check():
    """
    Health check endpoint.
    Returns the application status for Docker health checks and monitoring.
    """
    return {
        "status": "ok",
        "service": "masvs-audit-copilot",
        "version": "0.1.0",
    }


@router.get("/analyzer/status")
async def analyzer_status():
    """
    Check if the MobSF dynamic analyzer (emulator) is ready.
    """
    from app.engines.mobsf_client import MobSFClient
    client = MobSFClient()
    is_ready = client.is_analyzer_ready()
    return {
        "ready": is_ready,
        "message": "Dynamic analyzer is ready" if is_ready else "Dynamic analyzer is offline or not configured"
    }
