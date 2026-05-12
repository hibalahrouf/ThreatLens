"""
MASVS Audit Copilot — MobSF Dynamic Analysis API Client
Wraps MobSF v4.4.5 REST API endpoints for dynamic analysis operations.

Confirmed endpoints (all POST, all require 'hash' parameter):
  - /api/v1/dynamic/start_analysis
  - /api/v1/dynamic/stop_analysis
  - /api/v1/dynamic/report_json
  - /api/v1/frida/logs
"""

import logging
import time

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


# ─── Custom Exception ───

class MobSFDynamicError(Exception):
    """Raised when a MobSF dynamic analysis API call fails."""

    def __init__(self, message: str, status_code: int | None = None):
        self.status_code = status_code
        super().__init__(message)


# ─── Helpers ───

def _headers() -> dict:
    """Return the MobSF authorization headers."""
    return {"Authorization": settings.MOBSF_API_KEY}


def _mobsf_url(path: str) -> str:
    """Build the full MobSF URL for a given API path."""
    base = settings.MOBSF_URL.rstrip("/")
    return f"{base}{path}"


# ─── API Wrappers ───

def start_dynamic_analysis(apk_hash: str) -> dict:
    """
    Start dynamic analysis for an APK on the connected emulator/device.

    POST /api/v1/dynamic/start_analysis
    Required parameter: hash

    Retries up to 3 times with a 10-second delay between attempts.
    The emulator may need time to boot or the previous session to clear.

    Args:
        apk_hash: The MobSF MD5 hash of the uploaded APK.

    Returns:
        MobSF API response dict.

    Raises:
        MobSFDynamicError: If all 3 attempts fail.
    """
    url = _mobsf_url("/api/v1/dynamic/start_analysis")
    last_error = None

    for attempt in range(1, 4):
        try:
            logger.info(
                "start_dynamic_analysis attempt %d/3 for hash=%s",
                attempt, apk_hash,
            )
            with httpx.Client(timeout=60) as client:
                resp = client.post(url, headers=_headers(), data={"hash": apk_hash})
                resp.raise_for_status()
                data = resp.json()

            if "error" in data:
                raise MobSFDynamicError(
                    f"MobSF returned error: {data['error']}",
                    status_code=resp.status_code,
                )

            logger.info("Dynamic analysis started successfully for hash=%s", apk_hash)
            return data

        except Exception as exc:
            last_error = exc
            logger.warning(
                "start_dynamic_analysis attempt %d failed: %s", attempt, exc,
            )
            if attempt < 3:
                time.sleep(10)

    raise MobSFDynamicError(
        f"start_dynamic_analysis failed after 3 attempts: {last_error}"
    ) from last_error


def stop_dynamic_analysis(apk_hash: str) -> dict:
    """
    Stop dynamic analysis — collects logs and downloads runtime data.

    POST /api/v1/dynamic/stop_analysis
    Required parameter: hash

    Args:
        apk_hash: The MobSF MD5 hash of the uploaded APK.

    Returns:
        MobSF API response dict.

    Raises:
        MobSFDynamicError: On HTTP or API-level errors.
    """
    url = _mobsf_url("/api/v1/dynamic/stop_analysis")

    with httpx.Client(timeout=60) as client:
        resp = client.post(url, headers=_headers(), data={"hash": apk_hash})

    if resp.status_code != 200:
        raise MobSFDynamicError(
            f"stop_dynamic_analysis failed with HTTP {resp.status_code}: {resp.text[:500]}",
            status_code=resp.status_code,
        )

    data = resp.json()
    if "error" in data:
        raise MobSFDynamicError(
            f"MobSF returned error on stop: {data['error']}",
            status_code=resp.status_code,
        )

    logger.info("Dynamic analysis stopped for hash=%s", apk_hash)
    return data


def get_dynamic_report(apk_hash: str) -> dict:
    """
    Retrieve the full dynamic analysis JSON report.

    POST /api/v1/dynamic/report_json
    Required parameter: hash

    Args:
        apk_hash: The MobSF MD5 hash of the uploaded APK.

    Returns:
        Complete dynamic analysis report as a dict.

    Raises:
        MobSFDynamicError: On HTTP or API-level errors.
    """
    url = _mobsf_url("/api/v1/dynamic/report_json")

    with httpx.Client(timeout=120.0) as client:
        resp = client.post(url, headers=_headers(), data={"hash": apk_hash})

    if resp.status_code != 200:
        raise MobSFDynamicError(
            f"get_dynamic_report failed with HTTP {resp.status_code}: {resp.text[:500]}",
            status_code=resp.status_code,
        )

    data = resp.json()
    if "error" in data:
        raise MobSFDynamicError(
            f"MobSF returned error on report: {data['error']}",
            status_code=resp.status_code,
        )

    logger.info("Dynamic report retrieved for hash=%s", apk_hash)
    return data


def get_frida_logs(apk_hash: str) -> dict | None:
    """
    Retrieve Frida instrumentation logs.

    POST /api/v1/frida/logs
    Required parameter: hash

    This function NEVER raises — it returns None on any failure.
    Frida logs are optional and may not be available if Frida
    instrumentation was not performed during the dynamic session.

    Args:
        apk_hash: The MobSF MD5 hash of the uploaded APK.

    Returns:
        Frida logs dict if available, None otherwise.
    """
    try:
        url = _mobsf_url("/api/v1/frida/logs")

        with httpx.Client(timeout=60) as client:
            resp = client.post(url, headers=_headers(), data={"hash": apk_hash})

        if resp.status_code != 200:
            logger.debug(
                "Frida logs unavailable (HTTP %d) for hash=%s",
                resp.status_code, apk_hash,
            )
            return None

        data = resp.json()
        if "error" in data:
            logger.debug("Frida logs returned error for hash=%s: %s", apk_hash, data["error"])
            return None

        logger.info("Frida logs retrieved for hash=%s", apk_hash)
        return data

    except Exception:
        logger.debug("Frida logs unavailable for hash=%s (exception suppressed)", apk_hash)
        return None
