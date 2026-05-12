"""
MASVS Audit Copilot — MobSF API Client
Communicates with a MobSF instance to perform static analysis.
"""

import time
from typing import Optional

import httpx

from app.core.config import settings


class MobSFClient:
    """
    REST API client for Mobile Security Framework (MobSF).

    Handles:
    - File upload to MobSF
    - Triggering static analysis
    - Polling for scan completion
    - Retrieving the full JSON report
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 300,
    ):
        self.base_url = (base_url or settings.MOBSF_URL).rstrip("/")
        self.api_key = api_key or settings.MOBSF_API_KEY
        self.timeout = timeout
        self.headers = {"Authorization": self.api_key}

    def upload(self, file_data: bytes, filename: str) -> dict:
        """
        Upload an APK/IPA file to MobSF.

        Args:
            file_data: Raw file bytes.
            filename: Original filename (e.g., "app.apk").

        Returns:
            MobSF upload response containing 'hash', 'file_name', 'scan_type'.
        """
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(
                f"{self.base_url}/api/v1/upload",
                headers=self.headers,
                files={"file": (filename, file_data)},
            )
            response.raise_for_status()
            return response.json()

    def scan(self, file_hash: str, scan_type: str = "apk", re_scan: bool = False) -> dict:
        """
        Trigger a static scan on an uploaded file.

        Args:
            file_hash: The hash returned by the upload endpoint.
            scan_type: File type — "apk", "ipa", "appx", "zip".
            re_scan: Whether to force a re-scan.

        Returns:
            MobSF scan response.
        """
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(
                f"{self.base_url}/api/v1/scan",
                headers=self.headers,
                data={
                    "hash": file_hash,
                    "scan_type": scan_type,
                    "re_scan": "1" if re_scan else "0",
                },
            )
            response.raise_for_status()
            return response.json()

    def get_report(self, file_hash: str) -> dict:
        """
        Retrieve the full JSON report for a completed scan.

        Args:
            file_hash: The hash returned by the upload endpoint.

        Returns:
            Complete MobSF JSON report with all analysis results.
        """
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(
                f"{self.base_url}/api/v1/report_json",
                headers=self.headers,
                data={"hash": file_hash},
            )
            response.raise_for_status()
            return response.json()

    def get_scorecard(self, file_hash: str) -> dict:
        """Get the security scorecard for a scan."""
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(
                f"{self.base_url}/api/v1/scorecard",
                headers=self.headers,
                data={"hash": file_hash},
            )
            response.raise_for_status()
            return response.json()

    def scan_and_wait(
        self,
        file_data: bytes,
        filename: str,
        poll_interval: int = 5,
        max_wait: int = 600,
    ) -> dict:
        """
        Upload, scan, and poll until the report is ready.

        This is the main entry point for the scan orchestrator.

        Args:
            file_data: Raw file bytes.
            filename: Original filename.
            poll_interval: Seconds between polls.
            max_wait: Maximum wait time in seconds.

        Returns:
            Complete MobSF JSON report.

        Raises:
            TimeoutError: If the scan exceeds max_wait.
        """
        # Step 1: Upload
        upload_result = self.upload(file_data, filename)
        file_hash = upload_result["hash"]
        scan_type = upload_result.get("scan_type", "apk")

        # Step 2: Trigger scan
        self.scan(file_hash, scan_type)

        # Step 3: Poll for report
        elapsed = 0
        while elapsed < max_wait:
            try:
                report = self.get_report(file_hash)
                if report:
                    return report
            except httpx.HTTPStatusError:
                pass

            time.sleep(poll_interval)
            elapsed += poll_interval

        raise TimeoutError(
            f"MobSF scan timed out after {max_wait}s for file {filename}"
        )

    def delete_scan(self, file_hash: str) -> dict:
        """Delete a scan and its report from MobSF."""
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(
                f"{self.base_url}/api/v1/delete_scan",
                headers=self.headers,
                data={"hash": file_hash},
            )
            response.raise_for_status()
            return response.json()

    def get_source_file(
        self,
        file_hash: str,
        file_path: str,
        scan_type: str = "apk",
    ) -> "str | None":
        """
        Retrieve the decompiled source for a specific file inside a MobSF scan.

        Args:
            file_hash: The hash returned by the upload endpoint (md5).
            file_path: Relative path of the file inside the APK/IPA.
            scan_type: File type — "apk", "ipa", "appx", "zip".

        Returns:
            Source code string from the "data" field, or None on any error.
        """
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    f"{self.base_url}/api/v1/view_source",
                    headers=self.headers,
                    data={
                        "hash": file_hash,
                        "file": file_path,
                        "type": scan_type,
                    },
                )
                response.raise_for_status()
                return response.json().get("data")
        except Exception:
            return None

    def is_analyzer_ready(self) -> bool:
        """
        Check if the MobSF dynamic analyzer (emulator) is ready.
        
        Returns:
            True if the analyzer is online and ready for dynamic analysis.
        """
        try:
            with httpx.Client(timeout=10) as client:
                response = client.get(
                    f"{self.base_url}/api/v1/dynamic/is_analyzer_ready",
                    headers=self.headers,
                )
                if response.status_code == 200:
                    return response.json().get("status") == "ready"
        except Exception:
            pass
        return False
