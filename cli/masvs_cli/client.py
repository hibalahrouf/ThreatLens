"""
MASVS CLI — HTTP API Client
All CLI commands go through this client to communicate with the backend.
"""

import os
import sys
from typing import Optional

import httpx

# Default config path
CONFIG_DIR = os.path.expanduser("~/.masvs")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.toml")


def _load_config() -> dict:
    """Load CLI config from ~/.masvs/config.toml."""
    if not os.path.exists(CONFIG_FILE):
        return {"server_url": "http://localhost:8000", "token": ""}
    try:
        import tomli
        with open(CONFIG_FILE, "rb") as f:
            return tomli.load(f)
    except Exception:
        return {"server_url": "http://localhost:8000", "token": ""}


def _save_config(config: dict):
    """Save CLI config to ~/.masvs/config.toml."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    lines = []
    for key, value in config.items():
        if isinstance(value, str):
            lines.append(f'{key} = "{value}"')
        else:
            lines.append(f"{key} = {value}")
    with open(CONFIG_FILE, "w") as f:
        f.write("\n".join(lines) + "\n")


class APIClient:
    """HTTP client for the MASVS Audit Copilot API."""

    def __init__(self):
        config = _load_config()
        self.base_url = config.get("server_url", "http://localhost:8000").rstrip("/")
        self.token = config.get("token", "")

    @property
    def headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def get(self, path: str, **kwargs) -> httpx.Response:
        with httpx.Client(timeout=30) as client:
            return client.get(f"{self.base_url}{path}", headers=self.headers, **kwargs)

    def post(self, path: str, **kwargs) -> httpx.Response:
        with httpx.Client(timeout=300) as client:
            return client.post(f"{self.base_url}{path}", headers=self.headers, **kwargs)

    def patch(self, path: str, **kwargs) -> httpx.Response:
        with httpx.Client(timeout=30) as client:
            return client.patch(f"{self.base_url}{path}", headers=self.headers, **kwargs)

    def upload_file(self, path: str, file_path: str, data: dict = None) -> httpx.Response:
        """Upload a file via multipart form."""
        with httpx.Client(timeout=600) as client:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                headers = {}
                if self.token:
                    headers["Authorization"] = f"Bearer {self.token}"
                return client.post(
                    f"{self.base_url}{path}",
                    headers=headers,
                    files=files,
                    data=data or {},
                )

    def download_file(self, path: str, output_path: str) -> str:
        """Download a file and save it to disk."""
        with httpx.Client(timeout=120) as client:
            response = client.get(f"{self.base_url}{path}", headers=self.headers)
            response.raise_for_status()
            with open(output_path, "wb") as f:
                f.write(response.content)
            return output_path


def save_token(token: str):
    """Save API token to config."""
    config = _load_config()
    config["token"] = token
    _save_config(config)


def save_server_url(url: str):
    """Save server URL to config."""
    config = _load_config()
    config["server_url"] = url
    _save_config(config)
