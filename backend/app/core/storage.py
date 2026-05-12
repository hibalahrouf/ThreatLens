"""
MASVS Audit Copilot — MinIO Storage Helper
Handles file upload/download to MinIO object storage.
"""

import hashlib
from io import BytesIO
from typing import Optional

from minio import Minio
from minio.error import S3Error

from app.core.config import settings


class StorageClient:
    """MinIO object storage client for APK/IPA files and reports."""

    def __init__(self):
        self.client = Minio(
            endpoint=settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_USE_SSL,
        )
        self.bucket = settings.MINIO_BUCKET

    def ensure_bucket(self) -> None:
        """Create the bucket if it doesn't exist."""
        if not self.client.bucket_exists(self.bucket):
            self.client.make_bucket(self.bucket)

    def upload_file(
        self,
        file_data: bytes,
        object_name: str,
        content_type: str = "application/octet-stream",
    ) -> str:
        """
        Upload a file to MinIO.

        Args:
            file_data: Raw file bytes.
            object_name: Path in the bucket (e.g., "scans/123/app.apk").
            content_type: MIME type.

        Returns:
            The object name (path) in the bucket.
        """
        self.ensure_bucket()
        data_stream = BytesIO(file_data)
        self.client.put_object(
            bucket_name=self.bucket,
            object_name=object_name,
            data=data_stream,
            length=len(file_data),
            content_type=content_type,
        )
        return object_name

    def download_file(self, object_name: str) -> bytes:
        """
        Download a file from MinIO.

        Args:
            object_name: Path in the bucket.

        Returns:
            Raw file bytes.
        """
        response = self.client.get_object(self.bucket, object_name)
        data = response.read()
        response.close()
        response.release_conn()
        return data

    def get_presigned_url(
        self,
        object_name: str,
        expires_hours: int = 1,
    ) -> str:
        """
        Generate a presigned download URL.

        Args:
            object_name: Path in the bucket.
            expires_hours: URL validity in hours.

        Returns:
            Presigned URL string.
        """
        from datetime import timedelta

        return self.client.presigned_get_object(
            self.bucket,
            object_name,
            expires=timedelta(hours=expires_hours),
        )

    def delete_file(self, object_name: str) -> None:
        """Delete a file from MinIO."""
        self.client.remove_object(self.bucket, object_name)

    @staticmethod
    def compute_sha256(file_data: bytes) -> str:
        """Compute SHA-256 hash of file data."""
        return hashlib.sha256(file_data).hexdigest()


# ─── Singleton ───
storage_client = StorageClient()
