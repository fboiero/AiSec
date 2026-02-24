"""Cloud storage backends for uploading scan reports to S3, GCS, or Azure Blob."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aisec.core.config import AiSecConfig

logger = logging.getLogger(__name__)


class CloudStorageBackend(ABC):
    """Abstract base class for cloud storage backends."""

    def __init__(self, bucket: str, prefix: str = "aisec-reports/") -> None:
        self.bucket = bucket
        self.prefix = prefix.rstrip("/") + "/" if prefix else ""

    @abstractmethod
    def upload(self, local_path: Path, remote_key: str | None = None) -> str:
        """Upload a local file to cloud storage.

        Args:
            local_path: Path to the local file.
            remote_key: Optional remote key; defaults to prefix + filename.

        Returns:
            The remote URI (s3://..., gs://..., etc.).
        """

    @abstractmethod
    def list_reports(self, prefix: str | None = None) -> list[str]:
        """List report keys under the given prefix."""

    def _resolve_key(self, local_path: Path, remote_key: str | None) -> str:
        if remote_key:
            return remote_key
        return f"{self.prefix}{local_path.name}"


class S3Backend(CloudStorageBackend):
    """Amazon S3 storage backend."""

    def __init__(self, bucket: str, prefix: str = "aisec-reports/", **kwargs: Any) -> None:
        super().__init__(bucket, prefix)
        try:
            import boto3
        except ImportError as exc:
            raise ImportError(
                "boto3 is required for S3 storage. Install with: pip install aisec[cloud]"
            ) from exc
        self._client = boto3.client("s3", **kwargs)

    def upload(self, local_path: Path, remote_key: str | None = None) -> str:
        key = self._resolve_key(local_path, remote_key)
        logger.info("Uploading %s to s3://%s/%s", local_path, self.bucket, key)
        self._client.upload_file(str(local_path), self.bucket, key)
        return f"s3://{self.bucket}/{key}"

    def list_reports(self, prefix: str | None = None) -> list[str]:
        pfx = prefix or self.prefix
        resp = self._client.list_objects_v2(Bucket=self.bucket, Prefix=pfx)
        return [obj["Key"] for obj in resp.get("Contents", [])]


class GCSBackend(CloudStorageBackend):
    """Google Cloud Storage backend."""

    def __init__(self, bucket: str, prefix: str = "aisec-reports/", **kwargs: Any) -> None:
        super().__init__(bucket, prefix)
        try:
            from google.cloud import storage as gcs
        except ImportError as exc:
            raise ImportError(
                "google-cloud-storage is required for GCS storage. "
                "Install with: pip install aisec[cloud]"
            ) from exc
        client = gcs.Client(**kwargs)
        self._bucket = client.bucket(bucket)

    def upload(self, local_path: Path, remote_key: str | None = None) -> str:
        key = self._resolve_key(local_path, remote_key)
        logger.info("Uploading %s to gs://%s/%s", local_path, self.bucket, key)
        blob = self._bucket.blob(key)
        blob.upload_from_filename(str(local_path))
        return f"gs://{self.bucket}/{key}"

    def list_reports(self, prefix: str | None = None) -> list[str]:
        pfx = prefix or self.prefix
        return [blob.name for blob in self._bucket.list_blobs(prefix=pfx)]


class AzureBlobBackend(CloudStorageBackend):
    """Azure Blob Storage backend."""

    def __init__(self, bucket: str, prefix: str = "aisec-reports/", **kwargs: Any) -> None:
        super().__init__(bucket, prefix)
        try:
            from azure.storage.blob import BlobServiceClient
        except ImportError as exc:
            raise ImportError(
                "azure-storage-blob is required for Azure storage. "
                "Install with: pip install aisec[cloud]"
            ) from exc
        conn_str = kwargs.pop("connection_string", None)
        if conn_str:
            service = BlobServiceClient.from_connection_string(conn_str, **kwargs)
        else:
            account_url = kwargs.pop("account_url", f"https://{bucket}.blob.core.windows.net")
            service = BlobServiceClient(account_url=account_url, **kwargs)
        self._container_client = service.get_container_client(bucket)

    def upload(self, local_path: Path, remote_key: str | None = None) -> str:
        key = self._resolve_key(local_path, remote_key)
        logger.info("Uploading %s to azure://%s/%s", local_path, self.bucket, key)
        with open(local_path, "rb") as f:
            self._container_client.upload_blob(name=key, data=f, overwrite=True)
        return f"azure://{self.bucket}/{key}"

    def list_reports(self, prefix: str | None = None) -> list[str]:
        pfx = prefix or self.prefix
        return [blob.name for blob in self._container_client.list_blobs(name_starts_with=pfx)]


_BACKENDS: dict[str, type[CloudStorageBackend]] = {
    "s3": S3Backend,
    "gcs": GCSBackend,
    "azure": AzureBlobBackend,
}


def get_storage_backend(config: AiSecConfig) -> CloudStorageBackend:
    """Create a cloud storage backend from the AiSec configuration.

    Raises:
        ValueError: If the backend name is unrecognised or bucket is empty.
    """
    backend_name = config.cloud_storage_backend.lower().strip()
    if not backend_name:
        raise ValueError("cloud_storage_backend is not configured")
    if backend_name not in _BACKENDS:
        raise ValueError(
            f"Unknown cloud storage backend: {backend_name!r}. "
            f"Supported: {', '.join(_BACKENDS)}"
        )
    if not config.cloud_storage_bucket:
        raise ValueError("cloud_storage_bucket must be set when using cloud storage")

    cls = _BACKENDS[backend_name]
    return cls(bucket=config.cloud_storage_bucket, prefix=config.cloud_storage_prefix)
