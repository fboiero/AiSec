"""Tests for cloud storage backends (v1.7.0)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from aisec.core.cloud_storage import (
    CloudStorageBackend,
    S3Backend,
    GCSBackend,
    AzureBlobBackend,
    get_storage_backend,
    _BACKENDS,
)
from aisec.core.config import AiSecConfig


class TestCloudStorageBackendABC:
    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            CloudStorageBackend(bucket="test")

    def test_backends_registered(self):
        assert "s3" in _BACKENDS
        assert "gcs" in _BACKENDS
        assert "azure" in _BACKENDS

    def test_resolve_key_default(self):
        class DummyBackend(CloudStorageBackend):
            def upload(self, local_path, remote_key=None):
                return self._resolve_key(local_path, remote_key)

            def list_reports(self, prefix=None):
                return []

        b = DummyBackend(bucket="test", prefix="reports/")
        assert b._resolve_key(Path("/tmp/report.json"), None) == "reports/report.json"

    def test_resolve_key_custom(self):
        class DummyBackend(CloudStorageBackend):
            def upload(self, local_path, remote_key=None):
                return self._resolve_key(local_path, remote_key)

            def list_reports(self, prefix=None):
                return []

        b = DummyBackend(bucket="test", prefix="reports/")
        assert b._resolve_key(Path("/tmp/report.json"), "custom/key.json") == "custom/key.json"

    def test_prefix_normalisation(self):
        class DummyBackend(CloudStorageBackend):
            def upload(self, local_path, remote_key=None):
                return ""

            def list_reports(self, prefix=None):
                return []

        b = DummyBackend(bucket="test", prefix="no-trailing-slash")
        assert b.prefix == "no-trailing-slash/"


class TestS3Backend:
    @patch("aisec.core.cloud_storage.boto3", create=True)
    def test_upload(self, mock_boto3):
        import sys
        sys.modules["boto3"] = mock_boto3
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client

        backend = S3Backend.__new__(S3Backend)
        backend.bucket = "my-bucket"
        backend.prefix = "aisec-reports/"
        backend._client = mock_client

        result = backend.upload(Path("/tmp/report.json"))
        mock_client.upload_file.assert_called_once_with(
            "/tmp/report.json", "my-bucket", "aisec-reports/report.json"
        )
        assert result == "s3://my-bucket/aisec-reports/report.json"

    @patch("aisec.core.cloud_storage.boto3", create=True)
    def test_list_reports(self, mock_boto3):
        import sys
        sys.modules["boto3"] = mock_boto3
        mock_client = MagicMock()
        mock_client.list_objects_v2.return_value = {
            "Contents": [{"Key": "aisec-reports/r1.json"}, {"Key": "aisec-reports/r2.json"}]
        }

        backend = S3Backend.__new__(S3Backend)
        backend.bucket = "my-bucket"
        backend.prefix = "aisec-reports/"
        backend._client = mock_client

        result = backend.list_reports()
        assert len(result) == 2
        assert "aisec-reports/r1.json" in result


class TestGCSBackend:
    def test_upload_mocked(self):
        mock_blob = MagicMock()
        mock_bucket = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        backend = GCSBackend.__new__(GCSBackend)
        backend.bucket = "my-gcs-bucket"
        backend.prefix = "aisec-reports/"
        backend._bucket = mock_bucket

        result = backend.upload(Path("/tmp/report.html"))
        mock_bucket.blob.assert_called_once_with("aisec-reports/report.html")
        mock_blob.upload_from_filename.assert_called_once_with("/tmp/report.html")
        assert result == "gs://my-gcs-bucket/aisec-reports/report.html"

    def test_list_reports_mocked(self):
        mock_blob1 = MagicMock()
        mock_blob1.name = "aisec-reports/r1.json"
        mock_blob2 = MagicMock()
        mock_blob2.name = "aisec-reports/r2.html"

        mock_bucket = MagicMock()
        mock_bucket.list_blobs.return_value = [mock_blob1, mock_blob2]

        backend = GCSBackend.__new__(GCSBackend)
        backend.bucket = "my-gcs-bucket"
        backend.prefix = "aisec-reports/"
        backend._bucket = mock_bucket

        result = backend.list_reports()
        assert len(result) == 2


class TestAzureBlobBackend:
    def test_upload_mocked(self):
        mock_container_client = MagicMock()

        backend = AzureBlobBackend.__new__(AzureBlobBackend)
        backend.bucket = "my-container"
        backend.prefix = "aisec-reports/"
        backend._container_client = mock_container_client

        with patch("builtins.open", mock_open(read_data=b"data")):
            result = backend.upload(Path("/tmp/report.json"))

        assert result == "azure://my-container/aisec-reports/report.json"
        mock_container_client.upload_blob.assert_called_once()

    def test_list_reports_mocked(self):
        mock_blob1 = MagicMock()
        mock_blob1.name = "aisec-reports/r1.json"

        mock_container_client = MagicMock()
        mock_container_client.list_blobs.return_value = [mock_blob1]

        backend = AzureBlobBackend.__new__(AzureBlobBackend)
        backend.bucket = "my-container"
        backend.prefix = "aisec-reports/"
        backend._container_client = mock_container_client

        result = backend.list_reports()
        assert len(result) == 1


class TestGetStorageBackend:
    def test_empty_backend_raises(self):
        config = AiSecConfig(
            target_image="test:latest",
            cloud_storage_backend="",
        )
        with pytest.raises(ValueError, match="not configured"):
            get_storage_backend(config)

    def test_unknown_backend_raises(self):
        config = AiSecConfig(
            target_image="test:latest",
            cloud_storage_backend="dropbox",
            cloud_storage_bucket="b",
        )
        with pytest.raises(ValueError, match="Unknown cloud storage backend"):
            get_storage_backend(config)

    def test_missing_bucket_raises(self):
        config = AiSecConfig(
            target_image="test:latest",
            cloud_storage_backend="s3",
            cloud_storage_bucket="",
        )
        with pytest.raises(ValueError, match="cloud_storage_bucket must be set"):
            get_storage_backend(config)
