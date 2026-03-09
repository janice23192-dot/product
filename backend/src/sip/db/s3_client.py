"""S3/MinIO object storage client.

Manages raw data, archives, evidence, reports, and backups.
Req 12.1-12.12, 18.1-18.12.
"""

from __future__ import annotations

import io
from typing import Any


class S3Client:
    """S3-compatible object storage client."""

    def __init__(
        self,
        endpoint_url: str,
        access_key: str,
        secret_key: str,
        region: str = "us-east-1",
    ) -> None:
        self.endpoint_url = endpoint_url
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self._client: Any = None

    async def init(self, buckets: list[str] | None = None) -> None:
        """Initialize S3 client and create buckets."""
        import boto3

        self._client = boto3.client(
            "s3",
            endpoint_url=self.endpoint_url,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=self.region,
        )

        default_buckets = buckets or [
            "sip-raw-data", "sip-archived-data", "sip-evidence",
            "sip-reports", "sip-backups",
        ]
        for bucket in default_buckets:
            try:
                self._client.create_bucket(Bucket=bucket)
            except Exception:
                pass  # Bucket may already exist

    async def put_object(self, bucket: str, key: str, data: bytes, metadata: dict[str, str] | None = None) -> None:
        """Store an object. Req 12.9 - encrypted at rest via server-side encryption."""
        params: dict[str, Any] = {
            "Bucket": bucket,
            "Key": key,
            "Body": data,
            "ServerSideEncryption": "AES256",
        }
        if metadata:
            params["Metadata"] = metadata
        self._client.put_object(**params)

    async def get_object(self, bucket: str, key: str) -> bytes:
        """Retrieve an object."""
        response = self._client.get_object(Bucket=bucket, Key=key)
        return response["Body"].read()

    async def delete_object(self, bucket: str, key: str) -> None:
        """Delete an object. Req 12.11."""
        self._client.delete_object(Bucket=bucket, Key=key)

    async def list_objects(self, bucket: str, prefix: str = "", max_keys: int = 1000) -> list[dict[str, Any]]:
        """List objects in a bucket."""
        response = self._client.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=max_keys)
        return [
            {"key": obj["Key"], "size": obj["Size"], "last_modified": obj["LastModified"].isoformat()}
            for obj in response.get("Contents", [])
        ]

    async def get_object_metadata(self, bucket: str, key: str) -> dict[str, Any]:
        """Get object metadata without downloading content."""
        response = self._client.head_object(Bucket=bucket, Key=key)
        return {
            "content_length": response["ContentLength"],
            "content_type": response.get("ContentType", ""),
            "last_modified": response["LastModified"].isoformat(),
            "metadata": response.get("Metadata", {}),
        }

    def close(self) -> None:
        """Close the S3 client."""
        pass  # boto3 doesn't require explicit close

    def ping(self) -> bool:
        """Health check."""
        try:
            self._client.list_buckets()
            return True
        except Exception:
            return False
