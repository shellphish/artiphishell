"""This module contains repositories and other classes for interacting with S3-compatible bucket stores."""

from typing import Any, Dict, Literal, Optional, overload

from types_aiobotocore_s3.client import S3Client
from types_aiobotocore_s3.type_defs import CreateMultipartUploadOutputTypeDef
import botocore.exceptions
import botocore.utils

from pydatatask.host import LOCAL_HOST, Host
from pydatatask.session import Ephemeral
from pydatatask.utils import AReadText, AWriteText

from .base import BlobRepository, Repository, YamlMetadataRepository, job_getter

BUFFER_THRESHOLD = 1024 * 1024 * 5


class S3BucketBinaryWriter:
    """A class for streaming byte data to be written to an `S3BucketRepository`."""

    def __init__(self, mpu: CreateMultipartUploadOutputTypeDef, client: S3Client):
        self.mpu = mpu
        self.client = client
        self.etags = []
        self.buffer = bytearray()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        """Close and flush the data to the bucket."""
        if self.buffer:
            part = await self.client.upload_part(
                Bucket=self.mpu["Bucket"],
                Key=self.mpu["Key"],
                UploadId=self.mpu["UploadId"],
                PartNumber=len(self.etags) + 1,
                Body=self.buffer,
            )
            self.etags.append(part["ETag"])
            self.buffer.clear()

        parts = [{"ETag": etag, "PartNumber": i + 1} for i, etag in enumerate(self.etags)]
        await self.client.complete_multipart_upload(
            Bucket=self.mpu["Bucket"],
            Key=self.mpu["Key"],
            UploadId=self.mpu["UploadId"],
            MultipartUpload={"Parts": parts},
        )

    async def write(self, data: bytes, /) -> int:
        if not data:
            return 0
        self.buffer.extend(data)
        if len(self.buffer) >= BUFFER_THRESHOLD:
            """Write some data to the stream."""
            part = await self.client.upload_part(
                Bucket=self.mpu["Bucket"],
                Key=self.mpu["Key"],
                UploadId=self.mpu["UploadId"],
                PartNumber=len(self.etags) + 1,
                Body=self.buffer,
            )
            self.etags.append(part["ETag"])
            self.buffer.clear()
        return len(data)


class S3BucketReader:
    """A class for streaming byte data from an `S3BucketRepository`."""

    def __init__(self, body):
        self.body = body

    async def close(self):
        """Close and release the stream."""
        self.body.close()

    async def read(self, n=None):
        """Read the body of :he blob."""
        return await self.body.read(n)

    async def __aenter__(self):
        await self.body.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.body.__aexit__(exc_type, exc_val, exc_tb)


class S3BucketRepositoryBase(Repository):
    """A base class for repositories that store their contents in S3-compatible buckets."""

    def __init__(
        self,
        client: Ephemeral[S3Client],
        bucket: str,
        endpoints: Optional[Dict[Optional[Host], str]] = None,
    ):
        super().__init__()
        self._client = client
        self.bucket = bucket
        self.endpoints = endpoints or {}

    def footprint(self):
        yield self

    def __getstate__(self) -> Any:
        return (self.endpoints, self.bucket)

    @property
    def client(self):
        """The aiobotocore S3 client.

        This will raise an error if the client comes from a session which is not opened.
        """
        return self._client()

    def get_endpoint(self, host: Host) -> str:
        """Given a host, return the endpoint that makes sense."""
        if host == LOCAL_HOST:
            return self.client._endpoint.host  # type: ignore
        endpoint = self.endpoints.get(host, None)
        if endpoint is None:
            endpoint = self.endpoints.get(None, None)
        if endpoint is None:
            raise ValueError(f"No endpoint specified from host {host}")
        return endpoint


class S3BucketRepository(S3BucketRepositoryBase, BlobRepository):
    """A repository where keys are paths in a S3 bucket.

    Provides a streaming interface to the corresponding blobs.
    """

    def __init__(
        self,
        client: Ephemeral[S3Client],
        bucket: str,
        prefix: str = "",
        suffix: str = "",
        mimetype: str = "application/octet-stream",
        endpoints: Optional[Dict[Optional[Host], str]] = None,
    ):
        """
        :param client: A callable returning an aiobotocore S3 client connected and authenticated to the server you wish
                       to store things on.
        :param bucket: The name of the bucket from which to load and store.
        :param prefix: A prefix to put on the job name before translating it into a bucket path. If this is meant to be
                       a directory name it should end with a slash character.
        :param suffix: A suffix to put on the job name before translating it into a bucket path. If this is meant to
                          be a file extension it should start with a dot.
        :param mimetype: The MIME type to set the content when adding data.
        :param incluster_endpoint: Optional: An endpoint URL to provide as the result of info() queries instead of
                                   extracting the URL from ``client``.
        """
        super().__init__(client, bucket, endpoints)
        self.prefix = prefix
        self.suffix = suffix
        self.mimetype = mimetype

    async def cache_key(self, job):
        return f"bucket:{self.bucket}/{self.prefix}{job}{self.suffix}"

    def __getstate__(self):
        return (super().__getstate__(), self.prefix, self.suffix, self.mimetype)

    def __repr__(self):
        return f"<{type(self).__name__} {self.bucket}/{self.prefix}*{self.suffix}>"

    async def contains(self, item, /):
        try:
            await self.client.head_object(Bucket=self.bucket, Key=self.object_name(item))
        except botocore.exceptions.ClientError:
            return False
        else:
            return True

    async def unfiltered_iter(self):
        paginator = self.client.get_paginator("list_objects")
        async for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for obj in page.get("Contents", []):
                if obj.get("Key", "").endswith(self.suffix):
                    yield obj.get("Key", "")[len(self.prefix) : -len(self.suffix) if self.suffix else None]

    async def validate(self):
        try:
            await self.client.create_bucket(Bucket=self.bucket)
        except self.client.exceptions.BucketAlreadyOwnedByYou:
            pass
        await super().validate()

    def object_name(self, job):
        """Return the object name for the given job."""
        return f"{self.prefix}{job}{self.suffix}"

    @overload
    async def open(self, job: str, mode: Literal["r"]) -> AReadText: ...

    @overload
    async def open(self, job: str, mode: Literal["w"]) -> AWriteText: ...

    @overload
    async def open(self, job: str, mode: Literal["rb"]) -> S3BucketReader: ...

    @overload
    async def open(self, job: str, mode: Literal["wb"]) -> S3BucketBinaryWriter: ...

    @job_getter
    async def open(self, job, mode="r"):
        if not self.is_valid_job_id(job):
            raise KeyError(job)
        if mode == "wb":
            mpu = await self.client.create_multipart_upload(
                Bucket=self.bucket, Key=self.object_name(job), ContentType=self.mimetype
            )
            return S3BucketBinaryWriter(mpu, self.client)
        elif mode == "w":
            mpu = await self.client.create_multipart_upload(
                Bucket=self.bucket, Key=self.object_name(job), ContentType=self.mimetype
            )
            return AWriteText(S3BucketBinaryWriter(mpu, self.client))
        elif mode == "rb":
            return S3BucketReader((await self.client.get_object(Bucket=self.bucket, Key=self.object_name(job)))["Body"])
        elif mode == "r":
            return AReadText(
                S3BucketReader((await self.client.get_object(Bucket=self.bucket, Key=self.object_name(job)))["Body"])
            )
        else:
            raise ValueError(mode)

    async def delete(self, job, /):
        await self.client.delete_object(Bucket=self.bucket, Key=self.object_name(job))


class YamlMetadataS3Repository(YamlMetadataRepository):
    """A metadata repository based on a s3 bucket repository."""

    def __init__(self, client, bucket, prefix, suffix=".yaml", mimetype="text/yaml"):
        super().__init__(S3BucketRepository(client, bucket, prefix, suffix=suffix, mimetype=mimetype))

    @job_getter
    async def info(self, job, /):
        try:
            return await super().info(job)
        except botocore.exceptions.ClientError as e:
            if "NoSuchKey" in str(e):
                return {}
            else:
                raise
