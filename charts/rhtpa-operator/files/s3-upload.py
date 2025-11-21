#!/usr/bin/env python3
"""
S3 Upload Script for SBOM files
Uses boto3 to upload files to S3-compatible storage (NooBaa/MinIO/AWS S3)
"""
import os
import sys

import boto3  # type: ignore[import-untyped]
from botocore.client import Config  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]


def main() -> None:
    # Get parameters from environment variables
    file_path = os.environ.get("UPLOAD_FILE_PATH")
    bucket = os.environ.get("S3_BUCKET")
    s3_key = os.environ.get("UPLOAD_S3_KEY")
    endpoint = os.environ.get("S3_ENDPOINT")
    access_key = os.environ.get("S3_ACCESS_KEY")
    secret_key = os.environ.get("S3_SECRET_KEY")
    ca_bundle = os.environ.get(
        "S3_CA_BUNDLE", "/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt"
    )

    # Validate required parameters
    if not all([file_path, bucket, s3_key, endpoint, access_key, secret_key]):
        print("    ERROR: Missing required S3 parameters", file=sys.stderr)
        print(f"      File: {file_path or 'NOT SET'}", file=sys.stderr)
        print(f"      Bucket: {bucket or 'NOT SET'}", file=sys.stderr)
        print(f"      Key: {s3_key or 'NOT SET'}", file=sys.stderr)
        print(f"      Endpoint: {endpoint or 'NOT SET'}", file=sys.stderr)
        print(
            f"      Access Key: {'SET' if access_key else 'NOT SET'}", file=sys.stderr
        )
        print(
            f"      Secret Key: {'SET' if secret_key else 'NOT SET'}", file=sys.stderr
        )
        sys.exit(1)

    # Type narrowing - after validation, these are guaranteed to be strings
    file_path_str: str = file_path  # type: ignore[assignment]
    bucket_str: str = bucket  # type: ignore[assignment]
    s3_key_str: str = s3_key  # type: ignore[assignment]
    endpoint_str: str = endpoint  # type: ignore[assignment]
    access_key_str: str = access_key  # type: ignore[assignment]
    secret_key_str: str = secret_key  # type: ignore[assignment]

    try:
        # Determine SSL verification setting
        # Use service CA bundle if available, otherwise use system default
        verify_ssl = ca_bundle if os.path.exists(ca_bundle) else True

        # Create S3 client with custom endpoint and proper SSL verification
        s3_client = boto3.client(
            "s3",
            endpoint_url=endpoint_str,
            aws_access_key_id=access_key_str,
            aws_secret_access_key=secret_key_str,
            config=Config(signature_version="s3v4"),
            verify=verify_ssl,  # Use OpenShift service CA for SSL verification
        )

        # Upload file to S3
        with open(file_path_str, "rb") as f:
            s3_client.put_object(Bucket=bucket_str, Key=f"sboms/{s3_key_str}", Body=f)

        print(f"    SUCCESS: File uploaded to s3://{bucket_str}/sboms/{s3_key_str}")
        sys.exit(0)

    except FileNotFoundError:
        print(f"    ERROR: File not found: {file_path_str}", file=sys.stderr)
        sys.exit(1)
    except ClientError as e:
        print(f"    ERROR: S3 client error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"    ERROR: Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
