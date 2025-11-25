#!/usr/bin/env python3
"""
RHTPA API Upload Script
Uploads SBOMs to RHTPA (Trustify) API using OIDC authentication
"""
import os
import sys
from urllib.parse import urljoin

import requests  # type: ignore[import-untyped]
import urllib3

# Disable warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_env_var(name: str) -> str:
    """Get required environment variable."""
    value = os.environ.get(name)
    if not value:
        print(
            f"ERROR: Missing required environment variable: {name}",
            file=sys.stderr,
        )
        sys.exit(1)
    return value


def get_oidc_token(issuer_url: str, client_id: str, client_secret: str) -> str:
    """Get OIDC token using client credentials grant."""
    token_url = f"{issuer_url}/protocol/openid-connect/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }

    print(f"Requesting OIDC token from {token_url}...")
    try:
        # Verify SSL using environment variables (REQUESTS_CA_BUNDLE) or default
        verify_ssl = os.environ.get("REQUESTS_CA_BUNDLE", True)
        if verify_ssl == "False" or verify_ssl == "false":
            verify_ssl = False

        response = requests.post(token_url, data=data, verify=verify_ssl, timeout=30)
        response.raise_for_status()
        return response.json()["access_token"]
    except Exception as e:
        print(f"ERROR: Failed to get OIDC token: {e}", file=sys.stderr)
        if "response" in locals():
            print(f"Response: {response.text}", file=sys.stderr)
        sys.exit(1)


def upload_sbom(api_url: str, token: str, file_path: str) -> bool:
    """Upload SBOM to RHTPA API.

    Uses v2 API endpoint which automatically stores SBOM in S3
    and metadata in Postgres.
    Reference: https://github.com/guacsec/trustify-ui
    """
    upload_url = urljoin(api_url, "/api/v2/sbom")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    print(f"Uploading {file_path} to {upload_url}...")

    try:
        with open(file_path, "rb") as f:
            sbom_data = f.read()

        # Verify SSL
        verify_ssl = os.environ.get("REQUESTS_CA_BUNDLE", True)
        if verify_ssl == "False" or verify_ssl == "false":
            verify_ssl = False

        response = requests.post(
            upload_url,
            headers=headers,
            data=sbom_data,
            verify=verify_ssl,
            timeout=60,
        )
        response.raise_for_status()
        print(f"SUCCESS: Uploaded {file_path}")
        print(f"Response: {response.text}")
        return True
    except Exception as e:
        print(f"ERROR: Failed to upload SBOM: {e}", file=sys.stderr)
        if "response" in locals():
            print(f"Response: {response.text}", file=sys.stderr)
        return False


def main() -> None:
    """Main entry point."""
    rhtpa_api_url: str = get_env_var("RHTPA_API_URL")
    oidc_issuer_url: str = get_env_var("OIDC_ISSUER_URL")
    client_id: str = get_env_var("OIDC_CLIENT_ID")
    client_secret: str = get_env_var("OIDC_CLIENT_SECRET")
    sbom_file: str = get_env_var("SBOM_FILE")

    token = get_oidc_token(oidc_issuer_url, client_id, client_secret)

    if upload_sbom(rhtpa_api_url, token, sbom_file):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
