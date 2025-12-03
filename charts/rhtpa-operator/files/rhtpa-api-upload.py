#!/usr/bin/env python3
"""
RHTPA API Upload Script
Uploads SBOMs to RHTPA (Trustify) API using OIDC authentication

Uses Python standard library (urllib) instead of third-party packages.
"""
import json
import os
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen


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


def get_ssl_context() -> ssl.SSLContext:
    """Create SSL context for certificate verification."""
    ssl_context = ssl.create_default_context()
    
    # Load CA bundle if specified
    ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE")
    if ca_bundle and os.path.exists(ca_bundle):
        ssl_context.load_verify_locations(ca_bundle)
    
    return ssl_context


def get_oidc_token(issuer_url: str, client_id: str, client_secret: str, ssl_context: ssl.SSLContext) -> str:
    """Get OIDC token using client credentials grant."""
    token_url = f"{issuer_url}/protocol/openid-connect/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }

    print(f"Requesting OIDC token from {token_url}...")
    try:
        # Encode data as application/x-www-form-urlencoded
        encoded_data = urlencode(data).encode('utf-8')
        
        request = Request(
            token_url,
            data=encoded_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            method='POST'
        )
        
        response = urlopen(request, context=ssl_context, timeout=30)
        response_data = json.loads(response.read().decode('utf-8'))
        return response_data["access_token"]
    except HTTPError as e:
        error_body = e.read().decode('utf-8') if e.fp else "No response body"
        print(f"ERROR: Failed to get OIDC token: HTTP {e.code} {e.reason}", file=sys.stderr)
        print(f"Response: {error_body}", file=sys.stderr)
        sys.exit(1)
    except (URLError, Exception) as e:
        print(f"ERROR: Failed to get OIDC token: {e}", file=sys.stderr)
        sys.exit(1)


def upload_sbom(api_url: str, token: str, file_path: str, ssl_context: ssl.SSLContext) -> bool:
    """Upload SBOM to RHTPA API.

    Uses v2 API endpoint which automatically stores SBOM in S3
    and metadata in Postgres.
    Reference: https://github.com/guacsec/trustify-ui
    """
    upload_url = urljoin(api_url, "/api/v2/sbom")
    
    print(f"Uploading {file_path} to {upload_url}...")

    try:
        with open(file_path, "rb") as f:
            sbom_data = f.read()

        request = Request(
            upload_url,
            data=sbom_data,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            method='POST'
        )
        
        response = urlopen(request, context=ssl_context, timeout=60)
        response_body = response.read().decode('utf-8')
        print(f"SUCCESS: Uploaded {file_path}")
        print(f"Response: {response_body}")
        return True
    except HTTPError as e:
        error_body = e.read().decode('utf-8') if e.fp else "No response body"
        print(f"ERROR: Failed to upload SBOM: HTTP {e.code} {e.reason}", file=sys.stderr)
        print(f"Response: {error_body}", file=sys.stderr)
        return False
    except (URLError, IOError, Exception) as e:
        print(f"ERROR: Failed to upload SBOM: {e}", file=sys.stderr)
        return False


def main() -> None:
    """Main entry point."""
    rhtpa_api_url: str = get_env_var("RHTPA_API_URL")
    oidc_issuer_url: str = get_env_var("OIDC_ISSUER_URL")
    client_id: str = get_env_var("OIDC_CLIENT_ID")
    client_secret: str = get_env_var("OIDC_CLIENT_SECRET")
    sbom_file: str = get_env_var("SBOM_FILE")

    ssl_context = get_ssl_context()
    token = get_oidc_token(oidc_issuer_url, client_id, client_secret, ssl_context)

    if upload_sbom(rhtpa_api_url, token, sbom_file, ssl_context):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
