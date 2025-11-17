#!/usr/bin/env python3
"""
RHTPA API Upload Script
Uploads SBOMs to RHTPA (Trustify) API using OIDC authentication
"""
import os
import sys
import time
import json
import requests
from urllib.parse import urljoin

def get_env_var(name, required=True):
    value = os.environ.get(name)
    if required and not value:
        print(f"ERROR: Missing required environment variable: {name}", file=sys.stderr)
        sys.exit(1)
    return value

def get_oidc_token(issuer_url, client_id, client_secret):
    token_url = f"{issuer_url}/protocol/openid-connect/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    }
    
    print(f"Requesting OIDC token from {token_url}...")
    try:
        response = requests.post(token_url, data=data, verify=False) # verify=False for internal svc
        response.raise_for_status()
        return response.json()["access_token"]
    except Exception as e:
        print(f"ERROR: Failed to get OIDC token: {e}", file=sys.stderr)
        if 'response' in locals():
            print(f"Response: {response.text}", file=sys.stderr)
        sys.exit(1)

def upload_sbom(api_url, token, file_path):
    # Use v2 API endpoint - automatically stores SBOM in S3 and metadata in Postgres
    # Reference: https://github.com/guacsec/trustify-ui/blob/main/e2e/tests/api/dependencies/global.setup.ts#L38
    upload_url = urljoin(api_url, "/api/v2/sbom")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    print(f"Uploading {file_path} to {upload_url}...")
    
    try:
        with open(file_path, 'rb') as f:
            # Read file content to ensure it's valid JSON
            # Trustify expects the JSON body directly
            sbom_data = f.read()
            
        response = requests.post(upload_url, headers=headers, data=sbom_data, verify=False)
        response.raise_for_status()
        print(f"SUCCESS: Uploaded {file_path}")
        print(f"Response: {response.text}")
        return True
    except Exception as e:
        print(f"ERROR: Failed to upload SBOM: {e}", file=sys.stderr)
        if 'response' in locals():
            print(f"Response: {response.text}", file=sys.stderr)
        return False

def main():
    # Configuration
    rhtpa_api_url = get_env_var("RHTPA_API_URL")
    oidc_issuer_url = get_env_var("OIDC_ISSUER_URL")
    client_id = get_env_var("OIDC_CLIENT_ID")
    client_secret = get_env_var("OIDC_CLIENT_SECRET")
    sbom_file = get_env_var("SBOM_FILE")
    
    # Get Token
    token = get_oidc_token(oidc_issuer_url, client_id, client_secret)
    
    # Upload
    if upload_sbom(rhtpa_api_url, token, sbom_file):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    # Disable warnings for self-signed certs
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()

