#!/opt/app-root/bin/python
"""
RHTAS Artifact Signing Application
Signs container images and artifacts using cosign with SPIFFE identity
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class ArtifactSigner:
    """RHTAS artifact signer using cosign with SPIFFE identity"""

    def __init__(self):
        # Get configuration from environment variables
        self.fulcio_url = os.getenv("FULCIO_URL")
        self.rekor_url = os.getenv("REKOR_URL")
        self.tuf_url = os.getenv("TUF_URL")
        self.jwt_token_file = os.getenv("JWT_TOKEN_FILE", "/svids/jwt.token")
        self.cosign_binary = os.getenv("COSIGN_BINARY", "/usr/local/bin/cosign")
        self.namespace = os.getenv("NAMESPACE", "trusted-artifact-signer")

        # Validate required environment variables
        required_vars = {
            "FULCIO_URL": self.fulcio_url,
            "REKOR_URL": self.rekor_url,
            "TUF_URL": self.tuf_url,
        }

        missing_vars = [name for name, value in required_vars.items() if not value]
        if missing_vars:
            missing_str = ", ".join(missing_vars)
            raise ValueError(f"Missing required environment variables: {missing_str}")

        logger.info("Initialized ArtifactSigner with:")
        logger.info("  FULCIO_URL: %s", self.fulcio_url)
        logger.info("  REKOR_URL: %s", self.rekor_url)
        logger.info("  TUF_URL: %s", self.tuf_url)
        logger.info("  JWT_TOKEN_FILE: %s", self.jwt_token_file)
        logger.info("  COSIGN_BINARY: %s", self.cosign_binary)
        logger.info("  NAMESPACE: %s", self.namespace)

    def check_cosign(self):
        """Check if cosign binary is available"""
        logger.info("Checking for cosign binary...")
        if not os.path.exists(self.cosign_binary):
            logger.error("cosign binary not found at %s", self.cosign_binary)
            return False

        if not os.access(self.cosign_binary, os.X_OK):
            logger.error("cosign binary is not executable")
            return False

        try:
            result = subprocess.run(
                [self.cosign_binary, "version"],
                capture_output=True,
                text=True,
                check=False,
            )
            version_info = (
                result.stdout.strip().split("\n")[0] if result.stdout else "unknown"
            )
            logger.info("cosign is available: %s", version_info)
            return True
        except Exception as e:
            logger.error("Failed to check cosign version: %s", e)
            return False

    def check_jwt_svid(self):
        """Check if JWT-SVID is available"""
        logger.info("Checking for JWT-SVID...")
        if not os.path.exists(self.jwt_token_file):
            logger.error("JWT-SVID not found at %s", self.jwt_token_file)
            return False

        try:
            file_size = os.path.getsize(self.jwt_token_file)
            if file_size == 0:
                logger.error("JWT-SVID file is empty")
                return False

            logger.info("JWT-SVID found (%d bytes)", file_size)
            return True
        except Exception as e:
            logger.error("Failed to check JWT-SVID: %s", e)
            return False

    def get_jwt_svid(self):
        """Retrieve SPIFFE JWT token"""
        try:
            with open(self.jwt_token_file, "r", encoding="utf-8") as source:
                jwt_svid = source.read().strip()
            logger.debug(
                "Successfully retrieved SPIFFE JWT token (%d chars)",
                len(jwt_svid),
            )
            return jwt_svid
        except Exception as e:
            logger.error("Failed to retrieve SPIFFE token: %s", e)
            raise

    def validate_fulcio_availability(self):
        """Check if Fulcio is available"""
        try:
            health_url = f"{self.fulcio_url}/healthz"
            logger.info("Checking Fulcio availability: %s", health_url)

            # Create SSL context that doesn't verify certificates (self-signed certs)
            import ssl

            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            req = Request(health_url, method="GET")
            with urlopen(req, timeout=10, context=ssl_context) as response:
                if response.getcode() == 200:
                    logger.info("Fulcio is available and healthy")
                    return True
                else:
                    logger.warning(
                        "Fulcio returned status code: %s", response.getcode()
                    )
                    return False

        except (HTTPError, URLError) as e:
            logger.error("Fulcio is not reachable: %s", e)
            return False
        except Exception as e:
            logger.error("Unexpected error checking Fulcio: %s", e)
            return False

    def initialize_cosign_tuf(self, max_retries=5, initial_delay=5):
        """Initialize cosign with RHTAS TUF root with retry logic

        Args:
            max_retries: Maximum number of retry attempts
            initial_delay: Initial delay in seconds (doubles with each retry)
        """
        logger.info("Initializing cosign with RHTAS TUF root...")

        for attempt in range(1, max_retries + 1):
            try:
                logger.info("TUF initialization attempt %d/%d", attempt, max_retries)

                # Initialize TUF root for RHTAS
                env = os.environ.copy()
                result = subprocess.run(
                    [
                        self.cosign_binary,
                        "initialize",
                        f"--mirror={self.tuf_url}",
                        f"--root={self.tuf_url}/root.json",
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=30,  # 30 second timeout
                    check=False,
                )

                if result.returncode == 0:
                    logger.info("cosign initialized with RHTAS TUF root successfully")
                    return True
                else:
                    logger.warning(
                        "TUF initialization failed on attempt %d: %s",
                        attempt,
                        result.stderr,
                    )

                    if attempt < max_retries:
                        delay = initial_delay * (2 ** (attempt - 1))
                        logger.info("Retrying in %d seconds...", delay)
                        time.sleep(delay)
                    else:
                        logger.error(
                            "TUF initialization failed after %d attempts", max_retries
                        )
                        return False

            except subprocess.TimeoutExpired:
                logger.warning("TUF initialization timed out on attempt %d", attempt)
                if attempt < max_retries:
                    delay = initial_delay * (2 ** (attempt - 1))
                    logger.info("Retrying in %d seconds...", delay)
                    time.sleep(delay)
                else:
                    logger.error(
                        "TUF initialization timed out after %d attempts", max_retries
                    )
                    return False

            except Exception as e:
                logger.warning("Failed to initialize TUF on attempt %d: %s", attempt, e)
                if attempt < max_retries:
                    delay = initial_delay * (2 ** (attempt - 1))
                    logger.info("Retrying in %d seconds...", delay)
                    time.sleep(delay)
                else:
                    logger.error(
                        "TUF initialization failed after %d attempts", max_retries
                    )
                    return False

        return False

    def sign_artifact(self, image_reference):
        """Sign an artifact using cosign with SPIFFE identity"""
        logger.info("=" * 60)
        logger.info("Signing artifact: %s", image_reference)
        logger.info("=" * 60)

        # Get JWT-SVID
        if not self.check_jwt_svid():
            logger.error("Cannot proceed without JWT-SVID")
            return False

        try:
            jwt_token = self.get_jwt_svid()

            logger.info("Signing with SPIFFE identity via Fulcio...")
            logger.info("  Fulcio URL: %s", self.fulcio_url)
            logger.info("  Rekor URL: %s", self.rekor_url)

            # Build cosign sign command
            env = os.environ.copy()
            env["COSIGN_FULCIO_URL"] = self.fulcio_url
            env["COSIGN_REKOR_URL"] = self.rekor_url
            env["COSIGN_IDENTITY_TOKEN"] = jwt_token

            cmd = [
                self.cosign_binary,
                "sign",
                "--yes",
                f"--fulcio-url={self.fulcio_url}",
                f"--rekor-url={self.rekor_url}",
                f"--identity-token={jwt_token}",
                image_reference,
            ]

            logger.debug("Running: %s", " ".join(cmd[:7] + ["<JWT>", image_reference]))

            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

            if result.returncode == 0:
                logger.info("Artifact signed successfully!")
                logger.info("Signature logged to Rekor transparency log")
                if result.stdout:
                    logger.debug("Cosign output: %s", result.stdout)
                return True
            else:
                logger.error("Failed to sign artifact")
                logger.error("Cosign stderr: %s", result.stderr)
                return False

        except Exception as e:
            logger.error("Error signing artifact: %s", e)
            return False

    def verify_signature(self, image_reference):
        """Verify a signature"""
        logger.info("=" * 60)
        logger.info("Verifying signature: %s", image_reference)
        logger.info("=" * 60)

        try:
            cmd = [
                self.cosign_binary,
                "verify",
                f"--rekor-url={self.rekor_url}",
                "--certificate-identity-regexp=.*",
                "--certificate-oidc-issuer-regexp=.*",
                image_reference,
            ]

            logger.debug("Running: %s", " ".join(cmd))

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )

            if result.returncode == 0:
                logger.info("Signature verification successful!")
                if result.stdout:
                    try:
                        # Parse and display verification details
                        verification_data = json.loads(result.stdout)
                        logger.info("Verification details:")
                        for entry in verification_data:
                            if "critical" in entry:
                                identity = entry["critical"]["identity"].get(
                                    "docker-reference", "N/A"
                                )
                                issuer = entry["critical"]["identity"].get(
                                    "issuer", "N/A"
                                )
                                logger.info("  Identity: %s", identity)
                                logger.info("  Issuer: %s", issuer)
                    except json.JSONDecodeError:
                        logger.debug("Verification output: %s", result.stdout)
                return True
            else:
                logger.error("Signature verification failed")
                logger.error("Cosign stderr: %s", result.stderr)
                return False

        except Exception as e:
            logger.error("Error verifying signature: %s", e)
            return False

    def initialize(self):
        """Initialize the signing application (for init container)"""
        logger.info("Running initialization checks...")

        # Check cosign
        if not self.check_cosign():
            logger.error("Initialization failed: cosign not available")
            return False

        # Initialize TUF (with retries)
        if not self.initialize_cosign_tuf():
            logger.error("TUF initialization failed after retries")
            logger.error("Signing will not work without TUF initialization")
            return False

        # Check JWT-SVID
        if not self.check_jwt_svid():
            logger.warning(
                "JWT-SVID not available yet (spiffe-helper may still be fetching)"
            )
            logger.info("Will retry when signing...")

        # Check Fulcio (non-fatal)
        if not self.validate_fulcio_availability():
            logger.warning("Fulcio health check failed (will try signing anyway)")
        else:
            logger.info("Fulcio is healthy")

        logger.info("Initialization complete")
        return True

    def run_daemon(self):
        """Run as a daemon, ready to sign on demand"""
        logger.info("=" * 60)
        logger.info("RHTAS Artifact Signer with SPIFFE")
        logger.info("=" * 60)
        logger.info("")

        # Pre-flight checks
        if not self.check_cosign():
            logger.error("cosign not available, exiting")
            sys.exit(1)

        # Initialize cosign (with retries)
        if not self.initialize_cosign_tuf():
            logger.error("Failed to initialize TUF root after retries, exiting")
            sys.exit(1)

        # Check JWT-SVID is available
        if not self.check_jwt_svid():
            logger.error("JWT-SVID not available")
            logger.info("Waiting for spiffe-helper to fetch JWT-SVID...")
            time.sleep(5)
            if not self.check_jwt_svid():
                logger.error(
                    "JWT-SVID still not available, but will retry on signing requests"
                )

        logger.info("")
        logger.info("=" * 60)
        logger.info("Signing Application Ready")
        logger.info("=" * 60)
        logger.info("")
        logger.info("The signing application is now ready to sign artifacts.")
        logger.info("")
        logger.info("To sign an image, exec into the pod:")
        logger.info(
            "  oc exec -n %s deploy/rhtas-signer -c artifact-signer -- \\",
            self.namespace,
        )
        logger.info(
            "    python3 /opt/artifact-signer/artifact-signer.py "
            "sign <image-reference>"
        )
        logger.info("")
        logger.info("Example:")
        logger.info(
            "  oc exec -n %s deploy/rhtas-signer -c artifact-signer -- \\",
            self.namespace,
        )
        logger.info(
            "    python3 /opt/artifact-signer/artifact-signer.py "
            "sign quay.io/myorg/myimage:v1.0"
        )
        logger.info("")
        logger.info("To verify a signature:")
        logger.info(
            "  oc exec -n %s deploy/rhtas-signer -c artifact-signer -- \\",
            self.namespace,
        )
        logger.info(
            "    python3 /opt/artifact-signer/artifact-signer.py "
            "verify <image-reference>"
        )
        logger.info("")
        logger.info("Keeping pod running (ready to sign)...")

        # Keep the container running, ready to sign on demand
        while True:
            time.sleep(3600)  # Sleep 1 hour


def main():
    parser = argparse.ArgumentParser(
        description="RHTAS artifact signer using cosign with SPIFFE identity"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--init", action="store_true", help="Run initialization checks and exit"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Sign command
    sign_parser = subparsers.add_parser("sign", help="Sign an artifact")
    sign_parser.add_argument("image", help="Image reference to sign")

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify an artifact signature")
    verify_parser.add_argument("image", help="Image reference to verify")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        signer = ArtifactSigner()

        if args.init:
            # Init mode (for init container)
            success = signer.initialize()
            sys.exit(0 if success else 1)
        elif args.command == "sign":
            # Sign an artifact
            success = signer.sign_artifact(args.image)
            sys.exit(0 if success else 1)
        elif args.command == "verify":
            # Verify a signature
            success = signer.verify_signature(args.image)
            sys.exit(0 if success else 1)
        else:
            # Daemon mode (default)
            signer.run_daemon()

    except Exception as e:
        logger.error("Failed to run artifact signer: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
