"""CSP nonce utility for build-time injection."""

import base64
import secrets


def generate_nonce() -> str:
    """Generate a cryptographically random 16-byte base64-encoded nonce."""
    return base64.b64encode(secrets.token_bytes(16)).decode()


def inject_csp_nonce(html: str, nonce: str) -> str:
    """Replace {{CSP_NONCE}} placeholder with the given nonce value throughout html."""
    return html.replace("{{CSP_NONCE}}", nonce)
