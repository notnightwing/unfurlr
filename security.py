"""Input validation utilities for Unfurlr."""

from urllib.parse import urlparse


def validate_target_url(raw_url: str):
    """Validate and normalize a user-supplied URL.

    Returns (ok: bool, result: str) where result is the normalized URL
    on success or an error message on failure.
    """
    raw = (raw_url or "").strip()
    if not raw:
        return False, "No URL provided."

    # If there's a scheme, it must be http or https
    if "://" in raw:
        scheme = raw.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            return False, f"Unsupported scheme: {scheme}"
    else:
        # No scheme — prepend http://
        raw = "http://" + raw

    parsed = urlparse(raw)
    if not parsed.hostname:
        return False, "URL has no hostname."

    return True, raw
