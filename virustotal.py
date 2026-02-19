"""VirusTotal v3 API client for Unfurlr.

Provides URL reputation lookups with in-memory caching and rate limiting.
Degrades gracefully when the API key is missing or the API is unavailable.
"""

import base64
import os
import time

import requests

_VT_BASE = "https://www.virustotal.com/api/v3"
_CACHE = {}  # url -> (timestamp, result_dict)
_CACHE_TTL = 300  # 5 minutes
_RATE_DELAY = 15  # seconds between API calls (free tier: 4 req/min)
_last_call_ts = 0.0


def _get_api_key():
    return (os.getenv("VT_API_KEY") or "").strip()


def _url_id(url: str) -> str:
    """VT v3 URL identifier: base64url of the URL without trailing '='."""
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


def get_url_report(url: str):
    """Fetch a VT v3 URL analysis report.

    Returns a dict with keys: malicious, suspicious, harmless, undetected,
    reputation, threat_label — or None on any failure.
    """
    global _last_call_ts

    api_key = _get_api_key()
    if not api_key:
        return None

    # Check cache
    now = time.time()
    cached = _CACHE.get(url)
    if cached and (now - cached[0]) < _CACHE_TTL:
        return cached[1]

    # Rate-limit: sleep if needed
    elapsed = now - _last_call_ts
    if elapsed < _RATE_DELAY:
        time.sleep(_RATE_DELAY - elapsed)

    try:
        url_id = _url_id(url)
        resp = requests.get(
            f"{_VT_BASE}/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=15,
        )
        _last_call_ts = time.time()

        if resp.status_code == 429:
            return None
        if resp.status_code != 200:
            return None

        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation"),
            "threat_label": (
                attrs.get("popular_threat_classification", {})
                .get("suggested_threat_label")
            ),
        }
        _CACHE[url] = (time.time(), result)
        return result
    except Exception:
        return None


def enrich_chain(chain):
    """Add a 'vt' key to each hop dict in the redirect chain.

    Skips enrichment when no API key is configured.
    """
    if not _get_api_key():
        return
    for hop in chain:
        hop["vt"] = get_url_report(hop["url"])
