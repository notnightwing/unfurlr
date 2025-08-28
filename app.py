#!/usr/bin/env python3
import ipaddress
import os
import random
import time
from datetime import datetime
import secrets
from urllib.parse import urljoin

import requests
from dotenv import load_dotenv
from flask import Flask, redirect, render_template_string, request, url_for, send_file, abort
import socket
from urllib.parse import urlparse, quote
import re
import hashlib
import mimetypes

from security import validate_target_url

# Optional: Selenium
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options

    SELENIUM_AVAILABLE = True
except Exception:
    SELENIUM_AVAILABLE = False

# Load .env values
load_dotenv()

app = Flask(__name__)

# Basic config
_env = os.getenv("FLASK_ENV")
_is_dev = _env == "development"
_secret_from_env = os.getenv("SECRET_KEY", "").strip()
if _is_dev:
    # In development, generate an ephemeral key if not provided
    secret_key_value = _secret_from_env or secrets.token_urlsafe(32)
else:
    # In non-development, require a strong key
    if not _secret_from_env or _secret_from_env in {"dev-not-secret", "changeme", "secret"}:
        raise RuntimeError(
            "SECRET_KEY must be set to a strong value in production environments."
        )
    secret_key_value = _secret_from_env

app.config.update(
    SECRET_KEY=secret_key_value,
    SESSION_COOKIE_SECURE=False if _is_dev else True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Data directory for artifacts (outside static to avoid direct serving)
DATA_DIR = os.path.join(app.root_path, "data")
DOWNLOADS_DIR = os.path.join(DATA_DIR, "downloads")
os.makedirs(DOWNLOADS_DIR, exist_ok=True)

# Retention for artifacts (days)
app.config["ARTIFACT_RETENTION_DAYS"] = int(os.getenv("ARTIFACT_RETENTION_DAYS", "7"))


@app.after_request
def add_security_headers(response):
    csp = (
        "default-src 'none'; "
        "img-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'none'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'"
    )
    response.headers.setdefault("Content-Security-Policy", csp)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_ip_private(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in PRIVATE_NETS)
    except ValueError:
        return True  # treat unparsable as unsafe


def sanitize_user_agent(ua: str) -> str:
    # Strip control characters and cap length
    cleaned = "".join(ch for ch in (ua or "") if 32 <= ord(ch) < 127)
    return cleaned[:512]


def resolve_hostname_ips(hostname: str):
    try:
        infos = socket.getaddrinfo(hostname, None)
        ips = []
        for info in infos:
            addr = info[4][0]
            if addr not in ips:
                ips.append(addr)
        return ips
    except Exception:
        return []


def is_url_allowed(url: str) -> bool:
    try:
        p = urlparse(url)
        if p.scheme.lower() not in {"http", "https"}:
            return False
        if not p.hostname:
            return False
        ips = resolve_hostname_ips(p.hostname)
        if not ips:
            return False
        return not any(is_ip_private(ip) for ip in ips)
    except Exception:
        return False


# -------- User-Agent presets (2024–2025 realistic) --------
UA_PRESETS = {
    # Desktop browsers
    "chrome_win": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Safari/537.36"
    ),
    "chrome_mac": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Safari/537.36"
    ),
    "edge_win": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0"
    ),
    "firefox_win": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) "
        "Gecko/20100101 Firefox/130.0"
    ),
    "safari_mac": (
        # Safari 18 on macOS 15 Sequoia; version tokens are Safari-y
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
    ),
    # Mobile browsers
    "safari_ios": (
        # iPhone iOS 18 Safari
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
    ),
    "chrome_android": (
        "Mozilla/5.0 (Linux; Android 14; Pixel 7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Mobile Safari/537.36"
    ),
    "samsung_internet": (
        "Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S911B) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Mobile Safari/537.36 SamsungBrowser/26.0"
    ),
    # Link preview / in-app browsers (very handy for phishing triage)
    "facebook_inapp_ios": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 "
        "FBAN/FBIOS;FBAV/489.0.0.0.0;FBBV/0;FBDV/iPhone;FBMD/iPhone;"
    ),
    "instagram_inapp_ios": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 "
        "Instagram 350.0.0.0.0 (iPhone12,3; iOS 18_0; en_US; en-US; scale=3.00)"
    ),
    "tiktok_inapp_android": (
        "Mozilla/5.0 (Linux; Android 14; Pixel 7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Version/4.0 Chrome/128.0.0.0 Mobile Safari/537.36 "
        "Tiktok 35.0.0"
    ),
    "twitter_iphone": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 "
        "Twitter for iPhone"
    ),
    "outlook_win_preview": (
        # Outlook desktop link previewer often fetches links
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Safari/537.36 OutlookDesktop"
    ),
    "slackbot": "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
    # Crawlers / bots
    "googlebot_desktop": (
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    ),
    "googlebot_smartphone": (
        # Current pattern: Chrome-like UA + Googlebot token
        "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Mobile Safari/537.36 "
        "(compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    ),
    "bingbot": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    # Legacy (still occasionally useful)
    "ie11_win7": ("Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko"),
    # Special
    "random": "__RANDOM__",  # handled in resolve_user_agent()
    "custom": "",  # use text box
}

UA_LABELS = {
    "chrome_win": "Windows 10/11 : Chrome 128",
    "chrome_mac": "macOS : Chrome 128",
    "edge_win": "Windows 10/11 : Edge 128",
    "firefox_win": "Windows 10/11 : Firefox 130",
    "safari_mac": "macOS : Safari 18",
    "safari_ios": "iPhone (iOS 18) : Safari",
    "chrome_android": "Android 14 : Chrome",
    "samsung_internet": "Android 14 : Samsung Internet 26",
    "facebook_inapp_ios": "Facebook In-App (iOS)",
    "instagram_inapp_ios": "Instagram In-App (iOS)",
    "tiktok_inapp_android": "TikTok In-App (Android)",
    "twitter_iphone": "Twitter/X In-App (iPhone)",
    "outlook_win_preview": "Outlook Desktop Link Preview",
    "slackbot": "Slack Link Expander",
    "googlebot_desktop": "Googlebot (Desktop)",
    "googlebot_smartphone": "Googlebot (Smartphone)",
    "bingbot": "Bingbot",
    "ie11_win7": "Windows 7 : IE 11",
    "random": "Random (rotate)",
    "custom": "Custom…",
}

DEFAULT_UA_KEY = "chrome_win"

# Which UA keys should use a mobile viewport?
MOBILE_UA_KEYS = {
    "safari_ios",
    "chrome_android",
    "samsung_internet",
    "facebook_inapp_ios",
    "instagram_inapp_ios",
    "tiktok_inapp_android",
    "twitter_iphone",
    "googlebot_smartphone",
}


def is_mobile_ua_key(ua_key: str) -> bool:
    return (ua_key or "").strip() in MOBILE_UA_KEYS


def mobile_emulation_payload(ua_string: str, ua_key: str):
    """
    Returns a Chrome 'mobileEmulation' payload suitable for Selenium.
    Pick sizes that look realistic for the chosen family.
    """
    # Two sensible defaults
    if ua_key in {
        "safari_ios",
        "facebook_inapp_ios",
        "instagram_inapp_ios",
        "twitter_iphone",
    }:
        # iPhone 15 Pro-ish
        return {
            "deviceMetrics": {"width": 393, "height": 852, "pixelRatio": 3},  # CSS px
            "userAgent": ua_string,
        }
    # Android (Pixel 7 class)
    return {
        "deviceMetrics": {"width": 412, "height": 915, "pixelRatio": 2.625},
        "userAgent": ua_string,
    }


RANDOM_POOL = [
    "chrome_win",
    "chrome_mac",
    "edge_win",
    "firefox_win",
    "safari_ios",
    "chrome_android",
    "samsung_internet",
]


def resolve_user_agent(ua_key: str, ua_custom: str):
    """
    Returns (ua_string, ua_label)
    """
    key = (ua_key or "").strip() or DEFAULT_UA_KEY
    if key == "custom" and ua_custom.strip():
        return sanitize_user_agent(ua_custom.strip()), "Custom"
    if key == "random":
        picked = random.choice(RANDOM_POOL)
        return UA_PRESETS[picked], UA_LABELS.get(picked, picked)
    if key in UA_PRESETS and UA_PRESETS[key] not in (None, "__RANDOM__"):
        return UA_PRESETS[key], UA_LABELS.get(key, key)
    # fallback
    return UA_PRESETS[DEFAULT_UA_KEY], UA_LABELS.get(DEFAULT_UA_KEY, DEFAULT_UA_KEY)


# ---------- Core: follow redirects safely ----------
def get_redirect_chain(start_url, user_agent, max_hops=15, timeout=10):
    """
    Returns a list of hop dicts:
      { 'url': <url>, 'status': <int or None>, 'method': 'HEAD'|'GET'|None, 'elapsed_ms': <float|None> }
    First element is the normalized starting URL.
    Uses a shared requests.Session across hops for connection reuse.
    """
    if not start_url.lower().startswith(("http://", "https://")):
        start_url = "http://" + start_url.strip()

    vtq = quote(f"url:{start_url}", safe='')
    chain = [{"url": start_url, "status": None, "method": None, "elapsed_ms": None, "vt_query": vtq}]
    current = start_url

    # Initial guard
    if not is_url_allowed(current):
        return chain

    with requests.Session() as session:
        session.headers.update({"User-Agent": user_agent})

        for _ in range(max_hops):
            resp = None
            status = None
            method_used = None
            elapsed_ms = None

            # Try HEAD first
            try:
                t0 = time.monotonic()
                # Set Referer to previous hop when available
                head_headers = {}
                if len(chain) > 0:
                    ref = chain[-1]["url"]
                    if ref != current:
                        head_headers["Referer"] = ref
                resp = session.head(
                    current, allow_redirects=False, timeout=timeout, headers=head_headers or None
                )
                elapsed_ms = (time.monotonic() - t0) * 1000.0
                status = resp.status_code
                method_used = "HEAD"
            except requests.RequestException:
                # Fallback to GET if HEAD fails/is blocked
                try:
                    t0 = time.monotonic()
                    get_headers = {}
                    if len(chain) > 0:
                        ref = chain[-1]["url"]
                        if ref != current:
                            get_headers["Referer"] = ref
                    resp = session.get(
                        current, allow_redirects=False, timeout=timeout, headers=get_headers or None
                    )
                    elapsed_ms = (time.monotonic() - t0) * 1000.0
                    status = resp.status_code
                    method_used = "GET"
                except requests.RequestException:
                    chain[-1]["status"] = None
                    chain[-1]["method"] = None
                    chain[-1]["elapsed_ms"] = None
                    break

            chain[-1]["status"] = status
            chain[-1]["method"] = method_used
            chain[-1]["elapsed_ms"] = round(elapsed_ms, 2) if elapsed_ms is not None else None

            if not (300 <= status < 400):
                # Not an HTTP redirect. Look for HTML meta refresh if we have body.
                next_url = None
                try:
                    # If we only performed HEAD, do a lightweight GET to scan for meta refresh.
                    if method_used == "HEAD":
                        t0 = time.monotonic()
                        scan_headers = {"Referer": chain[-1]["url"]} if len(chain) > 0 else None
                        scan_resp = session.get(current, allow_redirects=False, timeout=min(timeout, 5), headers=scan_headers)
                        elapsed_ms = (time.monotonic() - t0) * 1000.0
                        status = scan_resp.status_code
                        method_used = "GET"
                        chain[-1]["status"] = status
                        chain[-1]["method"] = method_used
                        chain[-1]["elapsed_ms"] = round(elapsed_ms, 2)
                        resp = scan_resp
                    # Read a limited amount
                    if resp is not None and resp.headers.get("Content-Type", "").lower().startswith("text"):
                        body_bytes = resp.content[:65536]
                        try:
                            text = body_bytes.decode(resp.encoding or "utf-8", errors="ignore")
                        except Exception:
                            text = body_bytes.decode("utf-8", errors="ignore")
                        # Regex for meta refresh
                        m = re.search(r"<meta[^>]*http-equiv=[\"']?refresh[\"']?[^>]*content=[\"']?\s*([\d.]+)\s*;\s*url=([^\"'/>\s]+)", text, flags=re.IGNORECASE)
                        if m:
                            loc = m.group(2).strip()
                            next_url = urljoin(current, loc)
                except requests.RequestException:
                    pass

                if not next_url:
                    break
            else:
                loc = resp.headers.get("Location") if resp is not None else None
                if not loc:
                    break
                next_url = urljoin(current, loc)

            # enforce guards per hop
            if not is_url_allowed(next_url):
                chain.append({"url": next_url, "status": None, "method": None, "elapsed_ms": None, "vt_query": quote(f"url:{next_url}", safe='')})
                break

            # prevent loops
            if any(h["url"] == next_url for h in chain):
                chain.append({"url": next_url, "status": None, "method": None, "elapsed_ms": None})
                break

            chain.append({"url": next_url, "status": None, "method": None, "elapsed_ms": None, "vt_query": quote(f"url:{next_url}", safe='')})
            current = next_url

    return chain


# ---------- Optional: capture screenshot of final URL ----------


def capture_screenshot(
    final_url, user_agent, ua_key, outfile_rel="static/screens/final_screenshot.png"
):
    """
    Captures a screenshot of final_url into ./static/screens/ and
    returns a web path like '/static/screens/<file>.png'.
    Honors mobile UA by enabling Chrome mobile emulation.
    If Selenium isn’t available or fails, returns None.
    """
    if not SELENIUM_AVAILABLE:
        return None

    if not is_url_allowed(final_url):
        return None

    out_path = os.path.join(app.root_path, outfile_rel)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    try:
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-gpu")

        # Desktop default window; overridden by mobile emulation below
        options.add_argument("--window-size=1920,1080")

        if is_mobile_ua_key(ua_key):
            # Use Chrome's mobile emulation so layout + DPR look authentic
            options.add_experimental_option(
                "mobileEmulation", mobile_emulation_payload(user_agent, ua_key)
            )
        else:
            # Desktop: just set UA header
            options.add_argument(f"--user-agent={user_agent}")

        driver = webdriver.Chrome(options=options)
        try:
            driver.get(final_url)
            time.sleep(1.0)  # small settle time
            driver.save_screenshot(out_path)
        finally:
            driver.quit()

        return "/" + outfile_rel.replace("\\", "/")
    except Exception:
        return None


# ---------- Optional: detect auto-downloads on final URL ----------


def detect_auto_downloads(final_url, user_agent, ua_key, session_tag):
    """
    Visits final_url in headless Chrome with a dedicated download dir.
    Returns (detected_files_webpaths, note).
    Uses mobile emulation when a mobile UA was chosen.
    """
    if not SELENIUM_AVAILABLE:
        return [], "Selenium/ChromeDriver not available; skipped download detection."

    if not is_url_allowed(final_url):
        return [], "Final URL blocked by policy."

    dl_rel_dir = f"downloads/{session_tag}"
    dl_abs_dir = os.path.join(DOWNLOADS_DIR, session_tag)
    os.makedirs(dl_abs_dir, exist_ok=True)

    try:
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-gpu")
        options.add_argument(
            "--window-size=1280,800"
        )  # desktop default; ignored by mobile emu

        if is_mobile_ua_key(ua_key):
            options.add_experimental_option(
                "mobileEmulation", mobile_emulation_payload(user_agent, ua_key)
            )
        else:
            options.add_argument(f"--user-agent={user_agent}")

        prefs = {
            "download.default_directory": dl_abs_dir,
            "download.prompt_for_download": False,
            "download.directory_upgrade": True,
            "safebrowsing.enabled": True,
        }
        options.add_experimental_option("prefs", prefs)

        driver = webdriver.Chrome(options=options)
        try:
            before = set(os.listdir(dl_abs_dir))
            driver.get(final_url)

            total_wait = 0.0
            step = 0.5
            max_wait = 8.0
            while total_wait < max_wait:
                time.sleep(step)
                total_wait += step
                after = set(os.listdir(dl_abs_dir))
                new_items = after - before
                if any(not name.endswith(".crdownload") for name in new_items):
                    break

            final = set(os.listdir(dl_abs_dir))
            new_items = [n for n in (final - before) if not n.endswith(".crdownload")]
            items = []
            for name in new_items:
                abs_path = os.path.join(dl_abs_dir, name)
                try:
                    with open(abs_path, "rb") as f:
                        sha256 = hashlib.sha256(f.read()).hexdigest()
                except Exception:
                    sha256 = None
                mime, _ = mimetypes.guess_type(name)
                try:
                    size = os.path.getsize(abs_path)
                except Exception:
                    size = None
                items.append(
                    {
                        "url": url_for("serve_download", session=session_tag, filename=name),
                        "name": name,
                        "sha256": sha256,
                        "mime": mime,
                        "size": size,
                    }
                )
            if items:
                return items, None
            return [], "No downloads detected in the wait window."
        finally:
            driver.quit()
    except Exception as e:
        return [], f"Download detection failed: {e}"


# ---------- Templates ----------
FORM_HTML = """
<!doctype html>
<title>Redirect Checker</title>
<h1>Redirect Checker</h1>
<form action="{{ url_for('check_url') }}" method="get">
  <input type="text" name="url" placeholder="Enter URL"
         style="width: min(600px, 90%)"
         required autocorrect="off" autocapitalize="none" spellcheck="false">

  <details style="margin-top:10px;">
    <summary>Advanced options</summary>
    <div style="margin:8px 0 0 12px;">
     <label for="ua">User-Agent:</label>
     <select name="ua" id="ua">
      <option value="chrome_win" selected>Windows 10/11 : Chrome 128</option>
      <option value="chrome_mac">macOS : Chrome 128</option>
      <option value="edge_win">Windows 10/11 : Edge 128</option>
      <option value="firefox_win">Windows 10/11 : Firefox 130</option>
      <option value="safari_mac">macOS : Safari 18</option>

      <optgroup label="Mobile">
        <option value="safari_ios">iPhone (iOS 18) : Safari</option>
        <option value="chrome_android">Android 14 : Chrome</option>
        <option value="samsung_internet">Android 14 : Samsung Internet</option>
      </optgroup>

      <optgroup label="In-App / Link Preview">
        <option value="facebook_inapp_ios">Facebook In-App (iOS)</option>
        <option value="instagram_inapp_ios">Instagram In-App (iOS)</option>
        <option value="tiktok_inapp_android">TikTok In-App (Android)</option>
        <option value="twitter_iphone">Twitter/X In-App (iPhone)</option>
        <option value="outlook_win_preview">Outlook Desktop Link Preview</option>
        <option value="slackbot">Slack Link Expander</option>
      </optgroup>

      <optgroup label="Crawlers">
        <option value="googlebot_desktop">Googlebot (Desktop)</option>
        <option value="googlebot_smartphone">Googlebot (Smartphone)</option>
        <option value="bingbot">Bingbot</option>
      </optgroup>

      <optgroup label="Legacy">
        <option value="ie11_win7">Windows 7 : Internet Explorer 11</option>
      </optgroup>

      <option value="random">Random (rotate)</option>
      <option value="custom">Custom…</option>
    </select>
      <div style="margin-top:6px;">
        <input type="text" name="ua_custom" placeholder="Custom User-Agent"
               style="width: min(600px, 90%)"
               autocorrect="off" autocapitalize="none" spellcheck="false">
      </div>
    </div>
  </details>

  <div style="margin-top:10px;">
    <label>
     <input type="checkbox" name="screenshot" value="1">
     Take screenshot of final page
    </label>
    <br>
    <label>
     <input type="checkbox" name="detectdl" value="1">
     Detect auto-downloads on final page
    </label>
  </div>
  <br>
  <input type="submit" value="Check URL">
</form>
"""

RESULTS_HTML = """
<!doctype html>
<title>Results</title>
<h1>URL Redirect Results</h1>
<p>Redirect chain for: <code>{{ submitted_url }}</code></p>
<p><strong>User-Agent used:</strong> <code>{{ ua_label }}</code><br>
<small style="color:#666;">{{ ua_string }}</small></p>

<ol>
{% for hop in chain %}
  <li>
    {% set scheme = (hop.url.split('://', 1)[0] | lower) if '://' in hop.url else '' %}
    {% if scheme in ['http', 'https'] %}
      <a href="{{ hop.url }}" target="_blank" rel="noopener">{{ hop.url }}</a>
    {% else %}
      <code>{{ hop.url }}</code>
    {% endif %}
    {% if hop.status is not none %} — <strong>{{ hop.status }}</strong>{% endif %}
    {% if hop.method %} ({{ hop.method }}){% endif %}
    {% if hop.elapsed_ms is not none %} — {{ hop.elapsed_ms }} ms{% endif %}
    &nbsp;|&nbsp;
    <a
      href="https://www.virustotal.com/gui/search/{{ hop.vt_query }}"
      target="_blank"
      rel="noopener"
    >
      Check on VirusTotal
    </a>
  </li>
{% endfor %}
</ol>

{% if screenshot_path %}
  <h2>Final Page Screenshot</h2>
  <p
   style="color:#666;">
   (If the image is blank, the site may block headless browsers or require interaction.)
  </p>
  <img
   src="{{ screenshot_path }}"
   alt="Final page screenshot"
   style="max-width: 100%; height: auto; border:1px solid #ddd;"
  >
{% elif tried_screenshot %}
  <p><em>{{ screenshot_note or "Screenshot was requested but not available." }}</em></p>
{% endif %}

{% if tried_detectdl %}
  <h2>Auto-download Detection</h2>
  {% if download_items and download_items|length > 0 %}
    <p><strong>Downloads detected:</strong></p>
    <ul>
      {% for d in download_items %}
        <li>
          <a href="{{ d.url }}" rel="noopener">{{ d.name }}</a>
          {% if d.size %} — {{ d.size }} bytes{% endif %}
          {% if d.mime %} — {{ d.mime }}{% endif %}
          {% if d.sha256 %}<br><small>SHA-256: <code>{{ d.sha256 }}</code></small>{% endif %}
        </li>
      {% endfor %}
    </ul>
  {% else %}
    <p><em>{{ download_note or "No downloads detected." }}</em></p>
  {% endif %}
{% endif %}

<p><a href="{{ url_for('index') }}">Check another URL</a></p>
"""


# ---------- Routes ----------
@app.route("/", methods=["GET"])
def index():
    return render_template_string(FORM_HTML)


@app.route("/check-url", methods=["GET"])
def check_url():
    submitted_url = request.args.get("url", "").strip()
    ok, normalized = validate_target_url(submitted_url)
    if not ok:
        return render_template_string(
            "<p><strong>Invalid URL:</strong> {{ msg }}</p>"
            "<p><a href='{{ url_for('index') }}'>Back</a></p>",
            msg=normalized,
        )
    submitted_url = normalized

    # ✅ define these first
    ua_key = request.args.get("ua", DEFAULT_UA_KEY)
    ua_custom = request.args.get("ua_custom", "")
    want_shot = request.args.get("screenshot") == "1"
    want_detect = request.args.get("detectdl") == "1"

    if not submitted_url:
        return redirect(url_for("index"))

    # (optional) URL validation here…

    ua_string, ua_label = resolve_user_agent(ua_key, ua_custom)
    chain = get_redirect_chain(submitted_url, user_agent=ua_string)

    # Always initialize optionals (avoid UnboundLocalError)
    screenshot_path = None
    tried_screenshot = False
    screenshot_note = None

    tried_detectdl = False
    download_items = []
    download_note = None

    # Screenshot
    if want_shot and chain:
        tried_screenshot = True
        final_url = chain[-1]["url"]
        screenshot_path = capture_screenshot(
            final_url, user_agent=ua_string, ua_key=ua_key
        )
        if not screenshot_path:
            screenshot_note = (
                "Selenium/ChromeDriver not available or the screenshot failed."
            )

    # Auto-download detection
    if want_detect and chain:
        tried_detectdl = True
        final_url = chain[-1]["url"]
        session_tag = datetime.utcnow().strftime("%Y%m%dT%H%M%S%f")
        download_items, download_note = detect_auto_downloads(
            final_url, user_agent=ua_string, ua_key=ua_key, session_tag=session_tag
        )

    # render_template_string(... pass all vars ...)

    return render_template_string(
        RESULTS_HTML,
        submitted_url=submitted_url,
        ua_label=ua_label,
        ua_string=ua_string,
        chain=chain,
        screenshot_path=screenshot_path,
        tried_screenshot=tried_screenshot,
        screenshot_note=screenshot_note,  # now always defined
        tried_detectdl=tried_detectdl,
        download_items=download_items,
        download_note=download_note,  # now always defined
    )


@app.route("/downloads/<session>/<path:filename>")
def serve_download(session, filename):
    # Construct absolute path and prevent traversal
    base = os.path.realpath(DOWNLOADS_DIR)
    abs_path = os.path.realpath(os.path.join(base, session, filename))
    if not abs_path.startswith(os.path.join(base, "")):
        abort(404)
    if not os.path.isfile(abs_path):
        abort(404)
    mime, _ = mimetypes.guess_type(filename)
    return send_file(abs_path, as_attachment=True, download_name=os.path.basename(filename), mimetype=mime or "application/octet-stream")


@app.before_first_request
def scheduled_cleanup():
    try:
        purge_old_artifacts(app.config.get("ARTIFACT_RETENTION_DAYS", 7))
    except Exception:
        pass


def purge_old_artifacts(max_age_days: int = 7):
    now = time.time()
    cutoff = now - max_age_days * 86400
    # downloads
    for root, dirs, files in os.walk(DOWNLOADS_DIR, topdown=False):
        for name in files:
            p = os.path.join(root, name)
            try:
                if os.path.getmtime(p) < cutoff:
                    os.remove(p)
            except Exception:
                pass
        for d in dirs:
            full = os.path.join(root, d)
            try:
                if not os.listdir(full):
                    os.rmdir(full)
            except Exception:
                pass


if __name__ == "__main__":
    os.makedirs(app.static_folder, exist_ok=True)
    try:
        purge_old_artifacts(app.config.get("ARTIFACT_RETENTION_DAYS", 7))
    except Exception:
        pass
    # Only enable Flask debug when FLASK_ENV=development
    app.run(debug=os.getenv("FLASK_ENV") == "development")
