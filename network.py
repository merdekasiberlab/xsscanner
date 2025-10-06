# network.py

import threading
import time
import logging
import random    # <-- tambahan
from typing import Optional, Dict, Any


# ---------------------------------------------------------------------------
# Lightweight console spinner to indicate in-flight HTTP work. The spinner is
# intentionally stdout-based (instead of Rich) so it can be reused from worker
# threads without depending on CLI context.
# ---------------------------------------------------------------------------
_SPINNER_STATE = {
    "depth": 0,
    "lock": threading.Lock(),
    "message": "",
}
_SPINNER_PAD = 72


def _start_spinner(message: str) -> None:
    with _SPINNER_STATE["lock"]:
        depth = _SPINNER_STATE["depth"]
        _SPINNER_STATE["depth"] = depth + 1
        if depth == 0:
            _SPINNER_STATE["message"] = message
            line = message[:_SPINNER_PAD].ljust(_SPINNER_PAD)
            print("\r" + line, end="", flush=True)


def _stop_spinner() -> None:
    with _SPINNER_STATE["lock"]:
        depth = max(0, _SPINNER_STATE["depth"] - 1)
        _SPINNER_STATE["depth"] = depth
        if depth > 0:
            return
    # Clear line saat spinner stack kembali 0
    print("\r" + " " * _SPINNER_PAD + "\r", end="", flush=True)

import requests
from config import USER_AGENT, REQUEST_TIMEOUT, REQUEST_DELAY_MIN, REQUEST_DELAY_MAX

logger = logging.getLogger("xsscanner.network")

# --- Global session with custom User-Agent ---
session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

class RateLimiter:
    """
    Thread-safe rate limiter dengan jitter antara REQUEST_DELAY_MIN
    dan REQUEST_DELAY_MAX detik.
    """
    def __init__(self, min_interval: float, max_interval: float):
        self._min = min_interval
        self._max = max_interval
        self._lock = threading.Lock()
        self._last_call = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.time()
            # delay acak di antara min/max
            interval = random.uniform(self._min, self._max)
            elapsed = now - self._last_call
            sleep_for = max(0, interval - elapsed)
            if sleep_for > 0:
                time.sleep(sleep_for)
            self._last_call = time.time()

# inisialisasi dengan konstanta dari config
rate_limiter = RateLimiter(REQUEST_DELAY_MIN, REQUEST_DELAY_MAX)

# --- Optional WAF integration ---
_WAF = None  # detector instance
_ORIGIN_LAST: dict[str, float] = {}
_ORIGIN_CAP: dict[str, float] = {}  # origin -> min interval seconds based on safe_rps
_BACKOFF_MS: int = 0

def _origin(url: str) -> str:
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return url

def register_waf(detector) -> None:
    global _WAF
    _WAF = detector

def set_waf_throttle(origin: str, safe_rps: float, backoff_ms: int) -> None:
    try:
        _ORIGIN_CAP[origin] = max(0.0, 1.0 / max(0.1, float(safe_rps)))
        global _BACKOFF_MS
        _BACKOFF_MS = int(backoff_ms)
    except Exception:
        pass


def _jitter_user_agent(ua: str) -> str:
    # keep UA stable; jitter bisa memicu halaman anti-bot/minimal
    return ua

# daftar Accept-Language untuk dipilih acak
_ACCEPT_LANGS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "id-ID,id;q=0.9",
    "de-DE,de;q=0.8",
    "fr-FR,fr;q=0.8",
]


def _shorten_for_status(raw_url: str, limit: int = 52) -> str:
    try:
        from urllib.parse import urlparse
        parsed = urlparse(raw_url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}"
        if len(base) <= limit:
            return base
        return base[: limit - 3] + "..."
    except Exception:
        return raw_url[:limit]


def make_request(
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None,
    allow_redirects: bool = True
) -> Optional[requests.Response]:
    """
    HTTP request dengan:
      • jittered rate limiting
      • rotasi User-Agent (casing) & Accept-Language
      • logging + CSP warning
    """
    rate_limiter.wait()

    spinner_msg = f"Requesting {_shorten_for_status(url)}"
    _start_spinner(spinner_msg)

    # Per-origin throttle if WAF present
    origin = _origin(url)
    try:
        cap = _ORIGIN_CAP.get(origin)
        if cap:
            last = _ORIGIN_LAST.get(origin, 0.0)
            now_ts = time.time()
            sleep_for = (last + cap) - now_ts
            if sleep_for > 0:
                time.sleep(sleep_for)
            _ORIGIN_LAST[origin] = time.time()
    except Exception:
        pass

    # copy default headers, lalu tambahkan custom
    req_headers = session.headers.copy()
    if headers:
        req_headers.update(headers)

    # jitter User-Agent (and optional low-risk rotation)
    orig_ua = req_headers.get("User-Agent", USER_AGENT)
    try:
        if getattr(_WAF, 'rotate_ua', False):
            # rotate among a safe pool
            pool = [
                USER_AGENT,
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/116.0 Safari/537.36",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1",
            ]
            import random as _rnd
            req_headers["User-Agent"] = _rnd.choice(pool)
        else:
            req_headers["User-Agent"] = _jitter_user_agent(orig_ua)
    except Exception:
        req_headers["User-Agent"] = _jitter_user_agent(orig_ua)

    # tambahkan atau ganti Accept-Language
    try:
        if getattr(_WAF, 'header_camo', False):
            req_headers["Accept-Language"] = random.choice(_ACCEPT_LANGS)
            req_headers.setdefault("Connection", "keep-alive")
        else:
            req_headers["Accept-Language"] = random.choice(_ACCEPT_LANGS)
    except Exception:
        req_headers["Accept-Language"] = random.choice(_ACCEPT_LANGS)

    try:
        req_start = time.time()
        response = session.request(
            method=method.upper(),
            url=url,
            params=params,
            data=data,
            headers=req_headers,
            timeout=timeout or REQUEST_TIMEOUT,
            verify=session.verify,
            allow_redirects=allow_redirects
        )

        # Warn jika ada CSP header
        csp = response.headers.get("Content-Security-Policy")
        if csp:
            logger.warning(f"CSP detected on {url}: {csp.split(';')[0]}...")

        # WAF classify & throttle adjustments
        try:
            if _WAF is not None:
                t_ms = int((time.time() - req_start) * 1000)
                ev = _WAF.classify_response({"url": url, "method": method}, response, {"rtt_ms": t_ms})
                if ev and ev.type in ("rate_limited", "challenged_js", "blocked"):
                    dec = _WAF.should_throttle(ev)
                    if dec.apply:
                        set_waf_throttle(origin, dec.safe_rps, dec.backoff_ms)
                        if dec.backoff_ms > 0:
                            time.sleep(dec.backoff_ms / 1000.0)
        except Exception:
            pass
        return response

    except requests.RequestException as exc:
        logger.error(f"Request to {url} failed: {exc}")
        return None
    finally:
        _stop_spinner()
