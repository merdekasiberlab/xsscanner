from __future__ import annotations

import re
from typing import Dict, Tuple, Optional
from urllib.parse import urlparse

# Global CSRF token store: netloc -> token info
_CSRF_STORE: Dict[str, Dict[str, str]] = {}

_TOKEN_PARAM_NAMES = [
    "csrfmiddlewaretoken",
    "_csrf",
    "_csrf_token",
    "csrf_token",
    "authenticity_token",
    "xsrf_token",
    "__RequestVerificationToken",
]
_TOKEN_HEADER_NAMES = [
    "X-CSRF-Token",
    "X-XSRF-TOKEN",
]
_COOKIE_NAMES = [
    "csrftoken",
    "CSRF-TOKEN",
    "XSRF-TOKEN",
    "xsrf-token",
]


def _netloc(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def update_store(url: str, tokens: Dict[str, str]) -> None:
    host = _netloc(url)
    if not host or not tokens:
        return
    cur = _CSRF_STORE.setdefault(host, {})
    cur.update({k: v for k, v in (tokens or {}).items() if v})


def get_tokens_for_url(url: str) -> Dict[str, str]:
    return _CSRF_STORE.get(_netloc(url), {})


def extract_csrf_from_dom(html: str) -> Dict[str, str]:
    """
    Cari token dari meta & hidden input (name/value). Return dict: name->value
    Juga ekspose "csrf_meta" untuk header jika ditemukan.
    """
    out: Dict[str, str] = {}
    try:
        # Meta: <meta name="csrf-token" content="...">
        for m in re.finditer(r"<meta[^>]+name=['\"]([^'\"]*csrf[^'\"]*)['\"][^>]*content=['\"]([^'\"]+)['\"]", html, re.I):
            key = m.group(1).strip()
            val = m.group(2).strip()
            if val:
                out["csrf_meta"] = val
        # Hidden inputs: <input type="hidden" name="...token..." value="...">
        for m in re.finditer(r"<input[^>]+type=['\"]hidden['\"][^>]*name=['\"]([^'\"]+)['\"][^>]*value=['\"]([^'\"]*)['\"]", html, re.I):
            name = m.group(1)
            val = m.group(2)
            if val and any(x.lower() in name.lower() for x in ["csrf", "token", "verification", "authenticity"]):
                out[name] = val
    except Exception:
        pass
    return out


def extract_csrf_from_cookie_string(cookie_str: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for part in (cookie_str or "").split(";"):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            k = k.strip(); v = v.strip()
            if k in _COOKIE_NAMES and v:
                out[k] = v
    except Exception:
        pass
    return out


def apply_csrf(url: str, method: str, data, headers: Optional[Dict[str, str]] = None) -> Tuple[Dict[str, str], object]:
    """
    Tambahkan CSRF header/body bila tersedia di store untuk host URL.
    - headers: tambahkan X-CSRF-Token jika ada meta/cookie yang cocok
    - data (dict): set salah satu param token jika belum ada
    Return: (headers, data)
    """
    method = (method or "GET").upper()
    headers = dict(headers or {})
    tokens = get_tokens_for_url(url)
    if not tokens:
        return headers, data

    # Header token dari meta
    meta = tokens.get("csrf_meta")
    if meta:
        headers.setdefault("X-CSRF-Token", meta)

    # Dari cookie yang umum, gunakan sebagai header juga
    for ck in _COOKIE_NAMES:
        if ck in tokens and tokens[ck]:
            headers.setdefault("X-CSRF-Token", tokens[ck])
            break

    # Body param untuk POST/PUT/PATCH/DELETE dengan data dict
    if method in ("POST", "PUT", "PATCH", "DELETE") and isinstance(data, dict):
        already = set(k.lower() for k in data.keys())
        for name in _TOKEN_PARAM_NAMES:
            if name.lower() in already:
                break
        else:
            # inject first available token value
            val = meta or next((tokens[k] for k in _COOKIE_NAMES if k in tokens), "")
            if not val:
                # fallback: cari token param yang pernah disimpan di store
                for k, v in tokens.items():
                    if any(x.lower() in k.lower() for x in ["csrf", "token", "verification", "authenticity"]):
                        val = v; break
            if val:
                # pilih nama param paling lazim
                inject_name = "csrfmiddlewaretoken"
                for nm in ("_csrf", "csrf_token", "authenticity_token"):
                    inject_name = nm; break
                data[inject_name] = val

    return headers, data

