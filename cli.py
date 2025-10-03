#!/usr/bin/env python3

import argparse
import logging
import os
import sys
from pathlib import Path
import asyncio
from typing import Optional, List

from config import LOG_FILE, MAX_DEPTH_CRAWL, MAX_URLS_TO_CRAWL
from payloads import DEFAULT_XSS_PAYLOADS
from utils import load_payloads_from_yaml
from network import session
from tester import XSSTester
from ai_analysis import AIAnalyzer
import graphql_scanner
from utils import init_browser_pool, shutdown_browser_pool
from rich.console import Console
from rich.panel import Panel


logger = logging.getLogger("xsscanner")
console = Console()


# --- Minimal ANSI color helper (no external deps) ---
_COL = {
    "red": "31", "green": "32", "yellow": "33", "blue": "34",
    "magenta": "35", "cyan": "36", "bold": "1"
}

# Global flag whether ANSI colors are enabled
_ANSI_ENABLED = True

def _enable_windows_ansi() -> bool:
    """Try enable ANSI on Windows 10+ cmd; return True if enabled, else False."""
    if os.name != 'nt':
        return True
    try:
        import ctypes  # type: ignore
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        # STD_OUTPUT_HANDLE = -11
        h = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint()
        if not kernel32.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        new_mode = mode.value | 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if not kernel32.SetConsoleMode(h, new_mode):
            return False
        return True
    except Exception:
        return False

def color(text: str, name: str | None = None) -> str:
    if not name or not _ANSI_ENABLED:
        return text
    code = _COL.get(name)
    if not code:
        return text
    return f"\033[{code}m{text}\033[0m"

def display_banner() -> None:
    banner = r"""
██╗  ██╗███████╗███████╗ ██████╗ ███████╗███╗   ██╗ █████╗ ██╗
╚██╗██╔╝██╔════╝██╔════╝██╔════╝ ██╔════╝████╗  ██║██╔══██╗██║
 ╚███╔╝ ███████╗███████╗██║  ███╗█████╗  ██╔██╗ ██║███████║██║
 ██╔██╗ ╚════██║╚════██║██║   ██║██╔══╝  ██║╚██╗██║██╔══██║██║
██╔╝ ██╗███████║███████║╚██████╔╝███████╗██║ ╚████║██║  ██║██║
╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝
                                MerdekaSiberLab - Version 6.25
"""
    try:
        console.print(f"[bold bright_red]{banner}[/bold bright_red]")
        console.print(
            Panel(
                "XSS Scanner (Enhanced with [bold]Gemini AI Analysis[/bold] & Advanced Massive XSS Tools)",
                title="[bold]Welcome[/bold]",
                subtitle="[italic]A Modern Comperhensive XSS Scanning Tool[/italic]",
                border_style="cyan",
            )
        )
    except Exception:
        # Fallback to minimal banner if rich fails
        print(color("=============================================", "cyan"))
        print(color("        MerdekaSiberLab XSS Scanner", "magenta"))
        print(color("               Version 6.25", "magenta"))
        print(color("=============================================", "cyan"))


def parse_args() -> argparse.Namespace:
    # Quick subcommand switch: if 'show' used, parse a small viewer
    if len(sys.argv) > 1 and sys.argv[1] == 'show':
        sp = argparse.ArgumentParser(description="xsscanner show – tampilkan hasil scan (table/detail)")
        sp.add_argument('file', help='Path file hasil (JSON)')
        sp.add_argument('--id', help='ID temuan spesifik, contoh: F-12')
        sp.add_argument('--filter', default=None, help="Filter hasil, contoh: severity>=medium url~admin type=blind-xss")
        sp.add_argument('--top', type=int, default=0, help='Batasi hasil teratas (0=semua)')
        ns = sp.parse_args()
        setattr(ns, 'cmd', 'show')
        return ns

    epilog = (
        "Contoh:\n"
        "  xsscanner --preset fast https://target.tld\n"
        "  xsscanner --preset thorough --out results.json --format sarif https://target.tld\n"
        "  xsscanner --preset dom --filter 'severity>=medium url~admin' --top 50 https://target.tld\n"
        "  xsscanner show results.json --id F-01\n"
    )
    parser = argparse.ArgumentParser(description="xsscanner – fast XSS scanner (TTY-friendly)", epilog=epilog)
    parser.add_argument("url", help="URL awal untuk dipindai (http:// atau https://)")
    # New: presets (DEPRECATED alias: --mode)
    parser.add_argument("--preset", choices=["fast", "thorough", "dom", "api", "graphql", "blind"], default="fast")
    parser.add_argument("--mode", "-m", choices=["quick", "deep"], default=None, help="DEPRECATED: gunakan --preset")

    # Output & verbosity
    parser.add_argument("--summary-only", "-s", action="store_true", help="Ringkas (sembunyikan log detil)")
    parser.add_argument("--verbose", action="store_true", help="Tampilkan log lebih banyak")
    parser.add_argument("--debug", action="store_true", help="Tampilkan debug (sangat ramai)")
    parser.add_argument("--format", choices=["table", "json", "sarif", "html"], default="table",
                        help="Format artefak bila --out dipakai (selalu tampilkan table di TTY)")
    parser.add_argument("--out", help="Path file artefak hasil (json/sarif/html)")
    parser.add_argument("--evidence-dir", default=None, help="Simpan bukti eksekusi: screenshot/HTML/HAR")
    parser.add_argument("--redact", action="store_true", help="Samarkan data sensitif (email/token) di artefak hasil")
    parser.add_argument("--redact-evidence", action="store_true", help="Samarkan data sensitif di evidence HTML (mode basic)")
    parser.add_argument("--keep-raw-evidence", action="store_true", help="Simpan salinan raw evidence ke subfolder raw/ untuk debug lokal")

    # Filters
    parser.add_argument("--filter", default=None, help="Filter hasil, contoh: severity>=medium url~admin type=blind-xss")
    parser.add_argument("--top", type=int, default=0, help="Batasi hasil teratas (0=tidak dibatasi)")

    # Inputs & env
    parser.add_argument("--payloads", "-p", metavar="FILE")
    parser.add_argument("--cookie", "-c", metavar="COOKIE_STRING")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--depth", "-d", type=int, default=MAX_DEPTH_CRAWL)
    parser.add_argument("--max-urls", type=int, default=MAX_URLS_TO_CRAWL)
    parser.add_argument("--workers", "-w", type=int, default=10)
    parser.add_argument("--browsers", type=int, default=0, help="Pra-launch N Chromium untuk pooling (0=auto)")
    parser.add_argument("--progress-interval", type=int, default=10,
                        help="Cetak progress setiap N upaya (default: 10)")
    parser.add_argument("--sanitizer-detail", choices=["summary", "full"], default="summary",
                        help="Tampilan hasil sanitizer: ringkas (summary) atau lengkap (full)")
    # Hash fuzzing for SPA routers (default ON)
    parser.add_argument("--hash-fuzz", dest="hash_fuzz", action="store_true", default=True,
                        help="Fuzz location.hash to trigger SPA sinks (default: ON)")
    parser.add_argument("--no-hash-fuzz", dest="hash_fuzz", action="store_false",
                        help="Disable location.hash fuzzing")
    # Login / multi-step & 2FA fallback (manual)
    parser.add_argument("--manual-login", action="store_true",
                        help="Gunakan browser untuk login/2FA manual lalu simpan cookie.")
    parser.add_argument("--login-url", help="URL login untuk sesi (opsional)")
    parser.add_argument("--cookie-file", default="cookies.json", help="File storage_state Playwright untuk reuse sesi")
    parser.add_argument("--username", help="Username (auto-login opsional untuk mode deep)")
    parser.add_argument("--password", help="Password (auto-login opsional untuk mode deep)")
    parser.add_argument("--user-selector", help="Selector field username (auto-login)")
    parser.add_argument("--pass-selector", help="Selector field password (auto-login)")
    parser.add_argument("--submit-selector", help="Selector tombol submit (auto-login)")
    parser.add_argument("--api-key", "-A", help="API key Google GenAI (atau set ENV GENAI_API_KEY)")
    parser.add_argument("--ai-mode", choices=["interactive", "auto", "off"], default="interactive",
                        help="Mode analisis Gemini: interactive (default), auto, atau off.")
    parser.add_argument("--ai-auto-params", type=int, default=2,
                        help="Jumlah parameter teratas untuk dianalisis otomatis saat --ai-mode=auto (0=lewati).")
    parser.add_argument("--ai-summary", action="store_true",
                        help="Selalu jalankan ringkasan temuan oleh Gemini setelah scan.")
    parser.add_argument("--graphql", action="store_true")
    # WAF options
    parser.add_argument("--waf-detect", dest="waf_detect", action="store_true", default=True)
    parser.add_argument("--no-waf-detect", dest="waf_detect", action="store_false")
    parser.add_argument("--waf-mode", choices=["passive","active","aggressive"], default="passive")
    parser.add_argument("--waf-bypass-level", type=int, default=1)
    parser.add_argument("--waf-safe-rps", type=float, default=1.5)
    parser.add_argument("--waf-backoff", type=int, default=1500)
    parser.add_argument("--waf-header-camo", action="store_true")
    parser.add_argument("--waf-rotate-ua", action="store_true")
    parser.add_argument("--waf-trust-proxy", action="store_true")
    ns = parser.parse_args()
    setattr(ns, 'cmd', 'scan')
    return ns


def setup_logging(verbose: bool) -> None:
    logger.setLevel(logging.DEBUG)
    sh = logging.StreamHandler(stream=sys.stdout)
    sh.setLevel(logging.DEBUG if verbose else logging.INFO)
    # Filter agar log "CSP detected" dari network tidak mengganggu UI progress
    class _DropCSPFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:  # type: ignore
            try:
                if record.name.startswith("xsscanner.network"):
                    msg = record.getMessage()
                    if isinstance(msg, str) and msg.startswith("CSP detected"):
                        return False
            except Exception:
                pass
            return True
    sh.addFilter(_DropCSPFilter())
    logger.addHandler(sh)
    fh = logging.FileHandler(str(LOG_FILE), encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)


def _apply_preset(args: argparse.Namespace) -> argparse.Namespace:
    # Back-compat: map deprecated --mode if present
    if getattr(args, 'mode', None):
        print(color("[DEPRECATED] --mode diganti --preset. Memetakan otomatis.", "yellow"))
        args.preset = 'fast' if args.mode == 'quick' else 'thorough'
    p = getattr(args, 'preset', 'fast')
    # Defaults per preset (can be overridden by explicit flags)
    if p == 'fast':
        args.depth = min(args.depth, 3)
        args.max_urls = min(args.max_urls, 800)
        args.workers = max(6, args.workers)
        args.browsers = args.browsers or 2
        setattr(args, 'mode', 'quick')
    elif p == 'thorough':
        args.depth = max(args.depth, 4)
        args.max_urls = max(args.max_urls, 2000)
        args.workers = max(12, args.workers)
        args.browsers = args.browsers or 3
        setattr(args, 'mode', 'deep')
    elif p == 'dom':
        args.depth = max(args.depth, 3)
        args.max_urls = max(args.max_urls, 1200)
        args.browsers = args.browsers or 3
        setattr(args, 'mode', 'deep')
    elif p == 'api':
        args.depth = min(args.depth, 2)
        args.max_urls = min(args.max_urls, 600)
        args.workers = max(8, args.workers)
        args.browsers = args.browsers or 2
        setattr(args, 'mode', 'quick')
    elif p == 'graphql':
        args.graphql = True
        args.depth = min(args.depth, 2)
        args.browsers = args.browsers or 2
        setattr(args, 'mode', 'quick')
    elif p == 'blind':
        # Favor OAST and stored probes; no special flag needed here
        args.browsers = args.browsers or 2
        setattr(args, 'mode', 'deep')
    return args

def _hdr_line(label: str, value: str) -> str:
    return f"{label}: {value}"

def _print_header(args: argparse.Namespace) -> None:
    print(color(f"xsscanner • preset: {args.preset} • target: {args.url}", "magenta"))
    print(color(
        f"Crawl depth={args.depth} • browsers={args.browsers or '-'} • RPS≤~5/origin • blind=ON • hash-fuzz={'ON' if args.hash_fuzz else 'OFF'}",
        "cyan"
    ))

def _compute_severity(f: dict) -> str:
    clazz = (f.get('class') or '').lower()
    if clazz == 'executed':
        return 'High'
    if clazz == 'stored/blind':
        return 'High'
    if clazz == 'dom-sink-only':
        return 'Medium'
    if clazz in ('blocked-by-csp','blocked-by-sandbox'):
        return 'Info'
    # Fallback to type-based heuristic
    t = (f.get('type') or '').lower()
    if any(k in t for k in ('blind', 'stored')):
        return 'High'
    if any(k in t for k in ('header','path','fragment','static','coverage','csp')):
        return 'Medium'
    # Heuristic bump for sensitive routes
    try:
        import re as _re
        if _re.search(r"/(admin|moderation|preview|template|email|render)\b", (f.get('url') or ''), _re.I):
            return 'High' if clazz in ('executed','stored/blind') else 'Medium'
    except Exception:
        pass
    return 'Info'

def _filter_findings(findings: list[dict], expr: Optional[str], top: int) -> list[dict]:
    if not expr:
        out = findings
    else:
        parts = expr.split()
        out = findings
        for p in parts:
            try:
                if '>=' in p:
                    k, v = p.split('>=', 1)
                    if k == 'severity':
                        order = {'info':1, 'low':1, 'medium':2, 'high':3}
                        thr = order.get(v.strip().lower(), 1)
                        out = [x for x in out if order.get(_compute_severity(x).lower(),1) >= thr]
                elif '~' in p:
                    k, v = p.split('~', 1)
                    if k == 'url' or k == 'route':
                        out = [x for x in out if v.lower() in (x.get('url') or '').lower()]
                elif '=' in p:
                    k, v = p.split('=', 1)
                    if k == 'type':
                        out = [x for x in out if (x.get('type') or '').lower() == v.lower()]
            except Exception:
                continue
    if top and top > 0:
        out = out[:top]
    return out

def _as_sarif(findings: list[dict]) -> dict:
    runs = [{
        "tool": {"driver": {"name": "xsscanner", "version": "6.25"}},
        "results": []
    }]
    for f in findings:
        level = _compute_severity(f).lower()
        msg = f"XSS finding: {f.get('type') or 'xss'}"
        runs[0]["results"].append({
            "level": 'error' if level=='high' else ('warning' if level=='medium' else 'note'),
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.get('url') or ''}}}],
            "properties": f,
        })
    return {"version": "2.1.0", "runs": runs}


def _redact_text(s: str) -> str:
    try:
        import re as _re
        if not s:
            return s
        s = _re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[REDACTED_EMAIL]", s)
        s = _re.sub(r"eyJ[\w-]+\.[\w-]+\.[\w-]+", "[REDACTED_JWT]", s)
        s = _re.sub(r"\b[0-9a-fA-F]{24,}\b", "[REDACTED_HEX]", s)
        return s
    except Exception:
        return s

def _redact_findings(findings: list[dict]) -> list[dict]:
    out = []
    for f in findings:
        g = dict(f)
        for k in ('payload','url','param','type','class','detail'):
            if k in g and isinstance(g[k], str):
                g[k] = _redact_text(g[k])
        out.append(g)
    return out


def run() -> None:
    # Windows asyncio policy fix to avoid 'Event loop is closed' warnings
    if os.name == 'nt':
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except Exception:
            pass

    # Initialize ANSI color on Windows, or disable if not supported
    global _ANSI_ENABLED
    _ANSI_ENABLED = _enable_windows_ansi()

    args = parse_args()
    # Viewer mode (show)
    if getattr(args, 'cmd', '') == 'show':
        try:
            import json as _json
            data = _json.loads(Path(args.file).read_text(encoding='utf-8'))
        except Exception as e:
            print(color(f"[show] Gagal membaca file: {e}", "red"))
            sys.exit(2)
        findings = data if isinstance(data, list) else (data.get('findings') or [])
        findings = findings or []
        filtered = _filter_findings(findings, getattr(args,'filter',None), getattr(args,'top',0))
        if getattr(args,'id',None):
            try:
                idx = int(args.id.split('-')[-1])
                if 1 <= idx <= len(filtered):
                    f = list(reversed(filtered))[idx-1]
                    print(color("Detail Temuan:", "yellow"))
                    for k,v in f.items():
                        print(f"- {k}: {v}")
                    sys.exit(0)
            except Exception:
                pass
        # Tampilkan tabel ringkas
        print(color("[Findings] Ringkasan (terbaru dulu)", "yellow"))
        print("ID  | Class           | Severity | URL                             | Proof")
        print("----+-----------------+----------+----------------------------------+------")
        for i, f in enumerate(reversed(filtered), start=1):
            sev = _compute_severity(f)
            clazz = (f.get('class') or f.get('type') or 'Executed')
            u = (f.get('url') or '-')
            ev = f.get('evidence') or {}
            icon = '🖼' if ev.get('screenshot') else ('🧩' if ev.get('html') else '')
            print(f"F-{i:02d} | {clazz[:15]:15} | {sev:8.8} | {u[:34]:34} | {icon}")
        sys.exit(1 if filtered else 0)

    args = _apply_preset(args)
    # Verbosity: debug > verbose > summary-only
    verbose = True
    if args.summary_only and not (args.verbose or args.debug):
        verbose = False
    setup_logging(verbose or args.debug)
    session.verify = not args.insecure

    # Payloads
    payloads = DEFAULT_XSS_PAYLOADS
    if args.payloads:
        path = Path(args.payloads)
        if path.is_file():
            payloads = load_payloads_from_yaml(path)
        else:
            print(f"[!] File payload tidak ditemukan: {args.payloads}")

    # Cookie
    if args.cookie:
        session.headers.update({"Cookie": args.cookie})
        print(f"Cookie diset: {args.cookie}")

    # Banner + Header
    try:
        display_banner()
    except Exception:
        pass
    _print_header(args)

    # WAF detection (per-origin)
    waf_summary = {}
    if getattr(args, 'waf_detect', True):
        try:
            from waf_detector import WAFDetector
            from network import register_waf, set_waf_throttle
            fp = Path('waf_fingerprints.yaml')
            detector = WAFDetector(
                fp,
                mode=args.waf_mode,
                safe_rps=args.waf_safe_rps,
                backoff_ms=args.waf_backoff,
                bypass_level=args.waf_bypass_level,
                header_camo=args.waf_header_camo,
                rotate_ua=args.waf_rotate_ua,
                trust_proxy=args.waf_trust_proxy,
            )
            origin = args.url
            prof = detector.detect(origin)
            register_waf(detector)
            dec = detector.should_throttle(prof)
            if dec.apply:
                set_waf_throttle(prof.origin, dec.safe_rps, dec.backoff_ms)
            plan = detector.next_strategy(prof, None)
            waf_summary = {
                "origin": prof.origin, "vendor": prof.vendor, "confidence": prof.confidence,
                "mode": prof.mode, "safe_rps": prof.safe_rps, "challenge": prof.challenge,
                "rate_limit": prof.rate_limit, "notes": prof.notes,
                "matches": prof.matches,
                "metadata": prof.metadata,
                "applied_strategies": [k for k,v in plan.__dict__.items() if isinstance(v, bool) and v],
            }
            print(color(f"WAF: {prof.vendor or 'unknown'} (conf={prof.confidence}) \x07 mode={prof.mode} \x07 RPS cap={prof.safe_rps}", "yellow"))
            try:
                if isinstance(prof.matches, dict):
                    header_hits = prof.matches.get('headers') or []
                    cookie_hits = prof.matches.get('cookies') or []
                    body_hits = prof.matches.get('body') or []
                    if header_hits:
                        print(color(f"[WAF] header hits: {', '.join(str(h) for h in header_hits[:3])}", "cyan"))
                    if cookie_hits:
                        print(color(f"[WAF] cookie hits: {', '.join(str(c) for c in cookie_hits[:3])}", "cyan"))
                    if body_hits:
                        print(color(f"[WAF] body markers: {', '.join(str(b) for b in body_hits[:2])}", "cyan"))
                if prof.challenge != 'none':
                    print(color(f"[WAF] challenge detected: {prof.challenge}", "magenta"))
            except Exception:
                pass
            # Optional debug: print redirect/headers snapshot when unknown
            if (args.debug or args.verbose) and (prof.vendor == 'unknown'):
                try:
                    from network import make_request as _mr
                    print(color("[WAF debug] HEAD (no-redirect) headers:", "cyan"))
                    r = _mr(prof.origin, method='HEAD', allow_redirects=False)
                    if r:
                        for k,v in list(r.headers.items())[:12]:
                            print(f"  {k}: {v}")
                        if getattr(r, 'history', None):
                            print(color("[WAF debug] Redirect history:", "cyan"))
                            for h in r.history:
                                print(f"  {h.status_code} {getattr(h,'url','')} -> {h.headers.get('Location','')}")
                except Exception:
                    pass
        except Exception as e:
            print(color(f"[WAF] detection error: {e}", "red"))

    # Init browser pool early (best-effort)
    try:
        if (args.browsers or 0) != 0:
            ok = init_browser_pool(size=args.browsers)
            if ok:
                print(color(f"[Headless] Browser pool ready: {args.browsers} page(s)", "green"))
    except Exception:
        pass

    # Manual login / 2FA fallback (simpan cookie & storage_state)
    login_cfg = None
    storage_state_file = None
    if getattr(args, 'manual_login', False) and getattr(args, 'login_url', None):
        try:
            from login_flow import manual_login_capture
            cookie_file = Path(args.cookie_file)
            cookies = manual_login_capture(args.login_url, cookie_file, headless=False, reuse_existing=True)
            # Sinkronkan cookie ke requests session
            for c in cookies or []:
                try:
                    session.cookies.set(c.get('name'), c.get('value'), domain=c.get('domain'), path=c.get('path') or '/')
                except Exception:
                    continue
            storage_state_file = str(cookie_file)
            print(color(f"[Login] Manual login cookies loaded: {cookie_file}", "green"))
        except Exception as e:
            print(color(f"[Login] Gagal manual_login_capture: {e}", "red"))
    elif getattr(args, 'login_url', None) and getattr(args, 'username', None) and getattr(args, 'password', None):
        login_cfg = {
            "url": args.login_url,
            "username": args.username,
            "password": args.password,
            "user_field": args.user_selector,
            "pass_field": args.pass_selector,
            "submit_sel": args.submit_selector,
        }

    # Crawler
    if args.mode == "quick":
        from crawler.crawler import XSSCrawler
        print(color("[Crawler] Quick static crawler...", "cyan"))
        # Suppress per-param logs; we'll show a single-line progress instead
        crawler = XSSCrawler(start_url=args.url, max_depth=args.depth, max_urls=args.max_urls, verbose=False)
    else:
        from crawler.advanced_crawler import AdvancedXSSCrawler
        print(color("[Crawler] Advanced dynamic crawler...", "cyan"))
        crawler = AdvancedXSSCrawler(start_url=args.url, max_depth=args.depth, max_urls=args.max_urls, verbose=False,
                                     login_cfg=login_cfg, storage_state_file=storage_state_file)

    # Single-line crawling progress with simple spinner
    import threading, time as _time
    _stop = threading.Event()
    _frames = ['|','/','-','\\']
    _pad = 120
    def _crawl_progress():
        i = 0
        while not _stop.is_set():
            msg = f"[Crawl] {args.mode} { _frames[i % len(_frames)] } visited={len(crawler.visited)} params={len(crawler.discovered_parameters)} js={len(crawler.discovered_js)}"
            i += 1
            try:
                print("\r" + color(msg, "cyan").ljust(_pad), end="", flush=True)
            except Exception:
                pass
            _time.sleep(0.15)

    t = threading.Thread(target=_crawl_progress, daemon=True)
    t.start()

    # Run crawl (blocking)
    try:
        crawler.crawl_and_discover_parameters()
    finally:
        _stop.set(); t.join(timeout=1.0)
        print()  # finalize progress line

    params = crawler.discovered_parameters
    js_files = crawler.discovered_js
    print(color(f"[Crawler] Ditemukan params={len(params)} js_files={len(js_files)}", "yellow"))

    if not params and not js_files:
        print("Tidak ada parameter atau file JavaScript yang ditemukan untuk diuji.")
        return

    # AI Analyzer (opsional)
    analyzer = None
    api_key = (getattr(args, 'api_key', None) or os.getenv("GENAI_API_KEY", "")).strip()
    if api_key:
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            analyzer = AIAnalyzer(client)
            print("[AI] GenAI client initialized.")
        except Exception as e:
            print(f"[AI] Gagal init GenAI: {e}. Melewati analisis AI.")

    # Tester
    tester = XSSTester(
        payloads,
        max_workers=args.workers,
        progress_every=args.progress_interval,
        verbose=not args.summary_only,
        sanitizer_detail=args.sanitizer_detail,
        hash_fuzz=args.hash_fuzz,
        waf_plan=(plan.__dict__ if 'plan' in locals() and plan else None),
    )
    # Prioritize params by host profile score (framework/sink hints)
    try:
        from host_profile import get_priority
        params = sorted(params, key=lambda p: get_priority(p['url'], p['name']), reverse=True)
    except Exception:
        pass

    # Simple parameter selection menu
    if params:
        print(color("\n[Select] Pilih parameter untuk diuji:", "green"))
        print(color("  0) Semua parameter (uji semua)", "yellow"))
        # Kelompokkan berdasarkan nama param agar menu ringkas
        grouped: dict[str, List[dict]] = {}
        for p in params:
            grouped.setdefault(p['name'], []).append(p)
        names = sorted(grouped.keys())
        for idx, name in enumerate(names, start=1):
            count = len(grouped[name])
            label = f"  {idx}) {name}  (surface: {count})"
            print(color(label, "cyan"))
        try:
            choice = input(color("Masukkan nomor pilihan (default 0): ", "magenta"))
        except Exception:
            choice = "0"
        choice = (choice or "0").strip()

        selected: List[dict] = []
        if choice == "0":
            selected = params
        else:
            try:
                idx = int(choice)
                if 1 <= idx <= len(names):
                    selected = grouped[names[idx-1]]
                else:
                    print(color("Pilihan tidak valid, default ke semua.", "red"))
                    selected = params
            except Exception:
                print(color("Pilihan tidak valid, default ke semua.", "red"))
                selected = params
    else:
        selected = []

    for p in selected:
        print(color(f"\n[Test] [{p['method']}] {p['name']} @ {p['url']}", "green"))
        tester.test_parameter(p['url'], p['method'], p['name'], p['data_template'], p['is_form'])
        if analyzer:
            try:
                print("[AI] Analisis AI untuk parameter ini...")
                analyzer.perform_interactive_ai_for_parameter(p)
            except Exception as e:
                print(f"[AI] Gagal analisis AI: {e}")

    # Ringkasan sederhana
    findings = getattr(tester, 'vulns', []) or []
    try:
        total_v = len(findings)
        # Streamed summary table (latest first)
        if total_v:
            print(color("\n[Findings] Ringkasan (terbaru dulu)", "yellow"))
            print("ID  | Class           | Severity | URL                             | Proof")
            print("----+-----------------+----------+----------------------------------+------")
            for i, f in enumerate(reversed(findings), start=1):
                sev = _compute_severity(f)
                clazz = (f.get('class') or f.get('type') or 'Executed')
                u = (f.get('url') or '-')
                ev = f.get('evidence') or {}
                icon = '🖼' if ev.get('screenshot') else ('🧩' if ev.get('html') else '')
                print(f"F-{i:02d} | {clazz[:15]:15} | {sev:8.8} | {u[:34]:34} | {icon}")
        else:
            print(color("\n[Findings] Tidak ada temuan.", "yellow"))
    except Exception:
        pass

    # Proses revisit tugas yang due (stored/time-delayed)
    try:
        tester.process_revisits()
    except Exception:
        pass

    # Skor & deduplikasi temuan dengan AI (opsional)
    # Evidence (best-effort): screenshot + HTML per finding
    try:
        if args.evidence_dir and findings:
            from utils import capture_page_evidence
            base = Path(args.evidence_dir)
            base.mkdir(parents=True, exist_ok=True)
            for i, f in enumerate(findings, start=1):
                u = f.get('url') or None
                if not u:
                    continue
                sub = base / f"F-{i:02d}"
                ev = capture_page_evidence(u, sub, base_name="evidence", redact=bool(getattr(args,'redact_evidence', False)), keep_raw=bool(getattr(args,'keep_raw_evidence', False)))
                if ev:
                    f.setdefault('evidence', ev)
            print(color(f"[Evidence] Disimpan ke: {base}", "cyan"))
    except Exception as e:
        print(color(f"[Evidence] Gagal simpan: {e}", "red"))

    # Output artifacts (JSON/SARIF/HTML) if requested
    try:
        if args.out:
            import json as _json
            ofmt = (args.format or 'json').lower()
            # Optional filter & top for artifact
            filtered = _filter_findings(findings, args.filter, args.top)
            if args.redact:
                filtered = _redact_findings(filtered)
            outp = Path(args.out)
            outp.parent.mkdir(parents=True, exist_ok=True)
            if ofmt == 'json':
                payload = {"findings": filtered}
                if 'waf_summary' in locals() and waf_summary:
                    payload["waf"] = waf_summary
                outp.write_text(_json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
            elif ofmt == 'sarif':
                sarif = _as_sarif(filtered)
                outp.write_text(_json.dumps(sarif, ensure_ascii=False, indent=2), encoding='utf-8')
            elif ofmt == 'html':
                # Minimal HTML table
                rows = []
                for f in filtered:
                    rows.append(f"<tr><td>{_compute_severity(f)}</td><td>{(f.get('type') or '').upper()}</td><td>{(f.get('url') or '').replace('&','&amp;')}</td></tr>")
                html = """<html><head><meta charset='utf-8'><title>xsscanner report</title></head><body>
                <h3>xsscanner report</h3><table border='1' cellspacing='0' cellpadding='4'>
                <tr><th>Severity</th><th>Class</th><th>URL</th></tr>{rows}
                </table></body></html>""".replace("{rows}", "\n".join(rows))
                outp.write_text(html, encoding='utf-8')
            else:
                # table to file is not useful; fallback to json
                outp.write_text(_json.dumps(filtered, ensure_ascii=False, indent=2), encoding='utf-8')
            print(color(f"[Output] Artefak tersimpan: {outp}", "cyan"))
    except Exception as e:
        print(color(f"[Output] Gagal menulis artefak: {e}", "red"))

    # GraphQL (opsional)
    if args.graphql:
        print(color("\n[GraphQL] Scan introspection...", "cyan"))
        endpoints = graphql_scanner.discover_graphql_endpoints(args.url)
        if not endpoints:
            print("Tidak ada endpoint GraphQL umum.")
        else:
            for ep in endpoints:
                print(color(f"Introspecting: {ep}", "cyan"))
                schema = graphql_scanner.introspect_schema(ep)
                if schema:
                    graphql_scanner.test_graphql_xss(ep, schema)
                else:
                    print(color(f"Gagal introspeksi di {ep}", "red"))

    # Exit banner and code
    try:
        total_pages = len(getattr(crawler, 'visited', []) or [])
    except Exception:
        total_pages = 0
    try:
        total_params = len(getattr(crawler, 'discovered_parameters', []) or [])
    except Exception:
        total_params = 0
    total_findings = len(findings)
    print(color(f"\nDONE | Pages: {total_pages} | Params: {total_params}", "cyan"))
    if total_findings:
        print(color(f"Findings: {total_findings}", "yellow"))
    else:
        print(color("Findings: 0", "green"))

    # Exit codes: 0 no findings; 1 findings present; 2 fatal error handled above; 3 partial failure (not tracked)
    ec = 1 if total_findings > 0 else 0
    sys.exit(ec)


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(color("\nDibatalkan pengguna. Keluar.", "red"))
        sys.exit(1)
    except Exception:
        logger.error("Terjadi error tak terduga!", exc_info=True)
        sys.exit(2)
    finally:
        try:
            shutdown_browser_pool()
        except Exception:
            pass
