# cli.py

import argparse
import logging
import os
import sys
import re
from collections import Counter
from pathlib import Path
from typing import List, Dict

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.logging import RichHandler

from config import LOG_FILE, MAX_DEPTH_CRAWL, MAX_URLS_TO_CRAWL
from payloads import DEFAULT_XSS_PAYLOADS
from utils import load_payloads_from_yaml
from network import session, register_waf, set_waf_throttle, make_request
from tester import XSSTester, configure_ui
from ai_analysis import AIAnalyzer
from dynamic_dom_tester import dynamic_dom_inspect
import graphql_scanner
from parsers.context_parser import ContextParser
from waf_detector import WAFDetector
from sanitization_analyzer import analyze_param_sanitizer

logger = logging.getLogger("xsscanner")
console = Console(highlight=False)


def _friendly_waf_name(vendor: str) -> str:
    mapping = {
        'cloudflare': 'Cloudflare',
        'cloudfront': 'CloudFront',
        'akamai': 'Akamai',
        'aws_waf': 'AWS WAF',
        'imperva': 'Imperva (Incapsula)',
        'barracuda': 'Barracuda WAF',
        'bigip_asm': 'F5 BIG-IP ASM',
        'sucuri': 'Sucuri',
        'azure_waf': 'Azure WAF',
        'fastly': 'Fastly',
        'stackpath': 'StackPath',
        'naxsi': 'NAXSI',
        'sophos': 'Sophos UTM',
        'mod_security': 'ModSecurity',
        'shield': 'ShieldSquare',
        'dosarrest': 'DOSarrest',
        'comodo': 'Comodo WAF',
        'generic': 'WAF generik',
    }
    key = (vendor or '').strip().lower()
    if not key:
        return 'WAF tidak diketahui'
    return mapping.get(key, key.replace('_', ' ').title())


def display_banner():
    banner = r"""
██╗  ██╗███████╗███████╗ ██████╗ ███████╗███╗   ██╗ █████╗ ██╗
╚██╗██╔╝██╔════╝██╔════╝██╔════╝ ██╔════╝████╗  ██║██╔══██╗██║
 ╚███╔╝ ███████╗███████╗██║  ███╗█████╗  ██╔██╗ ██║███████║██║
 ██╔██╗ ╚════██║╚════██║██║   ██║██╔══╝  ██║╚██╗██║██╔══██║██║
██╔╝ ██╗███████║███████║╚██████╔╝███████╗██║ ╚████║██║  ██║██║
╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝
                    MerdekaSiberLab - Version 1.2.0 (Rinjani)
    """
    console.print(f"[bold bright_red]{banner}[/bold bright_red]")
    console.print(
        Panel(
            "XSS Scanner (Enhanced with [bold]Gemini AI Analysis[/bold] & Advanced Crawler)",
            title="[bold]Welcome[/bold]",
            subtitle="[italic]A Modern XSS Scanning Tool[/italic]",
            border_style="cyan"
        )
    )




def _shorten(text: str, limit: int = 80) -> str:
    if not text:
        return '-'
    cleaned = str(text).strip().replace('\n', ' ').replace('\r', '')
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: max(0, limit - 3)] + '...'


def _format_char_label(ch: str) -> str:
    if not ch:
        return '-'
    if ch == ' ':
        return '<sp>'
    if ch == '\n':
        return '<nl>'
    if ch == '\t':
        return '<tab>'
    if len(ch) == 1 and 32 <= ord(ch) <= 126:
        return ch
    if len(ch) == 1:
        return f"0x{ord(ch):02x}"
    return repr(ch)


def _render_sanitizer_overview(param_name: str, sanitizer_map: dict) -> dict:
    if not sanitizer_map:
        console.print('[yellow]Tidak ada karakter yang terpantau pada baseline refleksi.[/yellow]')
        return {'filtered': 0, 'encoded': 0, 'reflected': 0, 'total': 0}
    counts = Counter(sanitizer_map.values())
    table = Table(show_header=True, header_style='bold cyan', border_style='yellow')
    table.add_column('Status', style='cyan')
    table.add_column('Jumlah', justify='right', style='yellow')
    table.add_column('Contoh', style='magenta', overflow='fold')
    for status in ('reflected', 'encoded', 'filtered'):
        chars = [
            _format_char_label(ch)
            for ch, st in sanitizer_map.items()
            if st == status
        ]
        preview_items = list(dict.fromkeys(chars))
        preview = ' '.join(preview_items) if preview_items else '-'
        table.add_row(status.title(), str(counts.get(status, 0) or 0), preview)
    subtitle = f"Total sampel: {sum(counts.values())}"
    console.print(Panel(table, title=f"[bold yellow]Fingerprint Sanitizer '{param_name}'[/bold yellow]", border_style='yellow', subtitle=subtitle))
    return {
        'filtered': int(counts.get('filtered', 0) or 0),
        'encoded': int(counts.get('encoded', 0) or 0),
        'reflected': int(counts.get('reflected', 0) or 0),
        'total': int(sum(counts.values())),
    }


def _render_vuln_summary(vulns: List[dict]) -> None:
    if not vulns:
        console.print('[yellow]Belum ada payload yang terbukti dieksekusi.[/yellow]')
        return
    table = Table(title='[bold red]Payload Tereksekusi[/bold red]', border_style='red', show_lines=True)
    table.add_column('Jenis', style='red')
    table.add_column('Payload', style='magenta')
    table.add_column('Endpoint', style='green')
    for item in vulns:
        table.add_row(
            item.get('type', '-') or '-',
            _shorten(item.get('payload', '-'), 70),
            _shorten(item.get('url', '-') or '-', 70)
        )
    console.print(table)


def _prompt_analysis_actions(analyzer_available: bool) -> str:
    table = Table(title='[bold]Pilihan Analisis Parameter[/bold]', border_style='cyan', show_lines=True)
    table.add_column('Pilihan', style='bold yellow', justify='center')
    table.add_column('Aksi', style='cyan')
    table.add_column('Deskripsi', style='magenta')
    table.add_row('1', 'Full pipeline', 'Fingerprint + inspeksi DOM + fuzzing multi-phase')
    table.add_row('2', 'Inspeksi DOM dinamis', 'Render headless untuk mendeteksi sink runtime')
    if analyzer_available:
        table.add_row('3', 'Analisis HTML/JS (Gemini)', 'Gunakan Gemini untuk ringkas HTML, JS, CSP')
    else:
        table.add_row('3', 'Analisis HTML/JS (Gemini)', 'Tidak tersedia - butuh API key GEMINI')
    table.add_row('4', 'Lewati parameter', 'Lanjut tanpa pengujian tambahan')
    console.print(table)
    choice_map = {'1': 'full', '2': 'dom', '3': 'ai', '4': 'skip', '': 'full'}
    while True:
        choice = console.input('[bold cyan]Pilih mode analisis (default 1) > [/bold cyan]').strip().lower()
        if choice in choice_map:
            return choice_map[choice]
        if not choice:
            return 'full'
        console.print(f"[yellow]Pilihan '{choice}' tidak dikenali.[/yellow]")
def parse_args():
    parser = argparse.ArgumentParser(
        description="Advanced XSS Scanner CLI (Enhanced dengan GenAI & Dynamic Crawler)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("url", help="URL awal untuk dipindai (harus pakai http:// atau https://)")
    parser.add_argument("--api-key", "-A", help="API key Google GenAI (atau set ENV GENAI_API_KEY)")
    parser.add_argument("--mode", "-m", choices=['quick', 'deep'], default='quick',
                        help="Pilih mode crawling: 'quick' atau 'deep'")
    parser.add_argument("--summary-only", "-s", action="store_true",
                        help="Hanya tampilkan ringkasan akhir, tanpa detail proses")
    parser.add_argument("--payloads", "-p", metavar="FILE",
                        help="Path ke file YAML berisi XSS payloads kustom.")
    parser.add_argument("--cookie", "-c", metavar="COOKIE_STRING",
                        help="Masukkan Cookie header (misal: 'name=val; name2=val2').")
    parser.add_argument("--insecure", action="store_true",
                        help="Izinkan koneksi HTTPS tanpa verifikasi sertifikat")
    parser.add_argument("--depth", "-d", type=int, default=MAX_DEPTH_CRAWL,
                        help="Kedalaman maksimal crawling")
    parser.add_argument("--max-urls", type=int, default=MAX_URLS_TO_CRAWL,
                        help="Maks jumlah URL untuk dicrawl")
    parser.add_argument("--graphql", action="store_true",
                        help="Scan endpoint GraphQL untuk potensi XSS lewat introspection")
    parser.add_argument("--user-selector",
                        help="CSS selector untuk field username (default: input[name=username])")
    parser.add_argument("--pass-selector",
                        help="CSS selector untuk field password (default: input[type=password])")
    parser.add_argument("--submit-selector",
                        help="CSS selector untuk tombol submit (default: button[type=submit])")
    parser.add_argument("--login-url",
                        help="URL halaman login (misal: https://target.com/login)")
    parser.add_argument("--username", help="Username untuk login")
    parser.add_argument("--password", help="Password untuk login")
    parser.add_argument("--workers", "-w", type=int, default=10,
                        help="Jumlah thread worker untuk paralelisme pengujian payload (default: 10)")
    parser.add_argument("--manual-login", action="store_true",
                        help="Gunakan sesi headful; selesaikan login/CAPTCHA secara manual lalu lanjut scan.")
    parser.add_argument("--cookie-file", default="cookies.json",
                        help="Path file untuk memuat / menyimpan cookie Playwright.")
    return parser.parse_args()




_JS_SINK_HINTS = [
    ("innerHTML assignment", r"innerHTML\s*="),
    ("document.write", r"document\.(write|writeln)\s*\("),
    ("eval()", r"\beval\s*\("),
    ("Function()", r"\bFunction\s*\("),
    ("new Function", r"new\s+Function\s*\("),
    ("setTimeout string", r"setTimeout\s*\(\s*['\"]"),
    ("insertAdjacentHTML", r"insertAdjacentHTML\s*\("),
    ("createContextualFragment", r"createContextualFragment\s*\("),
    ("jQuery.html", r"\.(html|append|prepend|before|after|replaceWith)\s*\("),
]

_JS_SOURCE_HINTS = [
    ("location.*", r"location\.(hash|search|href)"),
    ("document.cookie", r"document\.cookie"),
    ("URLSearchParams", r"URLSearchParams\s*\("),
    ("postMessage", r"postMessage\s*\("),
    ("localStorage", r"localStorage\.(getItem|setItem)"),
]


def _extract_js_snippet(code: str, start: int, end: int, radius: int = 90) -> str:
    lower = max(0, start - radius)
    upper = min(len(code), end + radius)
    snippet = code[lower:upper]
    snippet = snippet.replace('\r', ' ').replace('\n', ' ')
    return re.sub(r'\s+', ' ', snippet).strip()
    return re.sub(r'\s+', ' ', snippet).strip()


def _fetch_js_metadata(js_url: str) -> Dict:
    try:
        resp = make_request(js_url)
    except Exception as exc:
        logger.debug(f"JS fetch failed for {js_url}: {exc}")
        return {'url': js_url, 'error': str(exc)}
    if not resp or not (resp.text or '').strip():
        return {'url': js_url, 'error': 'empty'}

    code = resp.text or ''
    contexts = ContextParser.parse(code, content_type="application/javascript")

    sink_hits: List[str] = []
    sink_snippets: List[Dict[str, str]] = []
    for label, pattern in _JS_SINK_HINTS:
        match = re.search(pattern, code, re.IGNORECASE)
        if match:
            sink_hits.append(label)
            sink_snippets.append({'label': label, 'snippet': _extract_js_snippet(code, match.start(), match.end())})

    source_hits: List[str] = []
    for label, pattern in _JS_SOURCE_HINTS:
        if re.search(pattern, code, re.IGNORECASE):
            source_hits.append(label)

    size = len(code)
    score = len(sink_hits) * 5 + len(source_hits) * 2 + min(size // 5000, 6)
    if 'eval()' in sink_hits:
        score += 2
    if any('Function' in hit for hit in sink_hits):
        score += 2

    return {
        'url': js_url,
        'code': code if len(code) <= 400000 else code[:400000],
        'contexts': contexts,
        'sink_hits': sink_hits,
        'source_hits': source_hits,
        'sink_snippets': sink_snippets,
        'size': size,
        'score': score,
        'error': None,
    }


def _prepare_js_overview(js_urls: List[str]) -> List[Dict]:
    metas: List[Dict] = []
    for url in js_urls:
        meta = _fetch_js_metadata(url)
        if not meta:
            continue
        metas.append(meta)
    metas.sort(key=lambda m: (m.get('score', 0), len(m.get('sink_hits', [])), len(m.get('source_hits', []))), reverse=True)
    return metas


def _render_js_overview(metas: List[Dict]) -> Dict[str, Dict]:
    table = Table(title='[bold]Prioritas File JavaScript[/bold]', border_style='cyan', show_lines=True)
    table.add_column('Pilihan', style='bold yellow', justify='center')
    table.add_column('Score', justify='right', style='magenta')
    table.add_column('Sinks', style='red')
    table.add_column('Sources', style='cyan')
    table.add_column('Size', justify='right', style='green')
    table.add_column('URL', style='white', overflow='fold')
    choice_map: Dict[str, Dict] = {}
    for idx, meta in enumerate(metas, start=1):
        sinks = ', '.join(meta.get('sink_hits')[:3]) or '-'
        sources = ', '.join(meta.get('source_hits')[:3]) or '-'
        size_kb = f"{meta.get('size', 0) / 1024:.1f} KB"
        table.add_row(str(idx), str(meta.get('score', 0)), sinks, sources, size_kb, meta.get('url', '-'))
        choice_map[str(idx)] = meta
    console.print(table)
    return choice_map


def _prompt_js_selection(metas: List[Dict]) -> List[Dict]:
    if not metas:
        return []
    choice_map = _render_js_overview(metas)
    while True:
        raw = console.input("[bold cyan]Pilih file JS (misal 1,3 atau 'top3'/'semua') > [/bold cyan]").strip().lower()
        if raw in {'', 'top', 'top1'}:
            return metas[:1]
        if raw in {'semua', 'all'}:
            return metas
        if raw.startswith('top'):
            try:
                num = int(raw[3:]) if len(raw) > 3 else 3
            except ValueError:
                num = 3
            num = max(1, min(num, len(metas)))
            return metas[:num]
        picks: List[Dict] = []
        valid = True
        for part in raw.split(','):
            key = part.strip()
            if not key:
                continue
            meta = choice_map.get(key)
            if not meta:
                valid = False
                break
            if meta not in picks:
                picks.append(meta)
        if valid and picks:
            return picks
        console.print(f"[yellow]Pilihan '{raw}' tidak dikenali.[/yellow]")


def _prompt_js_action(analyzer_available: bool) -> str:
    table = Table(title='[bold]Mode Analisis JS[/bold]', border_style='cyan', show_lines=True)
    table.add_column('Pilihan', style='bold yellow', justify='center')
    table.add_column('Aksi', style='cyan')
    table.add_column('Deskripsi', style='magenta')
    table.add_row('1', 'Ringkasan cepat', 'Deteksi sink & sumber tanpa AI')
    if analyzer_available:
        table.add_row('2', 'Analisis Gemini', 'Kirim ke Gemini untuk laporan lengkap')
    else:
        table.add_row('2', 'Analisis Gemini', 'Tidak tersedia - butuh API key')
    table.add_row('3', 'Lewati', 'Jangan analisis file ini')
    console.print(table)
    choice_map = {'1': 'summary', '2': 'ai', '3': 'skip', '': 'summary'}
    while True:
        choice = console.input('[bold cyan]Pilih mode untuk file ini (default 1) > [/bold cyan]').strip().lower()
        if choice in choice_map:
            return choice_map[choice]
        if not choice:
            return 'summary'
        console.print(f"[yellow]Pilihan '{choice}' tidak dikenali.[/yellow]")


def _print_js_quick_summary(meta: Dict) -> None:
    sinks = meta.get('sink_hits') or []
    sources = meta.get('source_hits') or []
    snippets = meta.get('sink_snippets') or []
    snippet_lines = "\n".join(
        f"- {item['label']}: {item['snippet']}" for item in snippets[:5]
    )
    if not snippet_lines:
        snippet_lines = '-'
    body = (
        f"Score: {meta.get('score', 0)}\n"
        f"Konsekuensi: Sinks={len(sinks)} | Sources={len(sources)}\n"
        f"Contexts: {', '.join(meta.get('contexts') or []) or '-'}\n\n"
        f"Snippet sink:\n{snippet_lines}"
    )
    console.print(Panel(body, title='[bold cyan]Ringkasan JS[/bold cyan]', border_style='cyan'))
def setup_logging(verbose: bool):
    logger.setLevel(logging.DEBUG)
    console_handler = RichHandler(
        rich_tracebacks=True, console=console, show_path=False, show_level=False
    )
    # 💡 Pakai DEBUG kalau verbose, bukan INFO
    console_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    logger.addHandler(console_handler)

    file_handler = logging.FileHandler(str(LOG_FILE), encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)


def run():
    args = parse_args()
    setup_logging(not args.summary_only)
    session.verify = not args.insecure

    login_cfg: dict | None = None
    waf_plan: dict | None = None
    # 1) Muat payloads
    payloads = DEFAULT_XSS_PAYLOADS
    if args.payloads:
        path = Path(args.payloads)
        if path.is_file():
            payloads = load_payloads_from_yaml(path)
        else:
            console.print(f"[bold red][!] File payload tidak ditemukan: {args.payloads}[/bold red]")

    # 2) Inisialisasi AI Analyzer (jika ada API key)
    api_key = args.api_key or os.getenv("GENAI_API_KEY", "")
    analyzer = None
    if api_key:
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            analyzer = AIAnalyzer(client, console_obj=console)
            console.print("[bold green]✔ Klien GenAI berhasil diinisialisasi.[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Gagal inisialisasi GenAI Client: {e}[/bold red]")
            console.print("[yellow]Analisis AI akan dilewati.[/yellow]")
    else:
        console.print("[yellow]Analisis AI akan dilewati (no API key).[/yellow]")

    # 3) Tampilkan banner & cookie
    display_banner()
    if args.cookie:
        session.headers.update({"Cookie": args.cookie})
        console.print(f"[green]✔ Cookie diset:[/green] [dim]{args.cookie}[/dim]")

    waf_detector = None
    fingerprints_path = Path(__file__).resolve().parent / "waf_fingerprints.yaml"
    if fingerprints_path.exists():
        try:
            waf_detector = WAFDetector(fingerprints_path=fingerprints_path)
            profile = waf_detector.detect(args.url)
            register_waf(waf_detector)
            matches = profile.matches or {}
            friendly_vendor = _friendly_waf_name(profile.vendor)
            waf_lines = [
                f"{friendly_vendor} terdeteksi",
                f"Origin : {profile.origin}",
                f"Vendor : {profile.vendor} (confidence: {profile.confidence})",
                f"Challenge : {profile.challenge} | Rate limit: {'yes' if profile.rate_limit else 'no'}",
                f"Safe RPS : {profile.safe_rps:.2f} req/s | Backoff: {profile.backoff_ms} ms",
            ]
            if matches.get("headers"):
                waf_lines.append("Header hits: " + ", ".join(matches["headers"][:3]))
            if matches.get("cookies"):
                waf_lines.append("Cookie hits: " + ", ".join(matches["cookies"][:3]))
            if matches.get("body"):
                waf_lines.append("Body markers: " + ", ".join(matches["body"][:2]))
            if profile.notes:
                waf_lines.append(f"Notes: {profile.notes}")
            console.print(Panel("\n".join(waf_lines), title='[bold yellow]WAF Detection[/bold yellow]', border_style='yellow'))
            set_waf_throttle(profile.origin, profile.safe_rps, profile.backoff_ms)
            if profile.vendor != 'unknown':
                decision = console.input('[bold yellow]Lanjutkan dengan strategi bypass ini? (y/n) > [/]').strip().lower()
                if decision not in {'y', 'ya', 'yes'}:
                    console.print('[yellow]Pemindaian dibatalkan oleh pengguna.[/yellow]')
                    return
                if profile.challenge in ('js', 'captcha') and args.mode == 'quick':
                    switch = console.input('[cyan]WAF memerlukan eksekusi JavaScript. Beralih ke mode dynamic? (Y/n) > [/cyan]').strip().lower()
                    if switch in {'', 'y', 'ya', 'yes'}:
                        args.mode = 'deep'
                waf_plan = {
                    'vendor': profile.vendor,
                    'bypass_level': profile.bypass_level,
                    'no_javascript_url': profile.metadata.get('no_javascript_url', profile.challenge in ('js', 'captcha')),
                    'reduce_inline_handlers': profile.metadata.get('reduce_inline_handlers', profile.challenge == 'js'),
                    'short_payloads': profile.metadata.get('short_payloads', profile.rate_limit or profile.safe_rps < 1.0),
                    'prefer_minimal_attr': True,
                }
            else:
                console.print('[green]Tidak ada fingerprint WAF yang dikenali secara pasti.[/green]')
        except Exception as exc:
            logger.debug(f'WAF detection failed: {exc}')
    else:
        logger.debug(f'Fingerprint WAF tidak ditemukan di {fingerprints_path}')

# ------------------------------------------------------------------
    # BLOK BARU: handle --manual-login
    # ------------------------------------------------------------------
    if args.manual_login and args.login_url:
        import json
        from login_flow import manual_login_capture  # helper yg Anda buat

        cookie_file = Path(args.cookie_file)

        if cookie_file.exists():
            console.print(f"[green]\u2714 Memuat cookie dari {cookie_file}[/green]")
            state = json.loads(cookie_file.read_text(encoding="utf-8"))
            for c in state["cookies"]:
                session.cookies.set(
                    c["name"],
                    c["value"],
                    domain=c.get("domain"),
                    path=c.get("path"),
                )
        else:
            cookies = manual_login_capture(
                args.login_url,
                Path(args.cookie_file),
                headless=False,  # Google perlu visible
            )
            for c in cookies:
                session.cookies.set(
                    c["name"],
                    c["value"],
                    domain=c.get("domain"),
                    path=c.get("path"),
                )
        # Matikan auto-login Playwright karena kita sudah punya sesi
        login_cfg = None

    # 4) Inisialisasi tester dengan thread pool
    tester = XSSTester(payloads, max_workers=args.workers, waf_plan=waf_plan)
    configure_ui(console=console, progress_style="log")

    # 5) Siapkan konfigurasi login (jika ada, dan belum diganti mode manual)
    if (not args.manual_login) and args.login_url and args.username and args.password:
        login_cfg = {
            "url":        args.login_url,
            "username":   args.username,
            "password":   args.password,
            "user_field": args.user_selector,
            "pass_field": args.pass_selector,
            "submit_sel": args.submit_selector,
        }


    # 6) Pilih crawler berdasarkan mode
    if args.mode == 'quick':
        from crawler.crawler import XSSCrawler
        console.print(Rule("[bold yellow]🚀 Memulai Quick Static Crawler[/bold yellow]", style="yellow"))
        crawler = XSSCrawler(
            start_url=args.url,
            max_depth=args.depth,
            max_urls=args.max_urls,
            verbose=not args.summary_only
        )
    else:
        from crawler.advanced_crawler import AdvancedXSSCrawler
        console.print(Rule("[bold cyan] Memulai Advanced Dynamic Crawler[/bold cyan]", style="cyan"))
        crawler = AdvancedXSSCrawler(
            start_url=args.url,
            max_depth=args.depth,
            max_urls=args.max_urls,
            verbose=not args.summary_only,
            login_cfg=login_cfg,
            storage_state_file=args.cookie_file
        )

    # 7) Crawl & temukan parameter/JS
    crawler.crawl_and_discover_parameters()
    console.print(Rule("[bold green]✅ Crawler Selesai[/bold green]", style="green"))

    params = crawler.discovered_parameters
    js_files = crawler.discovered_js

    if not params and not js_files:
        console.print("[yellow]Tidak ada parameter atau file JavaScript yang ditemukan untuk diuji.[/yellow]")
        return

    # 8) Loop testing
    while True:
        table = Table(
            title="[bold]Target Pengujian yang Ditemukan[/bold]",
            border_style="cyan", show_lines=True
        )
        table.add_column("Pilihan", style="bold yellow", justify="center")
        table.add_column("Parameter/File", style="cyan")
        table.add_column("Method/Jenis", style="magenta")
        table.add_column("Endpoint (Agregat)", style="green", overflow="fold")

        # Kelompokkan parameter per endpoint
        grouped = {}
        for p in params:
            key = (p['url'], p['method'])
            grouped.setdefault(key, {'names': set(), 'entries': []})
            grouped[key]['names'].add(p['name'])
            grouped[key]['entries'].append(p)

        choice_map = {}
        idx = 1
        for (url, method), info in grouped.items():
            names = ", ".join(sorted(info['names']))
            table.add_row(str(idx), names, method, url)
            choice_map[str(idx)] = info['entries']
            idx += 1

        if js_files:
            table.add_section()
            table.add_row("js", f"Analisis Semua JS ({len(js_files)} file)", "—", "DOM-based XSS scan")

        console.print(table)

        choice = console.input("[bold]Pilihan Anda ('semua', js, 'q' untuk keluar) > [/bold]").strip().lower()
        if choice in ("q", "keluar"):
            break

        selected_params = []
        selected_js = []

        if choice == "semua":
            selected_params = params.copy()
        elif choice == "js":
            selected_js = list(js_files)
        else:
            for part in choice.split(","):
                part = part.strip()
                if part in choice_map:
                    selected_params.extend(choice_map[part])
                else:
                    console.print(f"[yellow]Pilihan '{part}' tidak valid.[/yellow]")

        if not selected_params and not selected_js:
            console.print("[red]Tidak ada pilihan yang valid.[/red]")
            continue

        # Uji parameter dengan pipeline bertahap (static -> dynamic -> AI)
        for p in selected_params:
            console.print(Panel(
                (
                    f"[bold]Parameter:[/bold] [yellow]{p['name']}[/yellow]\n"
                    f"[bold]URL/Action:[/bold] [underline]{p['url']}[/underline]\n"
                    f"[bold]Method:[/bold] [magenta]{p['method']}[/magenta]"
                ),
                title='[bold bright_magenta]Menguji Parameter[/bold bright_magenta]',
                border_style='magenta'
            ))
            template = dict(p.get('data_template', {}))
            sanitizer_map: dict = {}
            sanitizer_summary = {}
            sanitizer_error = None
            with console.status('[cyan]Memprofilkan refleksi statis (HTML/CSS/JS)...[/cyan]', spinner='dots'):
                try:
                    sanitizer_map = analyze_param_sanitizer(p['url'], p['name'], template, p['method'], p['is_form']) or {}
                except Exception as exc:
                    sanitizer_error = exc
            if sanitizer_error:
                console.print(f'[red]Gagal menganalisis sanitizer: {sanitizer_error}[/red]')
                sanitizer_map = {}
            else:
                sanitizer_summary = _render_sanitizer_overview(p['name'], sanitizer_map)

            mode = _prompt_analysis_actions(analyzer is not None)

            runtime_findings: List[dict] = []

            if mode == 'skip':
                console.print('[yellow]Parameter dilewati sesuai permintaan pengguna.[/yellow]')
                continue

            if mode in {'full', 'dom'}:
                with console.status('[cyan]Menjalankan inspeksi DOM dinamis...[/cyan]', spinner='dots'):
                    try:
                        runtime_findings = dynamic_dom_inspect(p['url']) or []
                    except Exception as exc:
                        logger.debug(f'DOM inspect gagal: {exc}')
                        runtime_findings = []
                if runtime_findings:
                    console.print(Panel(f"{len(runtime_findings)} temuan runtime sink/mutation.", title='[cyan]Dynamic Findings[/cyan]'))
                else:
                    console.print('[yellow]Tidak ada temuan runtime dari inspeksi DOM.[/yellow]')

            if mode == 'dom':
                if analyzer:
                    ai_choice = console.input('[bold magenta]Lanjutkan dengan analisis Gemini? (Y/n) > [/bold magenta]').strip().lower()
                    if ai_choice in {'', 'y', 'ya', 'yes'}:
                        ai_payload = {
                            **p,
                            'sanitizer_map': sanitizer_map,
                            'sanitizer_summary': sanitizer_summary,
                            'taint_flow': runtime_findings,
                            'vulns': [],
                        }
                        analyzer.perform_interactive_ai_for_parameter(ai_payload, interactive=False)
                else:
                    console.print('[yellow]Analisis AI tidak tersedia (set GENAI_API_KEY untuk mengaktifkan).[/yellow]')
                continue

            if mode == 'ai':
                if not analyzer:
                    console.print('[yellow]Analisis AI tidak tersedia karena tidak ada API key Gemini.[/yellow]')
                else:
                    ai_payload = {
                        **p,
                        'sanitizer_map': sanitizer_map,
                        'sanitizer_summary': sanitizer_summary,
                        'taint_flow': runtime_findings,
                        'vulns': [],
                    }
                    analyzer.perform_interactive_ai_for_parameter(ai_payload, interactive=False)
                continue

            template_for_test = dict(template)
            before = len(tester.vulns)
            tester.test_parameter(
                p['url'],
                p['method'],
                p['name'],
                template_for_test,
                p['is_form'],
                sanitizer_baseline=sanitizer_map if sanitizer_map else None
            )
            after = len(tester.vulns)
            new_vulns = tester.vulns[before:after]
            if new_vulns:
                _render_vuln_summary(new_vulns)
            else:
                console.print('[yellow]Belum ada payload yang terbukti dieksekusi.[/yellow]')

            runtime_findings = runtime_findings or tester.last_runtime_findings
            if analyzer:
                ai_choice = console.input('[bold magenta]Perkuat dengan analisis Gemini? (Y/n) > [/bold magenta]').strip().lower()
                if ai_choice in {'', 'y', 'ya', 'yes'}:
                    ai_payload = {
                        **p,
                        'sanitizer_map': sanitizer_map,
                        'sanitizer_summary': sanitizer_summary,
                        'taint_flow': runtime_findings,
                        'vulns': new_vulns,
                    }
                    analyzer.perform_interactive_ai_for_parameter(ai_payload, interactive=False)

        # Uji JS eksternal
        if selected_js:
            metas = _prepare_js_overview(selected_js)
            if not metas:
                console.print('[yellow]Tidak ada file JavaScript yang dapat dianalisis.[/yellow]')
            else:
                chosen_js = _prompt_js_selection(metas)
                for meta in chosen_js:
                    console.print(Panel(
                        f"Menganalisis File JS: [underline]{meta['url']}[/underline]",
                        title="[bold]Target JavaScript[/bold]",
                        border_style="cyan"
                    ))
                    action = _prompt_js_action(analyzer is not None)
                    if action == 'skip':
                        console.print('[yellow]File JS dilewati sesuai permintaan pengguna.[/yellow]')
                        continue
                    if action == 'summary':
                        _print_js_quick_summary(meta)
                        if analyzer:
                            follow = console.input('[bold magenta]Jalankan analisis Gemini juga? (Y/n) > [/bold magenta]').strip().lower()
                            if follow in {'', 'y', 'ya', 'yes'}:
                                analyzer.analyze_external_js(meta['url'], mode='ai', js_code=meta.get('code'))
                        else:
                            console.print('[yellow]Analisis AI tidak tersedia (set GENAI_API_KEY untuk mengaktifkan).[/yellow]')
                        continue
                    if action == 'ai':
                        if analyzer:
                            analyzer.analyze_external_js(meta['url'], mode='ai', js_code=meta.get('code'))
                        else:
                            console.print('[yellow]Analisis AI tidak tersedia karena tidak ada API key Gemini.[/yellow]')
                            _print_js_quick_summary(meta)
                        continue

        again = console.input("\n[bold]Uji target lain? (y/n) > [/bold]").strip().lower()
        if again != 'y':
            break

    if tester.resilience_reports:
        summary = tester.resilience_summary()
        checklist_items = summary.get('checklist') or []
        checklist = "\n".join(f"- {item}" for item in checklist_items)
        panel_body = (
            f"Score: [bold]{summary.get('score', 0)}/100[/bold]\n"
            f"Confidence: {summary.get('confidence', 'unknown')}\n\n"
            f"{checklist or 'Tidak ada bukti terverifikasi.'}"
        )
        console.print(Panel(panel_body, title='[bold cyan]XSS Resilience Score[/bold cyan]', border_style='cyan'))
    else:
        console.print('[yellow]Tidak ada data resilience yang dapat dirangkum.[/yellow]')


    # 9) GraphQL XSS scan (opsional)
    if args.graphql:
        console.print(Rule("[bold magenta]🔍 GraphQL XSS Scan[/bold magenta]", style="magenta"))
        endpoints = graphql_scanner.discover_graphql_endpoints(args.url)
        if not endpoints:
            console.print("[yellow]Tidak ditemukan endpoint GraphQL umum.[/yellow]")
        else:
            for ep in endpoints:
                console.print(f"[blue]→ Introspecting {ep}…[/blue]")
                schema = graphql_scanner.introspect_schema(ep)
                if schema:
                    graphql_scanner.test_graphql_xss(ep, schema)
                else:
                    console.print(f"[bold red]✖ Gagal introspeksi di {ep}[/bold red]")


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        console.print("\n[bold red]Dibatalkan pengguna — keluar program.[/bold red]")
        sys.exit(1)
    except Exception:
        logger.error("Terjadi error tak terduga!", exc_info=True)
