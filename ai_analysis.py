# ai_analysis.py â€” ULTRA-MAX

from __future__ import annotations

import json
import logging
import math
import re
import time
from dataclasses import dataclass
from typing import List, Tuple, Union, Dict, Any, Optional
from urllib.parse import urljoin
from collections import OrderedDict

try:
    from rich.console import Console as _RichConsole
    from rich.panel import Panel as _RichPanel
    from rich.table import Table as _RichTable
    from rich.text import Text as _RichText
    from rich import box
    _HAS_RICH = True
except Exception:
    _RichConsole = _RichPanel = _RichTable = _RichText = None
    box = None
    _HAS_RICH = False

from bs4 import BeautifulSoup
from google.genai import types

from network import make_request
from parsers.context_parser import ContextParser
from utils import fetch_dynamic_html, strip_markdown, parse_csp

class _DummyStatus:
    def __init__(self, msg):
        self.msg = msg
    def __enter__(self):
        print(self.msg)
        return self
    def __exit__(self, exc_type, exc, tb):
        return False


class _SimpleConsole:
    def print(self, *args, **kwargs):
        print(*args)
    def status(self, msg, spinner="dots"):
        return _DummyStatus(msg)
    def input(self, prompt=""):
        return input(prompt)


def _fallback_panel(content, title=None, border_style=None):
    header = f"=== {title} ===\n" if title else ""
    return f"{header}{content}"


if _HAS_RICH:
    console = _RichConsole(highlight=False)
    Panel = _RichPanel
else:
    console = _SimpleConsole()
    Panel = _fallback_panel
logger = logging.getLogger("xsscanner.ai")


# =========================
# Heuristik ekstraksi JS
# =========================
SINK_PATTERNS = [
    r"\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln)\b",
    r"\b(eval|Function|setTimeout\s*\(|setInterval\s*\()\b",
    r"\b(createContextualFragment|parseFromString)\b",
    r"\.on(?:click|error|load|mouseover|focus|blur)\s*=",
    r"\b(addEventListener)\s*\(\s*['\"](?:click|error|load|mouseover|focus|blur)['\"]",
    r"\b(location|document)\.(hash|search|href|cookie)\b",
    r"\b(localStorage|sessionStorage)\.(getItem|setItem)\b",
    r"\b(\$|jQuery)\s*\([^)]*\)\.(html|append|prepend|before|after|replaceWith)\s*\(",
]
SINK_LABELS = [
    "innerHTML / document.write",
    "eval / Function / setTimeout string",
    "DOMParser / contextual fragment",
    "Inline event handler assignment",
    "addEventListener dynamic handler",
    "location / document.* sinks",
    "WebStorage access",
    "jQuery DOM injection",
]




SINK_REGEX = [re.compile(p, re.IGNORECASE) for p in SINK_PATTERNS]


def _normalize_ai_text(text: str) -> str:
    if not text:
        return ""
    try:
        text = text.encode('latin1').decode('utf-8')
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass
    replacements = {
        '\u2022': '- ',
        '\u00b7': '- ',
        '\u2013': '-',
        '\u2014': '-',
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text.strip()


def _extract_snippets(js: str, *, window: int = 220, max_snippets: int = 24) -> List[str]:
    """
    Potong bagian JS di sekitar sink agar hemat token untuk LLM,
    mengembalikan potongan unik & relevan.
    """
    seen = set()
    out: List[str] = []
    for rx in SINK_REGEX:
        for m in rx.finditer(js):
            start = max(0, m.start() - window)
            end = min(len(js), m.end() + window)
            seg = js[start:end]
            # normalisasi kecil agar dedupe lebih mudah
            key = re.sub(r"\s+", " ", seg.strip().lower())
            if key in seen:
                continue
            seen.add(key)
            out.append(seg.strip())
            if len(out) >= max_snippets:
                return out
    # fallback: kalau tidak ketemu pola, ambil head & tail kecil
    if not out:
        head = js[:500].strip()
        tail = js[-500:].strip()
        for seg in (head, tail):
            if seg and seg.lower() not in seen:
                out.append(seg)
    return out



SECTION_STYLE_MAP = {
    "summary": ("bold bright_yellow", "white"),
    "evidence": ("bold magenta", "white"),
    "exploit paths": ("bold red", "white"),
    "payloads": ("bold green", "white"),
    "mitigations": ("bold cyan", "white"),
    "validation plan": ("bold blue", "white"),
    "top actions": ("bold bright_white", "white"),
    "noise to ignore": ("bold bright_black", "white"),
    "clusters": ("bold magenta", "white"),
    "risks": ("bold red", "white"),
    "recommendations": ("bold cyan", "white"),
    "next steps": ("bold cyan", "white"),
    "details": ("bold white", "white"),
}


def _parse_ai_sections(text: str) -> OrderedDict[str, List[str]]:
    sections: OrderedDict[str, List[str]] = OrderedDict()
    if not text:
        return sections
    current_key: Optional[str] = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line and line[0] in "-*•":
            content = line[1:].strip()
            header_match = re.match(r"([^:]+):\s*(.*)", content)
            if header_match:
                current_key = header_match.group(1).strip()
                value = header_match.group(2).strip()
                sections.setdefault(current_key, [])
                if value:
                    sections[current_key].append(value)
            else:
                if current_key is None:
                    current_key = "details"
                    sections.setdefault(current_key, [])
                sections[current_key].append(content)
            continue

        number_match = re.match(r"^(\d+[.)]|L\d+)\s*(.+)", line, re.IGNORECASE)
        if number_match:
            if current_key is None:
                current_key = "details"
                sections.setdefault(current_key, [])
            sections[current_key].append(f"{number_match.group(1)} {number_match.group(2).strip()}")
            continue
        if current_key is None:
            current_key = "details"
            sections.setdefault(current_key, [])
        if sections[current_key]:
            sections[current_key][-1] = f"{sections[current_key][-1]} {line}"
        else:
            sections[current_key].append(line)
    return sections


def _format_section_lines(lines: List[str]) -> str:
    if not lines:
        return "-"
    formatted: List[str] = []
    for item in lines:
        text = item.strip()
        if not text:
            continue
        if re.match(r"^(\d+[.)]|L\d+)", text, re.IGNORECASE):
            formatted.append(text)
        elif text.startswith(tuple("-*")) or text.startswith("•"):
            formatted.append(text)
        else:
            formatted.append(f"- {text}")
    return "\n".join(formatted) if formatted else "-"


def _render_ai_output(console_obj, clean_text: str, *, title: str, border_style: str = "green") -> None:
    message = clean_text.strip() if clean_text else "(Tidak ada respons AI)"
    if _HAS_RICH and _RichTable and _RichText:
        sections = _parse_ai_sections(message)
        panel_title = f"[bold]{title}[/bold]"
        if sections:
            if box:
                table = _RichTable(show_header=False, expand=True, box=box.SIMPLE, pad_edge=False)
            else:
                table = _RichTable(show_header=False, expand=True)
            table.add_column("Bagian", style="bold cyan", no_wrap=True, ratio=1)
            table.add_column("Detail", style="white", ratio=3, overflow="fold")
            for header, items in sections.items():
                key_norm = header.lower().strip()
                header_style, body_style = SECTION_STYLE_MAP.get(key_norm, ("bold white", "white"))
                header_render = _RichText(header, style=header_style)
                body_render = _RichText(_format_section_lines(items), style=body_style)
                table.add_row(header_render, body_render)
            console_obj.print(Panel(table, title=panel_title, border_style=border_style))
            return
        console_obj.print(Panel(_RichText(message), title=panel_title, border_style=border_style))
    else:
        console_obj.print(Panel(message, title=title, border_style=border_style))



# =========================
# Util untuk Part & limit
# =========================
def _part_from_text(text: str, mime: str) -> types.Part:
    return types.Part.from_bytes(data=text.encode("utf-8", errors="ignore"), mime_type=mime)


def _chunk_bytes(s: str, max_bytes: int) -> List[str]:
    """
    Potong string s menjadi beberapa bagian ~max_bytes (UTF-8 safe-ish).
    """
    b = s.encode("utf-8", errors="ignore")
    if len(b) <= max_bytes:
        return [s]
    parts: List[bytes] = []
    for i in range(0, len(b), max_bytes):
        parts.append(b[i : i + max_bytes])
    return [p.decode("utf-8", errors="ignore") for p in parts]


@dataclass
class ModelPrefs:
    # Prioritaskan model stabil untuk analisis tekstual panjang
    prefer: str = 'gemini-1.5-pro-latest'
    fallbacks: Tuple[str, ...] = (
        'gemini-1.5-flash-latest',
        'gemini-2.0-flash-exp',
        'gemini-2.0-flash',
        'gemini-1.0-pro',
    )


DEFAULT_MODEL_PREFS = ModelPrefs()


SYSTEM_PROMPT_CORE = (
    "--- XSS/DOM-XSS ANALYSIS TASK ---\n"
    "You are a senior AppSec engineer specializing in XSS & DOM-XSS.\n"
    "Work strictly with the provided HTML/JS/runtime evidence. Be precise and practical.\n\n"
    "FORMAT (plain text bullets, no markdown/no code fences):\n"
    "â€¢ Summary: overall XSS risk & affected contexts.\n"
    "â€¢ Evidence: concrete reflection points (sourceâ†’sink), include minimal code lines from snippets.\n"
    "â€¢ Exploit paths: ranked 1..N with reasoning why exploitable.\n"
    "â€¢ Payloads:\n"
    "  - L1 (auto-exec): minimal payload using event/autofocus/onload/URI.\n"
    "  - L2 (polyglot/obfuscation): resilient to naive filters.\n"
    "  - L3 (encoding/case-mix): WAF/CSP-aware bypass.\n"
    "â€¢ Mitigations: encoding, trusted types, proper context-escaping, CSP hardening.\n"
    "â€¢ Validation plan: steps to confirm via headless/coverage.\n"
)


class AIAnalyzer:
    def __init__(
        self,
        ai_client,
        model_prefs: ModelPrefs = DEFAULT_MODEL_PREFS,
        *,
        console_obj=None,
        max_html_bytes: int = 200_000,     # ~200 KB untuk HTML (prettified)
        max_js_snippets: int = 36,         # total snippet JS dikirim
        max_snippet_bytes: int = 8_000,    # per snippet
        max_external_js_for_ai: int = 3,   # batas default file JS eksternal utk AI
        max_findings_json: int = 40,       # batasi temuan runtime
    ):
        """
        ai_client: genai.Client(api_key=...)
        """
        global console
        self.client = ai_client
        self.model_prefs = model_prefs
        self.max_html_bytes = max_html_bytes
        self.max_js_snippets = max_js_snippets
        self.max_snippet_bytes = max_snippet_bytes
        self.max_findings_json = max_findings_json
        self.max_external_js_for_ai = None if max_external_js_for_ai is None else max(0, int(max_external_js_for_ai))

        global console
        self.console = console_obj or console
        if console_obj is not None:
            console = self.console

        self.history: List[Union[types.Part, str]] = []
        self.last_response: str = ""
        self._model_catalog: List[str] = []
        self._refresh_model_catalog()

    # ---------------- AI Core ----------------

    def _refresh_model_catalog(self) -> None:
        catalog: List[str] = []
        try:
            for model in self.client.models.list():
                name = getattr(model, 'name', '') or ''
                methods = getattr(model, 'supported_generation_methods', []) or []
                if not name:
                    continue
                if methods and 'generateContent' not in methods:
                    continue
                catalog.append(name)
                if name.startswith('models/'):
                    alias = name.split('models/', 1)[1]
                    if alias:
                        catalog.append(alias)
        except Exception as exc:
            logger.debug(f'ListModels gagal: {exc}')
            catalog = []
        seen: set[str] = set()
        ordered: List[str] = []
        for item in catalog:
            item = (item or '').strip()
            if item and item not in seen:
                seen.add(item)
                ordered.append(item)
        self._model_catalog = ordered

    @staticmethod
    def _expand_model_aliases(seed: str) -> List[str]:
        seed = (seed or '').strip()
        if not seed:
            return []
        base = seed.split('/', 1)[1] if seed.startswith('models/') else seed
        candidates: List[str] = []
        seen: set[str] = set()

        def _push(value: str) -> None:
            value = (value or '').strip()
            if not value or value in seen:
                return
            seen.add(value)
            candidates.append(value)

        _push(seed)
        _push(base)
        _push(f'models/{base}')
        suffixes = ['-latest', '-exp']
        for suff in suffixes:
            if not base.endswith(suff.strip('-')):
                _push(f'{base}{suff}')
                _push(f'models/{base}{suff}')
        return candidates

    @staticmethod
    def _score_model_name(name: str) -> tuple[int, int, str]:
        key = name.lower()
        score = 0
        if 'pro' in key:
            score -= 100
        if '1.5' in key:
            score -= 20
        if key.endswith('latest'):
            score -= 5
        if 'flash' in key:
            score += 5
        return (score, len(name), name)

    def _candidate_model_ids(self) -> List[str]:
        if not self._model_catalog:
            self._refresh_model_catalog()
        seeds = [self.model_prefs.prefer] + list(self.model_prefs.fallbacks)
        manual: List[str] = []
        for seed in seeds:
            manual.extend(self._expand_model_aliases(seed))
        dedup: List[str] = []
        seen_manual: set[str] = set()
        for item in manual:
            item = (item or '').strip()
            if not item or item in seen_manual:
                continue
            seen_manual.add(item)
            dedup.append(item)
        manual = dedup
        if self._model_catalog:
            matched = [m for m in manual if m in self._model_catalog]
            if matched:
                return matched
            return sorted(self._model_catalog, key=self._score_model_name)
        return manual

    def _try_models(self, contents: List[Union[types.Part, str]]) -> str:
        errors: List[str] = []
        candidates = self._candidate_model_ids()
        for mid in candidates:
            try:
                with self.console.status(f"[bold blue]Meminta AI ({mid})[/bold blue]", spinner="dots"):
                    resp = self.client.models.generate_content(model=mid, contents=contents)
                text = (resp.text or "").strip()
                if not text:
                    raise RuntimeError("Empty AI response")
                self.last_response = text
                return text
            except Exception as e:
                msg = f"{type(e).__name__}: {e}"
                logger.warning(f"Model {mid} gagal: {msg}")
                errors.append(f"{mid}: {msg}")
                time.sleep(0.8)
        logger.error("Semua model gagal. Kandidat dicoba: " + ", ".join(candidates) + ". Detail: " + " | ".join(errors))
        return "[ERROR] AI invocation failed."

    # ---------------- High-level flows ----------------

    def _select_external_js_candidates(
        self,
        candidates: List[Dict[str, Any]],
        *,
        interactive: bool,
    ) -> List[Dict[str, Any]]:
        if not candidates:
            return []

        ordered = sorted(
            candidates,
            key=lambda c: (c.get("score", 0), len(c.get("snips") or []), len(c.get("contexts") or [])),
            reverse=True,
        )
        default_count = self.max_external_js_for_ai if self.max_external_js_for_ai is not None else len(ordered)
        if default_count < 0:
            default_count = 0
        default_count = min(default_count, len(ordered))
        default_selection = ordered[:default_count] if default_count else []

        if _HAS_RICH and _RichTable:
            if box:
                table = _RichTable(
                    title='[bold cyan]Prioritas JS Eksternal[/bold cyan]',
                    show_header=True,
                    header_style='bold cyan',
                    expand=True,
                    box=box.SIMPLE,
                    pad_edge=False,
                )
            else:
                table = _RichTable(
                    title='[bold cyan]Prioritas JS Eksternal[/bold cyan]',
                    show_header=True,
                    header_style='bold cyan',
                    expand=True,
                )
            table.add_column('#', style='bold yellow', justify='center', no_wrap=True)
            table.add_column('Score', style='magenta', justify='right')
            table.add_column('Snips', style='red', justify='right')
            table.add_column('Contexts', style='cyan')
            table.add_column('Size', style='green', justify='right')
            table.add_column('URL', style='white', overflow='fold')
            for idx_row, cand in enumerate(ordered, start=1):
                contexts_label = ', '.join(cand.get('contexts') or []) or '-'
                size_kb = f"{cand.get('size', 0) / 1024:.1f} KB"
                table.add_row(
                    str(idx_row),
                    str(int(cand.get('score', 0))),
                    str(len(cand.get('snips') or [])),
                    contexts_label,
                    size_kb,
                    cand.get('url', '-') or '-',
                )
            self.console.print(table)
        else:
            lines = ['Prioritas JS eksternal:']
            for idx_row, cand in enumerate(ordered, start=1):
                contexts_label = ', '.join(cand.get('contexts') or []) or '-'
                size_kb = f"{cand.get('size', 0) / 1024:.1f} KB"
                lines.append(
                    f"{idx_row}. score={int(cand.get('score', 0))} snips={len(cand.get('snips') or [])} ctx={contexts_label} size={size_kb} -> {cand.get('url', '-') or '-'}"
                )
            self.console.print("\n".join(lines))

        if not interactive:
            if default_selection:
                if len(default_selection) < len(ordered):
                    msg = f"Memakai {len(default_selection)} file JS teratas dari {len(ordered)} untuk prompt AI."
                    self.console.print(f"[dim]{msg}[/dim]" if _HAS_RICH else msg)
            else:
                msg = 'Tidak ada file JS eksternal terpilih otomatis untuk prompt AI.'
                self.console.print(f"[dim]{msg}[/dim]" if _HAS_RICH else msg)
            return list(default_selection)

        if default_selection:
            if len(default_selection) == len(ordered):
                enter_hint = 'all'
            else:
                enter_hint = f"top{len(default_selection)}"
        else:
            enter_hint = 'skip'
        prompt = f"[bold cyan]Pilih file JS untuk prompt AI (misal 1,3 atau 'top3'/'all'/'skip'; ENTER={enter_hint}) > [/bold cyan]"

        while True:
            choice = self.console.input(prompt).strip().lower()
            if not choice:
                chosen = list(default_selection)
                break
            if choice in {'skip', 'none', '0'}:
                chosen = []
                break
            if choice in {'all', 'semua', '*'}:
                chosen = ordered
                break
            if choice.startswith('top'):
                suffix = choice[3:].strip()
                if not suffix:
                    num = len(default_selection) or 3
                else:
                    try:
                        num = int(suffix)
                    except ValueError:
                        num = len(default_selection) or len(ordered)
                num = max(0, min(num, len(ordered)))
                chosen = ordered[:num]
                break
            if choice.isdigit():
                num = int(choice)
                num = max(0, min(num, len(ordered)))
                chosen = ordered[:num]
                break
            picks: List[Dict[str, Any]] = []
            valid = True
            for part in choice.split(','):
                part = part.strip()
                if not part:
                    continue
                if not part.isdigit():
                    valid = False
                    break
                idx_val = int(part)
                if idx_val < 1 or idx_val > len(ordered):
                    valid = False
                    break
                cand = ordered[idx_val - 1]
                if cand not in picks:
                    picks.append(cand)
            if valid and picks:
                chosen = picks
                break
            self.console.print(f"[yellow]Pilihan '{choice}' tidak dikenali.[/yellow]")

        if chosen:
            preview = ', '.join(c.get('url', '-') for c in chosen[:3])
            if len(chosen) > 3:
                preview += ', ...'
            msg = f"Mengirim {len(chosen)} file JS ke AI: {preview}"
            self.console.print(f"[dim]{msg}[/dim]" if _HAS_RICH else msg)
        else:
            msg = 'Tidak ada file JS eksternal yang dikirim ke AI.'
            self.console.print(f"[yellow]{msg}[/yellow]" if _HAS_RICH else msg)
        return list(chosen)


    def perform_interactive_ai_for_parameter(self, param_info: dict, *, interactive: bool = True):
        """
        Orkestrasi:
          1) Render/Fetch HTML (dynamic â†’ static fallback)
          2) Runtime inspection (caller menyediakan? kita lakukan minimal fetch untuk CSP)
          3) Context detection (HTML)
          4) Ekstrak JS (inline & eksternal â†’ sink-centric snippets)
          5) Rakit prompt + parts (batasi ukuran)
          6) Panggil AI & tampilkan
          7) Loop tanya-jawab kecil (optional)
        """
        url = param_info["url"]
        pname = param_info["name"]

        sanitizer_summary = param_info.get("sanitizer_summary") or {}
        sanitizer_map = param_info.get("sanitizer_map") or {}

        # 1) Render/fetch HTML
        with self.console.status(f"[bold blue]Memuat & merender: {url}[/bold blue]", spinner="dots"):
            html_content = fetch_dynamic_html(url) or ""
            if not html_content:
                resp = make_request(url)
                html_content = (resp.text or "") if resp else ""

        if not html_content:
            self.console.print(Panel("[red]Gagal memuat HTML untuk analisis AI[/red]", title="AI", border_style="red"))
            return

        # 2) (Ringan) Fetch header untuk CSP insight
        csp_summary = "-"
        try:
            head = make_request(url, method="HEAD")
            if head:
                directives = parse_csp(head.headers.get("Content-Security-Policy", ""))
                if directives:
                    csp_summary = "; ".join(f"{k} {' '.join(v)}".strip() for k, v in directives.items() if v)
        except Exception:
            pass

        # Temuan runtime dari caller (opsional)
        runtime_findings = param_info.get("taint_flow") or param_info.get("runtime_findings") or []

        # 3) Context detection (HTML)
        contexts = ContextParser.parse(html_content, content_type="text/html")

        self.console.print(
            Panel(
                f"[bold]Konteks:[/bold] {', '.join(contexts) or '-'}\n"
                f"[bold]Sanitizer:[/bold] filtered={sanitizer_summary.get('filtered','-')} | encoded={sanitizer_summary.get('encoded','-')} | reflected={sanitizer_summary.get('reflected','-')}\n"
                f"[bold]CSP:[/bold] {csp_summary or '-'}\n"
                f"[bold]Runtime findings:[/bold] {len(runtime_findings)}",
                title="[magenta]Pre-Analysis[/magenta]",
                border_style="magenta",
            )
        )

        # 4) Ekstrak JS
        soup = BeautifulSoup(html_content, "html.parser")

        # Inline scripts
        inline_js: List[str] = []
        for tag in soup.find_all("script", src=False):
            code = (tag.string or "").strip()
            if code:
                inline_js.extend(_extract_snippets(code))

        # External scripts â†’ ambil dan potong
        external_srcs = [urljoin(url, tag["src"]) for tag in soup.find_all("script", src=True) if tag.get("src")]
        external_srcs = list(dict.fromkeys(external_srcs))  # dedupe preserve order

        external_candidates: List[Dict[str, Any]] = []
        for js_url in external_srcs:
            try:
                jr = make_request(js_url)
                js_code = jr.text or ""
            except Exception:
                continue
            if not js_code:
                continue
            snips = _extract_snippets(js_code)
            if not snips:
                continue
            contexts_js = ContextParser.parse(js_code, content_type="application/javascript")
            size_bytes = len(js_code)
            score = len(snips) * 5 + len({ctx.lower() for ctx in contexts_js}) + min(size_bytes // 5000, 4)
            external_candidates.append(
                {
                    "url": js_url,
                    "snips": snips,
                    "contexts": contexts_js,
                    "size": size_bytes,
                    "score": score,
                }
            )

        # 5) Rakit prompt + parts (dengan limiter)
        system_prompt = (
            SYSTEM_PROMPT_CORE
            + f"\nPARAMETER: `{pname}`\nURL: {url}\nDetected Contexts: {', '.join(contexts) or '-'}\nCSP (summary): {csp_summary or '-'}\n"
            + f"Sanitizer summary: filtered={sanitizer_summary.get('filtered','-')}, encoded={sanitizer_summary.get('encoded','-')}, reflected={sanitizer_summary.get('reflected','-')}\n"
        )

        parts: List[Union[types.Part, str]] = [system_prompt]

        # HTML â†’ prettify & chunk
        prettied = soup.prettify()
        html_chunks = _chunk_bytes(prettied, self.max_html_bytes)
        # Ambil hanya chunk pertama jika terlalu besar (LLM tidak butuh semua whitespace)
        html_to_send = html_chunks[:1] if len(html_chunks) > 1 else html_chunks
        for ch in html_to_send:
            parts.append(_part_from_text(ch, "text/html"))

        # Runtime findings (dibatasi)
        if runtime_findings:
            try:
                trimmed = runtime_findings[: self.max_findings_json]
                parts.append("### Runtime Findings (JSON, truncated)")
                parts.append(json.dumps(trimmed, ensure_ascii=False, indent=2))
            except Exception:
                pass

        if sanitizer_map:
            try:
                parts.append("### Sanitizer Map (char -> status)")
                parts.append(json.dumps(sanitizer_map, ensure_ascii=False, indent=2))
            except Exception:
                pass

        # Inline JS snippets
        if inline_js:
            capped_inline = inline_js[: math.ceil(self.max_js_snippets * 0.4)]
            for code in capped_inline:
                for chunk in _chunk_bytes(code, self.max_snippet_bytes):
                    parts.append(_part_from_text(chunk, "text/javascript"))

        # External JS snippets (prioritaskan URL yang punya banyak sink)
        selected_js = self._select_external_js_candidates(external_candidates, interactive=interactive)
        remaining = self.max_js_snippets - int(len(inline_js) * 0.4)
        remaining = max(8, remaining)

        for cand in selected_js:
            if remaining <= 0:
                break
            ctx_label = ", ".join(cand.get("contexts") or []) or "-"
            parts.append(f"### External JS: {cand.get('url')} (contexts: {ctx_label})")
            for seg in cand.get("snips") or []:
                if remaining <= 0:
                    break
                for chunk in _chunk_bytes(seg, self.max_snippet_bytes):
                    parts.append(_part_from_text(chunk, "text/javascript"))
                remaining -= 1

        # 6) Panggil AI
        ai_text = self._try_models(parts)
        clean_ai = _normalize_ai_text(strip_markdown(ai_text))
        _render_ai_output(self.console, clean_ai, title="Hasil Analisis AI", border_style="green")

        if not interactive:
            return

        # 7) Loop follow-up ringan
        while True:
            q = self.console.input("\n[bold]Lanjut ('js'=refresh JS, 'back'=menu, ENTER=selesai) > [/bold]").strip().lower()
            if not q or q == "back":
                return
            if q == "js":
                # refresh potongan JS (misal setelah navigasi lanjut)
                refreshed_parts: List[Union[types.Part, str]] = [system_prompt]
                for ch in html_to_send:
                    refreshed_parts.append(_part_from_text(ch, "text/html"))
                if runtime_findings:
                    refreshed_parts += ["### Runtime Findings (JSON, truncated)", json.dumps(runtime_findings[: self.max_findings_json], ensure_ascii=False, indent=2)]
                # re-pick JS
                js_parts: List[Union[types.Part, str]] = []
                # inline (cap lagi)
                for code in inline_js[: math.ceil(self.max_js_snippets * 0.4)]:
                    for chunk in _chunk_bytes(code, self.max_snippet_bytes):
                        js_parts.append(_part_from_text(chunk, "text/javascript"))
                # eksternal (pilihan ulang)
                selected_js = self._select_external_js_candidates(external_candidates, interactive=True)
                remaining2 = self.max_js_snippets - int(len(inline_js) * 0.4)
                remaining2 = max(8, remaining2)
                for cand in selected_js:
                    if remaining2 <= 0:
                        break
                    ctx_label = ", ".join(cand.get("contexts") or []) or "-"
                    refreshed_parts.append(f"### External JS: {cand.get('url')} (contexts: {ctx_label})")
                    for seg in cand.get("snips") or []:
                        if remaining2 <= 0:
                            break
                        for chunk in _chunk_bytes(seg, self.max_snippet_bytes):
                            js_parts.append(_part_from_text(chunk, "text/javascript"))
                        remaining2 -= 1
                refreshed_parts += js_parts
                text = self._try_models(refreshed_parts + ["Analisis ulang dengan potongan JS terbaru."])
                clean = _normalize_ai_text(strip_markdown(text))
                _render_ai_output(self.console, clean, title="Analisis Ulang AI", border_style="green")
            else:
                text = self._try_models([system_prompt, f"Pertanyaan lanjutan: {q}"])
                clean = _normalize_ai_text(strip_markdown(text))
                _render_ai_output(self.console, clean, title="Jawaban Lanjutan AI", border_style="green")

    def analyze_external_js(self, js_url: str, *, mode: str = 'ai', js_code: Optional[str] = None):
        """
        Fokus review DOM-XSS di JS eksternal.
        """
        self.console.print(f"[dim]Mengambil JS eksternal: {js_url}[/dim]")
        code = js_code
        if code is None:
            resp = make_request(js_url)
            if not resp or not (resp.text or '').strip():
                self.console.print(f"[bold red]Gagal mengunduh {js_url}[/bold red]")
                return
            code = resp.text or ''

        contexts = ContextParser.parse(code, content_type="application/javascript")
        self.console.print(f"[magenta]Detected JS contexts:[/magenta] {', '.join(contexts) or '-'}")

        mode = (mode or 'ai').lower()
        if mode != 'ai':
            self._print_js_summary(js_url, code, contexts)
            return

        snips = _extract_snippets(code, window=260, max_snippets=40)
        intro_lines = [
            "--- JS-ONLY DOM-XSS REVIEW ---",
            "Tujuan: identifikasi sink & jalur source->sink, serta payload bypass yang realistis.",
            f"Target: {js_url}",
            f"Contexts: {', '.join(contexts) or '-'}",
            "FORMAT (bullets, plain text):",
            "- Sinks (innerHTML/eval/document.write/Function/...)",
            "- Possible sources (location/search/hash/cookie/referrer/inputs/storage/postMessage)",
            "- Chains (source->sink) & reasoning",
            "- 3 payloads (increasing stealth) & when they fire",
            "- Mitigation & refactor suggestions",
        ]
        parts: List[Union[types.Part, str]] = ["\n".join(intro_lines)]

        for seg in snips:
            for chunk in _chunk_bytes(seg, 8000):
                parts.append(_part_from_text(chunk, "text/javascript"))

        ai_text = self._try_models(parts + ["Analisis kode JS di atas."])
        clean = _normalize_ai_text(strip_markdown(ai_text))
        _render_ai_output(self.console, clean, title="Hasil Analisis JS Eksternal", border_style="green")

    def _print_js_summary(self, js_url: str, js_code: str, contexts: List[str]) -> None:
        sink_hits: List[str] = []
        for label, regex in zip(SINK_LABELS, SINK_REGEX):
            try:
                if regex.search(js_code):
                    sink_hits.append(label)
            except re.error:
                continue
        snippets = _extract_snippets(js_code, window=220, max_snippets=5)
        snippet_lines = "\n".join(
            re.sub(r"\s+", " ", seg).strip()[:160] for seg in snippets
        ) or '-'
        body = (
            f"URL: {js_url}\n"
            f"Contexts: {', '.join(contexts) or '-'}\n"
            f"Sinks terdeteksi: {len(sink_hits)}"
            + (f" ({', '.join(sink_hits)})" if sink_hits else '')
            + "\n\n"
            + f"Snippet indikasi:\n{snippet_lines}"
        )
        self.console.print(Panel(body, title='[bold cyan]Ringkasan JS[/bold cyan]', border_style='cyan'))

    def summarize_findings(self, findings: List[Dict[str, Any]]):
        """Ringkas & deduplikasi temuan via LLM (opsional)."""
        if not findings:
            self.console.print(Panel("(No findings)", title="[magenta]AI Summary[/magenta]"))
            return
        compact: List[Dict[str, Any]] = []
        for f in findings[:500]:
            item = {k: f.get(k) for k in ("url", "param", "payload", "type", "technique") if f.get(k) is not None}
            if item.get("payload"):
                p = str(item["payload"]).replace("\n", " ")
                if len(p) > 220:
                    p = p[:217] + "..."
                item["payload"] = p
            compact.append(item)

        prompt = (
            "You are an AppSec lead. Given a list of XSS findings (url,param,payload,type,technique),\n"
            "summarize and deduplicate them by sink/context/payload family/route/framework.\n"
            "Score/rank them by likelihood of true execution (executed > reflected; blind-xss high).\n"
            "Mark likely false positives (reflection-only without unescaped <> or safe contexts).\n"
            "Output concise bullets (no markdown fences):\n"
            "- Clusters: key, sample urls, payload family, sink, score 1..5\n"
            "- Top actions: 1–3 bullets\n"
            "- Noise to ignore: quick rationale.\n"
        )
        try:
            import json as _json
            parts: List[Union[types.Part, str]] = []
            parts.append(_part_from_text(prompt, "text/plain"))
            data = _json.dumps({"findings": compact}, ensure_ascii=False)
            for seg in _chunk_bytes(data, 90_000):
                parts.append(_part_from_text(seg, "application/json"))
            ai_text = self._try_models(parts)
            clean_summary = _normalize_ai_text(strip_markdown(ai_text))
            _render_ai_output(self.console, clean_summary, title="AI Summary", border_style="magenta")
        except Exception as e:
            logger.warning(f"AI summarize failed: {e}")
            buckets: Dict[str, List[Dict[str, Any]]] = {}
            for f in compact:
                key = f"{(f.get('url') or '')[:80]}::{f.get('param','')}"
                buckets.setdefault(key, []).append(f)
            lines: List[str] = ["Simple Summary (fallback):"]
            for k, lst in buckets.items():
                lines.append(f"- {k} → {len(lst)} hits (sample payload: {lst[0].get('payload','-')})")
            self.console.print(Panel("\n".join(lines), title="[magenta]AI Summary[/magenta]"))

