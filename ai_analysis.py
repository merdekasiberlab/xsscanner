# ai_analysis.py â€” ULTRA-MAX

from __future__ import annotations

import json
import logging
import math
import re
import time
from dataclasses import dataclass
from typing import Iterable, List, Tuple, Union, Dict, Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from google.genai import types
import sys

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

def Panel(content, title=None, border_style=None):
    header = f"=== {title} ===\n" if title else ""
    return f"{header}{content}"

console = _SimpleConsole()
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

SINK_REGEX = [re.compile(p, re.IGNORECASE) for p in SINK_PATTERNS]


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
    prefer: str = "gemini-1.5-pro"
    fallbacks: Tuple[str, ...] = ("gemini-2.0-pro", "gemini-2.0-flash", "gemini-2.5-flash")


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
        max_html_bytes: int = 200_000,     # ~200 KB untuk HTML (prettified)
        max_js_snippets: int = 36,         # total snippet JS dikirim
        max_snippet_bytes: int = 8_000,    # per snippet
        max_findings_json: int = 40,       # batasi temuan runtime
    ):
        """
        ai_client: genai.Client(api_key=...)
        """
        self.client = ai_client
        self.model_prefs = model_prefs
        self.max_html_bytes = max_html_bytes
        self.max_js_snippets = max_js_snippets
        self.max_snippet_bytes = max_snippet_bytes
        self.max_findings_json = max_findings_json

        self.history: List[Union[types.Part, str]] = []
        self.last_response: str = ""

    # ---------------- AI Core ----------------

    def _try_models(self, contents: List[Union[types.Part, str]]) -> str:
        errors: List[str] = []
        models = (self.model_prefs.prefer,) + tuple(self.model_prefs.fallbacks)
        for mid in models:
            try:
                with console.status(f"[bold blue]Meminta AI ({mid})[/bold blue]", spinner="dots"):
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
                # backoff ringan
                time.sleep(0.8)
        logger.error("Semua model gagal. Detail: " + " | ".join(errors))
        return "[ERROR] AI invocation failed."

    # ---------------- High-level flows ----------------

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

        # 1) Render/fetch HTML
        with console.status(f"[bold blue]Memuat & merender: {url}[/bold blue]", spinner="dots"):
            html_content = fetch_dynamic_html(url) or ""
            if not html_content:
                resp = make_request(url)
                html_content = (resp.text or "") if resp else ""

        if not html_content:
            console.print(Panel("[red]Gagal memuat HTML untuk analisis AI[/red]", title="AI", border_style="red"))
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

        console.print(
            Panel(
                f"[bold]Konteks:[/bold] {', '.join(contexts) or '-'}\n"
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

        external_snips: List[Tuple[str, List[str]]] = []
        for js_url in external_srcs:
            try:
                jr = make_request(js_url)
                js = jr.text or ""
                snips = _extract_snippets(js)
                external_snips.append((js_url, snips))
            except Exception:
                continue

        # 5) Rakit prompt + parts (dengan limiter)
        system_prompt = (
            SYSTEM_PROMPT_CORE
            + f"\nPARAMETER: `{pname}`\nURL: {url}\nDetected Contexts: {', '.join(contexts) or '-'}\nCSP (summary): {csp_summary or '-'}\n"
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

        # Inline JS snippets
        if inline_js:
            capped_inline = inline_js[: math.ceil(self.max_js_snippets * 0.4)]
            for code in capped_inline:
                for chunk in _chunk_bytes(code, self.max_snippet_bytes):
                    parts.append(_part_from_text(chunk, "text/javascript"))

        # External JS snippets (prioritaskan URL yang punya banyak sink)
        ranked = sorted(external_snips, key=lambda t: len(t[1]), reverse=True)
        remaining = self.max_js_snippets - int(len(inline_js) * 0.4)
        remaining = max(8, remaining)

        for js_url, snips in ranked:
            if remaining <= 0:
                break
            # Beri konteks kecil: URL & ringkasan contexts di file ini
            try:
                resp = make_request(js_url)
                js_code = resp.text or ""
                js_ctx = ", ".join(ContextParser.parse(js_code, content_type="application/javascript")) or "-"
                parts.append(f"### External JS: {js_url} (contexts: {js_ctx})")
            except Exception:
                parts.append(f"### External JS: {js_url}")

            for seg in snips:
                if remaining <= 0:
                    break
                for chunk in _chunk_bytes(seg, self.max_snippet_bytes):
                    parts.append(_part_from_text(chunk, "text/javascript"))
                remaining -= 1

        # 6) Panggil AI
        from rich.text import Text
        ai_text = self._try_models(parts)
        console.print(Panel(Text(strip_markdown(ai_text)), title="[bold green]Hasil Analisis AI[/bold green]", border_style="green"))

        if not interactive:
            return

        # 7) Loop follow-up ringan
        while True:
            q = console.input("\n[bold]Lanjut ('js'=refresh JS, 'back'=menu, ENTER=selesai) > [/bold]").strip().lower()
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
                # externals ranked
                remaining2 = self.max_js_snippets - int(len(inline_js) * 0.4)
                remaining2 = max(8, remaining2)
                for js_url, snips in ranked:
                    if remaining2 <= 0:
                        break
                    refreshed_parts.append(f"### External JS: {js_url}")
                    for seg in snips:
                        if remaining2 <= 0:
                            break
                        for chunk in _chunk_bytes(seg, self.max_snippet_bytes):
                            js_parts.append(_part_from_text(chunk, "text/javascript"))
                        remaining2 -= 1
                refreshed_parts += js_parts
                from rich.text import Text
                text = self._try_models(refreshed_parts + ["Analisis ulang dengan potongan JS terbaru."])
                console.print(Panel(Text(strip_markdown(text)), title="[bold green]Analisis Ulang AI[/bold green]", border_style="green"))
            else:
                from rich.text import Text
                text = self._try_models([system_prompt, f"Pertanyaan lanjutan: {q}"])
                console.print(Panel(Text(strip_markdown(text)), title="[bold green]Jawaban Lanjutan AI[/bold green]", border_style="green"))

    def analyze_external_js(self, js_url: str):
        """
        Fokus review DOM-XSS di JS eksternal (tanpa HTML).
        """
        console.print(f"[dim]Mengambil JS eksternal: {js_url}[/dim]")
        resp = make_request(js_url)
        if not resp or not resp.text:
            console.print(f"[bold red]Gagal mengunduh {js_url}[/bold red]")
            return

        js_code = resp.text
        contexts = ContextParser.parse(js_code, content_type="application/javascript")
        console.print(f"[magenta]Detected JS contexts:[/magenta] {', '.join(contexts) or '-'}")

        # Potong kode pada sink & batasi ukuran
        snips = _extract_snippets(js_code, window=260, max_snippets=40)
        parts: List[Union[types.Part, str]] = [
            (
                "--- JS-ONLY DOM-XSS REVIEW ---\n"
                "Tujuan: identifikasi sink & jalur sourceâ†’sink, serta payload bypass yang realistis.\n"
                f"Target: {js_url}\n"
                f"Contexts: {', '.join(contexts) or '-'}\n"
                "FORMAT (bullets, plain text):\n"
                "â€¢ Sinks (innerHTML/eval/document.write/Function/...)\n"
                "â€¢ Possible sources (location/search/hash/cookie/referrer/inputs/storage/postMessage)\n"
                "â€¢ Chains (sourceâ†’sink) & reasoning\n"
                "â€¢ 3 payloads (increasing stealth) & when they fire\n"
                "â€¢ Mitigation & refactor suggestions\n"
            )
        ]
        for seg in snips:
            for chunk in _chunk_bytes(seg, 8000):
                parts.append(_part_from_text(chunk, "text/javascript"))

        ai_text = self._try_models(parts + ["Analisis kode JS di atas."])
        console.print(
            Panel(
                strip_markdown(ai_text),
                title="[bold green]Hasil Analisis JS Eksternal[/bold green]",
                border_style="green",
            )
        )

    def summarize_findings(self, findings: List[Dict[str, Any]]):
        """Ringkas & deduplikasi temuan via LLM (opsional)."""
        if not findings:
            console.print(Panel("(No findings)", title="[magenta]AI Summary[/magenta]"))
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
            from rich.text import Text
            console.print(Panel(Text(strip_markdown(ai_text)), title="[magenta]AI Summary[/magenta]"))
        except Exception as e:
            logger.warning(f"AI summarize failed: {e}")
            buckets: Dict[str, List[Dict[str, Any]]] = {}
            for f in compact:
                key = f"{(f.get('url') or '')[:80]}::{f.get('param','')}"
                buckets.setdefault(key, []).append(f)
            lines: List[str] = ["Simple Summary (fallback):"]
            for k, lst in buckets.items():
                lines.append(f"- {k} → {len(lst)} hits (sample payload: {lst[0].get('payload','-')})")
            console.print(Panel("\n".join(lines), title="[magenta]AI Summary[/magenta]"))

