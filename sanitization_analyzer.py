# sanitization_analyzer.py — ULTRA-MAX (drop-in)
from __future__ import annotations

import re
from typing import Dict, Tuple, List
from urllib.parse import quote

from utils import prepare_request_args, decode_all
import json
from network import make_request
from csrf import apply_csrf


# --- Set karakter “berbahaya” yang kita uji (lebih lengkap) ---
_CHARSET = [
    "<", ">", '"', "'", "/", "\\", "=", ";", ":", "`", "(", ")", "{", "}", "[", "]", "&",
    ",", ".", " ", "\n", "\t", "|", "%", "+", "-", "_", "@", "!", "?", "$", "^", "~", "*"
]

# --- Named entities yang umum di HTML (untuk deteksi) ---
_NAMED_ENTITIES = {
    "<": ["&lt;"],
    ">": ["&gt;"],
    '"': ["&quot;"],
    "'": ["&apos;", "&#39;", "&#x27;"],  # &apos; kadang muncul dari backend/XML
    "&": ["&amp;"],
    "/": [],  # tak ada named standar, gunakan numeric
}

def _encoded_candidates_for_char(c: str) -> List[str]:
    """
    Kembalikan kandidat string untuk SATU karakter dalam berbagai encoding,
    TANPA konteks PROBE…PROBE (akan disusun di _encoded_probe_candidates()).
    """
    cand: List[str] = []

    # Named entities (kalau ada)
    cand.extend(_NAMED_ENTITIES.get(c, []))

    # Numeric decimal & hex (lower/UPPER, dengan leading zero)
    dec = f"&#{ord(c)};"
    hex_l = f"&#x{ord(c):x};"
    hex_u = f"&#x{ord(c):X};"
    dec_zeropad = f"&#{ord(c):04d};"
    cand.extend([dec, hex_l, hex_u, dec_zeropad])

    # Percent-encoding (%XX) — huruf kecil & besar
    p = quote(c)  # e.g. "<" -> "%3C"
    if p.startswith("%"):
        cand.append(p.lower())
        cand.append(p.upper())

        # double encoding
        pp = quote(p)
        cand.append(pp.lower())
        cand.append(pp.upper())

    # JS-style escapes
    cand.append(f"\\x{ord(c):02x}")
    cand.append(f"\\x{ord(c):02X}")
    cand.append(f"\\u{ord(c):04x}")
    cand.append(f"\\u{ord(c):04X}")

    # HTML entity tanpa titik koma (beberapa parser toleran)
    cand.append(dec[:-1])
    cand.append(hex_l[:-1])

    # variasi odd (spasi sebelum ';')
    cand.append(f"&#{ord(c)} ;")
    cand.append(f"&#x{ord(c):x} ;")

    # collapse whitespace: & # x H ; (kadang minifier/normalizer “rapi” berbeda)
    cand.append(f"& # {ord(c)} ;".replace(" ", ""))  # tetap "&##;" kalau di-strip
    cand.append(f"& # x {ord(c):x} ;".replace(" ", ""))

    return list(dict.fromkeys(cand))


def _encoded_probe_candidates(c: str, marker: str = "PROBE") -> List[str]:
    """
    Bentuk string PROBE{ENC(c)}PROBE untuk berbagai encoding c.
    """
    out = []
    for enc in _encoded_candidates_for_char(c):
        out.append(f"{marker}{enc}{marker}")
    return out


def _gather_probe_segments(raw_body: str, marker: str = "PROBE", radius: int = 80) -> List[str]:
    """Ambil potongan teks di sekitar marker untuk analisis lebih presisi."""
    raw = raw_body or ""
    if not raw:
        return [""]
    try:
        positions = [m.start() for m in re.finditer(re.escape(marker), raw)]
    except Exception:
        positions = []
    if not positions:
        return [raw]
    segments: List[str] = []
    for idx in positions:
        start = max(0, idx - radius)
        end = min(len(raw), idx + len(marker) + radius)
        segments.append(raw[start:end])
    return segments or [raw]


def _detect_status(raw_body: str, char: str, marker: str = "PROBE") -> str:
    """
    Status untuk satu karakter:
      - 'reflected' : muncul persis sebagai PROBE{char}PROBE di RAW body
      - 'encoded'   : tidak persis, tapi muncul sebagai salah-satu encoded candidates
      - 'filtered'  : tidak muncul setelah berbagai upaya decode/scan
    """
    segments = _gather_probe_segments(raw_body, marker)
    pure = f"{marker}{char}{marker}"
    for seg in segments:
        if pure in seg:
            return "reflected"

    encoded_candidates = _encoded_probe_candidates(char, marker)
    for seg in segments:
        lower = seg.lower()
        for cand in encoded_candidates:
            if cand.lower() in lower:
                return "encoded"

    for seg in segments:
        decoded = decode_all(seg)
        if pure in decoded:
            return "encoded"

    return "filtered"


def analyze_param_sanitizer(
    url: str,
    param: str,
    template: dict,
    method: str,
    is_form: bool
) -> Dict[str, str]:
    """
    Probe karakter-karakter XSS-prone untuk mengetahui status per-karakter.
    Return: dict karakter -> status ("reflected" | "encoded" | "filtered")

    Catatan akurasi:
    - Kita cek RAW response untuk refleksi/encoding,
      dan fallback ke decode_all() untuk kasus encoded → decoded terlihat.
    """
    mapping: Dict[str, str] = {}
    method = method.upper()
    last_raw = ""
    for c in _CHARSET:
        probe = f"PROBE{c}PROBE"
        tpl = dict(template)
        tpl[param] = probe
        req_url, _, body = prepare_request_args(url, method, tpl, is_form)

        if method == "GET" and not is_form:
            resp = make_request(req_url)
        else:
            headers: Dict[str, str] = {}
            send_data = body
            if method == "POST" and not is_form:
                headers["Content-Type"] = "application/json"
            if isinstance(body, dict):
                headers, body_with_csrf = apply_csrf(req_url, method, dict(body), headers)
                if method == "POST" and not is_form:
                    send_data = json.dumps(body_with_csrf)
                else:
                    send_data = body_with_csrf
            else:
                headers, _ = apply_csrf(req_url, method, {}, headers)
            resp = make_request(req_url, method, data=send_data, headers=headers or None)

        raw_text = resp.text if resp else ""
        last_raw = raw_text or last_raw
        mapping[c] = _detect_status(raw_text, c, marker="PROBE")

    try:
        globals()["LAST_HTML_CAPTURE"] = last_raw
    except Exception:
        pass
    return mapping


def pretty_print_map(param: str, mapping: Dict[str, str]) -> None:
    print(f"[sanitizer-analyzer] Parameter: {param}")
    # Best-effort CSP summary via meta http-equiv (from last analysis run if available)
    try:
        # Caller can set a global 'LAST_HTML_CAPTURE' in this module; else skip
        html_doc = globals().get('LAST_HTML_CAPTURE', '') or ''
        if html_doc:
            from utils import extract_meta_csp, parse_csp, derive_csp_flags
            raw = extract_meta_csp(html_doc)
            flags = derive_csp_flags(parse_csp(raw)) if raw else {}
            if raw or flags:
                print(f"  CSP(meta) : {raw[:80]}{'...' if len(raw)>80 else ''}")
                if flags:
                    # Print select flags for readability
                    keys = [k for k in ("no_inline_script","no_unsafe_eval","allow_data_script","allow_blob_script","strict_dynamic","style_no_inline") if flags.get(k) is not None]
                    print("  Flags    : " + ", ".join(f"{k}={flags.get(k)}" for k in keys))
    except Exception:
        pass
    # urutkan agar mudah dibaca: filtered → encoded → reflected
    order = {"filtered": 0, "encoded": 1, "reflected": 2}
    for ch, status in sorted(mapping.items(), key=lambda kv: (order.get(kv[1], 99), kv[0])):
        print(f"  {ch!r} : {status}")


def filter_payload_by_sanitizer(payload: str, sanitizer_map: Dict[str, str]) -> bool:
    """
    True bila payload TIDAK mengandung karakter dengan status 'filtered'.
    (reflected / encoded dianggap boleh; encoded akan ditangani dengan mutasi)
    """
    for ch, status in sanitizer_map.items():
        if status == "filtered" and ch in payload:
            return False
    return True


def _encode_char_for_bypass(ch: str, status: str) -> str:
    """
    Strategi encoding deterministik per karakter ‘filtered’.
    Tujuan: kompatibel lintas konteks umum HTML/attr tanpa over-encoding.
    """
    # preferensi: numeric HEX untuk tanda sudut & kutip (stabil di banyak parser)
    if ch == "<":
        return "&#x3c;"
    if ch == ">":
        return "&#x3e;"
    if ch == '"':
        return "&#x22;"
    if ch == "'":
        return "&#x27;"
    if ch == "&":
        return "&amp;"
    if ch == "/":
        return "&#x2f;"

    # fallback: numeric decimal
    return f"&#{ord(ch)};"


def mutate_payload_by_sanitizer(payload: str, sanitizer_map: Dict[str, str]) -> str:
    """
    Encode HANYA karakter dengan status 'filtered' (sekali, deterministik).
    Hindari chaining encode (entity → percent → unicode) seperti versi lama.
    """
    # bangun string per karakter agar tidak double-replace
    out_chars: List[str] = []
    for ch in payload:
        status = sanitizer_map.get(ch, "reflected")
        if status == "filtered":
            out_chars.append(_encode_char_for_bypass(ch, status))
        else:
            out_chars.append(ch)
    return "".join(out_chars)


# ==== (opsional) util tambahan untuk pemakaian internal / debugging ====

def analyze_param_sanitizer_verbose(
    url: str,
    param: str,
    template: dict,
    method: str,
    is_form: bool
) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    """
    Versi verbose: selain status per karakter, juga mengembalikan kandidat
    encoding yang ditemukan di RAW body (berguna untuk fingerprint WAF/filter).
    """
    found_forms: Dict[str, List[str]] = {}
    status_map = analyze_param_sanitizer(url, param, template, method, is_form)

    # ulang sekali lagi untuk kumpulkan bentuk encoded yang benar-benar muncul
    method = method.upper()
    for c in _CHARSET:
        probe = f"PROBE{c}PROBE"
        tpl = dict(template)
        tpl[param] = probe
        req_url, _, body = prepare_request_args(url, method, tpl, is_form)
        resp = (
            make_request(req_url)
            if method == "GET"
            else make_request(req_url, method, data=body)
        )
        raw = resp.text if resp else ""
        hits = []
        for cand in _encoded_probe_candidates(c):
            if cand in raw:
                hits.append(cand)
        if hits:
            found_forms[c] = hits

    return status_map, found_forms
