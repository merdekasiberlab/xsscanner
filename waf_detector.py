from __future__ import annotations

import re
import time
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from network import make_request


@dataclass
class WAFProfile:
    origin: str
    vendor: str = "unknown"
    confidence: str = "low"  # low|med|high
    challenge: str = "none"   # none|js|captcha
    rate_limit: bool = False
    matches: Dict[str, Any] = field(default_factory=dict)
    mode: str = "passive"     # passive|active|aggressive
    safe_rps: float = 1.5
    backoff_ms: int = 1500
    bypass_level: int = 1
    header_camo: bool = False
    rotate_ua: bool = False
    trust_proxy: bool = False
    notes: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WAFEvent:
    origin: str
    type: str                 # allowed|blocked|challenged_js|challenged_captcha|rate_limited
    vendor_guess: str
    status: int
    headers_subset: Dict[str, str] = field(default_factory=dict)
    cookie_hits: List[str] = field(default_factory=list)
    body_markers: List[str] = field(default_factory=list)
    rtt_ms: int = 0
    url: str = ""


@dataclass
class ThrottleDecision:
    apply: bool
    safe_rps: float
    backoff_ms: int


@dataclass
class BypassPlan:
    level: int
    no_javascript_url: bool = False
    prefer_minimal_attr: bool = True
    reduce_inline_handlers: bool = False
    short_payloads: bool = True
    header_camo: bool = False


class WAFDetector:
    def __init__(self, fingerprints_path: Path, *, mode: str = "passive", safe_rps: float = 1.5,
                 backoff_ms: int = 1500, bypass_level: int = 1, header_camo: bool = False,
                 rotate_ua: bool = False, trust_proxy: bool = False):
        self.mode = mode
        self.safe_rps = float(safe_rps)
        self.backoff_ms = int(backoff_ms)
        self.bypass_level = int(bypass_level)
        self.header_camo = bool(header_camo)
        self.rotate_ua = bool(rotate_ua)
        self.trust_proxy = bool(trust_proxy)
        self.fingerprints = self._load_fingerprints(fingerprints_path)
        self.events: Dict[str, List[WAFEvent]] = {}
        self.profiles: Dict[str, WAFProfile] = {}

    def _load_fingerprints(self, path: Path) -> List[Dict[str, Any]]:
        try:
            import yaml
            data = yaml.safe_load(path.read_text(encoding='utf-8'))
            return data.get('wafs', []) if isinstance(data, dict) else []
        except Exception:
            return []

    @staticmethod
    def _origin(url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def detect(self, origin_ctx: str) -> WAFProfile:
        origin = self._origin(origin_ctx)
        prof = WAFProfile(origin=origin, mode=self.mode, safe_rps=self.safe_rps, backoff_ms=self.backoff_ms,
                          bypass_level=self.bypass_level, header_camo=self.header_camo,
                          rotate_ua=self.rotate_ua, trust_proxy=self.trust_proxy)
        
        # Passive: try HEAD/GET with and without redirects to capture redirect headers (e.g., CloudFront)
        urls = [origin, origin + "/"]
        
        # Add apex/www variants to increase coverage across CDN frontends
        try:
            p = urlparse(origin)
            host = p.netloc or ""
            if host:
                if host.startswith("www."):
                    apex = host[4:]
                    if apex:
                        urls += [f"{p.scheme}://{apex}", f"{p.scheme}://{apex}/"]
                else:
                    urls += [f"{p.scheme}://www.{host}", f"{p.scheme}://www.{host}/"]
        except Exception:
            pass
            
        seen = []
        for u in urls:
            t0 = time.time()
            
            # Try HEAD without redirects first
            resp = make_request(u, method="HEAD", allow_redirects=False)
            if resp is None:
                resp = make_request(u, method="HEAD")
            if resp is None:
                resp = make_request(u, method="GET", allow_redirects=False)
            if resp is None:
                resp = make_request(u, method="GET")
                
            rtt = int((time.time() - t0) * 1000)
            if resp is None:
                continue
                
            # Match on final response
            v, conf, ch, rl, matches, meta = self._match(resp)
            if v:
                prof.vendor = v
                prof.confidence = conf
                prof.challenge = ch
                prof.rate_limit = rl
                prof.matches = matches
                if meta:
                    prof.metadata = meta
                    prof.notes = meta.get('notes', prof.notes)
                    if meta.get('safe_rps'):
                        try: prof.safe_rps = float(meta['safe_rps'])
                        except Exception: pass
                    if meta.get('backoff_ms'):
                        try: prof.backoff_ms = int(meta['backoff_ms'])
                        except Exception: pass
                    if meta.get('header_camo') is not None:
                        prof.header_camo = bool(meta['header_camo'])
                    if meta.get('rotate_ua') is not None:
                        prof.rotate_ua = bool(meta['rotate_ua'])
                    if meta.get('trust_proxy') is not None:
                        prof.trust_proxy = bool(meta['trust_proxy'])
                        
                # Update detector-level toggles based on profile insights
                self.header_camo = self.header_camo or prof.header_camo
                self.rotate_ua = self.rotate_ua or prof.rotate_ua
                self.trust_proxy = self.trust_proxy or prof.trust_proxy
                self.profiles[origin] = prof
                return prof
                
            # Also consider redirect chain
            try:
                for h in (getattr(resp, 'history', None) or []):
                    v, conf, ch, rl, matches, meta = self._match(h)
                    if v:
                        prof.vendor = v
                        prof.confidence = conf
                        prof.challenge = ch
                        prof.rate_limit = rl
                        prof.matches = matches
                        if meta:
                            prof.metadata = meta
                            prof.notes = meta.get('notes', prof.notes)
                            if meta.get('safe_rps'):
                                try: prof.safe_rps = float(meta['safe_rps'])
                                except Exception: pass
                            if meta.get('backoff_ms'):
                                try: prof.backoff_ms = int(meta['backoff_ms'])
                                except Exception: pass
                            if meta.get('header_camo') is not None:
                                prof.header_camo = bool(meta['header_camo'])
                            if meta.get('rotate_ua') is not None:
                                prof.rotate_ua = bool(meta['rotate_ua'])
                            if meta.get('trust_proxy') is not None:
                                prof.trust_proxy = bool(meta['trust_proxy'])
                        break
                if prof.vendor != 'unknown':
                    # Update detector-level toggles based on profile insights
                    self.header_camo = self.header_camo or prof.header_camo
                    self.rotate_ua = self.rotate_ua or prof.rotate_ua
                    self.trust_proxy = self.trust_proxy or prof.trust_proxy
                    self.profiles[origin] = prof
                    return prof
            except Exception:
                pass
            seen.append((resp.status_code, rtt))
            
        # Active mode: light probes
        if prof.vendor == "unknown" and self.mode in ("active", "aggressive"):
            for meth in ("OPTIONS", "HEAD", "TRACE"):
                r = make_request(origin, method=meth)
                if r is None:
                    continue
                v, conf, ch, rl, matches, meta = self._match(r)
                if v:
                    prof.vendor, prof.confidence, prof.challenge, prof.rate_limit, prof.matches = v, conf, ch, rl, matches
                    if meta:
                        prof.metadata = meta
                        prof.notes = meta.get('notes', prof.notes)
                        if meta.get('safe_rps'):
                            try: prof.safe_rps = float(meta['safe_rps'])
                            except Exception: pass
                        if meta.get('backoff_ms'):
                            try: prof.backoff_ms = int(meta['backoff_ms'])
                            except Exception: pass
                        if meta.get('header_camo') is not None:
                            prof.header_camo = bool(meta['header_camo'])
                        if meta.get('rotate_ua') is not None:
                            prof.rotate_ua = bool(meta['rotate_ua'])
                        if meta.get('trust_proxy') is not None:
                            prof.trust_proxy = bool(meta['trust_proxy'])
                            
                    # Update detector-level toggles based on profile insights
                    self.header_camo = self.header_camo or prof.header_camo
                    self.rotate_ua = self.rotate_ua or prof.rotate_ua
                    self.trust_proxy = self.trust_proxy or prof.trust_proxy
                    self.profiles[origin] = prof
                    return prof
                    
        # Aggressive mode: specific WAF bypass techniques
        if prof.vendor == "unknown" and self.mode == "aggressive":
            # Try with common WAF bypass headers
            bypass_headers = [
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Real-IP": "127.0.0.1"},
                {"X-Originating-IP": "127.0.0.1"},
                {"X-Remote-IP": "127.0.0.1"},
                {"X-Remote-Addr": "127.0.0.1"},
                {"X-Client-IP": "127.0.0.1"},
                {"X-Host": "127.0.0.1"},
                {"X-Forwarded-Host": "127.0.0.1"},
            ]
            
            for headers in bypass_headers:
                r = make_request(origin, method="GET", headers=headers)
                if r is None:
                    continue
                v, conf, ch, rl, matches, meta = self._match(r)
                if v:
                    prof.vendor, prof.confidence, prof.challenge, prof.rate_limit, prof.matches = v, conf, ch, rl, matches
                    if meta:
                        prof.metadata = meta
                        prof.notes = meta.get('notes', prof.notes)
                        if meta.get('safe_rps'):
                            try: prof.safe_rps = float(meta['safe_rps'])
                            except Exception: pass
                        if meta.get('backoff_ms'):
                            try: prof.backoff_ms = int(meta['backoff_ms'])
                            except Exception: pass
                        if meta.get('header_camo') is not None:
                            prof.header_camo = bool(meta['header_camo'])
                        if meta.get('rotate_ua') is not None:
                            prof.rotate_ua = bool(meta['rotate_ua'])
                        if meta.get('trust_proxy') is not None:
                            prof.trust_proxy = bool(meta['trust_proxy'])
                            
                    # Update detector-level toggles based on profile insights
                    self.header_camo = self.header_camo or prof.header_camo
                    self.rotate_ua = self.rotate_ua or prof.rotate_ua
                    self.trust_proxy = self.trust_proxy or prof.trust_proxy
                    self.profiles[origin] = prof
                    return prof
                    
        # Update detector-level toggles based on profile insights
        self.header_camo = self.header_camo or prof.header_camo
        self.rotate_ua = self.rotate_ua or prof.rotate_ua
        self.trust_proxy = self.trust_proxy or prof.trust_proxy
        self.profiles[origin] = prof
        return prof

    def _match(self, resp) -> tuple[str, str, str, bool, Dict[str, Any], Dict[str, Any]]:
        hdrs = {k.lower(): v for k, v in (resp.headers or {}).items()}
        body = resp.text or ""
        cookies = list(getattr(resp, 'cookies', []) or [])

        def _hdr_collect(pattern: str) -> List[str]:
            hits: List[str] = []
            p = pattern.strip()
            if not p:
                return hits
            try:
                if ":" in p:
                    kp, vp = p.split(":", 1)
                    kp = kp.strip()
                    vp = vp.strip()
                    for k, v in hdrs.items():
                        if re.search(kp, k, re.I) and re.search(vp, v or "", re.I):
                            hits.append(f"{k}: {v}")
                else:
                    for k, v in hdrs.items():
                        if re.search(p, k, re.I) or re.search(p, v or "", re.I):
                            hits.append(f"{k}: {v}")
            except re.error:
                return []
            return hits

        def _cookie_collect(pattern: str) -> List[str]:
            hits: List[str] = []
            try:
                for c in cookies:
                    if re.search(pattern, c.name or "", re.I):
                        hits.append(c.name)
            except re.error:
                return []
            return hits

        def _body_collect(pattern: str) -> List[str]:
            hits: List[str] = []
            try:
                m = re.search(pattern, body, re.I)
                if m:
                    snippet = m.group(0)
                    hits.append(snippet[:160])
            except re.error:
                return []
            return hits

        # First, try fingerprint matching
        for fp in self.fingerprints:
            name = fp.get('name', '').lower()
            header_hits: List[str] = []
            cookie_hits: List[str] = []
            body_hits: List[str] = []

            # headers_any
            ha = fp.get('headers_any', []) or []
            if ha:
                matched_any = False
                for pattern in ha:
                    hits = _hdr_collect(pattern)
                    if hits:
                        matched_any = True
                        header_hits.extend(hits)
                if not matched_any:
                    continue

            # headers_all
            hall = fp.get('headers_all', []) or []
            if hall:
                all_hits: List[str] = []
                for pattern in hall:
                    hits = _hdr_collect(pattern)
                    if not hits:
                        all_hits = []
                        break
                    all_hits.extend(hits)
                if not all_hits:
                    continue
                header_hits.extend(all_hits)

            # cookies_any
            ca = fp.get('cookies_any', []) or []
            if ca:
                matched_cookie = False
                for pattern in ca:
                    hits = _cookie_collect(pattern)
                    if hits:
                        matched_cookie = True
                        cookie_hits.extend(hits)
                if not matched_cookie:
                    continue

            # body_regex (any)
            br = fp.get('body_regex', []) or []
            if br:
                matched_body = False
                for pattern in br:
                    hits = _body_collect(pattern)
                    if hits:
                        matched_body = True
                        body_hits.extend(hits)
                if not matched_body:
                    continue

            # status_any
            sa = fp.get('status_any', []) or []
            if sa and (resp.status_code not in sa):
                continue

            # challenge signals
            cs = fp.get('challenge_signals', []) or []
            challenge = fp.get('challenge', 'none') or 'none'
            if challenge not in ('none', 'js', 'captcha'):
                challenge = 'none'
            if cs:
                serialized = json.dumps({"headers": hdrs, "body": body[:2000]})
                if any(re.search(p, serialized, re.I) for p in cs):
                    challenge = 'js' if challenge == 'none' else challenge

            confidence = 'high' if (ha or hall or ca or br) else 'med'
            rate_limit = (resp.status_code == 429)

            matches = {
                "headers": list(dict.fromkeys(header_hits))[:10],
                "cookies": list(dict.fromkeys(cookie_hits))[:10],
                "body": body_hits[:5],
                "status": sa or ([resp.status_code] if resp.status_code else []),
            }

            meta = {}
            for key in ("notes", "safe_rps", "backoff_ms", "header_camo", "rotate_ua", "trust_proxy", "reduce_inline_handlers", "no_javascript_url"):
                if key in fp:
                    meta[key] = fp[key]
            if matches["headers"]:
                meta.setdefault("matched_headers", matches["headers"])
            if matches["cookies"]:
                meta.setdefault("matched_cookies", matches["cookies"])
            if matches["body"]:
                meta.setdefault("matched_body", matches["body"])

            return name, confidence, challenge, rate_limit, matches, meta
            
        # Enhanced heuristics with specific patterns
        try:
            server_header = (hdrs.get('server') or '').lower()
            cf_headers = [k for k in hdrs if k.startswith('cf-')]
            if cf_headers or 'cloudflare' in server_header:
                challenge = 'js' if ('please enable javascript' in body.lower() or 'cf-chl-' in body.lower()) else 'none'
                matches = {
                    "headers": [f"{k}: {hdrs[k]}" for k in cf_headers[:5]],
                    "cookies": [c.name for c in cookies if c.name.lower().startswith('__cf')] if cookies else [],
                    "body": [m.group(0)[:160] for m in re.finditer(r"cf-ray|please enable javascript|ray id", body, re.I)][:3],
                    "status": [resp.status_code] if resp.status_code else [],
                }
                meta = {
                    "header_camo": True,
                    "rotate_ua": True,
                    "reduce_inline_handlers": True,
                    "no_javascript_url": True,
                    "matched_headers": matches["headers"],
                }
                return 'cloudflare', 'high', challenge, (resp.status_code == 429), matches, meta

            cf_pop_headers = [k for k in hdrs if k.startswith('x-amz-cf') or k.startswith('x-cache')]
            if 'cloudfront' in server_header or cf_pop_headers:
                matches = {
                    "headers": [f"{k}: {hdrs[k]}" for k in (cf_pop_headers or ['server']) if k in hdrs][:5],
                    "cookies": [],
                    "body": [m.group(0)[:160] for m in re.finditer(r"cloudfront|request could not be satisfied", body, re.I)][:3],
                    "status": [resp.status_code] if resp.status_code else [],
                }
                meta = {
                    "notes": "CloudFront detected",
                    "safe_rps": 1.0,
                    "trust_proxy": True,
                    "matched_headers": matches["headers"],
                }
                return 'cloudfront', 'high', 'none', (resp.status_code == 429), matches, meta
                
            # Akamai detection
            ak_headers = [k for k in hdrs if 'akamai' in k.lower() or 'x-ak' in k.lower()]
            if ak_headers or 'akamai' in server_header or 'akamaighost' in server_header:
                matches = {
                    "headers": [f"{k}: {hdrs[k]}" for k in ak_headers[:5]],
                    "cookies": [c.name for c in cookies if 'ak' in c.name.lower()] if cookies else [],
                    "body": [m.group(0)[:160] for m in re.finditer(r"akamai|access denied", body, re.I)][:3],
                    "status": [resp.status_code] if resp.status_code else [],
                }
                meta = {
                    "notes": "Akamai detected",
                    "reduce_inline_handlers": True,
                    "matched_headers": matches["headers"],
                }
                return 'akamai', 'high', 'none', (resp.status_code == 429), matches, meta
                
            # AWS WAF detection
            aws_headers = [k for k in hdrs if 'x-amzn' in k.lower() or 'x-amz' in k.lower()]
            if aws_headers or 'aws' in server_header or 'amazon' in server_header:
                matches = {
                    "headers": [f"{k}: {hdrs[k]}" for k in aws_headers[:5]],
                    "cookies": [],
                    "body": [m.group(0)[:160] for m in re.finditer(r"aws|amazon|web application firewall", body, re.I)][:3],
                    "status": [resp.status_code] if resp.status_code else [],
                }
                meta = {
                    "notes": "AWS WAF detected",
                    "short_payloads": True,
                    "matched_headers": matches["headers"],
                }
                return 'aws_waf', 'high', 'none', (resp.status_code == 429), matches, meta
                
            # Imperva/Incapsula detection
            imperva_headers = [k for k in hdrs if any(token in k.lower() for token in ['incap', 'visid', 'x-cdn'])]
            if imperva_headers or 'incapsula' in server_header or 'imperva' in server_header:
                challenge = 'js' if ('_Incapsula_Resource' in body or 'captcha' in body.lower()) else 'none'
                matches = {
                    "headers": [f"{k}: {hdrs[k]}" for k in imperva_headers[:5]],
                    "cookies": [c.name for c in cookies if any(token in c.name.lower() for token in ['incap', 'visid'])] if cookies else [],
                    "body": [m.group(0)[:160] for m in re.finditer(r"incapsula|imperva|_Incapsula_Resource|captcha", body, re.I)][:3],
                    "status": [resp.status_code] if resp.status_code else [],
                }
                meta = {
                    "notes": "Imperva/Incapsula detected",
                    "header_camo": True,
                    "reduce_inline_handlers": True,
                    "matched_headers": matches["headers"],
                }
                return 'imperva', 'high', challenge, (resp.status_code == 429), matches, meta
                
            # Barracuda detection
            if 'barracuda' in server_header or any('barracuda' in v.lower() for v in hdrs.values()):
                matches = {
                    "headers": [f"{k}: {v}" for k, v in hdrs.items() if 'barracuda' in k.lower() or 'barracuda' in v.lower()][:5],
                    "cookies": [],
                    "body": [m.group(0)[:160] for m in re.finditer(r"barracuda|access denied", body, re.I)][:3],
                    "status": [resp.status_code] if resp.status_code else [],
                }
                meta = {
                    "notes": "Barracuda detected",
                    "reduce_inline_handlers": True,
                    "matched_headers": matches["headers"],
                }
                return 'barracuda', 'high', 'none', (resp.status_code == 429), matches, meta
                
            # F5 Big-IP ASM detection
            if 'big-ip' in server_header or any('big-ip' in v.lower() for v in hdrs.values()) or 'x-forwarded-for' in hdrs:
                matches = {
                    "headers": [f"{k}: {v}" for k, v in hdrs.items() if 'big-ip' in k.lower() or 'big-ip' in v.lower()][:5],
                    "cookies": [],
                    "body": [m.group(0)[:160] for m in re.finditer(r"big-ip|f5|access denied", body, re.I)][:3],
                    "status": [resp.status_code] if resp.status_code else [],
                }
                meta = {
                    "notes": "F5 Big-IP ASM detected",
                    "reduce_inline_handlers": True,
                    "matched_headers": matches["headers"],
                }
                return 'bigip_asm', 'high', 'none', (resp.status_code == 429), matches, meta
                
            # Sucuri detection
            if 'sucuri' in server_header or any('sucuri' in v.lower() for v in hdrs.values()):
                challenge = 'js' if ('sucuri' in body.lower() and 'cloudproxy' in body.lower()) else 'none'
                matches = {
                    "headers": [f"{k}: {v}" for k, v in hdrs.items() if 'sucuri' in k.lower() or 'sucuri' in v.lower()][:5],
                    "cookies": [c.name for c in cookies if 'sucuri' in c.name.lower()] if cookies else [],
                    "body": [m.group(0)[:160] for m in re.finditer(r"sucuri|cloudproxy", body, re.I)][:3],
                    "status": [resp.status_code] if resp.status_code else [],
                }
                meta = {
                    "notes": "Sucuri detected",
                    "header_camo": True,
                    "matched_headers": matches["headers"],
                }
                return 'sucuri', 'high', challenge, (resp.status_code == 429), matches, meta
                
        except Exception:
            pass

        # Generic detection with more specific patterns
        if resp.status_code in (403, 406, 501, 429):
            body_lower = body.lower()
            if re.search(r"access\s*denied|request\s*blocked|web\s*application\s*firewall|the\s*request\s*could\s*not\s*be\s*satisfied|generated\s*by\s*cloudfront|blocked|forbidden|unauthorized|rate limit|too many requests", body_lower, re.I):
                matches = {
                    "headers": [],
                    "cookies": [],
                    "body": [m.group(0)[:160] for m in re.finditer(r"access denied|request blocked|waf|blocked|forbidden|rate limit|too many requests", body_lower, re.I)][:3],
                    "status": [resp.status_code]
                }
                # Try to guess vendor from body content
                if 'cloudflare' in body_lower:
                    return 'cloudflare', 'med', 'none', (resp.status_code == 429), matches, {}
                elif 'aws' in body_lower or 'amazon' in body_lower:
                    return 'aws_waf', 'med', 'none', (resp.status_code == 429), matches, {}
                elif 'akamai' in body_lower:
                    return 'akamai', 'med', 'none', (resp.status_code == 429), matches, {}
                elif 'imperva' in body_lower or 'incapsula' in body_lower:
                    return 'imperva', 'med', 'none', (resp.status_code == 429), matches, {}
                elif 'barracuda' in body_lower:
                    return 'barracuda', 'med', 'none', (resp.status_code == 429), matches, {}
                elif 'sucuri' in body_lower:
                    return 'sucuri', 'med', 'none', (resp.status_code == 429), matches, {}
                elif 'f5' in body_lower or 'big-ip' in body_lower:
                    return 'bigip_asm', 'med', 'none', (resp.status_code == 429), matches, {}
                else:
                    return 'generic', 'low', 'none', (resp.status_code == 429), matches, {}
                    
        if resp.status_code == 429:
            matches = {
                "headers": [],
                "cookies": [],
                "body": [],
                "status": [resp.status_code]
            }
            return 'generic', 'low', 'none', True, matches, {}
            
        # Heuristic vendor guess from headers when explicit fingerprint missed
        try:
            hdr_dump = json.dumps(hdrs).lower()
            heur = [
                ('cloudflare', 'cloudflare', 'high'),
                ('cloudfront', 'cloudfront', 'high'),
                ('akamai', 'akamai', 'high'),
                ('akamaighost', 'akamai', 'high'),
                ('incapsula', 'imperva', 'high'),
                ('x-amzn-', 'aws_waf', 'high'),
                ('x-amz-cf-', 'cloudfront', 'high'),
                ('sucuri', 'sucuri', 'high'),
                ('big-ip', 'bigip_asm', 'high'),
                ('x-forwarded-for', 'bigip_asm', 'med'),
                ('fastly', 'fastly', 'high'),
                ('stackpath', 'stackpath', 'high'),
                ('naxsi', 'naxsi', 'high'),
                ('azure', 'azure_waf', 'high'),
                ('barracuda', 'barracuda', 'high'),
                ('sophos', 'sophos', 'high'),
                ('mod_security', 'mod_security', 'med'),
                ('shield', 'shield', 'med'),
                ('dosarrest', 'dosarrest', 'med'),
                ('comodo', 'comodo', 'med'),
            ]
            for token, vendor, conf in heur:
                if token in hdr_dump:
                    matches = {
                        "headers": [],
                        "cookies": [],
                        "body": [],
                        "status": [resp.status_code] if resp.status_code else []
                    }
                    return vendor, conf, 'none', (resp.status_code == 429), matches, {}
        except Exception:
            pass
            
        return '', 'low', 'none', False, {"headers": [], "cookies": [], "body": [], "status": []}, {}

    def classify_response(self, req: Dict[str, Any], resp, rt_metrics: Dict[str, Any]) -> Optional[WAFEvent]:
        try:
            origin = self._origin(req.get('url') or '')
        except Exception:
            return None
        status = getattr(resp, 'status_code', 0) if resp is not None else 0
        hdrs = {k.lower(): v for k, v in (getattr(resp, 'headers', {}) or {}).items()}
        cookies = list(getattr(resp, 'cookies', []) or [])
        body = (getattr(resp, 'text', '') or '')[:4000]
        vendor_guess, conf, ch, rl, matches, meta = self._match(resp) if resp is not None else ('', 'low', 'none', False, {}, {})
        ev_type = 'allowed'
        
        # Trust proxy/redirects as challenge if enabled
        try:
            if self.trust_proxy and hasattr(resp, 'history'):
                for h in (resp.history or []):
                    loc = (getattr(h, 'headers', {}) or {}).get('Location', '') or getattr(h, 'url', '')
                    l = (loc or '').lower()
                    if any(s in l for s in ('/cdn-cgi/', 'challenge', 'captcha', '_incapsula_', 'blocked', 'accessdenied', 'validate', 'verify')):
                        ev_type = 'challenged_js'
                        break
        except Exception:
            pass

        if rl or status == 429 or re.search(r"rate\s*limit|too\s*many\s*requests|exceeded", body, re.I):
            ev_type = 'rate_limited'
        elif status in (403, 406, 501, 405):
            ev_type = 'blocked'
        elif ch != 'none' or status in (503, 429):
            ev_type = 'challenged_js'
        # captcha markers
        try:
            if re.search(r"(g-recaptcha|h-captcha|recaptcha|data-sitekey|captcha|verification|validate|proof of work)", body, re.I):
                ev_type = 'challenged_captcha'
        except Exception:
            pass
            
        subset_headers: Dict[str, str] = {k: hdrs.get(k) for k in list(hdrs.keys())[:6]}
        matched_headers = (matches.get('headers') if isinstance(matches, dict) else []) if matches else []
        if matched_headers:
            subset_headers = {}
            for idx, hv in enumerate(matched_headers[:6]):
                if isinstance(hv, str) and ':' in hv:
                    k, v = hv.split(':', 1)
                    subset_headers[k.strip()] = v.strip()
                else:
                    subset_headers[f"hit_{idx}"] = str(hv)

        cookie_hits = [c.name for c in cookies][:6] if cookies else []
        if matches and isinstance(matches, dict) and matches.get('cookies'):
            cookie_hits = list(dict.fromkeys([str(c) for c in matches['cookies']]))[:6]

        body_markers = []
        if matches and isinstance(matches, dict) and matches.get('body'):
            body_markers = matches['body'][:5]

        ev = WAFEvent(
            origin=origin,
            type=ev_type,
            vendor_guess=vendor_guess or self.profiles.get(origin, WAFProfile(origin)).vendor,
            status=status,
            headers_subset=subset_headers,
            cookie_hits=cookie_hits,
            body_markers=body_markers,
            rtt_ms=int(rt_metrics.get('rtt_ms') or 0),
            url=req.get('url') or ''
        )
        self.events.setdefault(origin, []).append(ev)
        
        # Update profile on the fly based on events
        try:
            prof = self.profiles.get(origin)
            if not prof:
                prof = WAFProfile(origin=origin, mode=self.mode, safe_rps=self.safe_rps, backoff_ms=self.backoff_ms,
                                  bypass_level=self.bypass_level, header_camo=self.header_camo,
                                  rotate_ua=self.rotate_ua, trust_proxy=self.trust_proxy)
                self.profiles[origin] = prof
            if prof.vendor == 'unknown' and ev.vendor_guess:
                prof.vendor = ev.vendor_guess
                prof.confidence = max(prof.confidence, ev.vendor_guess.count('high') if 'high' in ev.vendor_guess else 'med')
            if ev.type == 'rate_limited':
                prof.rate_limit = True
            if ev.type in ('challenged_js','challenged_captcha'):
                prof.challenge = 'js' if ev.type == 'challenged_js' else 'captcha'
            if matches and not prof.matches:
                prof.matches = matches
            if meta:
                prof.metadata = {**prof.metadata, **meta}
        except Exception:
            pass
        return ev

    def should_throttle(self, target: WAFEvent | WAFProfile) -> ThrottleDecision:
        if isinstance(target, WAFEvent):
            if target.type in ('rate_limited', 'challenged_js', 'blocked'):
                return ThrottleDecision(True, self.safe_rps, self.backoff_ms)
            return ThrottleDecision(False, self.safe_rps, self.backoff_ms)
        # Profile-based
        if target.rate_limit or target.vendor != 'unknown':
            return ThrottleDecision(True, target.safe_rps, target.backoff_ms)
        return ThrottleDecision(False, target.safe_rps, target.backoff_ms)

    def next_strategy(self, profile: WAFProfile, last_event: Optional[WAFEvent]) -> BypassPlan:
        level = max(0, int(profile.bypass_level))
        strict = (profile.vendor != 'unknown') or (last_event and last_event.type in ('blocked','challenged_js','rate_limited'))
        plan = BypassPlan(
            level=level,
            no_javascript_url=strict,
            prefer_minimal_attr=True,
            reduce_inline_handlers=strict,
            short_payloads=True,
            header_camo=profile.header_camo or profile.rotate_ua,
        )
        vendor = (profile.vendor or '').lower()
        meta = profile.metadata or {}

        if meta.get('no_javascript_url'):
            plan.no_javascript_url = True
        if meta.get('reduce_inline_handlers'):
            plan.reduce_inline_handlers = True
        if meta.get('header_camo'):
            plan.header_camo = True
        if meta.get('rotate_ua'):
            plan.header_camo = True

        if vendor in ('cloudflare', 'imperva', 'aws_waf'):
            plan.no_javascript_url = True
            plan.reduce_inline_handlers = True
        if vendor in ('akamai', 'barracuda', 'bigip_asm'):
            plan.reduce_inline_handlers = True
        if vendor in ('cloudflare', 'akamai', 'imperva', 'aws_waf') or (last_event and last_event.type == 'rate_limited'):
            plan.short_payloads = True

        return plan