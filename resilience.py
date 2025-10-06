from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any, Dict, List

from playwright.sync_api import sync_playwright, Error as PWError

from config import USER_AGENT
from utils import parse_csp, extract_meta_csp, derive_csp_flags, extract_nonces

_MAX_SAMPLES = 5

_SINK_KEYWORD_PATTERNS = {
    'innerHTML': r'innerHTML',
    'outerHTML': r'outerHTML',
    'dangerouslySetInnerHTML': r'dangerouslySetInnerHTML',
    'createContextualFragment': r'createContextualFragment',
    'insertAdjacentHTML': r'insertAdjacentHTML',
    'document.write': r'document\.write',
    'srcdoc': r'srcdoc',
    'eval_call': r'\beval\s*\(',
}

_FRAMEWORK_PATTERNS = {
    'react': [r'data-reactroot', r'data-nextjs-data', r'dangerouslysetinnerhtml'],
    'angular': [r'ng-version', r'ng-app', r'ng-controller', r'ng-bind'],
    'vue': [r'data-v-app', r'v-cloak', r'vue\.js'],
    'svelte': [r'data-svelte'],
    'dompurify': [r'dompurify'],
    'lit': [r'litelement', r'data-litappid'],
}

class _SinkInventoryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.event_handlers: List[tuple[str, str]] = []
        self.srcdoc_frames: List[tuple[str, str]] = []
        self.javascript_urls: List[tuple[str, str, str]] = []
        self.sandbox_iframes: List[str] = []
        self.inline_scripts = 0
        self.external_scripts: List[str] = []
        self.script_nonces = 0
        self.module_scripts = 0
        self.forms = 0
        self.templates = 0

    def handle_starttag(self, tag: str, attrs: List[tuple[str, str]]) -> None:
        tag_l = tag.lower()
        attr_map = {(k or '').lower(): (v or '') for k, v in attrs}

        for key, value in attr_map.items():
            if key.startswith('on'):
                if len(self.event_handlers) < _MAX_SAMPLES:
                    self.event_handlers.append((tag_l, key))
            if key == 'srcdoc' and value and len(self.srcdoc_frames) < _MAX_SAMPLES:
                self.srcdoc_frames.append((tag_l, value[:120]))
            if key in {'href', 'src', 'xlink:href', 'formaction'}:
                v = value.strip()
                if v.lower().startswith('javascript:') and len(self.javascript_urls) < _MAX_SAMPLES:
                    self.javascript_urls.append((tag_l, key, v[:120]))

        if tag_l == 'iframe' and 'sandbox' in attr_map:
            if len(self.sandbox_iframes) < _MAX_SAMPLES:
                self.sandbox_iframes.append(attr_map.get('sandbox', '')[:120])

        if tag_l == 'script':
            if 'src' in attr_map and attr_map['src']:
                if len(self.external_scripts) < _MAX_SAMPLES:
                    self.external_scripts.append(attr_map['src'][:160])
            else:
                self.inline_scripts += 1
            if attr_map.get('type', '').lower() == 'module':
                self.module_scripts += 1
            if 'nonce' in attr_map:
                self.script_nonces += 1

        if tag_l == 'form':
            self.forms += 1

        if tag_l == 'template':
            self.templates += 1

    def get_inventory(self) -> Dict[str, Any]:
        return {
            'event_handlers': self.event_handlers,
            'javascript_urls': self.javascript_urls,
            'iframe_srcdoc': self.srcdoc_frames,
            'sandbox_iframes': self.sandbox_iframes,
            'inline_script_count': self.inline_scripts,
            'external_script_samples': self.external_scripts,
            'script_nonce_count': self.script_nonces,
            'module_script_count': self.module_scripts,
            'form_count': self.forms,
            'template_count': self.templates,
        }

def _keyword_hits(html: str) -> Dict[str, int]:
    results: Dict[str, int] = {}
    if not html:
        return results
    for name, pattern in _SINK_KEYWORD_PATTERNS.items():
        try:
            hits = re.findall(pattern, html, flags=re.IGNORECASE)
        except re.error:
            continue
        count = len(hits)
        if count:
            results[name] = min(count, 50)
    return results

def build_sink_inventory(html: str) -> Dict[str, Any]:
    parser = _SinkInventoryParser()
    try:
        parser.feed(html or '')
        parser.close()
    except Exception:
        pass
    inventory = parser.get_inventory()
    inventory['keyword_hits'] = _keyword_hits(html or '')
    inventory['has_high_risk_sink'] = bool(inventory['event_handlers'] or inventory['javascript_urls'] or inventory['iframe_srcdoc'] or inventory['keyword_hits'])
    return inventory

def extract_framework_markers(html: str) -> Dict[str, List[str]]:
    markers: Dict[str, List[str]] = {}
    if not html:
        return markers
    lowered = html.lower()
    for name, patterns in _FRAMEWORK_PATTERNS.items():
        for pat in patterns:
            try:
                if re.search(pat, lowered, flags=re.IGNORECASE):
                    markers.setdefault(name, []).append(pat)
            except re.error:
                continue
    return markers

def _safe_headers(response) -> Dict[str, str]:
    try:
        hdrs = response.headers
        if isinstance(hdrs, dict):
            return hdrs
    except Exception:
        pass
    try:
        return response.headers()
    except Exception:
        return {}

def run_resilience_browser_probe(url: str, timeout: int = 30000) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        'csp': {},
        'trusted_types': {},
        'csp_ladder': {},
        'frameworks': {},
        'framework_markers': {},
        'sink_inventory': {},
        'html_excerpt': '',
    }
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            java_script_enabled=True,
            user_agent=USER_AGENT,
            locale='id-ID',
            timezone_id='Asia/Jakarta',
            ignore_https_errors=True,
        )
        page = context.new_page()
        try:
            nav = page.goto(url, wait_until='load', timeout=timeout)
        except PWError:
            nav = page.goto(url, wait_until='domcontentloaded', timeout=timeout * 2)
        html_doc = page.content() or ''
        result['html_excerpt'] = html_doc[:1200]

        hdr_map = _safe_headers(nav) if nav else {}
        hdr = hdr_map.get('content-security-policy', '') or hdr_map.get('Content-Security-Policy', '') or ''
        meta_tag = extract_meta_csp(html_doc) if html_doc else ''
        raw = hdr or meta_tag or ''
        flags = derive_csp_flags(parse_csp(raw)) if raw else {}
        nonces = extract_nonces(html_doc) if html_doc else []
        result['csp'] = {
            'header': hdr,
            'meta': meta_tag,
            'raw': raw,
            'flags': flags,
            'nonce_values': nonces[:5],
            'nonce_count': len(nonces),
        }

        try:
            result['sink_inventory'] = build_sink_inventory(html_doc)
        except Exception:
            result.setdefault('errors', []).append('inventory')
        try:
            result['framework_markers'] = extract_framework_markers(html_doc)
        except Exception:
            result.setdefault('errors', []).append('framework_markers')

        tt_probe = """
(() => {
  const result = {
    supported: !!window.trustedTypes,
    default_policy: null,
    policy_names: [],
    innerHTML: { attempted: true, allowed: false, blocked: false, error: null },
    setHTML: { attempted: false, allowed: false, blocked: false, error: null },
    enforced: false
  };
  try {
    if (window.trustedTypes) {
      try {
        result.default_policy = window.trustedTypes.defaultPolicy ? 'custom' : null;
      } catch (e) {}
      try {
        if (typeof window.trustedTypes.getPolicyNames === 'function') {
          result.policy_names = Array.from(window.trustedTypes.getPolicyNames());
        }
      } catch (e) {}
    }
    const parent = document.body || document.documentElement;
    const el = document.createElement('div');
    el.setAttribute('data-tt-probe', '1');
    if (parent && parent.appendChild) {
      parent.appendChild(el);
    }
    try {
      el.innerHTML = '<img src=x onerror=window.__ttProbeHit = true>';
      result.innerHTML.allowed = true;
    } catch (err) {
      result.innerHTML.blocked = true;
      result.innerHTML.error = String(err);
    }
    if (typeof el.setHTML === 'function') {
      result.setHTML.attempted = true;
      try {
        el.setHTML('<b>tt</b>');
        result.setHTML.allowed = true;
      } catch (err) {
        result.setHTML.blocked = true;
        result.setHTML.error = String(err);
      }
    }
    if (el.remove) {
      el.remove();
    }
    result.enforced = !!(result.innerHTML.blocked || result.setHTML.blocked);
  } catch (err) {
    result.error = String(err);
  }
  return result;
})();
"""
        try:
            result['trusted_types'] = page.evaluate(tt_probe)
        except Exception:
            result.setdefault('errors', []).append('trusted_types')

        ladder_probe = """
(async () => {
  const out = {
    inline: { executed: false, violation: false, violations: [], error: null },
    external_blob: { executed: false, violation: false, violations: [], error: null },
    url_handler: { executed: false, violation: false, violations: [], error: null }
  };
  const snapshot = () => Array.isArray(window.__xss_findings) ? window.__xss_findings.slice() : [];
  const diff = (before) => snapshot().slice(before).filter(f => f && f.type === 'tainted_csp_violation').map(f => String(f.detail || ''));
  try {
    const marker = '__XSS_INLINE__' + Math.random().toString(36).slice(2);
    window[marker] = 0;
    const before = snapshot().length;
    const script = document.createElement('script');
    script.text = 'window.' + marker + " = (window." + marker + "||0)+1;";
    (document.documentElement || document.body || document.head).appendChild(script);
    await new Promise(r => setTimeout(r, 60));
    out.inline.executed = (window[marker] || 0) > 0;
    out.inline.violations = diff(before);
    out.inline.violation = out.inline.violations.length > 0;
    script.remove();
  } catch (err) {
    out.inline.error = String(err);
  }
  try {
    const before = snapshot().length;
    window.__XSS_BLOB_EXEC__ = 0;
    const blob = new Blob(['window.__XSS_BLOB_EXEC__ = (window.__XSS_BLOB_EXEC__||0)+1;'], { type: 'text/javascript' });
    const url = URL.createObjectURL(blob);
    const script = document.createElement('script');
    script.src = url;
    (document.documentElement || document.body || document.head).appendChild(script);
    await new Promise(r => setTimeout(r, 120));
    out.external_blob.executed = (window.__XSS_BLOB_EXEC__ || 0) > 0;
    out.external_blob.violations = diff(before);
    out.external_blob.violation = out.external_blob.violations.length > 0;
    script.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    out.external_blob.error = String(err);
  }
  try {
    const before = snapshot().length;
    window.__XSS_URL_HANDLER__ = 0;
    const anchor = document.createElement('a');
    anchor.href = 'javascript:window.__XSS_URL_HANDLER__ = (window.__XSS_URL_HANDLER__||0)+1;';
    anchor.style.display = 'none';
    (document.body || document.documentElement).appendChild(anchor);
    anchor.click();
    await new Promise(r => setTimeout(r, 80));
    out.url_handler.executed = (window.__XSS_URL_HANDLER__ || 0) > 0;
    out.url_handler.violations = diff(before);
    out.url_handler.violation = out.url_handler.violations.length > 0;
    anchor.remove();
  } catch (err) {
    out.url_handler.error = String(err);
  }
  return out;
})();
"""
        try:
            result['csp_ladder'] = page.evaluate(ladder_probe)
        except Exception:
            result.setdefault('errors', []).append('csp_ladder')

        framework_probe = """
(() => {
  const info = {};
  const capture = (name, data) => { info[name] = data; };
  try {
    const reactRoot = document.querySelector('[data-reactroot],[data-reactid],[data-nextjs-data]');
    if (reactRoot || window.React || window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
      capture('react', {
        present: true,
        evidence: reactRoot ? reactRoot.tagName.toLowerCase() : 'global-react',
        auto_escape: true
      });
    }
  } catch (e) {}
  try {
    const ngNode = document.querySelector('[ng-version],[ng-app],[ng-controller]');
    if (ngNode || window.ng) {
      capture('angular', {
        present: true,
        evidence: ngNode ? ngNode.tagName.toLowerCase() : 'window.ng',
        auto_escape: true
      });
    }
  } catch (e) {}
  try {
    const vueNode = document.querySelector('[data-v-app],[v-cloak]');
    if (vueNode || window.Vue || window.__VUE_DEVTOOLS_GLOBAL_HOOK__) {
      capture('vue', {
        present: true,
        evidence: vueNode ? (vueNode.hasAttribute('data-v-app') ? 'data-v-app' : 'v-cloak') : 'global-vue',
        auto_escape: true
      });
    }
  } catch (e) {}
  try {
    const svelteStyle = document.querySelector('style[data-svelte]');
    if (svelteStyle) {
      capture('svelte', { present: true, evidence: 'style[data-svelte]', auto_escape: true });
    }
  } catch (e) {}
  try {
    if (window.litHtml || window.LitElement) {
      capture('lit', { present: true, evidence: 'lit-element', auto_escape: true });
    }
  } catch (e) {}
  try {
    const dompurify = window.DOMPurify;
    if (dompurify && typeof dompurify.sanitize === 'function') {
      const cfg = dompurify.defaultConfig || {};
      capture('dompurify', {
        present: true,
        evidence: 'DOMPurify.sanitize',
        version: dompurify.version || null,
        return_trusted_type: !!(cfg.RETURN_TRUSTED_TYPE || cfg.RETURN_TRUSTED_TYPE === 0),
        allow_unknown_protocols: !!cfg.ALLOW_UNKNOWN_PROTOCOLS
      });
    }
  } catch (e) {}
  return info;
})();
"""
        try:
            result['frameworks'] = page.evaluate(framework_probe)
        except Exception:
            result.setdefault('errors', []).append('frameworks')

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

    return result

def compute_resilience_score(reports: List[Dict[str, Any]], has_vulns: bool = False) -> Dict[str, Any]:
    if not reports:
        return {
            'score': 0,
            'confidence': 'low',
            'checklist': ['No resilience evidence collected'],
            'details': [],
        }

    total = len(reports)
    strong_csp = 0
    tt_enforced = 0
    ladder_inline_blocked = 0
    ladder_blob_blocked = 0
    ladder_url_blocked = 0
    sink_exposed = 0
    framework_guards = 0
    sanitizer_filtered = 0
    runtime_hits = 0
    errors = 0
    positive: List[str] = []
    warnings: List[str] = []

    for rep in reports:
        probe = rep.get('resilience_probe') or {}
        csp_flags = (probe.get('csp') or {}).get('flags') or {}
        if csp_flags.get('no_inline_script'):
            strong_csp += 1
        if csp_flags.get('strict_dynamic'):
            strong_csp += 0.2

        tt = probe.get('trusted_types') or {}
        if tt.get('enforced'):
            tt_enforced += 1
        elif tt.get('supported') and not tt.get('enforced'):
            warnings.append(f"Trusted Types supported but not enforced on {rep.get('url')}")

        ladder = probe.get('csp_ladder') or {}
        inline_info = ladder.get('inline') or {}
        blob_info = ladder.get('external_blob') or {}
        url_info = ladder.get('url_handler') or {}
        if not inline_info.get('executed', True):
            ladder_inline_blocked += 1
        else:
            warnings.append(f"Inline script executed during probe on {rep.get('url')}")
        if not blob_info.get('executed', True):
            ladder_blob_blocked += 1
        if not url_info.get('executed', True):
            ladder_url_blocked += 1

        sink_inv = probe.get('sink_inventory') or {}
        if sink_inv.get('has_high_risk_sink'):
            sink_exposed += 1

        frameworks = probe.get('frameworks') or {}
        for data in frameworks.values():
            if isinstance(data, dict) and data.get('auto_escape'):
                framework_guards += 1
                break

        sanitizer_summary = rep.get('sanitizer_summary') or {}
        sanitizer_filtered += int(sanitizer_summary.get('filtered') or 0)

        runtime_findings = rep.get('runtime_findings') or []
        if runtime_findings:
            runtime_hits += 1

        errs = probe.get('errors') or []
        errors += len(errs)

    score = 40
    if total:
        score += min((strong_csp / total) * 20, 20)
        score += min((tt_enforced / total) * 15, 15)
        score += min((ladder_inline_blocked / total) * 10, 10)
        score += min((ladder_blob_blocked / total) * 5, 5)
        score += min((ladder_url_blocked / total) * 5, 5)
        score += min(framework_guards, 2) * 5
        score += min(sanitizer_filtered / max(total, 1), 10)

    score -= sink_exposed * 8
    score -= runtime_hits * 12
    score -= errors * 2

    if has_vulns:
        score = max(5, score - 40)

    score = int(max(0, min(100, round(score))))

    if strong_csp:
        positive.append(f"CSP blocked inline scripts on {strong_csp:.1f}/{total} pages")
    else:
        warnings.append("CSP allowed inline script execution on every page tested")

    if tt_enforced:
        positive.append(f"Trusted Types enforced on {tt_enforced}/{total} pages")
    else:
        warnings.append("Trusted Types enforcement not observed")

    if ladder_inline_blocked:
        positive.append(f"Inline ladder probe stopped on {ladder_inline_blocked}/{total} attempts")
    if ladder_blob_blocked:
        positive.append(f"Blob/script-src ladder blocked on {ladder_blob_blocked}/{total} attempts")
    if ladder_url_blocked:
        positive.append(f"javascript: URL handlers blocked on {ladder_url_blocked}/{total} attempts")

    if sink_exposed:
        warnings.append(f"High-risk sinks detected on {sink_exposed}/{total} pages")
    else:
        positive.append("No high-risk sinks observed in inventory")

    if framework_guards:
        positive.append(f"Auto-escaping framework guard detected ({framework_guards} instances)")

    if sanitizer_filtered:
        positive.append(f"Sanitizers filtered {sanitizer_filtered} characters across probes")

    if runtime_hits:
        warnings.append(f"Runtime taint signals observed on {runtime_hits}/{total} pages")

    confidence = 'medium'
    if errors == 0 and ladder_inline_blocked == total and tt_enforced:
        confidence = 'high'
    elif errors > total or total == 0:
        confidence = 'low'

    checklist = [f"[+] {item}" for item in positive]
    checklist.extend(f"[!] {item}" for item in warnings)

    return {
        'score': score,
        'confidence': confidence,
        'checklist': checklist,
        'details': reports,
    }
