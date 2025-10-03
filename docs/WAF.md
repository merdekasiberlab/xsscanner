# WAF Detection & Adaptive Bypass

Dokumen ini menjelaskan bagaimana modul WAF bekerja di XSS Scanner:

- Fingerprinting pasif berdasarkan headers/cookies/body/status (lihat `waf_fingerprints.yaml`).
- Probe aktif ringan (mode `active|aggressive`) tanpa payload berbahaya.
- Klasifikasi event per respons: `allowed | blocked | challenged_js | challenged_captcha | rate_limited`.
- Adaptasi: throttling (RPS cap + backoff), payload morph (ringan & etis), header camouflage.
- Logging sinyal yang cocok (header/cookie/body) untuk transparansi & diagnosa manual.

## Mode

- `passive` (default): hanya fingerprint pasif saat warmup.
- `active`: tambah HEAD/OPTIONS/GET aman untuk menyimpulkan challenge/rate-limit.
- `aggressive`: variasi sedikit lebih banyak (tetap aman), semua strategi bypass non-intrusif aktif.

## Flags CLI

- `--waf-detect / --no-waf-detect`
- `--waf-mode [passive|active|aggressive]`
- `--waf-bypass-level [0..3]`
- `--waf-safe-rps FLOAT` (default 1.5)
- `--waf-backoff INT(ms)` (default 1500)
- `--waf-header-camo` (UA/Accept-Language/Connection)
- `--waf-rotate-ua` (pool UA modern)
- `--waf-trust-proxy`

Fingerprint kini dapat menetapkan metadata bawaan (`safe_rps`, `backoff_ms`, `header_camo`, `rotate_ua`, `reduce_inline_handlers`, `no_javascript_url`) untuk menyesuaikan strategi secara otomatis.

## Output

Bagian `waf` di artefak JSON:

```
{
  "waf": {
    "origin": "https://example.com",
    "vendor": "cloudflare",
    "confidence": "high",
    "mode": "active",
    "safe_rps": 0.5,
    "challenge": "js",
    "rate_limit": false,
    "matches": {
      "headers": ["cf-ray: 6fb...", "server: cloudflare"],
      "cookies": ["__cf_bm"],
      "body": ["Please enable JavaScript"]
    },
    "metadata": {
      "header_camo": true,
      "rotate_ua": true,
      "reduce_inline_handlers": true,
      "safe_rps": 0.5,
      "notes": "Cloudflare IUAM/JS challenge"
    },
    "applied_strategies": ["prefer_minimal_attr","short_payloads","header_camo","reduce_inline_handlers"],
    "notes": "Cloudflare IUAM/JS challenge"
  },
  "findings": [ ... ]
}
```

## Etika & Batasan

- Tidak melakukan brute-force captcha/challenge.
- `low-and-slow` secara default, menghormati batasan situs.
- Gunakan dalam konteks legal yang sah.
