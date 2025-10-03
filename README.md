# 🎯 MerdekaSiberLab XSS Scanner — Hyper-Accurate DOM Execution Suite

![Animated Radar](https://media.giphy.com/media/26Fxy3Iz1ari8oytO/giphy.gif)

> **Dual Language Guide / Panduan Dua Bahasa** — switch between English and Bahasa Indonesia without losing critical detail.

| 🌐 Language | Jump Link |
|-------------|-----------|
| 🇬🇧 English | [Go to English Guide](#-english-guide) |
| 🇮🇩 Indonesia | [Ke Panduan Indonesia](#-panduan-bahasa-indonesia) |

---

## ✨ Feature Highlights

- ⚔️ **Context-aware payload engine** with sanitizer heuristics, DOM execution feedback, and WAF-aware scoring
- 🕸️ **Playwright-powered crawling** (SPA routers, hash fuzzing, storage/event stimulation)
- 🛰️ **Blind/OAST XSS orchestration** with tokenised callbacks and local evidence caching
- 🧭 **GraphQL discovery & exploitation** (introspection, persisted queries, variable fuzzing)
- 🧠 **AI triage (Gemini)** to cluster findings, rewrite payloads, and produce human-friendly summaries
- 🛡️ **Adaptive WAF detector** (fingerprints + behavioural hints + per-vendor throttling plan)
- 📸 **Forensic artefacts** (screenshots, HTML snippets, redaction presets, SARIF/JSON/HTML exports)
- ♻️ **Browser pooling & revisit scheduler** for stored/delayed execution pathways

---

## 📚 Table of Contents

1. [Prerequisites](#-prerequisites)
2. [Quickstart Cheatsheet](#-quickstart-cheatsheet)
3. [English Guide](#-english-guide)
4. [Panduan Bahasa Indonesia](#-panduan-bahasa-indonesia)
5. [Module Map](#-module-map)
6. [FAQ](#-faq)
7. [Safety & Responsible Use](#-safety--responsible-use)
8. [Credits](#-credits)

---

## 🧰 Prerequisites

- Python 3.10+
- Chromium via Playwright (`python -m playwright install chromium`)
- `pip install -r requirements.txt`
- Optional: `playwright-stealth`, `GENAI_API_KEY`, `OAST_BASE_URL`

---

## ⚡ Quickstart Cheatsheet

| Scenario | Command |
|----------|---------|
| Install dependencies | ``pip install -r requirements.txt`` |
| Install browser | ``python -m playwright install chromium`` |
| Fast reconnaissance | ``python main.py --preset fast https://target.tld`` |
| Thorough DOM coverage | ``python main.py --preset thorough https://target.tld`` |
| Manual login capture | ``python main.py --preset thorough https://target.tld --manual-login --login-url https://target.tld/login`` |
| Enable OAST | ``OAST_BASE_URL=https://oast.tld python main.py https://target.tld`` |
| AI-assisted triage | ``GENAI_API_KEY=xxx python main.py https://target.tld --api-key $GENAI_API_KEY`` |
| Export SARIF + evidence | ``python main.py --preset thorough --out results.sarif --format sarif --evidence-dir evidence https://target.tld`` |

---

## 🇬🇧 English Guide

### 1. Installation & Environment

1. Clone or unpack this repository.
2. Install dependencies and browser drivers:

   ```bash
   pip install -r requirements.txt
   python -m playwright install chromium
   ```

3. (Optional) Configure environment variables:

   ```bash
   export GENAI_API_KEY=your_gemini_key
   export OAST_BASE_URL=https://oast.yourdomain/inbound
   ```

### 2. Core Workflow

1. **Target Selection** — Provide the base URL.
2. **Preset Tuning** — Choose `fast`, `thorough`, `dom`, `api`, `graphql`, or `blind` to align runtime vs coverage.
3. **Crawling** — Dynamic instrumentation stimulates hash routes, local/session storage, XHR/fetch, WebSocket, BroadcastChannel, and shadow DOM sinks.
4. **Payload Strategy** — Sanitizer analysis plus runtime DOM signals feed the SuperBypass engine to craft minimal yet potent payloads.
5. **Execution Confirmation** — Playwright verifies actual DOM/script execution using dialog hooks, CSP violations, and console traces.
6. **Reporting** — Findings stream in real time; final summary exported via Table, JSON, SARIF, or HTML.

### 3. Advanced Scenarios

- **Manual or scripted login**: capture cookies, reuse storage states, or supply selectors (`--username --password --user-selector ...`).
- **GraphQL Fuzzing**: auto-discover endpoints (`--graphql`) and probe directives, aliases, persisted queries.
- **Blind XSS / OAST**: tokenised payload insertion with SSE/polling receiver (configure `OAST_BASE_URL`).
- **Custom payload libraries**: merge your YAML via `--payloads custom.yml`.
- **Evidence capture**: `--evidence-dir evidence --redact-evidence --keep-raw-evidence`.

### 4. Key CLI Flags

| Flag | Purpose |
|------|---------|
| `--preset fast|thorough|dom|api|graphql|blind` | Optimise runtime vs coverage |
| `--mode quick|deep` | Backward-compatible alias (maps to presets) |
| `--summary-only` | Compact console output |
| `--verbose` / `--debug` | Increase log verbosity |
| `--payloads FILE` | Merge custom payload YAML |
| `--cookie STRING` | Inject initial Cookie header |
| `--depth INT` / `--max-urls INT` | Crawl boundaries |
| `--workers INT` | Static testing thread pool size |
| `--browsers INT` | Pre-launch Playwright pages (0 = auto) |
| `--sanitizer-detail summary|full` | Toggle sanitizer mapping verbosity |
| `--graphql` | Enable GraphQL endpoint probing |
| `--hash-fuzz/--no-hash-fuzz` | Toggle SPA `location.hash` fuzzing |
| `--manual-login` / `--login-url` / `--cookie-file` | Guided login capture |
| `--username` / `--password` / selector flags | Scripted login |
| `--waf-*` flags | Control detection mode, bypass level, throttling |
| `--evidence-dir PATH` | Persist screenshots & HTML per finding |
| `--out PATH --format json|sarif|html` | Machine-readable exports |

### 5. WAF & Throttling Intelligence

The scanner fingerprints Cloudflare, Akamai, Imperva, AWS WAF, ModSecurity, and more. Each fingerprint ships metadata (RPS caps, header camouflage, inline-handler reduction). The CLI prints matched headers/cookies/body cues and toggles payload strategies accordingly. Throttling decisions feed `network.py` to respect safe request pacing.

### 6. CI/CD & Automation

- **SARIF uploads**: integrate with GitHub/GitLab security dashboards.
- **JSON pipelines**: use the machine artifact to gate builds or feed analytics.
- **Headless evidence**: store screenshots/HTML per finding for regression diffing.
- **Matrix testing**: leverage `tools/eval` mocks to benchmark bypass accuracy.

---

## 🇮🇩 Panduan Bahasa Indonesia

### 1. Persiapan Lingkungan

1. Salin atau ekstrak repositori ini.
2. Pasang dependensi & browser Chromium:

   ```bash
   pip install -r requirements.txt
   python -m playwright install chromium
   ```

3. (Opsional) Atur variabel lingkungan:

   ```bash
   set GENAI_API_KEY=api_key_gemini
   set OAST_BASE_URL=https://oast.domainmu/masuk
   ```

### 2. Alur Dasar Pemindaian

1. **Masukkan URL target** (contoh: `https://contoh.com`).
2. **Pilih preset** sesuai kebutuhan: `fast` (cepat), `thorough` (cakupan penuh), `dom`, `api`, `graphql`, atau `blind` (Blind XSS).
3. **Crawler dinamis** akan menjelajahi link, form, hash router, storage, WebSocket, hingga shadow DOM.
4. **Strategi payload** menilai bagaimana server menyaring karakter, lalu membuat payload kecil tapi efektif.
5. **Konfirmasi eksekusi** memakai Playwright (dialog/event/CSP) sehingga hanya XSS nyata yang dilaporkan.
6. **Ringkasan akhir** tampil di terminal dan bisa diekspor (Table/JSON/SARIF/HTML).

### 3. Mode Lanjutan

- **Login manual**: `--manual-login --login-url ... --cookie-file cookies.json` untuk menahan sesi.
- **Login otomatis**: sertakan `--username`, `--password`, dan selector elemen.
- **GraphQL**: aktifkan `--graphql` untuk menemukan dan menguji endpoint GraphQL.
- **Blind XSS**: set `OAST_BASE_URL` lalu jalankan preset `blind` atau `thorough`.
- **Payload kustom**: gabungkan file YAML sendiri dengan `--payloads jalur/anda.yml`.
- **Simpan bukti**: `--evidence-dir bukti --redact-evidence` agar aman dibagikan.

### 4. Flag CLI Penting

| Flag | Fungsi Singkat |
|------|----------------|
| `--preset fast|thorough|dom|api|graphql|blind` | Menentukan strategi pemindaian |
| `--summary-only` | Menyederhanakan log di terminal |
| `--verbose` / `--debug` | Menampilkan log lebih detail |
| `--payloads FILE` | Menambahkan payload kustom |
| `--cookie STRING` | Menyetel cookie awal |
| `--depth` / `--max-urls` | Batas kedalaman & jumlah URL crawler |
| `--workers` | Jumlah thread analisis statis |
| `--browsers` | Jumlah instance Playwright yang dipra-buka |
| `--graphql` | Menguji endpoint GraphQL |
| `--hash-fuzz/--no-hash-fuzz` | Mengaktifkan/menonaktifkan fuzz hash SPA |
| `--manual-login` + opsi login | Menangkap sesi secara manual |
| `--username` + selector | Login otomatis dengan kredensial |
| `--waf-mode`, `--waf-bypass-level`, dsb. | Mengatur strategi bypass WAF |
| `--evidence-dir` | Menyimpan bukti (screenshot/HTML) |
| `--out` + `--format` | Mengekspor hasil (JSON/SARIF/HTML) |

### 5. WAF & Pengaturan Kecepatan

Detektor WAF otomatis mengenali vendor populer dan menampilkan sinyal yang cocok (header/cookie/body). Tool akan otomatis memperlambat permintaan, mengganti header, atau meminimalkan payload sesuai rekomendasi fingerprint.

### 6. Integrasi dan Otomasi

- **CI/CD**: gunakan keluaran SARIF/JSON untuk pipeline DevSecOps.
- **Laporan bukti**: screenshot dan HTML siap untuk audit.
- **Evaluasi internal**: direktori `tools/eval` menyediakan mock WAF & target uji untuk regression testing.

---

## 🧭 Module Map

| Module | Ringkasan |
|--------|-----------|
| `cli.py` | Argument parsing, UI banner, WAF summary, progress orchestration |
| `tester.py` | Phase pipeline (probe, sanitizer, DOM runtime, coverage, static brute) & revisit scheduler |
| `payload_strategy.py` | Context-aware payload scoring, WAF plan adaptation, Blind XSS tokenisation |
| `sanitization_analyzer.py` | Character probing with CSRF-aware requests & segment-aware reflection detection |
| `dynamic_dom_tester.py` | Playwright instrumentation (shadow DOM, fragments, sendBeacon, window.open, CSP hooks) |
| `crawler/advanced_crawler.py` | SPA-aware crawling, parameter dedupe, CSRF token harvesting |
| `network.py` | Rate limiting, WAF-driven throttling, header camouflage |
| `graphql_scanner.py` | Endpoint discovery, schema introspection, payload fuzzing |
| `oast.py` | Blind XSS payload factory & receiver integration |
| `ai_analysis.py` | Gemini-based summarisation & payload rewriting |

---

## ❓ FAQ

<details>
<summary><strong>Does the scanner handle heavy CSP + Trusted Types?</strong></summary>
It maps CSP headers, meta tags, and Trusted Types policies; payload selection avoids inline/script-unsafe sinks unless a bypass is likely. Full bypass is not guaranteed against perfectly hardened CSP+TT combinations.
</details>

<details>
<summary><strong>Apakah bisa digunakan tanpa Playwright headless?</strong></summary>
Secara default tool memakai Playwright. Anda dapat menonaktifkan fitur dinamis (preset `fast` atau `api`) untuk mode tanpa browser, namun akurasi DOM XSS akan turun.
</details>

<details>
<summary><strong>Bagaimana cara menjalankan di CI/CD?</strong></summary>
Gunakan preset yang sesuai, simpan hasil ke JSON/SARIF (`--out results.json --format json`), lalu unggah artefak. Anda juga dapat menambahkan langkah `python -m pyflakes` sebelum commit.
</details>

---

## 🛡️ Safety & Responsible Use

- Scan only assets you are authorised to test.
- Respect site performance limits; adaptive throttling is built in but you remain accountable.
- Report vulnerabilities privately and responsibly.
- Use the tool for defensive security, research, or sanctioned pentesting only.

---

## 🤝 Credits

- Inspired by OWASP benchmarks (DVWA, bWAPP, Juice Shop, WebGoat, NodeGoat, RailsGoat)
- Powered by the Playwright ecosystem and the wider security community
- Contributions welcome! Submit issues or PRs with clear repro steps and linted code (`python -m pyflakes`).

---

![Neon Grid Animation](https://media.giphy.com/media/3o7aD2saalBwwftBIY/giphy.gif)