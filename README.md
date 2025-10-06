<div align="center">

<img src="docs/assets/xssgenai.jpg" alt="XSS Scanner Hero Banner" width="820" />

![XSSGENAI - Merdeka Siber](https://readme-typing-svg.demolab.com?font=Fira+Code&size=30&pause=1200&color=F70000&center=true&vCenter=true&width=800&height=100&lines=XSSGENAI+-+Merdeka+Siber;WAF+Aware+%7C+AI-Assisted+%7C+Crawler-Driven)

</div>

---

# XSS Scanner – User Guide / Panduan Pengguna

> **EN:** A bilingual guide for operating the MerdekaSiberLab XSS Scanner.
>
> **ID:** Panduan dwibahasa untuk mengoperasikan XSS Scanner MerdekaSiberLab.

## Table of Contents / Daftar Isi
1. [At a Glance / Sekilas](#1-at-a-glance--sekilas)
2. [Feature Highlights / Sorotan Fitur](#2-feature-highlights--sorotan-fitur)
3. [Architecture & Components / Arsitektur & Komponen](#3-architecture--components--arsitektur--komponen)
4. [System Requirements / Prasyarat Sistem](#4-system-requirements--prasyarat-sistem)
5. [Installation & Setup / Instalasi & Persiapan](#5-installation--setup--instalasi--persiapan)
6. [Usage Cookbook / Panduan Penggunaan](#6-usage-cookbook--panduan-penggunaan)
7. [Advanced Capabilities / Fitur Lanjutan](#7-advanced-capabilities--fitur-lanjutan)
8. [Logs, Reports & Data Hygiene / Log, Laporan & Kebersihan Data](#8-logs-reports--data-hygiene--log-laporan--kebersihan-data)
9. [Troubleshooting & FAQ / Pemecahan Masalah & FAQ](#9-troubleshooting--faq--pemecahan-masalah--faq)
10. [Roadmap & Contribution Ideas / Rencana & Ide Kontribusi](#10-roadmap--contribution-ideas--rencana--ide-kontribusi)
11. [Legal Notice / Catatan Hukum](#11-legal-notice--catatan-hukum)

---

## 1. At a Glance / Sekilas
- **EN:** XSS Scanner is a modern assessment suite that discovers, validates, and prioritises cross-site scripting issues across server-rendered and SPA workloads.
- **ID:** XSS Scanner adalah rangkaian asesmen modern untuk menemukan, memvalidasi, dan memprioritaskan celah XSS pada aplikasi SSR maupun SPA.

- **EN:** Supports hybrid crawling, runtime DOM inspection, WAF-aware payload strategy, optional Google Gemini analysis, and resilience scoring.
- **ID:** Mendukung perayapan hibrida, inspeksi DOM runtime, strategi payload sadar-WAF, analisis Gemini opsional, dan penilaian ketahanan.

- **EN:** Designed for red-teamers, security engineers, QA, and DevSecOps teams needing repeatable, high-signal XSS results.
- **ID:** Dirancang untuk red team, engineer keamanan, QA, serta tim DevSecOps yang membutuhkan hasil XSS yang presisi dan dapat diulang.

## 2. Feature Highlights / Sorotan Fitur
- **EN:** **Hybrid Crawler** – static HTML parsing plus Playwright-enabled crawling for SPA navigation.
- **ID:** **Crawler Hibrida** – parsing HTML statis ditambah Playwright untuk menavigasi aplikasi SPA.

- **EN:** **Context-Aware Payload Engine** (`payload_strategy.py`) tailors payloads using sanitisation fingerprints, context hints, and WAF bypass plans.
- **ID:** **Mesin Payload Kontekstual** (`payload_strategy.py`) menyesuaikan payload dengan fingerprint sanitasi, konteks, dan rencana bypass WAF.

- **EN:** **Dynamic DOM Tester** (`dynamic_dom_tester.py`) observes runtime mutations, events, and sink execution opportunities.
- **ID:** **Dynamic DOM Tester** (`dynamic_dom_tester.py`) memantau mutasi runtime, event, serta peluang eksekusi sink.

- **EN:** **Gemini AI Analysis** (`ai_analysis.py`) summarises HTML/JS contexts, ranks sinks, and suggests mitigations when a Google GenAI key is provided.
- **ID:** **Analisis Gemini AI** (`ai_analysis.py`) merangkum konteks HTML/JS, memberi ranking sink, dan menyarankan mitigasi bila tersedia API key Google GenAI.

- **EN:** **WAF Detector** (`waf_detector.py`) fingerprints popular vendors, proposes throttle settings, and hands hints to payload strategy.
- **ID:** **WAF Detector** (`waf_detector.py`) mengenali vendor populer, menyarankan limitasi request, dan memberi hint ke strategi payload.

- **EN:** **GraphQL Scanner** (`graphql_scanner.py`) enumerates endpoints, validates introspection, and injects XSS vectors into resolvers.
- **ID:** **GraphQL Scanner** (`graphql_scanner.py`) memetakan endpoint, memvalidasi introspeksi, dan menyuntikkan vektor XSS ke resolver.

- **EN:** **Resilience Score** (`tester.py` + `resilience.py`) aggregates CSP, Trusted Types, and sink coverage to highlight defensive posture.
- **ID:** **Resilience Score** (`tester.py` + `resilience.py`) menggabungkan CSP, Trusted Types, dan cakupan sink untuk menilai ketahanan.

## 3. Architecture & Components / Arsitektur & Komponen
```
cli.py                  # Operator console & workflow orchestration
main.py                 # Thin entry point wrapper
network.py              # Session handling, throttling, header camo, WAF hooks
waf_detector.py         # Vendor fingerprints & bypass guidance
dynamic_dom_tester.py   # Playwright-powered DOM instrumentation
tester.py               # Payload execution pipeline & resilience scoring
payload_strategy.py     # Payload generator + sanitiser fingerprint logic
ai_analysis.py          # Gemini AI integration & reporting panels
graphql_scanner.py      # GraphQL discovery, introspection, fuzzing
crawler/                # BFS crawler + advanced Playwright crawler
parsers/                # Context parsers for sink/source detection
docs/                   # Reference documentation & evaluation notes
waf_fingerprints.yaml   # Fingerprint library for supported WAFs
i18n.py                 # Language selector & translation helper
```

## 4. System Requirements / Prasyarat Sistem
- **EN:** Python 3.10+ (Windows, macOS, or Linux).
- **ID:** Python 3.10 atau lebih baru (Windows, macOS, atau Linux).

- **EN:** `pip install -r requirements.txt` (includes Playwright, HTTP libraries, rich console, etc.).
- **ID:** `pip install -r requirements.txt` (sudah termasuk Playwright, pustaka HTTP, rich console, dan lainnya).

- **EN:** Playwright browser binaries (`python -m playwright install chromium`).
- **ID:** Binary browser Playwright (`python -m playwright install chromium`).

- **EN:** Optional Google GenAI API Key (`GENAI_API_KEY`) for Gemini analysis.
- **ID:** Opsional API Key Google GenAI (`GENAI_API_KEY`) untuk analisis Gemini.

- **EN:** Network access to target, and permission to test.
- **ID:** Akses jaringan ke target dan izin pengujian yang sah.

## 5. Installation & Setup / Instalasi & Persiapan
### 5.1 Clone & Virtual Environment / Kloning & Lingkungan Virtual
```bash
# EN: Clone repository and enter directory
# ID: Kloning repositori dan masuk ke direktori

git clone https://github.com/merdekasiberlab/xsscanner.git
cd xsscanner

# EN: Create & activate virtual environment (PowerShell)
# ID: Membuat & mengaktifkan virtual environment (PowerShell)
python -m venv .venv
. .venv/Scripts/Activate.ps1
# macOS/Linux: source .venv/bin/activate
```

### 5.2 Dependencies & Playwright / Dependensi & Playwright
```bash
pip install -r requirements.txt
python -m playwright install chromium
```
- **EN:** Use `pip install -r requirements-dev.txt` if you maintain the project.
- **ID:** Gunakan `pip install -r requirements-dev.txt` bila Anda turut mengembangkan proyek.

### 5.3 Environment Variables / Variabel Lingkungan
- **EN:** `GENAI_API_KEY` – Google GenAI key for Gemini AI analysis.
- **ID:** `GENAI_API_KEY` – API key Google GenAI untuk analisis Gemini.

- **EN:** `HTTP_PROXY` / `HTTPS_PROXY` – configure outbound proxies when required.
- **ID:** `HTTP_PROXY` / `HTTPS_PROXY` – atur proxy keluar bila diperlukan.

## 6. Usage Cookbook / Panduan Penggunaan
> **Tip:** The CLI now prompts for language at startup. Choose `id` or `en` to switch all prompts.

### 6.1 Quick Scan / Pemindaian Cepat
```bash
python main.py --mode quick --max-urls 80 --depth 4 https://target.tld
```
- **EN:** Performs static crawling, parameter discovery, baseline payload execution, and quick DOM inspection.
- **ID:** Melakukan crawling statis, penemuan parameter, eksekusi payload dasar, dan inspeksi DOM cepat.

### 6.2 Deep Scan with Manual Login / Pemindaian Deep dengan Login Manual
```bash
python main.py \
  --mode deep \
  --manual-login \
  --login-url https://app.tld/login \
  --cookie-file session.json \
  --max-urls 150 \
  --depth 6 \
  https://app.tld
```
- **EN:** Launches a headful browser to capture authenticated state, then runs Playwright-based crawling.
- **ID:** Membuka browser headful untuk menangkap sesi autentikasi, lalu menjalankan crawling berbasis Playwright.

### 6.3 AI-Assisted Triage / Triase Berbantuan AI
```bash
set GENAI_API_KEY=your-google-genai-key
python main.py --mode deep --api-key %GENAI_API_KEY% https://portal.tld
```
- **EN:** Sends contextual HTML/JS snippets and runtime findings to Gemini for sink ranking, payload suggestions, and mitigations.
- **ID:** Mengirim potongan HTML/JS dan temuan runtime ke Gemini untuk ranking sink, saran payload, dan mitigasi.

### 6.4 GraphQL Recon & XSS / Rekon & XSS GraphQL
```bash
python main.py --mode quick --graphql https://api.tld
```
- **EN:** Discovers GraphQL endpoints, attempts introspection, and fuzzes resolvers for XSS vectors.
- **ID:** Menemukan endpoint GraphQL, mencoba introspeksi, dan melakukan fuzzing resolver untuk vektor XSS.

### 6.5 CLI Options Quick Reference / Ringkasan Opsi CLI
| Flag | English Description | Deskripsi Indonesia |
|------|---------------------|---------------------|
| `--mode {quick,deep}` | Choose crawler depth (static vs Playwright). | Pilih kedalaman crawler (statis vs Playwright). |
| `--max-urls N` | Limit URLs crawled. | Batas jumlah URL yang dipindai. |
| `--depth N` | Recursion depth guard. | Pengaman kedalaman rekursi. |
| `--payloads FILE` | Merge custom payloads from YAML. | Gabungkan payload kustom dari YAML. |
| `--cookie "k=v;"` | Inject cookies for authenticated scans. | Masukkan cookie untuk pemindaian terautentikasi. |
| `--manual-login` | Headful login capture (requires `--login-url`). | Tangkap login via browser headful (butuh `--login-url`). |
| `--graphql` | Enable GraphQL probing. | Aktifkan pemindaian GraphQL. |
| `--api-key KEY` | Provide Google GenAI key (overrides env). | Menyediakan API key Google GenAI (override env). |
| `--summary-only` | Print only final summary. | Tampilkan ringkasan akhir saja. |
| `--workers N` | Payload execution threads. | Jumlah thread eksekusi payload. |
| `--insecure` | Disable TLS verification. | Nonaktifkan verifikasi TLS. |

## 7. Advanced Capabilities / Fitur Lanjutan
### 7.1 WAF Detection & Throttling / Deteksi & Throttling WAF
- **EN:** `waf_detector.py` fingerprints headers, cookies, and body markers. When a vendor is matched, the CLI displays throttle guidance and bypass hints (e.g., short payloads, avoid inline handlers).
- **ID:** `waf_detector.py` mencocokkan header, cookie, dan marker body. Jika vendor terdeteksi, CLI menampilkan panduan throttle dan hint bypass (misal payload pendek, hindari handler inline).

- **EN:** `network.set_waf_throttle()` enforces safe RPS and backoff automatically.
- **ID:** `network.set_waf_throttle()` menerapkan batas RPS dan jeda secara otomatis.

### 7.2 Dynamic DOM Tester / Dynamic DOM Tester
- **EN:** Uses Playwright to evaluate runtime sinks (e.g., `innerHTML`, event handlers, location-based sources). Records taint flows and runtime findings for AI analysis and resilience scoring.
- **ID:** Menggunakan Playwright untuk mengevaluasi sink runtime (misal `innerHTML`, event handler, sumber lokasi). Mencatat alur taint dan temuan runtime untuk analisis AI dan penilaian ketahanan.

### 7.3 Gemini AI Analyzer / Analis Gemini AI
- **EN:** Grabs HTML, CSP headers, inline scripts, and ranked external JS snippets to craft a Gemini prompt. Outputs sectioned panels with sinks, exploit paths, payload ladders, and mitigations.
- **ID:** Mengumpulkan HTML, header CSP, skrip inline, serta snippet JS eksternal terpilih untuk membentuk prompt Gemini. Menghasilkan panel terstruktur berisi sink, jalur eksploitasi, ladder payload, dan mitigasi.

### 7.4 Resilience Score / Skor Ketahanan
- **EN:** After scans, `tester.py` aggregates CSP/Trusted Types probes, sink coverage, and confirmed payloads into a 0–100 score with actionable checklist.
- **ID:** Setelah pemindaian, `tester.py` menggabungkan probe CSP/Trusted Types, cakupan sink, dan payload terkonfirmasi menjadi skor 0–100 beserta daftar tindakan.

### 7.5 Multilingual CLI / CLI Multibahasa
- **EN:** Language selection occurs at startup via `_prompt_language_choice()`. You can switch languages between runs; translations live in `i18n.py`.
- **ID:** Pemilihan bahasa dilakukan saat startup lewat `_prompt_language_choice()`. Bahasa dapat diganti antar sesi; terjemahan berada di `i18n.py`.

## 8. Logs, Reports & Data Hygiene / Log, Laporan & Kebersihan Data
- **EN:** Runtime logs are stored under `logs/`. Clear the directory before sharing results.
- **ID:** Log runtime disimpan di `logs/`. Bersihkan direktori sebelum membagikan hasil.

- **EN:** Playwright state files (cookies, storage) may contain credentials; treat them as secrets.
- **ID:** File state Playwright (cookie, storage) dapat berisi kredensial; perlakukan sebagai rahasia.

- **EN:** AI panels and resilience summaries can be exported by copying console output or piping to a log file.
- **ID:** Panel AI dan ringkasan ketahanan dapat diekspor dengan menyalin output console atau mengalihkan ke file log.

## 9. Troubleshooting & FAQ / Pemecahan Masalah & FAQ
| Issue / Masalah | EN Fix | Solusi ID |
|-----------------|--------|-----------|
| WAF not detected | Extend `waf_fingerprints.yaml` with new header/body regex. | Tambah regex baru di `waf_fingerprints.yaml` untuk header/body. |
| Playwright launch error | Run `python -m playwright install chromium`. | Jalankan `python -m playwright install chromium`. |
| Cannot delete log file on Windows | Stop the running scan (Ctrl+C); log handle releases on exit. | Hentikan proses pemindaian (Ctrl+C); handle log akan dilepas saat keluar. |
| Gemini import error | Ensure `google-genai` is installed or run without `--api-key`. | Pastikan `google-genai` terpasang atau jalankan tanpa `--api-key`. |
| High false positives | Review context manually, adjust payload sets in `payloads.yml`. | Tinjau konteks secara manual, sesuaikan payload di `payloads.yml`. |
| Scan too slow behind WAF | Use `--mode quick`, reduce `--max-urls`, or accept suggested throttle. | Gunakan `--mode quick`, kurangi `--max-urls`, atau terapkan throttle yang disarankan. |

## 10. Roadmap & Contribution Ideas / Rencana & Ide Kontribusi
- **EN:** Automated OAST callback integration, richer report exporters (HTML, SARIF), CI smoke-test pipeline, and remote fingerprint feeds.
- **ID:** Integrasi callback OAST otomatis, ekspor laporan yang lebih kaya (HTML, SARIF), pipeline smoke-test CI, dan feed fingerprint jarak jauh.

- **EN:** Contributions welcome via pull request. Please follow lint (`ruff`), type check (`mypy`), and compile checks.
- **ID:** Kontribusi dipersilakan melalui pull request. Ikuti lint (`ruff`), pemeriksa tipe (`mypy`), dan cek kompilasi.

## 11. Legal Notice / Catatan Hukum
- **EN:** Use this toolkit only on systems you own or have explicit written permission to test.
- **ID:** Gunakan alat ini hanya pada sistem milik sendiri atau yang memiliki izin tertulis eksplisit untuk diuji.

- **EN:** You are responsible for complying with laws, regulations, and contractual obligations.
- **ID:** Anda bertanggung jawab mematuhi hukum, regulasi, dan kewajiban kontraktual yang berlaku.

- **EN:** MerdekaSiberLab and contributors are not liable for misuse or damages arising from this software.
- **ID:** MerdekaSiberLab dan kontributor tidak bertanggung jawab atas penyalahgunaan maupun kerugian akibat penggunaan perangkat lunak ini.

---
