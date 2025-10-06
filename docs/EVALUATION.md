Evaluation Matrix and Methodology

Scope
- Measure detection/execution quality over diverse contexts and runtimes.
- Reduce false positives via sink/context awareness and AI-assisted dedup.

Matrix (dimensions)
- Context: HTML text, attribute (dq/sq/unq), JS string (dq/sq), URL scheme, CSS (url/expression), SVG/MathML, event handler
- Quote mode: double, single, unquoted
- Event triggers: autofocus/onload/onerror/click/hover/RAF/timeout
- Framework: React, Angular, Vue, Svelte, jQuery, plain
- Rendering: SSR vs CSR
- CSP: strict-dynamic/nonce/hash only vs loose
- Input channel: query, body, header, hash, storage, postMessage

Datasets
- DVWA, bWAPP, OWASP Juice Shop, WebGoat, NodeGoat, RailsGoat
- Internal pages (if available), user-provided targets
- Canary pages: crafted pages covering each matrix cell to prevent overfitting

Metrics
- Reflection-only: do not count as true positive (TP) unless executed
- Executed XSS: count as TP
- False Positive (FP): reflection-only or escaped payloads marked as vulnerable
- Precision = TP / (TP + FP)
- Recall = TP / (Total Exploitable)
- F1 = 2 * (Prec * Rec) / (Prec + Rec)

Procedure
1) Run scans across targets with standardized settings
2) Export raw findings (logs/findings_*.json)
3) Label executed vs reflected, blind vs in-band
4) Compute metrics per dimension and overall
5) Use AI summary to merge duplicates and flag probable FP

Reporting
- Per target: executed counts, FP counts, notable bypasses (CSP/TT/WAF)
- Per dimension: heatmap of F1
- Delta over time: track regressions/improvements



## XSS Resilience Score

The tester now records CSP/Trusted Types probes, sink inventory, and framework guards. When a scan finishes without exploitable XSS, the CLI prints a resilience score with a checklist of observed controls. Use this output alongside vulnerability results to demonstrate hardening on DVWA/bWAPP and other benchmarks.