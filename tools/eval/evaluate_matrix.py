#!/usr/bin/env python3
"""
Evaluate scanner results against ground truth.

Usage:
  python tools/eval/evaluate_matrix.py \
    --ground tools/eval/ground_truth.yaml \
    --scan /path/to/results.json \
    --oast tools/eval/oast_hits.db \
    --report /path/to/eval_report.md \
    --csv /path/to/eval_metrics.csv

Exit codes:
  0 -> no findings
  1 -> findings present (>= Low)
  2 -> invalid input
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
from dataclasses import dataclass
from typing import Dict, List, Tuple

import yaml


CLASSES = ["Executed", "Stored/Blind", "DOM-sink-only", "Blocked-by-CSP"]


def _route_of(url: str) -> str:
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return (p.path or '/').rstrip('/') or '/'
    except Exception:
        return url


def _normalize_class(f: dict, oast_db: str | None) -> str:
    # Prefer explicit class if present
    clazz = (f.get('class') or '').strip()
    if clazz in CLASSES:
        return clazz
    # Check OAST
    if oast_db:
        try:
            token = None
            pl = f.get('payload') or ''
            m = re.search(r"<oast:([a-fA-F0-9\-]+)>", str(pl))
            if m:
                token = m.group(1)
            if token:
                conn = sqlite3.connect(oast_db)
                cur = conn.cursor()
                cur.execute("SELECT COUNT(1) FROM hits WHERE token=?", (token,))
                c = cur.fetchone()[0]
                conn.close()
                if c and c > 0:
                    return "Stored/Blind"
        except Exception:
            pass
    # Execution flag or hints
    t = (f.get('type') or '').lower()
    if 'executed' in t or f.get('executed') is True:
        return "Executed"
    # CSP blocked flags
    if 'csp' in t or 'blocked' in (f.get('class') or '').lower():
        return "Blocked-by-CSP"
    return "DOM-sink-only"


def _context_from_finding(f: dict) -> str:
    # Best-effort from type/flags
    t = (f.get('type') or '').lower()
    if 'header' in t: return 'header'
    if 'path' in t: return 'path'
    if 'fragment' in t: return 'fragment'
    if 'static_attr' in t: return 'attr'
    if 'static_js' in t or 'js' in t: return 'js_string'
    if 'coverage' in t: return 'html_tag'
    if 'csp' in t: return 'csp'
    return 'unknown'


@dataclass
class Counters:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    def precision(self) -> float:
        d = self.tp + self.fp
        return (self.tp / d) if d else 0.0

    def recall(self) -> float:
        d = self.tp + self.fn
        return (self.tp / d) if d else 0.0

    def f1(self) -> float:
        p, r = self.precision(), self.recall()
        return (2 * p * r / (p + r)) if (p + r) else 0.0


def evaluate(ground_path: str, scan_path: str, oast_db: str | None) -> Tuple[Dict[str, Counters], List[dict]]:
    with open(ground_path, 'r', encoding='utf-8') as f:
        ground = yaml.safe_load(f) or {}
    routes = ground.get('routes', {})

    with open(scan_path, 'r', encoding='utf-8') as f:
        findings = json.load(f) or []

    # Map route -> expected class
    expected = {r: (v or {}).get('expected_class') for r, v in routes.items()}

    # Normalize findings
    norm = []
    for f in findings:
        url = f.get('url') or ''
        route = _route_of(url)
        c = _normalize_class(f, oast_db)
        ctx = _context_from_finding(f)
        norm.append({
            'route': route,
            'context': ctx,
            'class': c,
            'payload': f.get('payload'),
            'url': url,
        })

    # Metrics per class
    metrics: Dict[str, Counters] = {k: Counters() for k in CLASSES}

    # For each route in ground truth, count TPs where any finding of same route matches expected class.
    for route, exp_class in expected.items():
        if not exp_class:
            continue
        has = any(n['route'] == route and n['class'] == exp_class for n in norm)
        if has:
            metrics[exp_class].tp += 1
        else:
            metrics[exp_class].fn += 1

    # FPs: any finding whose class is not expected for that route
    for n in norm:
        exp = expected.get(n['route'])
        if exp and n['class'] != exp:
            metrics[n['class']].fp += 1

    return metrics, norm


def write_report(metrics: Dict[str, Counters], norm: List[dict], md_path: str, csv_path: str | None) -> None:
    lines = []
    lines.append("# XSS Scanner Evaluation\n")
    lines.append("| Class | TP | FP | FN | Precision | Recall | F1 |\n")
    lines.append("|---|---:|---:|---:|---:|---:|---:|\n")
    tot_tp = tot_fp = tot_fn = 0
    for c in CLASSES:
        m = metrics[c]
        tot_tp += m.tp; tot_fp += m.fp; tot_fn += m.fn
        lines.append(f"| {c} | {m.tp} | {m.fp} | {m.fn} | {m.precision():.2f} | {m.recall():.2f} | {m.f1():.2f} |\n")
    # Overall
    overall = Counters(tot_tp, tot_fp, tot_fn)
    lines.append("\n## Overall\n")
    lines.append(f"Precision: {overall.precision():.2f}  ")
    lines.append(f"Recall: {overall.recall():.2f}  ")
    lines.append(f"F1: {overall.f1():.2f}\n")

    lines.append("\n## Findings (normalized)\n")
    lines.append("| Route | Context | Class | Payload | URL |\n")
    lines.append("|---|---|---|---|---|\n")
    for n in norm:
        payload = (str(n.get('payload')) or '').replace('|','\\|')
        lines.append(f"| {n['route']} | {n['context']} | {n['class']} | {payload[:40]} | {n['url']} |\n")

    with open(md_path, 'w', encoding='utf-8') as f:
        f.write("".join(lines))

    if csv_path:
        try:
            import csv
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(["route","context","class","payload","url"])
                for n in norm:
                    w.writerow([n['route'], n['context'], n['class'], n.get('payload'), n['url']])
        except Exception:
            pass


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument('--ground', required=True)
    p.add_argument('--scan', required=True)
    p.add_argument('--oast', default=None)
    p.add_argument('--report', required=True)
    p.add_argument('--csv', default=None)
    args = p.parse_args()
    if not (os.path.isfile(args.ground) and os.path.isfile(args.scan)):
        print("[evaluator] invalid input paths")
        return 2
    metrics, norm = evaluate(args.ground, args.scan, args.oast)
    write_report(metrics, norm, args.report, args.csv)
    return 1 if len(norm) > 0 else 0


if __name__ == '__main__':
    raise SystemExit(main())

