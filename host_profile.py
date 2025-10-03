from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlparse

_HP: Dict[str, Dict] = {}

FRAMEWORK_HINTS = (
    (re.compile(r"react|preact", re.I), 3),
    (re.compile(r"angular|ng-", re.I), 3),
    (re.compile(r"vue|v-\w+", re.I), 3),
    (re.compile(r"svelte", re.I), 2),
    (re.compile(r"jquery|\$\(.+\)\.(html|append|prepend|before|after|replaceWith)", re.I), 2),
)
TEMPLATE_HINTS = (
    (re.compile(r"\{\{[^}]+\}\}", re.I), 2),
    (re.compile(r"handlebars|mustache", re.I), 2),
)
SINK_HINTS = (
    (re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|createContextualFragment", re.I), 2),
    (re.compile(r"on(click|error|load|mouseover|focus|blur)=", re.I), 1),
)


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def update_host_profile(url: str, html: str, js_urls: List[str] | None = None) -> None:
    h = _host(url)
    if not h:
        return
    prof = _HP.setdefault(h, {"score": 0, "seen_params": {}, "hits": 0})
    s = 0
    doc = html or ""
    # Framework hints (HTML/script URLs)
    bundle = (doc + "\n" + "\n".join(js_urls or [])).lower()
    for rx, w in FRAMEWORK_HINTS:
        if rx.search(bundle):
            s += w
    # Template hints
    for rx, w in TEMPLATE_HINTS:
        if rx.search(doc):
            s += w
    # Sink hints
    for rx, w in SINK_HINTS:
        if rx.search(doc):
            s += w
    # Tags indicating dynamic content
    if re.search(r"<template|<script[^>]+type=\"text/x-handlebars-template\"", doc, re.I):
        s += 1
    prof["score"] = max(prof.get("score", 0), s)
    prof["hits"] = prof.get("hits", 0) + 1


def note_param(url: str, name: str) -> None:
    h = _host(url)
    if not h:
        return
    prof = _HP.setdefault(h, {"score": 0, "seen_params": {}, "hits": 0})
    prof["seen_params"][name] = prof["seen_params"].get(name, 0) + 1


def get_priority(url: str, name: str | None = None) -> int:
    h = _host(url)
    prof = _HP.get(h) or {}
    base = int(prof.get("score", 0))
    # params that appear often get slight boost
    if name:
        base += min(2, int((prof.get("seen_params", {}).get(name, 0) or 0) / 3))
    return base

