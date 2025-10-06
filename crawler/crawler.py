# xsscanner/crawler/crawler.py

import json
import logging
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup
from network import make_request
from .base import BaseCrawler

logger = logging.getLogger("xsscanner.crawler")


class XSSCrawler(BaseCrawler):
    def crawl_and_discover_parameters(self):
        while not self.to_visit.empty() and len(self.visited) < self.max_urls:
            url, depth = self.to_visit.get()
            if url in self.visited or depth > self.max_depth:
                continue
            self.visited.add(url)

            resp = make_request(url)
            if not resp or not resp.text:
                continue

            # 1) JSON endpoint
            ctype = resp.headers.get("Content-Type", "")
            if "application/json" in ctype:
                self._discover_in_json(resp, url)

            # 2) HTML page
            soup = BeautifulSoup(resp.text, "html.parser")
            base = resp.url

            self._discover_in_links(soup, base)
            self._discover_in_forms(soup, base)

            # 3) JS eksternal
            for tag in soup.find_all("script", src=True):
                js_url = urljoin(base, tag["src"])
                if not self._is_out_of_scope(js_url):
                    self.discovered_js.add(js_url)

            # 4) Enqueue semua link same-domain
            for a in soup.find_all("a", href=True):
                href = urljoin(base, a["href"])
                parsed = urlparse(href)
                if parsed.netloc.endswith(self._base_netloc):
                    norm = parsed._replace(fragment="").geturl()
                    if norm not in self.visited:
                        self.to_visit.put((norm, depth + 1))

    def _discover_in_json(self, resp, url: str):
        try:
            data = json.loads(resp.text)
        except Exception:
            return

        def walk(obj, prefix=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    walk(v, prefix + k + ".")
            elif isinstance(obj, list):
                for idx, v in enumerate(obj):
                    walk(v, prefix + str(idx) + ".")
            elif isinstance(obj, str):
                info = {
                    "url": url,
                    "method": "GET",
                    "data_template": {prefix.rstrip("."): obj},
                    "is_form": False
                }
                self._add_param_if_new(info)

        walk(data)

    def _discover_in_links(self, soup, base_url: str):
        for a in soup.find_all("a", href=True):
            full = urljoin(base_url, a["href"])
            if "?" not in full:
                continue
            parsed = urlparse(full)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for name, vals in qs.items():
                info = {
                    "url": self._get_normalized_url(full),
                    "method": "GET",
                    "data_template": {name: vals[0]},
                    "is_form": False
                }
                self._add_param_if_new(info)

    def _discover_in_forms(self, soup, base_url: str):
        for form in soup.find_all("form"):
            action = form.get("action") or base_url
            full = urljoin(base_url, action)
            method = form.get("method", "GET").upper()
            for inp in form.find_all(["input", "textarea", "select"], attrs={"name": True}):
                name = inp["name"]
                value = inp.get("value") or ""
                info = {
                    "url": self._get_normalized_url(full),
                    "method": method,
                    "data_template": {name: value},
                    "is_form": True
                }
                self._add_param_if_new(info)
