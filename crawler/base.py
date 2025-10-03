# xsscanner/crawler/base.py

import logging
from abc import ABC, abstractmethod
from queue import Queue
from threading import Lock
from urllib.parse import urlparse, urljoin
from typing import Set, Dict, List, Tuple

logger = logging.getLogger("xsscanner.crawler.base")

JUNK_PARAM_NAMES = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "_ga", "_gid", "msclkid",
    "sessionid", "jsessionid", "csrf_token", "nonce", "__requestverificationtoken",
}


class BaseCrawler(ABC):
    def __init__(
        self,
        start_url: str,
        max_depth: int,
        max_urls: int,
        verbose: bool
    ):
        self.start_url = start_url
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.verbose = verbose

        self.to_visit = Queue()
        self.to_visit.put((start_url, 0))

        self.visited: Set[str] = set()
        self.processed_surfaces: Set[Tuple[str, frozenset]] = set()
        self.discovered_parameters: List[Dict] = []
        self.discovered_js: Set[str] = set()

        self._base_netloc = urlparse(start_url).netloc
        self.lock = Lock()

    def _get_normalized_url(self, url: str) -> str:
        """Normalize URL ke bentuk scheme://netloc/path tanpa query/fragment."""
        parsed = urlparse(url)
        return urljoin(f"{parsed.scheme}://{parsed.netloc}", parsed.path)

    def _is_out_of_scope(self, url: str) -> bool:
        try:
            return not urlparse(url).netloc.endswith(self._base_netloc)
        except Exception:
            return True

    def _is_junk_param(self, name: str) -> bool:
        return name.lower() in JUNK_PARAM_NAMES

    def _get_surface_key(self, url: str, params: Dict) -> Tuple[str, frozenset]:
        norm = self._get_normalized_url(url)
        return norm, frozenset(params.keys())

    def _add_param_if_new(self, info: Dict):
        """Filter junk params, dedupe surface, lalu simpan ke discovered_parameters."""
        params = {
            k: v for k, v in info.get("data_template", {}).items()
            if k and not self._is_junk_param(k)
        }
        if not params:
            return

        key = self._get_surface_key(info["url"], params)
        with self.lock:
            if key in self.processed_surfaces:
                return
            self.processed_surfaces.add(key)

        entry = info.copy()
        entry["data_template"] = params
        entry["name"] = next(iter(params))
        entry["url"] = key[0]
        self.discovered_parameters.append(entry)

        if self.verbose:
            logger.info(f"[param][{info['method']}] {key[0]} → params {list(params.keys())}")

    @abstractmethod
    def crawl_and_discover_parameters(self):
        """Implementasi khusus di subclass: static vs dynamic crawler."""
        ...
