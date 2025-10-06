# xsscanner/crawler/advanced_crawler.py — ULTRA-MAX

from __future__ import annotations

import re
import logging
import asyncio
from pathlib import Path
from threading import Lock, Thread
from queue import Queue
from urllib.parse import urlparse, urljoin, parse_qs

from playwright.sync_api import sync_playwright, Page, Request, Response, Error

from config import MAX_DEPTH_CRAWL, MAX_URLS_TO_CRAWL
from network import session
from crawler.base import BaseCrawler
from host_profile import update_host_profile, note_param
from config import ORIGIN_MIN_DELAY, CRAWLER_CONCURRENCY
from csrf import extract_csrf_from_dom, extract_csrf_from_cookie_string, update_store
from network import session as _req_session

logger = logging.getLogger("xsscanner.advanced_crawler")

# File-type yang kita skip saat enqueue link (tetap boleh diload oleh page bila perlu)
IGNORED_EXTENSIONS = {
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".pdf",
    ".zip", ".rar", ".7z", ".gz"
}

# Resource type yang boleh di-abort aman tanpa ganggu analisis form/JS
ABORTABLE_RES_TYPES = {"image", "media", "font", "stylesheet"}


class AdvancedXSSCrawler(BaseCrawler):
    """
    Dynamic crawler berbasis Playwright dengan:
      • Perekaman parameter dari GET/POST/fetch/XHR (request listener)
      • Penemuan form di DOM (termasuk method/action + field bernama)
      • Dedup permukaan serangan via pola agregat (id/uuid/slug)
      • Deteksi file JS dari <script src> dan response Content-Type
      • Simulasi interaksi ringan (klik/hover/tab) agar event-based XSS terpicu
      • Opsi login otomatis (login_cfg) atau persistent session (storage_state_file)
    """

    def __init__(
        self,
        start_url: str,
        max_depth: int = MAX_DEPTH_CRAWL,
        max_urls: int = MAX_URLS_TO_CRAWL,
        verbose: bool = True,
        login_cfg: dict | None = None,
        storage_state_file: str | None = None
    ):
        super().__init__(start_url, max_depth, max_urls, verbose)
        self.login_cfg = login_cfg or {}
        self.storage_state_file = storage_state_file
        self.lock = Lock()

        # Fallback queue jika BaseCrawler belum men-setup (jaga kompatibilitas)
        if not hasattr(self, "to_visit") or self.to_visit is None:
            self.to_visit: Queue[tuple[str, int]] = Queue()
        if not hasattr(self, "visited") or self.visited is None:
            self.visited: set[str] = set()
        if not hasattr(self, "processed_surfaces") or self.processed_surfaces is None:
            self.processed_surfaces: set[tuple[str, frozenset]] = set()
        if not hasattr(self, "discovered_parameters") or self.discovered_parameters is None:
            self.discovered_parameters: list[dict] = []
        if not hasattr(self, "discovered_js") or self.discovered_js is None:
            self.discovered_js: set[str] = set()

    # --------------------------- Normalization/Dedupe ---------------------------

    def _aggregate_url_pattern(self, url: str) -> str:
        """Ganti angka/UUID/slug jadi placeholder untuk deduplikasi yang lebih baik."""
        try:
            parsed = urlparse(url)
            path = parsed.path or "/"
            # angka panjang → {id}
            path = re.sub(r"/\d{5,}", "/{id}", path)
            # UUID → {uuid}
            path = re.sub(
                r"/[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}",
                "/{uuid}",
                path,
            )
            # slug panjang → {slug}
            path = re.sub(r"/[a-z0-9-]{25,}", "/{slug}", path)
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        except Exception:
            return self._get_normalized_url(url)

    def _get_attack_surface_key(self, url: str, params: dict) -> tuple[str, frozenset]:
        norm_url = self._aggregate_url_pattern(url)
        return norm_url, frozenset(params.keys())

    # ------------------------------ Login Helpers ------------------------------

    def _auto_login(self, page: Page) -> None:
        """
        Login sederhana: isi username/password lalu submit.
        login_cfg:
          url, username, password, user_field, pass_field, submit_sel
        """
        if not self.login_cfg:
            return
        try:
            login_url = self.login_cfg.get("url")
            if login_url:
                page.goto(login_url, wait_until="domcontentloaded", timeout=25000)

            user_sel = self.login_cfg.get("user_field") or "input[name=username], input#username, input[type=email]"
            pass_sel = self.login_cfg.get("pass_field") or "input[name=password], input#password, input[type=password]"
            submit_sel = self.login_cfg.get("submit_sel") or "button[type=submit], input[type=submit], button"

            # Isi kredensial
            page.fill(user_sel, self.login_cfg.get("username", ""), timeout=8000)
            page.fill(pass_sel, self.login_cfg.get("password", ""), timeout=8000)

            # Submit
            try:
                page.click(submit_sel, timeout=8000, no_wait_after=True)
            except Error:
                # fallback: tekan Enter di field password
                page.press(pass_sel, "Enter", timeout=4000)

            # Tunggu redirect/login selesai
            page.wait_for_load_state("domcontentloaded", timeout=25000)
            page.wait_for_timeout(1200)
            logger.info("[login] Auto login attempt finished.")
        except Error as e:
            logger.warning(f"[login] Auto login failed: {e}")

    # --------------------------- Request/Response taps --------------------------

    def _handle_request(self, request: Request):
        """
        Tangkap parameter dari setiap request yang in-scope.
        """
        url = request.url
        if self._is_out_of_scope(url):
            return

        # Skip asset heavy
        try:
            ext = Path(urlparse(url).path).suffix.lower()
            if ext in IGNORED_EXTENSIONS:
                return
        except Exception:
            pass

        method = request.method.upper()
        params = {}

        # GET query params
        if method == "GET":
            try:
                params = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
            except Exception:
                params = {}

        # POST body
        elif method == "POST":
            try:
                ct = (request.headers or {}).get("content-type", "").lower()
                if "application/json" in ct:
                    raw = request.post_data_json
                    if isinstance(raw, dict):
                        params = {k: ("" if v is None else v) for k, v in raw.items()}
                    else:
                        params = {}
                else:
                    body = request.post_data or ""
                    params = {k: v[0] for k, v in parse_qs(body).items()}
            except Exception:
                params = {}

        if not isinstance(params, dict) or not params:
            return

        # bentuk entri parameter (gunakan URL agregat utk dedupe permukaan)
        info = {
            "url": url,
            "method": method,
            "data_template": params,
            "is_form": "application/x-www-form-urlencoded" in (request.headers or {}).get("content-type", "").lower()
        }

        surface_key = self._get_attack_surface_key(url, params)
        with self.lock:
            if surface_key not in self.processed_surfaces:
                self.processed_surfaces.add(surface_key)
                entry = info.copy()
                entry["url"] = surface_key[0]
                entry["name"] = next(iter(params))  # pilih satu param representatif (akan diuji satu-satu di fase berikut)
                self.discovered_parameters.append(entry)
                try:
                    note_param(url, entry["name"])
                except Exception:
                    pass
                if self.verbose:
                    logger.info(f"[param][{method}] New surface: {surface_key[0]}  params={list(params.keys())}")

    def _handle_response(self, response: Response):
        """
        Deteksi file JS dari response header atau ekstensi, tambah ke discovered_js.
        """
        try:
            url = response.url
            if self._is_out_of_scope(url):
                return

            ct = (response.headers or {}).get("content-type", "").lower()
            path = urlparse(url).path.lower()
            is_js = (
                ".js" in path or
                "javascript" in ct or
                "ecmascript" in ct
            )
            if is_js:
                with self.lock:
                    self.discovered_js.add(url)
        except Exception:
            pass

    # ------------------------- DOM discovery & interaction ----------------------

    def _discover_in_forms(self, page: Page, base_url: str):
        """Temukan form di DOM & tambahkan param via BaseCrawler._add_param_if_new."""
        try:
            for form in page.query_selector_all("form"):
                action = form.get_attribute("action") or ""
                method = (form.get_attribute("method") or "GET").upper()
                full = urljoin(base_url, action)
                if self._is_out_of_scope(full):
                    continue

                params = {
                    inp.get_attribute("name"): (inp.get_attribute("value") or "test")
                    for inp in form.query_selector_all("[name]")
                    if inp.get_attribute("name")
                }
                if params:
                    self._add_param_if_new({
                        "url": full,
                        "method": method,
                        "data_template": params,
                        "is_form": True
                    })
        except Error as e:
            logger.warning(f"Failed processing forms at {base_url}: {e}")

    def _simulate_interaction(self, page: Page):
        """Klik/hover/tab/ketik ringan untuk memicu event-based XSS dan SPA routes."""
        try:
            selectors = ["button", "a[href]", "[role='button']", "[onclick]", "input[type=submit]"]
            for sel in selectors:
                elems = page.query_selector_all(sel)
                for el in elems[:25]:
                    if el.is_visible() and el.is_enabled():
                        try:
                            el.click(timeout=800, no_wait_after=True)
                            page.wait_for_timeout(120)
                        except Error:
                            continue
            # Fokus semua kontrol yang bisa diketik lalu ketik "xss"
            focusable = page.query_selector_all("input, textarea, [contenteditable], select")
            for el in focusable[:40]:
                try:
                    tag = (el.evaluate("el => el.tagName") or "").lower()
                    if tag in ("input", "textarea") and el.is_visible() and el.is_enabled():
                        el.focus()
                        try:
                            el.fill("xss", timeout=500)
                        except Error:
                            page.keyboard.type("xss")
                        page.wait_for_timeout(60)
                except Error:
                    continue
            # Hover body + beberapa link
            page.hover("body")
            for el in page.query_selector_all("a[href]")[:15]:
                try:
                    el.hover()
                except Error:
                    pass
            # Scroll agar lazy-loaded handler terpanggil
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            page.wait_for_timeout(150)
            page.evaluate("window.scrollTo(0, 0)")
        except Error as e:
            logger.debug(f"Interaction simulation stopped at {page.url}: {e}")

    def _stimulate_dom_sources(self, page: Page, marker: str = "DOMPROBE"):
        """Stimulasi sumber DOM-based XSS: hash/localStorage/postMessage/history.*"""
        js = f"""
            (()=>{{
              try{{ location.hash = {marker!r}; }}catch(e){{}}
              try{{ window.name = {marker!r}; }}catch(e){{}}
              try{{
                const common=['q','query','search','s','id','ref','token','next','redirect','return','state'];
                common.forEach(k=>{{ try{{ localStorage.setItem(k, {marker!r}) }}catch(e){{}} }});
              }}catch(e){{}}
              try{{ window.postMessage({marker!r}, '*') }}catch(e){{}}
              try{{ history.pushState(null,'', location.pathname+'?q='+encodeURIComponent({marker!r})+location.hash) }}catch(e){{}}
              try{{ history.replaceState(null,'', location.pathname+'#'+encodeURIComponent({marker!r})) }}catch(e){{}}
              // Wrap fetch/XHR to append benign probe param for same-origin GET
              try{{
                const a = document.createElement('a');
                const sameOrigin = (u)=>{{ try{{ a.href=u; return a.origin===location.origin }}catch(e){{ return false }} }};
                const _f = window.fetch;
                window.fetch = function(input, init){{
                  try{{
                    let url = typeof input==='string'? input : (input && input.url) || '';
                    if (url && sameOrigin(url)){{
                      const u = new URL(url, location.href);
                      if (!u.searchParams.has('xssprobe')) u.searchParams.append('xssprobe', {marker!r});
                      input = u.href;
                    }}
                  }}catch(e){{}}
                  return _f.call(this, input, init);
                }};
              }}catch(e){{}}
              try{{
                const XO = window.XMLHttpRequest;
                window.XMLHttpRequest = function(){{ const x=new XO(); const o=x.open; x.open=function(m,u, ...r){{
                  try{{ if(typeof u==='string'){{ const U=new URL(u, location.href); if(U.origin===location.origin && m&&m.toUpperCase()==='GET' && !U.searchParams.has('xssprobe')) U.searchParams.append('xssprobe', {marker!r}); u=U.href; }} }}catch(e){{}}
                  return o.call(this,m,u,...r) }}; return x; }};
              }}catch(e){{}}
            }})();
        """
        try:
            page.evaluate(js)
            page.wait_for_timeout(200)
        except Error:
            pass

    def _install_spa_hook(self, context):
        """Hook router SPA (history.push/replace & hashchange) untuk enqueue path baru."""
        try:
            # Expose enqueue binding once per context
            context.expose_binding("__xss_enqueue", lambda source, u: self._enqueue_spa_url(u))
        except Exception:
            pass
        try:
            context.add_init_script(
                """
                (()=>{
                  const send=(u)=>{ try{ window.__xss_enqueue(u instanceof URL ? u.href : String(u)) }catch(e){} };
                  try{
                    const p=history.pushState; history.pushState=function(s,t,u){ try{ if(u){ const U=new URL(u, location.href); send(U) } }catch(e){}; return p.apply(this, arguments) };
                  }catch(e){}
                  try{
                    const r=history.replaceState; history.replaceState=function(s,t,u){ try{ if(u){ const U=new URL(u, location.href); send(U) } }catch(e){}; return r.apply(this, arguments) };
                  }catch(e){}
                  try{ window.addEventListener('hashchange', ()=>send(location.href)) }catch(e){}
                })();
                """
            )
        except Error:
            pass

    def _enqueue_spa_url(self, url: str):
        try:
            if not url or self._is_out_of_scope(url):
                return
            ext = Path(urlparse(url).path).suffix.lower()
            if ext in IGNORED_EXTENSIONS:
                return
            norm = self._get_normalized_url(url)
            with self.lock:
                if norm not in self.visited and len(self.visited) + self.to_visit.qsize() < self.max_urls:
                    self.to_visit.put((url, 0))
                    if self.verbose:
                        logger.info(f"[spa] enqueue: {url}")
        except Exception:
            pass

    def _enqueue_links(self, page: Page, base_url: str, depth: int):
        if depth >= self.max_depth:
            return
        try:
            for a in page.query_selector_all("a[href]"):
                href = a.get_attribute("href") or ""
                href = href.strip()
                if not href or href.lower().startswith(("javascript:", "mailto:", "#")):
                    continue
                full = urljoin(base_url, href)
                if self._is_out_of_scope(full):
                    continue
                ext = Path(urlparse(full).path).suffix.lower()
                if ext in IGNORED_EXTENSIONS:
                    continue
                norm = self._get_normalized_url(full)
                with self.lock:
                    if norm not in self.visited and len(self.visited) + self.to_visit.qsize() < self.max_urls:
                        self.to_visit.put((full, depth + 1))
        except Error:
            pass

    # ------------------------------- Page driver --------------------------------

    def _process_page(self, page: Page, url: str, depth: int):
        norm = self._get_normalized_url(url)
        with self.lock:
            if norm in self.visited:
                return
            self.visited.add(norm)

        if self.verbose:
            logger.info(f"Crawling [Depth:{depth}] {url}")

        # hook jaringan
        page.on("request", self._handle_request)
        page.on("response", self._handle_response)

        try:
            # Origin rate-limit
            try:
                from time import time as _now, sleep as _sleep
                origin = urlparse(url).netloc
                if not hasattr(self, "_last_origin_ts"):
                    self._last_origin_ts = {}
                last = self._last_origin_ts.get(origin, 0.0)
                delta = _now() - last
                if delta < ORIGIN_MIN_DELAY:
                    _sleep(ORIGIN_MIN_DELAY - delta)
            except Exception:
                pass
            page.goto(url, wait_until="domcontentloaded", timeout=25000)
            page.wait_for_timeout(800)
            try:
                self._last_origin_ts[origin] = _now()
            except Exception:
                pass
        except Error as e:
            logger.warning(f"Failed to navigate {url}: {e}")
            page.remove_listener("request", self._handle_request)
            page.remove_listener("response", self._handle_response)
            return

        # CSRF discovery (DOM/meta/cookie) + host profiling
        try:
            html = page.content()
            toks = extract_csrf_from_dom(html)
            # from cookie string
            try:
                ck = page.evaluate("() => document.cookie") or ""
                toks.update(extract_csrf_from_cookie_string(ck))
            except Error:
                pass
            if toks:
                update_store(url, toks)
            # Host profile update (framework/sink hints)
            try:
                js_urls = []
                for t in page.query_selector_all("script[src]"):
                    src = t.get_attribute("src")
                    if src:
                        js_urls.append(urljoin(url, src))
                update_host_profile(url, html, js_urls)
            except Exception:
                pass
        except Error:
            pass

        # forms + <script src>
        self._discover_in_forms(page, url)
        for tag in page.query_selector_all("script[src]"):
            src = tag.get_attribute("src")
            if not src:
                continue
            full = urljoin(url, src)
            if not self._is_out_of_scope(full):
                with self.lock:
                    self.discovered_js.add(full)

        # interaksi & enqueue
        self._simulate_interaction(page)
        self._enqueue_links(page, url, depth)

        # Sync cookies back to requests session for reuse across threads/phases
        try:
            for c in page.context.cookies():
                try:
                    _req_session.cookies.set(c.get("name"), c.get("value"), domain=c.get("domain"), path=c.get("path") or "/")
                except Exception:
                    continue
        except Exception:
            pass

        page.remove_listener("request", self._handle_request)
        page.remove_listener("response", self._handle_response)

    # ----------------------------- Crawl main loop ------------------------------

    def crawl_and_discover_parameters(self):
        """Main crawl loop with asyncio-awareness."""
        if self._in_running_event_loop():
            self._crawl_via_thread()
        else:
            self._crawl_with_playwright()

    def _in_running_event_loop(self) -> bool:
        try:
            loop = asyncio.get_running_loop()
            return loop.is_running()
        except RuntimeError:
            return False

    def _crawl_via_thread(self) -> None:
        errors: list[BaseException] = []

        def runner() -> None:
            try:
                self._crawl_with_playwright()
            except BaseException as exc:
                errors.append(exc)

        thread = Thread(target=runner, name="xsscanner-playwright", daemon=True)
        thread.start()
        thread.join()
        if errors:
            raise errors[0]

    def _crawl_with_playwright(self) -> None:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)

            ctx_kwargs = {}
            if self.storage_state_file and Path(self.storage_state_file).exists():
                ctx_kwargs["storage_state"] = self.storage_state_file

            context = browser.new_context(java_script_enabled=True, **ctx_kwargs)
            self._install_spa_hook(context)

            def _router(route, request: Request):
                try:
                    if request.resource_type in ABORTABLE_RES_TYPES:
                        return route.abort()
                except Exception:
                    pass
                return route.continue_()

            try:
                context.route("**/*", _router)
            except Error:
                pass

            try:
                for c in session.cookies:
                    try:
                        context.add_cookies([{
                            "name": c.name,
                            "value": c.value,
                            "domain": c.domain if c.domain else urlparse(self.start_url).hostname,
                            "path": c.path or "/",
                            "secure": c.secure or False,
                            "httpOnly": False,
                        }])
                    except Exception:
                        continue
            except Exception:
                pass

            pages = [context.new_page() for _ in range(max(1, int(CRAWLER_CONCURRENCY)))]

            if self.login_cfg:
                self._auto_login(pages[0])

            self.to_visit.put((self.start_url, 0))

            while not self.to_visit.empty():
                if len(self.visited) >= self.max_urls:
                    if self.verbose:
                        logger.info(f"[limit] Reached max URLs: {self.max_urls}")
                    break

                url, depth = self.to_visit.get()
                try:
                    pg = pages[(len(self.visited) + self.to_visit.qsize()) % len(pages)]
                    self._process_page(pg, url, depth)
                    try:
                        self._stimulate_dom_sources(pg, marker="DOMPROBE")
                    except Exception:
                        pass
                except Exception as e:
                    logger.debug(f"process_page error for {url}: {e}")

            for pg in pages:
                try:
                    pg.close()
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

