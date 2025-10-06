# login_flow.py
from pathlib import Path
from typing import List, Callable, Optional
from contextlib import suppress
from playwright.sync_api import sync_playwright, BrowserContext

try:
    # stealth optional; tidak error jika tak di-install
    from playwright_stealth import stealth_sync
except ImportError:  # pragma: no cover
    stealth_sync = None


def _default_logged_in(ctx) -> bool:
    """Login dianggap sukses jika salah satu tab bukan accounts.google.com."""
    return any("accounts.google." not in p.url.lower() for p in ctx.pages)


def manual_login_capture(
    login_url: str,
    cookie_path: Path,
    *,
    headless: bool = False,
    channel: str = "chrome",
    user_data_dir: Optional[str] = None,
    reuse_existing: bool = True,
    on_logged_in: Callable[[BrowserContext], bool] | None = None,
) -> List[dict]:
    """
    Buka browser headful, tunggu user login, lalu dump storage_state & cookies.

    Args:
        login_url      : halaman login awal
        cookie_path    : path file JSON untuk menyimpan storage_state
        headless       : set True untuk headless; Google biasanya butuh False
        channel        : 'chrome' | 'chromium' | 'msedge' …
        user_data_dir  : folder profil Chrome (persistent context). Jika None,
                         memakai context ephemeral.
        reuse_existing : kalau cookie_path sudah ada → cukup load & return
        on_logged_in   : callback(ctx) -> bool  untuk deteksi otomatis sesi siap.
                         Default = heuristik Google (`_default_logged_in`).

    Returns:
        list[dict]  : daftar cookie Playwright
    """
    if reuse_existing and cookie_path.exists():
        # baca & return cookie tanpa membuka browser lagi
        import json
        state = json.loads(cookie_path.read_text(encoding="utf-8"))
        return state.get("cookies", [])

    on_logged_in = on_logged_in or _default_logged_in

    launch_kwargs = dict(
        headless=headless,
        channel=channel,
        args=["--disable-blink-features=AutomationControlled"],
    )

    with sync_playwright() as p:
        print("🖥️  Meluncurkan browser…")
        if user_data_dir:
            # persistent context
            ctx = p.chromium.launch_persistent_context(user_data_dir, **launch_kwargs)
        else:
            browser = p.chromium.launch(**launch_kwargs)
            ctx = browser.new_context()

        page = ctx.new_page()
        if stealth_sync:
            stealth_sync(page)

        print(f"🔑  Membuka {login_url} – silakan login/CAPTCHA secara manual.")
        page.goto(login_url, wait_until="domcontentloaded")

        # polling auto-detect sukses login
        for _ in range(600):     # ~5 menit
            if on_logged_in(ctx):
                break
            with suppress(Exception):
                page.wait_for_timeout(500)
        else:
            input("❓  Tekan ENTER jika login sudah selesai…")

        # dump storage_state
        ctx.storage_state(path=str(cookie_path))
        print(f"✅  Cookie + localStorage tersimpan di {cookie_path}")

        cookies = ctx.cookies()
        ctx.close()
        return cookies
