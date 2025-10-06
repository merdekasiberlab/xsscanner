from __future__ import annotations

from typing import Dict, Optional

_LANG = 'id'
_FALLBACK_LANG = 'id'

LANGUAGE_LABELS: Dict[str, str] = {
    'id': 'Bahasa Indonesia',
    'en': 'English',
}

TRANSLATIONS: Dict[str, Dict[str, str]] = {
    'en': {
        # Language setup
        "Pilih bahasa (misal id/en) > ": "Select language (e.g. id/en) > ",
        "[bold green]Bahasa diganti ke[/bold green] {lang}": "[bold green]Language set to[/bold green] {lang}",
        "[yellow]Bahasa tidak dikenal, gunakan default.[/yellow]": "[yellow]Unknown language, using default.[/yellow]",
        # Generic outputs
        "Tidak ada": "None",
        "Ya": "Yes",
        "Tidak": "No",
    },
}

def available_languages() -> Dict[str, str]:
    return LANGUAGE_LABELS.copy()

def get_language() -> str:
    return _LANG

def set_language(lang: str) -> str:
    global _LANG
    lang = (lang or '').strip().lower()
    if not lang:
        return _LANG
    if lang not in LANGUAGE_LABELS:
        lang = _FALLBACK_LANG
    _LANG = lang
    return _LANG

def tr(id_text: str, en_text: Optional[str] = None, **kwargs) -> str:
    if en_text is None:
        return translate(id_text, **kwargs)
    template = en_text if _LANG == 'en' else id_text
    if kwargs:
        try:
            return template.format(**kwargs)
        except Exception:
            return template
    return template

def translate(text: str, **kwargs) -> str:
    if text is None:
        return ''
    current_map = TRANSLATIONS.get(_LANG, {})
    fallback_map = TRANSLATIONS.get(_FALLBACK_LANG, {})
    template = current_map.get(text)
    if template is None:
        if _LANG != _FALLBACK_LANG:
            template = fallback_map.get(text, text)
        else:
            template = text
    if kwargs:
        try:
            return template.format(**kwargs)
        except Exception:
            return template
    return template

__all__ = [
    'available_languages',
    'get_language',
    'set_language',
    'translate',
    'tr',
    'LANGUAGE_LABELS',
]
