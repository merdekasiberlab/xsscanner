from pathlib import Path
text = Path('cli.py').read_text(encoding='utf-8')
old = "def _extract_js_snippet(code: str, start: int, end: int, radius: int = 90) -> str:\n    lower = max(0, start - radius)\n    upper = min(len(code), end + radius)\n    snippet = code[lower:upper]\n    snippet = snippet.replace('"\nreplacement???)
