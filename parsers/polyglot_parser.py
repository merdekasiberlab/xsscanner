# xsscanner/parsers/polyglot_parser.py

import re

class PolyglotContextParser:
    @staticmethod
    def parse(content: str) -> list[str]:
        """
        Deteksi konteks 'polyglot'—literal string/backtick yang
        mengandung HTML tag <…> atau JS comment /*…*/ di dalamnya.
        """
        contexts = set()
        poly_re = re.compile(
            r"""(['"`])          # buka quote/backtick
                 (?:(?!\1).)*    # isi selain penutup
                 (<[^>]+>|/\*.*?\*/)  # HTML tag atau JS comment
                 (?:(?!\1).)*    # sebelum penutup
             \1""",
            re.DOTALL | re.VERBOSE
        )
        if poly_re.search(content):
            contexts.add("polyglot")
        return sorted(contexts)
