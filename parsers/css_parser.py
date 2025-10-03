# xsscanner/parsers/css_parser.py

import tinycss2

class CSSContextParser:
    @staticmethod
    def parse(content: str) -> list[str]:
        """
        Deteksi konteks CSS:
          - 'css_import'      : aturan @import
          - 'css_url'         : fungsi url(...) dengan payload
          - 'css_expression'  : fungsi expression(...)
        """
        contexts = set()
        try:
            rules = tinycss2.parse_stylesheet(content, skip_comments=True, skip_whitespace=True)
            for rule in rules:
                if rule.type == 'at-rule' and rule.lower_at_keyword == 'import':
                    contexts.add('css_import')
                if rule.type == 'qualified-rule':
                    decls = tinycss2.parse_declaration_list(rule.content)
                    for d in decls:
                        name = getattr(d, "name", "").lower()
                        val = getattr(d, "value", [])
                        if name in ('background','background-image','list-style-image','src'):
                            contexts.add('css_url')
                        # detect expression(...) anywhere in declaration
                        text = "".join(tok.serialize() for tok in val)
                        if 'expression(' in text:
                            contexts.add('css_expression')
        except Exception:
            # Fallback minimal: regex search
            if '@import' in content:
                contexts.add('css_import')
            if 'url(' in content:
                contexts.add('css_url')
            if 'expression(' in content:
                contexts.add('css_expression')
        return sorted(contexts)
