# xsscanner/parsers/js_parser.py

import re

try:
    import esprima
except ImportError:
    esprima = None

class JSContextParser:
    @staticmethod
    def parse(content: str) -> list[str]:
        """
        Deteksi konteks JavaScript:
          - 'js_string'         : literal string '…' atau "…"
          - 'template_literal'  : backtick template ES6
          - 'regex_literal'     : literal RegExp /…/
          - 'function_call'     : panggilan eval, Function, setTimeout, dll.
        """
        contexts = set()
        sinks = {
            "eval", "Function", "setTimeout",
            "setInterval", "document.write", "document.writeln"
        }

        # 1) AST-based detection (jika esprima tersedia)
        if esprima:
            try:
                tree = esprima.parseScript(content, tolerant=True)
                def visit(node):
                    t = node.type
                    if t == "Literal" and isinstance(node.value, str):
                        contexts.add("js_string")
                    if t == "Literal" and getattr(node, "regex", None):
                        contexts.add("regex_literal")
                    if t == "TemplateLiteral":
                        contexts.add("template_literal")
                    if t == "CallExpression":
                        callee = node.callee
                        name = getattr(callee, "name", None) or getattr(callee, "property", None) and callee.property.name
                        if name in sinks:
                            contexts.add("function_call")
                    # Rekursi ke semua child nodes
                    for child in getattr(node, "childNodes", lambda: [])():
                        visit(child)
                visit(tree)
            except Exception:
                pass

        # 2) Fallback regex-based detection
        if re.search(r"(['\"])(?:(?!\1).)*\1", content):
            contexts.add("js_string")
        if re.search(r"`[^`]*`", content):
            contexts.add("template_literal")
        if re.search(r"/[^/\\\n]+/[gimsuy]*", content):
            contexts.add("regex_literal")
        for fn in sinks:
            if re.search(rf"\b{fn}\s*\(", content):
                contexts.add("function_call")

        return sorted(contexts)
