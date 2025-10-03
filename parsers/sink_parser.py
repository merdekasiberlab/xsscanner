# xsscanner/parsers/sink_parser.py

import re

try:
    import esprima
except ImportError:
    esprima = None

class SinkContextParser:
    @staticmethod
    def parse(content: str) -> list[str]:
        """
        Deteksi konteks sink XSS:
          - DOM assignments: innerHTML, outerHTML, textContent, innerText, outerText, srcdoc
          - insertAdjacentHTML / insertAdjacentText
          - document.write / writeln
          - eval() / Function()
          - setTimeout/setInterval dengan argumen string
        """
        contexts = set()

        # 1) AST-based detection
        if esprima:
            try:
                tree = esprima.parseScript(content, tolerant=True)
                def visit(node):
                    t = node.type
                    # Assignment sinks
                    if t == "AssignmentExpression":
                        left = node.left
                        prop = getattr(left.property, "name", None) if hasattr(left, "property") else None
                        if prop in ("innerHTML","outerHTML","textContent","innerText","outerText","srcdoc"):
                            contexts.add(prop)
                    # CallExpression sinks
                    if t == "CallExpression":
                        callee = node.callee
                        name = getattr(callee, "name", None) or (getattr(callee, "property", None) and callee.property.name)
                        if name in ("insertAdjacentHTML","insertAdjacentText",
                                    "document.write","document.writeln",
                                    "eval","Function"):
                            contexts.add(name)
                        if name in ("setTimeout","setInterval"):
                            # string-based invocation
                            if node.arguments and node.arguments[0].type == "Literal":
                                contexts.add(f"{name}-string")
                    # Recurse
                    for child in getattr(node, "childNodes", lambda: [])():
                        visit(child)
                visit(tree)
            except Exception:
                pass

        # 2) Fallback regex-based detection
        sinks = {
            "innerHTML":           r"\.innerHTML\s*=",
            "outerHTML":           r"\.outerHTML\s*=",
            "textContent":         r"\.textContent\s*=",
            "innerText":           r"\.innerText\s*=",
            "outerText":           r"\.outerText\s*=",
            "srcdoc":              r"\.srcdoc\s*=",
            "insertAdjacentHTML":  r"\.insertAdjacentHTML\s*\(",
            "insertAdjacentText":  r"\.insertAdjacentText\s*\(",
            "document.write":      r"document\.write\s*\(",
            "document.writeln":    r"document\.writeln\s*\(",
            "eval":                r"\beval\s*\(",
            "Function":            r"\bFunction\s*\(",
            "setTimeout-string":   r"\bsetTimeout\s*\(\s*['\"]",
            "setInterval-string":  r"\bsetInterval\s*\(\s*['\"]",
        }
        for name, pat in sinks.items():
            if re.search(pat, content, re.IGNORECASE):
                contexts.add(name)

        return sorted(contexts)
