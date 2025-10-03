# xsscanner/parsers/attr_parser.py

import re
from lxml import html

# Atribut HTML kritikal untuk scoring/pelaporan
KNOWN_ATTRS = {
    "src", "href", "style", "data", "action",
    "formaction", "value", "srcdoc", "placeholder", "alt"
}

class AttrContextParser:
    @staticmethod
    def parse(content: str) -> list[str]:
        """
        Deteksi konteks atribut HTML:
          - 'attr_generic'       : ada atribut apa pun
          - 'attr_<name>'        : atribut eksplisit dari KNOWN_ATTRS
          - 'attr_quoted'        : nilai dalam "…" atau '…'
          - 'attr_unquoted'      : nilai tanpa kutip
          - 'data_attribute'     : atribut data-*
          - 'srcdoc_attr'        : atribut srcdoc
          - 'css_inline'         : atribut style
        """
        contexts = set()

        try:
            doc = html.fromstring(content)
            for elt in doc.iter():
                for attr, val in elt.items():
                    low = attr.lower()
                    # 1) Generic presence
                    contexts.add("attr_generic")
                    # 2) Explicit known attrs
                    if low in KNOWN_ATTRS:
                        contexts.add(f"attr_{low}")
                    # 3) Data-* attributes
                    if low.startswith("data-"):
                        contexts.add("data_attribute")
                    # 4) srcdoc attribute
                    if low == "srcdoc":
                        contexts.add("srcdoc_attr")
                    # 5) inline CSS
                    if low == "style":
                        contexts.add("css_inline")
                    # 6) quoted/unquoted (lxml always returns string → assume quoted)
                    contexts.add("attr_quoted")
        except Exception:
            # Fallback regex-based detection
            if re.search(r'\b[\w-]+\s*=\s*["\'][^"\']*["\']', content):
                contexts.add("attr_quoted")
            if re.search(r'\b[\w-]+\s*=\s*[^"\'>\s]+', content):
                contexts.add("attr_unquoted")
            if re.search(r'\bdata-[\w-]+\s*=\s*["\']?[^"\']+["\']?', content):
                contexts.add("data_attribute")
            if re.search(r'\bsrcdoc\s*=\s*["\'].*?["\']', content):
                contexts.add("srcdoc_attr")
            for attr in KNOWN_ATTRS:
                if re.search(rf'\b{attr}\s*=', content, re.IGNORECASE):
                    contexts.add(f"attr_{attr}")
            # Generic fallback: ada atribut apa pun
            if re.search(r'\b[\w-]+\s*=', content):
                contexts.add("attr_generic")

        return sorted(contexts)
