# xsscanner/parsers/html_parser.py

import re
from lxml import html, etree

# Tag HTML kritikal yang sering jadi titik XSS
KNOWN_TAGS = {
    "script", "img", "iframe", "svg", "body", "meta",
    "link", "object", "embed", "xmp", "plaintext"
}

class HTMLContextParser:
    @staticmethod
    def parse(content: str) -> list[str]:
        """
        Deteksi konteks HTML:
          - 'html_tag'            : ada tag HTML apa pun
          - 'tag_<name>'          : tag eksplisit dari KNOWN_TAGS
          - 'script_tag'          : ada <script>…</script>
          - 'tag_comment'         : ada komentar <!--…-->
        """
        contexts = set()
        try:
            doc = html.fromstring(content)
            # 1) Generic HTML tag presence
            if doc.xpath("//*"):
                contexts.add("html_tag")
            # 2) Explicit known tags
            for tag in KNOWN_TAGS:
                if doc.xpath(f"//{tag}"):
                    contexts.add(f"tag_{tag}")
            # 3) Script tag
            if doc.xpath("//script"):
                contexts.add("script_tag")
            # 4) HTML comments
            for _ in doc.xpath("//comment()"):
                contexts.add("tag_comment")
                break
            # 5) Embedded HTML via data URI
            for elt in doc.xpath("//*[@src]"):
                src = elt.get("src", "")
                if src.lower().startswith("data:text/html"):
                    contexts.add("html_tag")
                    break
        except etree.ParserError:
            # Fallback regex-based detection
            if re.search(r"<\w+", content):
                contexts.add("html_tag")
            for tag in KNOWN_TAGS:
                if re.search(fr"<{tag}\b", content, re.IGNORECASE):
                    contexts.add(f"tag_{tag}")
            if re.search(r"<script\b[^>]*>.*?</script>", content, re.IGNORECASE | re.DOTALL):
                contexts.add("script_tag")
            if re.search(r"(?<!&lt;)(<\w+)", content):
                contexts.add("html_tag")
        return sorted(contexts)
