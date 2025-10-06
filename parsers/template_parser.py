# xsscanner/parsers/template_parser.py

import re
from lxml import html, etree

class TemplateContextParser:
    @staticmethod
    def parse(content: str) -> list[str]:
        """
        Deteksi konteks template engines:
          - 'handlebars_triple_mustache' : {{{…}}}
          - 'handlebars_double_mustache' : {{…}}
          - 'angular_expression'         : {{…}}
          - 'angular_directive'          : atribut ng-*
          - 'vue_v_html', 'vue_v_text'   : v-html, v-text
          - 'vue_v_bind'                 : v-bind:… atau :…
          - 'vue_shorthand_event'        : @…
        """
        contexts = set()
        text = content

        # 1) Handlebars triple: {{{…}}}
        if re.search(r"\{\{\{.+?\}\}\}", text, re.DOTALL):
            contexts.add("handlebars_triple_mustache")

        # 2) Handlebars double & Angular expression: {{…}}
        if re.search(r"\{\{[^{}]+\}\}", text):
            contexts.add("handlebars_double_mustache")
            contexts.add("angular_expression")

        # 3) DOM-based detection of attributes
        try:
            doc = html.fromstring(content)
            for elt in doc.iter():
                for attr in elt.keys():
                    low = attr.lower()
                    # Angular directive
                    if low.startswith("ng-"):
                        contexts.add("angular_directive")
                    # Vue directives
                    if low == "v-html":
                        contexts.add("vue_v_html")
                    if low == "v-text":
                        contexts.add("vue_v_text")
                    if low.startswith("v-bind:"):
                        contexts.add("vue_v_bind")
                    if low.startswith(":"):
                        contexts.add("vue_v_bind")
                    if low.startswith("@"):
                        contexts.add("vue_shorthand_event")
        except etree.ParserError:
            # fallback regex-only
            if re.search(r"\bng-[\w-]+=", text):
                contexts.add("angular_directive")
            if re.search(r"\bv-html\b", text):
                contexts.add("vue_v_html")
            if re.search(r"\bv-text\b", text):
                contexts.add("vue_v_text")
            if re.search(r"\bv-bind:[\w-]+=", text) or re.search(r":[\w-]+=", text):
                contexts.add("vue_v_bind")
            if re.search(r"@[\w-]+=", text):
                contexts.add("vue_shorthand_event")

        return sorted(contexts)
