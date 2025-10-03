# xsscanner/parsers/context_parser.py

from functools import lru_cache
from .json_parser      import JSONContextParser
from .html_parser      import HTMLContextParser
from .template_parser  import TemplateContextParser
from .attr_parser      import AttrContextParser
from .event_parser     import EventContextParser
from .css_parser       import CSSContextParser
from .uri_parser       import URIContextParser
from .js_parser        import JSContextParser
from .sink_parser      import SinkContextParser
from .polyglot_parser  import PolyglotContextParser

class ContextParser:
    @staticmethod
    @lru_cache(maxsize=256)
    def parse(content: str, content_type: str | None = None) -> list[str]:
        """
        1) Jika content_type jelas (JSON/HTML/JS) → early‐exit setelah parser relevan
        2) Jika prefix '{','[','<' → pilih parser sesuai prefix + fallback
        3) Fallback → jalankan semua parser sesuai urutan:
           JSON → HTML → Template → Attr → Event → CSS → URI → JS → Polyglot → Sink
        """
        contexts: list[str] = []
        seen: set[str] = set()

        def add(ctxs: list[str]):
            for c in ctxs:
                if c not in seen:
                    seen.add(c)
                    contexts.append(c)

        # 1. Berdasar header
        if content_type:
            ct = content_type.split(";",1)[0].strip().lower()
            if ct.endswith("+json") or ct == "application/json":
                add(JSONContextParser.parse(content))
                return contexts
            if ct in ("text/html","application/xhtml+xml"):
                add(HTMLContextParser.parse(content))
                add(TemplateContextParser.parse(content))
                add(AttrContextParser.parse(content))
                add(EventContextParser.parse(content))
                add(CSSContextParser.parse(content))
                add(URIContextParser.parse(content))
                add(JSContextParser.parse(content))
                add(PolyglotContextParser.parse(content))
                add(SinkContextParser.parse(content))
                return contexts
            if ct in ("application/javascript","text/javascript"):
                add(JSContextParser.parse(content))
                add(PolyglotContextParser.parse(content))
                add(SinkContextParser.parse(content))
                return contexts

        # 2. Berdasar prefix
        t = content.lstrip()
        if t.startswith(("{","[")):
            add(JSONContextParser.parse(content))
            return contexts
        if t.startswith("<"):
            add(HTMLContextParser.parse(content))
            add(TemplateContextParser.parse(content))
            add(AttrContextParser.parse(content))
            add(EventContextParser.parse(content))
            add(CSSContextParser.parse(content))
            add(URIContextParser.parse(content))
            add(JSContextParser.parse(content))
            add(PolyglotContextParser.parse(content))
            add(SinkContextParser.parse(content))
            return contexts

        # 3. Fallback lengkap
        add(JSONContextParser.parse(content))
        add(HTMLContextParser.parse(content))
        add(TemplateContextParser.parse(content))
        add(AttrContextParser.parse(content))
        add(EventContextParser.parse(content))
        add(CSSContextParser.parse(content))
        add(URIContextParser.parse(content))
        add(JSContextParser.parse(content))
        add(PolyglotContextParser.parse(content))
        add(SinkContextParser.parse(content))

        return contexts
