# xsscanner/parsers/event_parser.py

import re
from lxml import html

# Daftar event “penting” untuk scoring/pelaporan
KNOWN_EVENTS = {
    "onclick", "ondblclick", "onmousedown", "onmouseup", "onmouseover", "onmouseout",
    "onmouseenter", "onmouseleave", "onmousemove", "oncontextmenu",
    "ondrag", "ondragstart", "ondragend", "ondrop",
    "onkeydown", "onkeypress", "onkeyup",
    "onfocus", "onblur", "onchange", "oninput", "onsubmit",
    "onload", "onerror", "onresize", "onscroll",
    "onpointerdown", "onpointerup", "onpointerenter", "onpointerleave",
    "ontouchstart", "ontouchend", "ontouchmove"
}

class EventContextParser:
    @staticmethod
    def parse(content: str) -> list[str]:
        """
        Hybrid detection:
         - 'event_handler' untuk semua atribut berawalan 'on*'
         - nama event eksplisit jika termasuk KNOWN_EVENTS
        """
        contexts = set()

        try:
            doc = html.fromstring(content)
            for elt in doc.iter():
                for attr in elt.keys():
                    low = attr.lower()
                    if low.startswith("on"):
                        contexts.add("event_handler")
                        if low in KNOWN_EVENTS:
                            contexts.add(low)
        except Exception:
            # Fallback regex-based
            for ev in KNOWN_EVENTS:
                if re.search(rf"\b{ev}\s*=", content, re.IGNORECASE):
                    contexts.add("event_handler")
                    contexts.add(ev)

        return sorted(contexts)
