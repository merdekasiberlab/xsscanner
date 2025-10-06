# xsscanner/parsers/uri_parser.py

import re
from html import unescape

class URIContextParser:
    @staticmethod
    def parse(content: str) -> list[str]:
        """
        Deteksi konteks berbasis URI:
          - 'uri_javascript', 'uri_data', 'uri_vbscript', 'uri_livescript',
            'uri_blob', 'uri_mhtml', 'uri_filesystem'
          - tangkap juga obfuscated/protocol-relative schemes
        """
        contexts = set()
        txt = unescape(content)

        schemes = {
            'uri_javascript':    r'javascript\s*:',
            'uri_data':          r'data\s*:[^"\'>\s]+',
            'uri_vbscript':      r'vbscript\s*:',
            'uri_livescript':    r'livescript\s*:',
            'uri_blob':          r'blob\s*:[^"\'>\s]+',
            'uri_mhtml':         r'mhtml\s*:[^"\'>\s]+',
            'uri_filesystem':    r'filesystem\s*:[^"\'>\s]+',
        }
        for name, pat in schemes.items():
            if re.search(pat, txt, re.IGNORECASE):
                contexts.add(name)

        # protocol-relative obfuscated javascript://
        if re.search(r'//\s*javascript\s*:', txt, re.IGNORECASE):
            contexts.add('uri_javascript')

        return sorted(contexts)
