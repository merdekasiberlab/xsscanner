# xsscanner/parsers/json_parser.py

import re
import json

class JSONContextParser:
    @staticmethod
    def parse(content: str) -> list[str]:
        """
        Deteksi konteks JSON/JSONP:
          - 'jsonp_callback'       : callbackName({...});
          - 'json_object'          : objek JSON
          - 'json_array'           : array JSON
          - 'json_key'             : string key "…":
          - 'json_value_string'    : nilai string
          - 'json_value_number'    : nilai numerik
          - 'json_value_literal'   : true/false/null
          - 'json_context'         : deteksi probe key/value
        """
        contexts = set()
        txt = content.strip()

        # 1) JSONP callback
        m = re.match(r'^([a-zA-Z_$][\w$]*)\s*\(\s*(.*)\s*\)\s*;?$', txt, re.DOTALL)
        if m:
            contexts.add("jsonp_callback")
            txt = m.group(2).strip()

        # 2) Try parse JSON
        try:
            data = json.loads(txt)
            if isinstance(data, dict):
                contexts.add("json_object")
                for k, v in data.items():
                    contexts.add("json_key")
                    if isinstance(v, str):
                        contexts.add("json_value_string")
                    elif isinstance(v, (int, float)):
                        contexts.add("json_value_number")
                    elif v is True or v is False or v is None:
                        contexts.add("json_value_literal")
            elif isinstance(data, list):
                contexts.add("json_array")
                for v in data:
                    if isinstance(v, str):
                        contexts.add("json_value_string")
                    elif isinstance(v, (int, float)):
                        contexts.add("json_value_number")
                    elif v is True or v is False or v is None:
                        contexts.add("json_value_literal")
        except Exception:
            # 3) Fallback regex
            if re.search(r'"[^"]+"\s*:', txt):
                contexts.add("json_key")
            if re.search(r':\s*"[^"]*"', txt):
                contexts.add("json_value_string")
            if re.search(r':\s*\d+(\.\d+)?', txt):
                contexts.add("json_value_number")
            if re.search(r'\b(true|false|null)\b', txt):
                contexts.add("json_value_literal")
            if re.search(r'^\s*\{.*\}\s*$', txt, re.DOTALL):
                contexts.add("json_object")
            if re.search(r'^\s*\[.*\]\s*$', txt, re.DOTALL):
                contexts.add("json_array")

        # 4) Probe context (json_context)
        # misal "probeKey": atau : "probeValue"
        if re.search(rf'"[^"]+"\s*:\s*["\']?PROBE["\']?', content):
            contexts.add("json_context")

        return sorted(contexts)
