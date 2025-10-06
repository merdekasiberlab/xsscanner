#!/usr/bin/env python3
"""
Canary XSS server for evaluation.

Run locally:
  python tools/eval/canary_xss_server.py --port 5000

With docker-compose (recommended):
  docker compose -f tools/eval/docker-compose.yaml up canary

Endpoints:
  /html?x=        -> reflect into HTML node
  /attr_dq?x=     -> reflect into attribute with double quotes
  /attr_sq?x=     -> reflect into attribute with single quotes
  /attr_uq?x=     -> reflect into unquoted attribute
  /js_dq?x=       -> reflect into JS string (double quotes), then sink
  /js_sq?x=       -> reflect into JS string (single quotes), then sink
  /url?x=         -> plant into href/src
  /svg?x=         -> insert into SVG element
  /css?x=         -> insert into inline style and <style>
  /srcdoc?x=      -> set <iframe srcdoc="...">
  /hash_router    -> SPA page that reads location.hash and sinks it
  /storage        -> reads localStorage["x"] and sinks it on click
  /ws_client      -> opens WS to ws://host/ws and sinks messages
  /ws             -> WebSocket echo server (Flask-Sock)
  /postmessage    -> listens to postMessage and sinks event.data
  /forms          -> two forms (urlencoded + JSON fetch)
  /forms/result   -> reflects POSTed input
  /csp/loose?x=   -> loose CSP (none)
  /csp/strict?x=  -> strict CSP blocks inline/event/js: URLs

All endpoints are intentionally lax to exercise the scanner in varied contexts.
"""
from __future__ import annotations

import argparse
import datetime as _dt
from flask import Flask, request, Response, make_response
from flask_sock import Sock

app = Flask(__name__)
sock = Sock(app)


def _log_request(tag: str) -> None:
    try:
        now = _dt.datetime.utcnow().isoformat()
        q = request.query_string.decode("utf-8", "ignore")[:200]
        b = request.get_data(as_text=True)[:200]
        print(f"[{now}] {tag} {request.method} {request.path}?{q} body={b}")
    except Exception:
        pass


def _html_page(body: str, headers: dict | None = None) -> Response:
    resp = make_response(body)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    for k, v in (headers or {}).items():
        resp.headers[k] = v
    return resp


@app.route("/")
def index() -> Response:
    _log_request("/")
    return _html_page(
        """
        <html><head><title>Canary XSS</title></head>
        <body>
          <h3>Canary XSS Server</h3>
          <ul>
            <li><a href="/html?x=%3Csvg%20onload%3Dalert(1)%3E">/html</a></li>
            <li><a href="/attr_dq?x=%22%20onmouseover%3Dalert(1)%20x%3D%22">/attr_dq</a></li>
            <li><a href="/attr_sq?x='%20onerror%3Dalert(1)%20x%3D'">/attr_sq</a></li>
            <li><a href="/attr_uq?x=onload%3Dalert(1)">/attr_uq</a></li>
            <li><a href="/js_dq?x=%22%3Balert(1)%2F%2F">/js_dq</a></li>
            <li><a href="/js_sq?x='%3Balert(1)%2F%2F">/js_sq</a></li>
            <li><a href="/url?x=javascript:alert(1)">/url</a></li>
            <li><a href="/svg?x=%3Cscript%3Ealert(1)%3C%2Fscript%3E">/svg</a></li>
            <li><a href="/css?x=width:expression(alert(1))">/css</a></li>
            <li><a href="/srcdoc?x=%3Cscript%3Ealert(1)%3C%2Fscript%3E">/srcdoc</a></li>
            <li><a href="/hash_router#%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E">/hash_router</a></li>
            <li><a href="/storage">/storage</a></li>
            <li><a href="/ws_client">/ws_client</a></li>
            <li><a href="/postmessage">/postmessage</a></li>
            <li><a href="/forms">/forms</a></li>
            <li><a href="/csp/loose?x=%3Cscript%3Ealert(1)%3C%2Fscript%3E">/csp/loose</a></li>
            <li><a href="/csp/strict?x=%3Cscript%3Ealert(1)%3C%2Fscript%3E">/csp/strict</a></li>
          </ul>
        </body></html>
        """
    )


@app.route("/health")
def health() -> Response:
    return Response("ok", mimetype='text/plain')


@app.route("/html")
def html_reflect() -> Response:
    _log_request("/html")
    x = request.args.get("x", "")
    return _html_page(f"<html><body><div id='out'>{x}</div></body></html>")


@app.route("/attr_dq")
def attr_dq() -> Response:
    _log_request("/attr_dq")
    x = request.args.get("x", "")
    return _html_page(f"<html><body><img alt=\"{x}\" src=x onerror=console.log('err')></body></html>")


@app.route("/attr_sq")
def attr_sq() -> Response:
    _log_request("/attr_sq")
    x = request.args.get("x", "")
    return _html_page(f"<html><body><img alt='{x}' src=x onerror=console.log('err')></body></html>")


@app.route("/attr_uq")
def attr_uq() -> Response:
    _log_request("/attr_uq")
    x = request.args.get("x", "")
    return _html_page(f"<html><body><div data-x={x}>unquoted</div></body></html>")


@app.route("/js_dq")
def js_dq() -> Response:
    _log_request("/js_dq")
    x = request.args.get("x", "")
    body = f"""
    <html><body>
      <div id="out"></div>
      <script>
        var s = "{x}"; // dq
        document.getElementById('out').innerHTML = s;
      </script>
    </body></html>
    """
    return _html_page(body)


@app.route("/js_sq")
def js_sq() -> Response:
    _log_request("/js_sq")
    x = request.args.get("x", "")
    body = f"""
    <html><body>
      <div id="out"></div>
      <script>
        var s = '{x}'; // sq
        document.getElementById('out').innerHTML = s;
      </script>
    </body></html>
    """
    return _html_page(body)


@app.route("/url")
def url_page() -> Response:
    _log_request("/url")
    x = request.args.get("x", "")
    return _html_page(f"<html><body><a id='a' href='{x}'>link</a><img id='i' src='{x}'></body></html>")


@app.route("/svg")
def svg_page() -> Response:
    _log_request("/svg")
    x = request.args.get("x", "")
    return _html_page(f"<html><body><svg id='s'>{x}</svg></body></html>")


@app.route("/css")
def css_page() -> Response:
    _log_request("/css")
    x = request.args.get("x", "")
    return _html_page(
        f"<html><head><style>#d{{ {x} }}</style></head><body><div id='d' style='{x}'>css</div></body></html>"
    )


@app.route("/srcdoc")
def srcdoc_page() -> Response:
    _log_request("/srcdoc")
    x = request.args.get("x", "")
    return _html_page(f"<html><body><iframe srcdoc=\"{x}\"></iframe></body></html>")


@app.route("/hash_router")
def hash_router() -> Response:
    _log_request("/hash_router")
    return _html_page(
        """
        <html><body>
          <a id="a" href="#">home</a>
          <div id="out">hash-router</div>
          <script>
            function render(){
              var h = location.hash ? location.hash.slice(1) : '';
              document.getElementById('out').innerHTML = h;
              document.getElementById('a').setAttribute('href', h);
            }
            window.addEventListener('hashchange', render);
            render();
          </script>
        </body></html>
        """
    )


@app.route("/storage")
def storage_page() -> Response:
    _log_request("/storage")
    return _html_page(
        """
        <html><body>
          <button id="b">render</button>
          <div id="out"></div>
          <script>
            try { localStorage.setItem('x', location.search.split('x=')[1] || ''); } catch(e){}
            document.getElementById('b').addEventListener('click', function(){
              var v = localStorage.getItem('x') || '';
              document.getElementById('out').innerHTML = v;
              try{ document.getElementById('out').setAttribute('data-x', v); }catch(e){}
            });
          </script>
        </body></html>
        """
    )


@sock.route('/ws')
def ws_echo(ws):
    # Simple echo that also pushes a greeting
    try:
        ws.send('welcome-from-server')
    except Exception:
        pass
    while True:
        try:
            data = ws.receive()
        except Exception:
            break
        if data is None:
            break
        try:
            ws.send(f"echo:{data}")
        except Exception:
            break


@app.route("/ws_client")
def ws_client() -> Response:
    _log_request("/ws_client")
    # Point to same host, http -> ws
    ws_url = f"ws://{request.host}/ws"
    return _html_page(
        f"""
        <html><body>
          <div id="out">ws</div>
          <script>
            try {{
              const ws = new WebSocket('{ws_url}');
              ws.addEventListener('message', (ev)=>{{
                const d = String(ev.data||'');
                document.getElementById('out').innerHTML = d;
                try{{ document.getElementById('out').setAttribute('data-x', d); }}catch(e){{}}
              }});
            }}catch(e){{}}
          </script>
        </body></html>
        """
    )


@app.route("/postmessage")
def postmessage() -> Response:
    _log_request("/postmessage")
    return _html_page(
        """
        <html><body>
          <div id="out">pm</div>
          <script>
            window.addEventListener('message', function(ev){
              var d = String(ev.data||'');
              document.getElementById('out').innerHTML = d;
              try{ document.getElementById('out').setAttribute('data-x', d); }catch(e){}
              try{ document.getElementById('out').setAttribute('onclick', d); }catch(e){}
            });
          </script>
        </body></html>
        """
    )


@app.route("/forms", methods=["GET"])
def forms() -> Response:
    _log_request("/forms")
    return _html_page(
        """
        <html><body>
          <h4>Forms</h4>
          <form method="POST" action="/forms/result">
            <input name="x" placeholder="value" />
            <button type="submit">POST urlencoded</button>
          </form>
          <button id="send">POST JSON via fetch</button>
          <script>
            document.getElementById('send').onclick = function(){
              fetch('/forms/result', {
                method: 'POST',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({x: (new URLSearchParams(location.search)).get('x') || 'json'})
              }).then(r=>r.text()).then(html=>{ document.body.insertAdjacentHTML('beforeend', html) });
            };
          </script>
        </body></html>
        """
    )


@app.route("/forms/result", methods=["POST"])
def forms_result() -> Response:
    _log_request("/forms/result")
    x = ""
    if request.is_json:
        try:
            x = (request.get_json(silent=True) or {}).get('x', '')
        except Exception:
            x = ""
    else:
        x = request.form.get("x", "")
    return _html_page(
        f"""
        <div id='res'>Form result</div>
        <div id='out'>{x}</div>
        <img alt="{x}" src=x onerror=console.log('err')>
        <script>
          var s = "{x}"; document.getElementById('res').innerHTML = s;
        </script>
        """
    )


@app.route("/csp/loose")
def csp_loose() -> Response:
    _log_request("/csp/loose")
    x = request.args.get("x", "")
    return _html_page(f"<html><body><div id='out'>{x}</div><script>document.body.insertAdjacentHTML('beforeend','{x}');</script></body></html>")


@app.route("/csp/strict")
def csp_strict() -> Response:
    _log_request("/csp/strict")
    x = request.args.get("x", "")
    headers = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; style-src 'self'"
    }
    return _html_page(f"<html><body><div id='out'>{x}</div><a href='{x}'>a</a></body></html>", headers=headers)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--port', type=int, default=5000)
    args = p.parse_args()
    print(f"[canary] listening on 0.0.0.0:{args.port}")
    # Flask-Sock requires threaded server for dev
    app.run(host='0.0.0.0', port=args.port, threaded=True)


if __name__ == '__main__':
    main()
