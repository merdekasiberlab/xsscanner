#!/usr/bin/env python3
"""
Local OAST/Blind-XSS receiver with SQLite storage and SSE stream.

Run locally:
  python tools/eval/oast_receiver.py --port 9000 --store tools/eval/oast_hits.db

With docker-compose:
  docker compose -f tools/eval/docker-compose.yaml up oast

Endpoints:
  /t/<token>   -> accept GET/POST (works as <img>/<script>/<link>/<style>) and store hit
  /events      -> SSE stream of latest hits (for debugging)
"""
from __future__ import annotations

import argparse
import sqlite3
import time
from flask import Flask, request, Response
import os

app = Flask(__name__)

# Default DB path for containerized runs; can be overridden via CLI or env
DB_PATH = os.environ.get('OAST_DB', '/work/oast_hits.db')
subscribers: list[sqlite3.Connection] = []  # dummy placeholder for typing
_sse_clients = []  # list of queues


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS hits (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          token TEXT,
          ts INTEGER,
          method TEXT,
          ua TEXT,
          referer TEXT,
          query TEXT,
          body_prefix TEXT
        )
        """
    )
    conn.commit()
    return conn


def _insert_hit(token: str, method: str, ua: str, referer: str, query: str, body_prefix: str) -> None:
    conn = _db()
    conn.execute(
        "INSERT INTO hits (token, ts, method, ua, referer, query, body_prefix) VALUES (?,?,?,?,?,?,?)",
        (token, int(time.time()), method, ua, referer, query, body_prefix),
    )
    conn.commit()
    conn.close()
    try:
        msg = f"hit:{token}:{method}"
        for q in list(_sse_clients):
            try:
                q.append(msg)
            except Exception:
                pass
    except Exception:
        pass


@app.route('/t/<token>', methods=['GET', 'POST'])
def hit(token: str) -> Response:
    ua = request.headers.get('User-Agent', '')
    referer = request.headers.get('Referer', '')
    query = request.query_string.decode('utf-8', 'ignore')[:200]
    body = request.get_data(cache=False, as_text=True) or ''
    body_prefix = body[:200]
    print(f"[oast] hit token={token} method={request.method} ua={ua[:20]} referer={referer[:40]} query={query}")
    _insert_hit(token, request.method, ua, referer, query, body_prefix)
    # Serve content that can be used for <script> or <img>
    if 'text/javascript' in (request.headers.get('Accept', '') or '') or request.path.endswith('.js'):
        return Response("console.log('oast-ok')", mimetype='application/javascript')
    return Response("ok", mimetype='text/plain')


@app.route('/events')
def events() -> Response:
    # Simple SSE; each client gets a per-connection list as a queue
    q: list[str] = []
    _sse_clients.append(q)

    def _stream():
        yield 'event: ready\n' 'data: ok\n\n'
        try:
            while True:
                if q:
                    msg = q.pop(0)
                    yield f"data: {msg}\n\n"
                time.sleep(0.5)
        except GeneratorExit:
            pass
        finally:
            try:
                _sse_clients.remove(q)
            except Exception:
                pass

    return Response(_stream(), mimetype='text/event-stream')


@app.route('/health')
def health() -> Response:
    return Response('ok', mimetype='text/plain')


def main() -> None:
    global DB_PATH
    p = argparse.ArgumentParser()
    p.add_argument('--port', type=int, default=9000)
    p.add_argument('--store', default='tools/eval/oast_hits.db')
    args = p.parse_args()
    DB_PATH = args.store
    print(f"[oast] listening on 0.0.0.0:{args.port} db={DB_PATH}")
    app.run(host='0.0.0.0', port=args.port, threaded=True)


if __name__ == '__main__':
    main()
