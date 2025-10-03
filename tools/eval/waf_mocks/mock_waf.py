#!/usr/bin/env python3
from __future__ import annotations

from flask import Flask, request, Response
import time

app = Flask(__name__)

@app.route('/block_modsec')
def block_modsec():
    return Response('Access denied by ModSecurity', status=403, mimetype='text/plain')

@app.route('/cf_iuam')
def cf_iuam():
    # Simulate IUAM: first hit 503 with JS marker, then 200 after 5s
    t = request.args.get('t')
    if not t:
        resp = Response('<html><title>Attention Required! | Cloudflare</title><script>setTimeout(()=>{location.search="?t=ok"},5000)</script></html>', status=503)
        resp.headers['CF-Ray'] = '1234abcd-test'
        return resp
    return Response('ok', status=200)

@app.route('/captcha')
def captcha():
    return Response('<html><div class="h-captcha">captcha</div></html>', status=200)

_COUNTER = 0
@app.route('/ratelimit')
def ratelimit():
    global _COUNTER
    _COUNTER += 1
    if _COUNTER % 11 == 0:
        return Response('Too Many Requests', status=429)
    return Response('ok', status=200)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5055)

