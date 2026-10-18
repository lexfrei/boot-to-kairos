#!/usr/bin/env python3
"""Print each progress report boot-to-kairos posts as one JSON line.

Usage: report-receiver.py [--bind ADDR] [--port PORT] [--cert PEM --key PEM]
"""
import argparse, http.server, json, ssl, sys

p = argparse.ArgumentParser()
p.add_argument("--bind", default="0.0.0.0")
p.add_argument("--port", type=int, default=8080)
p.add_argument("--cert")
p.add_argument("--key")
a = p.parse_args()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            print(json.dumps(json.loads(body)), flush=True)
        except ValueError:
            self.send_response(400)
        else:
            self.send_response(204)
        self.end_headers()

    def log_message(self, fmt, *args):
        print(self.address_string(), fmt % args, file=sys.stderr)


srv = http.server.ThreadingHTTPServer((a.bind, a.port), Handler)
if a.cert:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
