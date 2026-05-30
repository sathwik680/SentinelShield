# main.py
# SentinelShield - Main Server
# Connects WAF Engine + Rate Limiter + Logger into one running system

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import json

from waf_engine   import inspect_request
from rate_limiter import check_rate_limit
from logger       import log_event, generate_summary

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────
HOST = "127.0.0.1"
PORT = 8080

# ─────────────────────────────────────────
# REQUEST HANDLER
# ─────────────────────────────────────────
class SentinelHandler(BaseHTTPRequestHandler):

    def handle_request(self, method, body=None):
        ip     = self.client_address[0]
        path   = self.path
        headers = dict(self.headers)

        # ── Step 1: Rate Limit Check ──
        rate_result = check_rate_limit(ip)
        if rate_result["status"] == "BLOCKED":
            log_event(
                ip, method, path, body,
                [], "BLOCKED",
                rate_result["reason"]
            )
            self._respond(429, {
                "status" : "BLOCKED",
                "reason" : rate_result["reason"],
                "ip"     : ip,
            })
            return

        # ── Step 2: WAF Inspection ──
        waf_result = inspect_request(method, path, headers, body)

        # ── Step 3: Log the Event ──
        log_event(
            ip, method, path, body,
            waf_result["detections"],
            waf_result["action"],
        )

        # ── Step 4: Respond ──
        if waf_result["is_malicious"]:
            self._respond(403, {
                "status"    : "BLOCKED",
                "reason"    : "Malicious request detected",
                "detections": waf_result["detections"],
            })
        else:
            self._respond(200, {
                "status" : "ALLOWED",
                "message": "Request processed successfully",
                "path"   : path,
            })

    def _respond(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Serve summary on /summary route
        if self.path == "/summary":
            summary = generate_summary()
            body = json.dumps(summary, indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.handle_request("GET")

    def do_POST(self):
        # Read POST body
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode("utf-8") if length else None
        self.handle_request("POST", body)

    # Suppress default server log (we use our own)
    def log_message(self, format, *args):
        pass


# ─────────────────────────────────────────
# START SERVER
# ─────────────────────────────────────────
if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), SentinelHandler)
    print("\n" + "="*55)
    print("   SentinelShield — WAF Server Running")
    print("="*55)
    print(f"  URL     : http://{HOST}:{PORT}")
    print(f"  Summary : http://{HOST}:{PORT}/summary")
    print(f"  Logs    : logs/alerts.log")
    print("  Press CTRL+C to stop")
    print("="*55 + "\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
