#!/usr/bin/env python
"""Simple HTTP server to serve the dashboard with test results."""
import http.server
import socketserver
import webbrowser
from pathlib import Path

PORT = 8765

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        return super().end_headers()

# Change to the Mailtrack directory
import os
os.chdir(Path(__file__).parent)

with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
    url = f"http://localhost:{PORT}/dashboard.html"
    print(f"🚀 Dashboard serving at {url}")
    print(f"📊 Press Ctrl+C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n✅ Server stopped")
