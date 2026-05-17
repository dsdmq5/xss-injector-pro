"""
XSS Vulnerability Detector
Detects XSS vulnerabilities using tight context-aware pattern matching.
Reduces false positives by verifying payload reflection is in an executable context.
"""

import re
from typing import Tuple
from html import unescape
import hashlib


class VulnerabilityDetector:
    """Detects XSS vulnerabilities in responses with context-aware analysis"""

    def __init__(self, config):
        self.config = config
        self.ml_enabled = config.ml_detection

        if self.ml_enabled:
            try:
                from .ml_detector import MLDetector
                self.ml_detector = MLDetector()
            except ImportError:
                print("[WARNING] ML dependencies not available. Falling back to pattern matching.")
                self.ml_enabled = False

    def detect_xss(self, response_body: str, response_headers: dict, payload: str) -> Tuple[bool, str]:
        """
        Detect if payload resulted in XSS vulnerability.
        Uses a unique marker approach to reduce false positives.
        Returns: (is_vulnerable, detection_method)
        """
        # Generate a unique fingerprint for this payload to track reflection
        fingerprint = self._get_payload_fingerprint(payload)

        # Method 1: Direct unescaped payload reflection in HTML context
        if self._check_unescaped_reflection(response_body, payload):
            return True, "Unescaped Payload Reflection"

        # Method 2: Payload reflected inside executable script context
        if self._check_script_context_reflection(response_body, payload, fingerprint):
            return True, "Script Context Reflection"

        # Method 3: Event handler injection confirmed
        if self._check_event_handler_injection(response_body, payload, fingerprint):
            return True, "Event Handler Injection"

        # Method 4: JavaScript protocol in href/src attributes
        if self._check_javascript_protocol_injection(response_body, payload, fingerprint):
            return True, "JavaScript Protocol Injection"

        # Method 5: DOM sink with payload content
        if self._check_dom_sink_injection(response_body, payload, fingerprint):
            return True, "DOM Sink Injection"

        # Method 6: ML-based detection (if enabled)
        if self.ml_enabled:
            if self._ml_based_detection(response_body, payload):
                return True, "ML-Based Detection"

        return False, ""

    def _get_payload_fingerprint(self, payload: str) -> str:
        """Extract unique identifiable parts of the payload for matching"""
        # Use a hash-based short marker if payload is generic
        return hashlib.md5(payload.encode()).hexdigest()[:8]

    def _check_unescaped_reflection(self, response: str, payload: str) -> bool:
        """
        Check if the exact payload appears unescaped in the response body.
        Only flag if the payload is present in the RAW response (not just after decoding).
        If the payload only appears after HTML entity decoding, it means the server
        properly escaped it — not vulnerable.
        """
        if payload not in response:
            # The payload is NOT in the raw response.
            # Even if unescape(response) contains it, that means it was entity-encoded = safe.
            return False

        # Payload IS in the raw response — confirm it's actually dangerous
        dangerous_patterns = [
            r'<script',
            r'<img\b',
            r'<svg\b',
            r'<body\b',
            r'<iframe\b',
            r'<object\b',
            r'<embed\b',
            r'<details\b',
            r'<marquee\b',
            r'<math\b',
            r'<form\b',
            r'<input\b',
            r'on\w+\s*=',
            r'javascript:',
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True

        return False

    def _check_script_context_reflection(self, response: str, payload: str, fingerprint: str) -> bool:
        """Check if payload content appears inside a <script> block in the response"""
        # Find all script blocks in the response
        script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', response, re.IGNORECASE | re.DOTALL)

        # Extract key executable parts from the payload
        executable_markers = self._extract_executable_markers(payload)
        if not executable_markers:
            return False

        for block in script_blocks:
            for marker in executable_markers:
                if marker in block:
                    return True

        return False

    def _check_event_handler_injection(self, response: str, payload: str, fingerprint: str) -> bool:
        """Check if an event handler from our payload was injected into an HTML tag"""
        # Extract event handler from payload
        payload_handlers = re.findall(r'(on\w+)\s*=\s*["\']?([^"\'>\s]+)', payload, re.IGNORECASE)
        if not payload_handlers:
            return False

        # Check if those same handlers appear in the response HTML tags
        for handler_name, handler_value in payload_handlers:
            # Look for the handler in an HTML attribute context
            pattern = rf'<[^>]+{re.escape(handler_name)}\s*=\s*["\']?{re.escape(handler_value)}'
            if re.search(pattern, response, re.IGNORECASE):
                return True

        return False

    def _check_javascript_protocol_injection(self, response: str, payload: str, fingerprint: str) -> bool:
        """Check if javascript: protocol from payload appears in href/src/action attributes"""
        if 'javascript:' not in payload.lower():
            return False

        # Extract the javascript: URI from the payload
        js_match = re.search(r'javascript:(.+?)(?:["\'>]|$)', payload, re.IGNORECASE)
        if not js_match:
            return False

        js_code = js_match.group(1)

        # Check if it appears in an attribute context in the response
        patterns = [
            rf'href\s*=\s*["\']?javascript:{re.escape(js_code)}',
            rf'src\s*=\s*["\']?javascript:{re.escape(js_code)}',
            rf'action\s*=\s*["\']?javascript:{re.escape(js_code)}',
        ]

        for pattern in patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return True

        return False

    def _check_dom_sink_injection(self, response: str, payload: str, fingerprint: str) -> bool:
        """Check for DOM-based XSS where payload flows into a dangerous sink"""
        # Only flag if the payload itself contains DOM sink patterns AND is reflected
        dom_sinks = ['document.write', 'innerHTML', 'outerHTML', 'eval(', 'setTimeout(', 'setInterval(']

        payload_has_sink = any(sink in payload for sink in dom_sinks)
        if not payload_has_sink:
            return False

        # Verify the payload (or its key parts) is reflected
        executable_markers = self._extract_executable_markers(payload)
        for marker in executable_markers:
            if marker in response:
                return True

        return False

    def _extract_executable_markers(self, payload: str) -> list:
        """Extract unique executable markers from a payload for correlation"""
        markers = []

        # Look for alert/prompt/confirm calls with specific arguments
        calls = re.findall(r'(alert|prompt|confirm)\s*\(([^)]*)\)', payload, re.IGNORECASE)
        for func, arg in calls:
            markers.append(f"{func}({arg})")

        # Look for document.cookie, document.domain references
        if 'document.cookie' in payload:
            markers.append('document.cookie')
        if 'document.domain' in payload:
            markers.append('document.domain')

        # Look for unique string literals in the payload
        strings = re.findall(r"['\"]([^'\"]{3,})['\"]", payload)
        for s in strings:
            if s not in ('text/html', 'utf-8'):
                markers.append(s)

        # If payload has a distinctive prefix (e.g. closing tags)
        if payload.startswith('</'):
            markers.append(payload[:20])

        return markers

    def _ml_based_detection(self, response: str, payload: str) -> bool:
        """ML-based vulnerability detection (experimental)"""
        if not self.ml_enabled:
            return False

        try:
            return self.ml_detector.predict(response, payload)
        except Exception:
            return False

    def get_context_snippet(self, response: str, payload: str, context_size: int = 200) -> str:
        """Extract context around payload in response"""
        try:
            index = response.find(payload)
            if index == -1:
                # Try to find partial match
                markers = self._extract_executable_markers(payload)
                for marker in markers:
                    index = response.find(marker)
                    if index != -1:
                        break

            if index != -1:
                start = max(0, index - context_size)
                end = min(len(response), index + len(payload) + context_size)
                return response[start:end]
        except Exception:
            pass

        return response[:500]  # Default: first 500 chars
