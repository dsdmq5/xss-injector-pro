"""
Tests for the XSS Vulnerability Detector.
Validates that detection logic correctly identifies true positives
and avoids false positives.
"""

import pytest
from src.detector import VulnerabilityDetector
from src.config import Config


@pytest.fixture
def config():
    return Config(target_url="http://example.com", ml_detection=False)


@pytest.fixture
def detector(config):
    return VulnerabilityDetector(config)


class TestUnescapedReflection:
    """Tests for direct payload reflection detection"""

    def test_exact_script_tag_reflected(self, detector):
        payload = "<script>alert('XSS')</script>"
        response = f"<html><body>Search results for: {payload}</body></html>"
        is_vuln, method = detector.detect_xss(response, {}, payload)
        assert is_vuln is True
        assert method == "Unescaped Payload Reflection"

    def test_img_onerror_reflected(self, detector):
        payload = "<img src=x onerror=alert('XSS')>"
        response = f"<html><body>{payload}</body></html>"
        is_vuln, method = detector.detect_xss(response, {}, payload)
        assert is_vuln is True

    def test_properly_escaped_payload_not_flagged(self, detector):
        """Escaped output should NOT be flagged as vulnerable"""
        payload = "<script>alert('XSS')</script>"
        escaped = "&lt;script&gt;alert('XSS')&lt;/script&gt;"
        response = f"<html><body>Search results for: {escaped}</body></html>"
        is_vuln, _ = detector.detect_xss(response, {}, payload)
        assert is_vuln is False

    def test_payload_not_present_at_all(self, detector):
        """If payload is not reflected, no vulnerability"""
        payload = "<script>alert('XSS')</script>"
        response = "<html><body>Welcome to our site</body></html>"
        is_vuln, _ = detector.detect_xss(response, {}, payload)
        assert is_vuln is False


class TestEventHandlerInjection:
    """Tests for event handler detection"""

    def test_onerror_in_img_tag(self, detector):
        payload = "<img src=x onerror=alert(1)>"
        response = '<html><body><img src=x onerror=alert(1)></body></html>'
        is_vuln, method = detector.detect_xss(response, {}, payload)
        assert is_vuln is True

    def test_legitimate_onerror_not_flagged(self, detector):
        """A page with its own onerror handler should not be flagged
        when the payload is not reflected"""
        payload = "<img src=x onerror=alert('XSS')>"
        response = '<html><body><img src="logo.png" onerror="this.style.display=\'none\'"></body></html>'
        is_vuln, _ = detector.detect_xss(response, {}, payload)
        assert is_vuln is False


class TestJavaScriptProtocol:
    """Tests for javascript: protocol injection"""

    def test_javascript_href_injection(self, detector):
        payload = "<a href=javascript:alert('XSS')>click</a>"
        response = "<html><body><a href=javascript:alert('XSS')>click</a></body></html>"
        is_vuln, method = detector.detect_xss(response, {}, payload)
        assert is_vuln is True

    def test_no_javascript_protocol_in_response(self, detector):
        payload = "<a href=javascript:alert('XSS')>click</a>"
        response = "<html><body><a href='/safe-page'>click</a></body></html>"
        is_vuln, _ = detector.detect_xss(response, {}, payload)
        assert is_vuln is False


class TestScriptContextReflection:
    """Tests for payload reflected inside script blocks"""

    def test_alert_inside_script_block(self, detector):
        payload = "'; alert('XSS'); //"
        response = "<html><script>var x = ''; alert('XSS'); //';</script></html>"
        is_vuln, method = detector.detect_xss(response, {}, payload)
        assert is_vuln is True
        assert method == "Script Context Reflection"

    def test_unrelated_script_not_flagged(self, detector):
        """Existing page scripts should not trigger false positives"""
        payload = "<script>alert('XSS')</script>"
        # Page has its own analytics script, payload is NOT reflected
        response = "<html><script>ga('send', 'pageview');</script><body>Hello</body></html>"
        is_vuln, _ = detector.detect_xss(response, {}, payload)
        assert is_vuln is False


class TestDOMSinkInjection:
    """Tests for DOM sink detection"""

    def test_document_write_with_payload(self, detector):
        payload = "<script>document.write('<img src=x>')</script>"
        response = f"<html><body>{payload}</body></html>"
        is_vuln, _ = detector.detect_xss(response, {}, payload)
        assert is_vuln is True

    def test_page_with_own_document_write_not_flagged(self, detector):
        """Page's own document.write should not be flagged if payload not reflected"""
        payload = "<script>document.write('evil')</script>"
        response = "<html><script>document.write(new Date())</script><body>Hi</body></html>"
        is_vuln, _ = detector.detect_xss(response, {}, payload)
        assert is_vuln is False


class TestContextSnippet:
    """Tests for context extraction"""

    def test_snippet_around_payload(self, detector):
        payload = "<script>alert(1)</script>"
        response = "A" * 300 + payload + "B" * 300
        snippet = detector.get_context_snippet(response, payload, context_size=50)
        assert payload in snippet
        assert len(snippet) < len(response)

    def test_snippet_fallback_when_not_found(self, detector):
        payload = "not_in_response"
        response = "A" * 1000
        snippet = detector.get_context_snippet(response, payload)
        assert snippet == response[:500]
