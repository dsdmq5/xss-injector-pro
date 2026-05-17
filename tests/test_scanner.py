"""
Tests for the XSS Scanner core module.
Tests thread safety and integration of components.
"""

import pytest
from unittest.mock import patch, MagicMock
from src.scanner import XSSScanner
from src.config import Config


@pytest.fixture
def config():
    return Config(
        target_url="http://example.com",
        mode='semi',
        depth=1,
        max_urls=5,
        threads=2,
        delay=0,
        timeout=5,
        payload_level='basic',
        verbose=False,
        respect_robots=False
    )


class TestScannerInit:
    """Test scanner initialization"""

    def test_scanner_creates_session(self, config):
        scanner = XSSScanner(config)
        assert scanner.session is not None

    def test_scanner_initializes_stats(self, config):
        scanner = XSSScanner(config)
        assert scanner.stats['urls_scanned'] == 0
        assert scanner.stats['vulnerabilities_found'] == 0

    def test_scanner_with_cookies(self):
        config = Config(
            target_url="http://example.com",
            cookie="session=abc123; user=admin"
        )
        scanner = XSSScanner(config)
        assert 'session' in scanner.session.cookies
        assert scanner.session.cookies['session'] == 'abc123'

    def test_scanner_with_custom_headers(self):
        config = Config(
            target_url="http://example.com",
            headers=["Authorization: Bearer token123", "X-Custom: value"]
        )
        scanner = XSSScanner(config)
        assert scanner.session.headers['Authorization'] == 'Bearer token123'
        assert scanner.session.headers['X-Custom'] == 'value'

    def test_scanner_with_proxy(self):
        config = Config(
            target_url="http://example.com",
            proxy="http://127.0.0.1:8080"
        )
        scanner = XSSScanner(config)
        assert scanner.session.proxies['http'] == "http://127.0.0.1:8080"
        assert scanner.session.verify is False


class TestFormExtraction:
    """Test form detection"""

    @patch('src.scanner.XSSScanner._create_session')
    def test_extracts_forms_with_inputs(self, mock_session_factory, config):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.text = '''
        <html><body>
            <form action="/search" method="get">
                <input type="text" name="q" value="">
                <input type="submit" name="submit" value="Search">
            </form>
        </body></html>
        '''
        mock_session.get.return_value = mock_response
        mock_session_factory.return_value = mock_session

        scanner = XSSScanner(config)
        scanner.session = mock_session
        forms = scanner._extract_forms("http://example.com")

        assert len(forms) == 1
        assert forms[0]['method'] == 'get'
        assert len(forms[0]['inputs']) == 2

    @patch('src.scanner.XSSScanner._create_session')
    def test_skips_forms_without_named_inputs(self, mock_session_factory, config):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.text = '''
        <html><body>
            <form action="/submit">
                <input type="text">
                <button>Go</button>
            </form>
        </body></html>
        '''
        mock_session.get.return_value = mock_response
        mock_session_factory.return_value = mock_session

        scanner = XSSScanner(config)
        scanner.session = mock_session
        forms = scanner._extract_forms("http://example.com")

        # Form has no named inputs, should be skipped
        assert len(forms) == 0


class TestThreadSafety:
    """Test that concurrent operations don't corrupt shared state"""

    def test_stats_increment_thread_safe(self, config):
        import threading

        scanner = XSSScanner(config)

        def increment_stats():
            for _ in range(100):
                with scanner._stats_lock:
                    scanner.stats['parameters_tested'] += 1

        threads = [threading.Thread(target=increment_stats) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert scanner.stats['parameters_tested'] == 1000

    def test_vulnerability_append_thread_safe(self, config):
        import threading

        scanner = XSSScanner(config)

        def append_vuln(i):
            for j in range(50):
                with scanner._vuln_lock:
                    scanner.vulnerabilities.append({'id': f'{i}-{j}'})

        threads = [threading.Thread(target=append_vuln, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(scanner.vulnerabilities) == 500

    def test_tested_vectors_dedup_thread_safe(self, config):
        import threading

        scanner = XSSScanner(config)
        results = []

        def add_vector(vector_id):
            with scanner._vectors_lock:
                if vector_id in scanner.tested_vectors:
                    results.append(False)
                else:
                    scanner.tested_vectors.add(vector_id)
                    results.append(True)

        # All threads try to add the same vector
        threads = [threading.Thread(target=add_vector, args=("same_vector",)) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Only one should have succeeded
        assert results.count(True) == 1
        assert results.count(False) == 9
