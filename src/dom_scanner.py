"""
DOM-based XSS Scanner using Headless Browser
Uses Playwright to render pages and detect DOM XSS that only
manifests in the browser (never touches the server).
"""

import re
import time
from typing import List, Dict, Optional
from colorama import Fore, Style


# DOM sources - where user input enters the DOM
DOM_SOURCES = [
    'document.URL',
    'document.documentURI',
    'document.referrer',
    'document.baseURI',
    'location.href',
    'location.search',
    'location.hash',
    'location.pathname',
    'window.name',
    'document.cookie',
    'history.pushState',
    'history.replaceState',
    'localStorage',
    'sessionStorage',
    'postMessage',
]

# DOM sinks - where data gets executed
DOM_SINKS = [
    'eval(',
    'setTimeout(',
    'setInterval(',
    'Function(',
    'document.write(',
    'document.writeln(',
    '.innerHTML',
    '.outerHTML',
    '.insertAdjacentHTML(',
    '.onevent',
    'element.setAttribute(',
    'element.style.cssText',
    'jQuery.html(',
    '$.html(',
    '.append(',
    '.prepend(',
    '.after(',
    '.before(',
    'location.assign(',
    'location.replace(',
    'window.open(',
]


class DOMScanner:
    """Scans for DOM-based XSS using headless browser execution"""

    def __init__(self, config):
        self.config = config
        self.playwright = None
        self.browser = None
        self.available = False
        self._init_browser()

    def _init_browser(self):
        """Initialize Playwright browser"""
        try:
            from playwright.sync_api import sync_playwright
            self._playwright_module = sync_playwright
            self.available = True
        except ImportError:
            if self.config.verbose:
                print(f"  {Fore.YELLOW}[DOM] Playwright not installed. DOM XSS scanning disabled.{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}[DOM] Install with: pip install playwright && playwright install chromium{Style.RESET_ALL}")
            self.available = False

    def scan_url(self, url: str) -> List[Dict]:
        """Scan a single URL for DOM XSS vulnerabilities"""
        if not self.available:
            return []

        vulnerabilities = []

        try:
            pw = self._playwright_module().__enter__()
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent=self.config.user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            page = context.new_page()

            # Step 1: Static analysis of page source for DOM patterns
            static_vulns = self._static_dom_analysis(page, url)
            vulnerabilities.extend(static_vulns)

            # Step 2: Dynamic testing with hash-based payloads
            hash_vulns = self._test_hash_injection(page, url)
            vulnerabilities.extend(hash_vulns)

            # Step 3: Dynamic testing with URL parameter payloads
            param_vulns = self._test_param_injection(page, url)
            vulnerabilities.extend(param_vulns)

            browser.close()
            pw.__exit__(None, None, None)

        except Exception as e:
            if self.config.verbose:
                print(f"  {Fore.YELLOW}[DOM] Browser error: {str(e)}{Style.RESET_ALL}")

        return vulnerabilities

    def _static_dom_analysis(self, page, url: str) -> List[Dict]:
        """Analyze page JavaScript for dangerous source-to-sink flows"""
        vulnerabilities = []

        try:
            page.goto(url, timeout=self.config.timeout * 1000, wait_until='networkidle')
            page_source = page.content()

            # Extract all inline scripts
            scripts = re.findall(r'<script[^>]*>(.*?)</script>', page_source, re.DOTALL | re.IGNORECASE)

            # Also get external script content
            script_tags = page.query_selector_all('script[src]')
            for tag in script_tags:
                try:
                    src = tag.get_attribute('src')
                    if src:
                        script_resp = page.evaluate(f"""
                            async () => {{
                                try {{
                                    const resp = await fetch('{src}');
                                    return await resp.text();
                                }} catch(e) {{ return ''; }}
                            }}
                        """)
                        if script_resp:
                            scripts.append(script_resp)
                except Exception:
                    continue

            # Analyze each script for source-to-sink patterns
            for script in scripts:
                flows = self._find_source_sink_flows(script)
                for flow in flows:
                    vulnerabilities.append({
                        'type': 'DOM XSS (Static Analysis)',
                        'severity': 'Medium',
                        'url': url,
                        'parameter': f"Source: {flow['source']}",
                        'payload': f"Sink: {flow['sink']}",
                        'method': 'DOM',
                        'detection_method': 'Static Source-Sink Analysis',
                        'details': f"Potential flow from {flow['source']} to {flow['sink']}",
                        'timestamp': ''
                    })

        except Exception as e:
            if self.config.verbose:
                print(f"  {Fore.YELLOW}[DOM] Static analysis error on {url}: {str(e)}{Style.RESET_ALL}")

        return vulnerabilities

    def _find_source_sink_flows(self, script: str) -> List[Dict]:
        """Find potential source-to-sink data flows in JavaScript"""
        flows = []

        for source in DOM_SOURCES:
            if source in script:
                for sink in DOM_SINKS:
                    if sink in script:
                        # Basic proximity check - source and sink within 500 chars
                        source_positions = [m.start() for m in re.finditer(re.escape(source), script)]
                        sink_positions = [m.start() for m in re.finditer(re.escape(sink), script)]

                        for s_pos in source_positions:
                            for k_pos in sink_positions:
                                if 0 < k_pos - s_pos < 500:
                                    flows.append({'source': source, 'sink': sink})
                                    break
                            else:
                                continue
                            break

        return flows

    def _test_hash_injection(self, page, url: str) -> List[Dict]:
        """Test DOM XSS via URL hash/fragment"""
        vulnerabilities = []

        payloads = [
            ('#<img src=x onerror=alert(1)>', 'Hash IMG XSS'),
            ('#"><img src=x onerror=alert(1)>', 'Hash Attr Break XSS'),
            ('#javascript:alert(1)', 'Hash JS Protocol'),
            ('#\';alert(1);//', 'Hash Script Break'),
        ]

        for payload_suffix, xss_type in payloads:
            test_url = url.split('#')[0] + payload_suffix

            try:
                # Set up dialog handler to catch alert()
                alert_fired = []
                page.on('dialog', lambda dialog: (alert_fired.append(True), dialog.dismiss()))

                page.goto(test_url, timeout=self.config.timeout * 1000, wait_until='domcontentloaded')
                page.wait_for_timeout(1000)  # Wait for JS execution

                if alert_fired:
                    vulnerabilities.append({
                        'type': f'DOM XSS - {xss_type}',
                        'severity': 'High',
                        'url': test_url,
                        'parameter': 'location.hash',
                        'payload': payload_suffix,
                        'method': 'DOM',
                        'detection_method': 'Headless Browser Alert Detection',
                        'timestamp': ''
                    })

                # Remove dialog listener for next iteration
                page.remove_listener('dialog', lambda d: None)

            except Exception:
                continue

        return vulnerabilities

    def _test_param_injection(self, page, url: str) -> List[Dict]:
        """Test DOM XSS via URL parameters"""
        vulnerabilities = []

        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulnerabilities

        dom_payloads = [
            ('<img src=x onerror=alert(1)>', 'Param IMG XSS'),
            ('"><img src=x onerror=alert(1)>', 'Param Attr Break XSS'),
            ("';alert(1);//", 'Param Script Break'),
        ]

        for param_name in params:
            for payload, xss_type in dom_payloads:
                test_params = dict(params)
                test_params[param_name] = [payload]

                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                try:
                    alert_fired = []
                    page.on('dialog', lambda dialog: (alert_fired.append(True), dialog.dismiss()))

                    page.goto(test_url, timeout=self.config.timeout * 1000, wait_until='domcontentloaded')
                    page.wait_for_timeout(1000)

                    if alert_fired:
                        vulnerabilities.append({
                            'type': f'DOM XSS - {xss_type}',
                            'severity': 'High',
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'method': 'DOM',
                            'detection_method': 'Headless Browser Alert Detection',
                            'timestamp': ''
                        })

                    page.remove_listener('dialog', lambda d: None)

                except Exception:
                    continue

        return vulnerabilities

    def scan_urls(self, urls: List[str]) -> List[Dict]:
        """Scan multiple URLs for DOM XSS"""
        if not self.available:
            print(f"  {Fore.YELLOW}[DOM] Playwright not available, skipping DOM XSS scan{Style.RESET_ALL}")
            return []

        all_vulns = []
        for i, url in enumerate(urls):
            if self.config.verbose:
                print(f"  {Fore.BLUE}[DOM] Scanning ({i+1}/{len(urls)}): {url}{Style.RESET_ALL}")
            vulns = self.scan_url(url)
            all_vulns.extend(vulns)
            time.sleep(self.config.delay)

        return all_vulns
