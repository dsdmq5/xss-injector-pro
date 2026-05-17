"""
XSS Scanner Core Module - Professional Edition
Integrates all scanning modules: context analysis, WAF detection,
DOM scanning, stored XSS, parameter discovery, blind XSS,
confidence scoring, adaptive rate limiting, and session handling.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from typing import List, Dict, Set, Optional
from .spider import Spider
from .payloads import PayloadManager
from .detector import VulnerabilityDetector
from .context_analyzer import ContextAnalyzer
from .waf_detector import WAFDetector
from .dom_scanner import DOMScanner
from .stored_xss import StoredXSSScanner
from .param_discovery import ParamDiscovery
from .blind_xss import BlindXSSScanner
from .confidence import ConfidenceScorer
from .rate_limiter import AdaptiveRateLimiter
from .session_handler import SessionHandler


class XSSScanner:
    """Main XSS scanning engine - Professional Edition"""

    def __init__(self, config):
        self.config = config
        self.session = self._create_session()

        # Core modules
        self.spider = Spider(config, self.session)
        self.payload_manager = PayloadManager(config)
        self.detector = VulnerabilityDetector(config)

        # Advanced modules
        self.context_analyzer = ContextAnalyzer() if config.context_aware else None
        self.waf_detector = WAFDetector(self.session, config) if config.waf_detection else None
        self.dom_scanner = DOMScanner(config) if config.dom_scan else None
        self.stored_xss_scanner = StoredXSSScanner(config, self.session) if config.stored_xss else None
        self.param_discovery = ParamDiscovery(config, self.session) if config.param_discovery else None
        self.blind_xss_scanner = BlindXSSScanner(config, config.callback_url, config.callback_port) if config.blind_xss else None
        self.confidence_scorer = ConfidenceScorer()
        self.rate_limiter = AdaptiveRateLimiter(config) if config.adaptive_rate_limit else None
        self.session_handler = SessionHandler(config, self.session)

        # State
        self.vulnerabilities: List[Dict] = []
        self.stats = {
            'urls_scanned': 0,
            'forms_tested': 0,
            'parameters_tested': 0,
            'vulnerabilities_found': 0,
            'start_time': datetime.now(),
            'end_time': None,
            'scan_duration': '',
            'waf_detected': None,
            'dom_vulns_found': 0,
            'stored_vulns_found': 0,
            'blind_callbacks': 0,
            'hidden_params_found': 0,
        }

        self.tested_vectors: Set[str] = set()

        # Locks for thread safety
        self._vuln_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._vectors_lock = threading.Lock()

    def _create_session(self):
        """Create configured requests session"""
        session = requests.Session()

        headers = {
            'User-Agent': self.config.user_agent or
                         'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

        if self.config.headers:
            for header in self.config.headers:
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()

        session.headers.update(headers)

        if self.config.cookie:
            cookies = {}
            for cookie in self.config.cookie.split(';'):
                if '=' in cookie:
                    key, value = cookie.split('=', 1)
                    cookies[key.strip()] = value.strip()
            session.cookies.update(cookies)

        if self.config.proxy:
            session.proxies = {
                'http': self.config.proxy,
                'https': self.config.proxy
            }
            session.verify = False

        return session

    def get_start_time(self) -> str:
        """Get scan start time"""
        return self.stats['start_time'].strftime('%Y-%m-%d %H:%M:%S')

    def scan(self) -> Dict:
        """Main scanning orchestrator"""
        try:
            # Phase 0: Login if configured
            self._phase_login()

            # Phase 1: WAF Detection
            self._phase_waf_detection()

            # Phase 2: Spider / URL collection
            urls = self._phase_url_collection()

            # Phase 3: Parameter discovery
            extra_points = self._phase_param_discovery(urls)

            # Phase 4: Find injection points
            injection_points = self._phase_injection_detection(urls)
            injection_points.extend(extra_points)

            # Phase 5: Context-aware testing
            self._phase_xss_testing(injection_points)

            # Phase 6: DOM XSS scanning
            self._phase_dom_scan(urls)

            # Phase 7: Stored XSS verification
            self._phase_stored_xss(injection_points, urls)

            # Phase 8: Blind XSS injection
            self._phase_blind_xss(injection_points)

            # Phase 9: Confidence scoring
            self._phase_confidence_scoring()

            return self._build_results()

        finally:
            self.stats['end_time'] = datetime.now()
            duration = self.stats['end_time'] - self.stats['start_time']
            self.stats['scan_duration'] = str(duration).split('.')[0]

            # Cleanup
            if self.blind_xss_scanner:
                self.blind_xss_scanner.stop_callback_server()

    def _phase_login(self):
        """Phase 0: Authenticate if login is configured"""
        if self.config.login_url and self.config.login_username:
            print(f"{Fore.CYAN}[*] Phase 0: Authenticating...{Style.RESET_ALL}")
            self.session_handler.configure_login(
                login_url=self.config.login_url,
                username_field=self.config.login_username_field,
                username_value=self.config.login_username,
                password_field=self.config.login_password_field,
                password_value=self.config.login_password or '',
                csrf_field=self.config.login_csrf_field,
                success_indicator=self.config.login_success_indicator,
            )
            if self.session_handler.login():
                print(f"{Fore.GREEN}[+] Authentication successful{Style.RESET_ALL}\n")
            else:
                print(f"{Fore.YELLOW}[!] Authentication failed, continuing without auth{Style.RESET_ALL}\n")

    def _phase_waf_detection(self):
        """Phase 1: Detect WAF"""
        if not self.waf_detector:
            return

        print(f"{Fore.CYAN}[*] Phase 1: WAF Detection...{Style.RESET_ALL}")
        waf_result = self.waf_detector.detect(self.config.target_url)

        if waf_result['detected']:
            self.stats['waf_detected'] = waf_result['waf_name']
            print(f"{Fore.YELLOW}[!] WAF Detected: {waf_result['waf_name']} (confidence: {waf_result['confidence']:.0%}){Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] WAF evasion payloads will be included{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.GREEN}[+] No WAF detected{Style.RESET_ALL}\n")

    def _phase_url_collection(self) -> List[str]:
        """Phase 2: Collect URLs via spider or file"""
        if self.config.mode == 'auto':
            print(f"{Fore.CYAN}[*] Phase 2: Spidering target...{Style.RESET_ALL}")
            urls = self.spider.crawl(self.config.target_url)
            print(f"{Fore.GREEN}[+] Found {len(urls)} URLs{Style.RESET_ALL}\n")
        else:
            urls = []
            if self.config.url_list_file:
                print(f"{Fore.CYAN}[*] Phase 2: Loading URLs from file...{Style.RESET_ALL}")
                try:
                    with open(self.config.url_list_file, 'r', encoding='utf-8') as f:
                        urls = [line.strip() for line in f if line.strip() and line.strip().startswith('http')]
                    print(f"{Fore.GREEN}[+] Loaded {len(urls)} URLs{Style.RESET_ALL}\n")
                except FileNotFoundError:
                    print(f"{Fore.RED}[ERROR] File not found: {self.config.url_list_file}{Style.RESET_ALL}")
                    urls = [self.config.target_url]
            else:
                urls = [self.config.target_url]
                print(f"{Fore.CYAN}[*] Phase 2: Testing single URL: {self.config.target_url}{Style.RESET_ALL}\n")

        return urls

    def _phase_param_discovery(self, urls: List[str]) -> List[Dict]:
        """Phase 3: Discover hidden parameters"""
        if not self.param_discovery:
            return []

        print(f"{Fore.CYAN}[*] Phase 3: Discovering hidden parameters...{Style.RESET_ALL}")
        self.param_discovery.discover(urls, self.config.param_wordlist)
        extra_points = self.param_discovery.get_injection_points()
        self.stats['hidden_params_found'] = len(extra_points)
        print(f"{Fore.GREEN}[+] Discovered {len(extra_points)} hidden injection points{Style.RESET_ALL}\n")
        return extra_points

    def _phase_injection_detection(self, urls: List[str]) -> List[Dict]:
        """Phase 4: Find injection points"""
        print(f"{Fore.CYAN}[*] Phase 4: Detecting injection points...{Style.RESET_ALL}")
        injection_points = self._find_injection_points(urls)
        print(f"{Fore.GREEN}[+] Found {len(injection_points)} potential injection points{Style.RESET_ALL}\n")
        return injection_points

    def _phase_xss_testing(self, injection_points: List[Dict]):
        """Phase 5: Test injection points with context-aware payloads"""
        print(f"{Fore.CYAN}[*] Phase 5: Testing for XSS vulnerabilities...{Style.RESET_ALL}")

        if self.context_analyzer:
            print(f"  {Fore.CYAN}Using context-aware payload generation{Style.RESET_ALL}")

        self._test_injection_points(injection_points)

    def _phase_dom_scan(self, urls: List[str]):
        """Phase 6: DOM XSS scanning with headless browser"""
        if not self.dom_scanner or not self.dom_scanner.available:
            return

        print(f"\n{Fore.CYAN}[*] Phase 6: DOM XSS scanning (headless browser)...{Style.RESET_ALL}")
        dom_vulns = self.dom_scanner.scan_urls(urls[:20])  # Limit to 20 URLs for performance

        if dom_vulns:
            with self._vuln_lock:
                self.vulnerabilities.extend(dom_vulns)
            with self._stats_lock:
                self.stats['dom_vulns_found'] = len(dom_vulns)
                self.stats['vulnerabilities_found'] += len(dom_vulns)
            print(f"{Fore.RED}[!] Found {len(dom_vulns)} DOM XSS vulnerabilities{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] No DOM XSS found{Style.RESET_ALL}")

    def _phase_stored_xss(self, injection_points: List[Dict], urls: List[str]):
        """Phase 7: Stored XSS injection and verification"""
        if not self.stored_xss_scanner:
            return

        # Only test POST form inputs
        post_points = [p for p in injection_points if p.get('form_method') == 'post']
        if not post_points:
            return

        print(f"\n{Fore.CYAN}[*] Phase 7: Stored XSS testing...{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Injecting markers into {len(post_points)} POST endpoints...{Style.RESET_ALL}")

        injected = self.stored_xss_scanner.inject_payloads(post_points)
        print(f"  {Fore.CYAN}Injected {injected} payloads, waiting before verification...{Style.RESET_ALL}")

        # Wait a bit for stored data to propagate
        time.sleep(2)

        # Re-visit pages to check for stored payloads
        stored_vulns = self.stored_xss_scanner.verify_stored_xss(urls)

        if stored_vulns:
            with self._vuln_lock:
                self.vulnerabilities.extend(stored_vulns)
            with self._stats_lock:
                self.stats['stored_vulns_found'] = len(stored_vulns)
                self.stats['vulnerabilities_found'] += len(stored_vulns)
            print(f"{Fore.RED}[!] Confirmed {len(stored_vulns)} stored XSS vulnerabilities{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] No stored XSS confirmed{Style.RESET_ALL}")

    def _phase_blind_xss(self, injection_points: List[Dict]):
        """Phase 8: Blind XSS payload injection"""
        if not self.blind_xss_scanner:
            return

        print(f"\n{Fore.CYAN}[*] Phase 8: Blind XSS injection...{Style.RESET_ALL}")

        # Start callback server
        self.blind_xss_scanner.start_callback_server()

        # Inject blind payloads into all form inputs
        injected = 0
        for point in injection_points:
            if point.get('type') != 'form_input':
                continue

            url = point.get('url', '')
            param = point.get('parameter', '')
            form_action = point.get('form_action', '')
            form_method = point.get('form_method', 'get')

            payloads = self.blind_xss_scanner.get_payloads(url, param)

            for payload_data in payloads[:2]:  # Limit to 2 blind payloads per param
                try:
                    data = {param: payload_data['payload']}
                    if form_method == 'post':
                        self.session.post(form_action, data=data, timeout=self.config.timeout)
                    else:
                        self.session.get(form_action, params=data, timeout=self.config.timeout)
                    injected += 1
                    time.sleep(self.config.delay)
                except Exception:
                    continue

        print(f"  {Fore.CYAN}Injected {injected} blind XSS payloads{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Callback server listening on port {self.config.callback_port}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Note: Blind XSS may trigger hours/days later in admin panels{Style.RESET_ALL}")

        # Wait briefly to catch immediate callbacks
        time.sleep(3)
        callbacks = self.blind_xss_scanner.get_callbacks()
        if callbacks:
            blind_vulns = self.blind_xss_scanner.get_confirmed_vulnerabilities()
            with self._vuln_lock:
                self.vulnerabilities.extend(blind_vulns)
            with self._stats_lock:
                self.stats['blind_callbacks'] = len(callbacks)
                self.stats['vulnerabilities_found'] += len(blind_vulns)
            print(f"{Fore.RED}[!] {len(callbacks)} blind XSS callbacks received!{Style.RESET_ALL}")

    def _phase_confidence_scoring(self):
        """Phase 9: Apply confidence scores to all findings"""
        with self._vuln_lock:
            self.vulnerabilities = self.confidence_scorer.enrich_all(self.vulnerabilities)

            # Filter by minimum confidence if configured
            if self.config.min_confidence > 0:
                before = len(self.vulnerabilities)
                self.vulnerabilities = [
                    v for v in self.vulnerabilities
                    if v.get('confidence_score', 0) >= self.config.min_confidence
                ]
                filtered = before - len(self.vulnerabilities)
                if filtered > 0 and self.config.verbose:
                    print(f"  {Fore.YELLOW}[Confidence] Filtered {filtered} low-confidence findings{Style.RESET_ALL}")

        with self._stats_lock:
            self.stats['vulnerabilities_found'] = len(self.vulnerabilities)

    def _find_injection_points(self, urls: List[str]) -> List[Dict]:
        """Find all potential XSS injection points"""
        injection_points: List[Dict] = []

        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for param in params:
                        injection_points.append({
                            'type': 'url_parameter',
                            'url': url,
                            'parameter': param,
                            'method': 'GET'
                        })

                forms = self._extract_forms(url)
                for form in forms:
                    for input_field in form['inputs']:
                        injection_points.append({
                            'type': 'form_input',
                            'url': url,
                            'form_action': form['action'],
                            'form_method': form['method'],
                            'parameter': input_field['name'],
                            'input_type': input_field['type']
                        })

                with self._stats_lock:
                    self.stats['urls_scanned'] += 1

                if self.config.verbose:
                    print(f"  {Fore.BLUE}[+] Analyzed: {url}{Style.RESET_ALL}")

                if self.rate_limiter:
                    self.rate_limiter.wait()
                else:
                    time.sleep(self.config.delay)

            except Exception as e:
                if self.config.verbose:
                    print(f"  {Fore.YELLOW}[!] Error analyzing {url}: {str(e)}{Style.RESET_ALL}")

        return injection_points

    def _extract_forms(self, url: str) -> List[Dict]:
        """Extract all forms from a URL"""
        forms: List[Dict] = []

        try:
            response = self.session.get(url, timeout=self.config.timeout)

            if self.rate_limiter:
                self.rate_limiter.record_response(response.status_code)

            soup = BeautifulSoup(response.text, 'html.parser')

            for form in soup.find_all('form'):
                form_details = {
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }

                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_type = input_tag.get('type', 'text')
                    input_name = input_tag.get('name')

                    if input_name:
                        form_details['inputs'].append({
                            'name': input_name,
                            'type': input_type,
                            'value': input_tag.get('value', '')
                        })

                if form_details['inputs']:
                    forms.append(form_details)
                    with self._stats_lock:
                        self.stats['forms_tested'] += 1

        except Exception as e:
            if self.config.verbose:
                print(f"  {Fore.YELLOW}[!] Error extracting forms from {url}: {str(e)}{Style.RESET_ALL}")

        return forms

    def _test_injection_points(self, injection_points: List[Dict]):
        """Test all injection points with context-aware or standard payloads"""
        # Get base payloads
        payloads = self.payload_manager.get_payloads()

        # Add WAF evasion payloads if WAF detected
        if self.waf_detector and self.stats.get('waf_detected'):
            waf_payloads = self.waf_detector.get_evasion_payloads()
            payloads.extend(waf_payloads)

        total_tests = len(injection_points) * len(payloads)
        current_test = 0
        progress_lock = threading.Lock()

        print(f"  {Fore.CYAN}Total tests to perform: {total_tests}{Style.RESET_ALL}")

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = []

            for point in injection_points:
                # If context-aware, first probe with canary then use targeted payloads
                if self.context_analyzer:
                    context_payloads = self._get_context_payloads(point)
                    if context_payloads:
                        for payload in context_payloads:
                            future = executor.submit(self._test_single_injection, point, payload)
                            futures.append(future)
                        continue

                # Fallback to standard payloads
                for payload in payloads:
                    future = executor.submit(self._test_single_injection, point, payload)
                    futures.append(future)

            # Update total after context-aware adjustment
            total_tests = len(futures)

            for future in as_completed(futures):
                with progress_lock:
                    current_test += 1
                    if current_test % 10 == 0 or current_test == total_tests:
                        progress = (current_test / total_tests) * 100
                        print(f"  {Fore.CYAN}Progress: {current_test}/{total_tests} ({progress:.1f}%){Style.RESET_ALL}", end='\r')

                try:
                    result = future.result()
                    if result:
                        with self._vuln_lock:
                            self.vulnerabilities.append(result)
                        with self._stats_lock:
                            self.stats['vulnerabilities_found'] += 1
                        print(f"\n  {Fore.RED}[!] VULNERABILITY: {result['type']} at {result['url']}{Style.RESET_ALL}")
                except Exception as e:
                    if self.config.verbose:
                        print(f"\n  {Fore.YELLOW}[!] Test error: {str(e)}{Style.RESET_ALL}")

        print()

    def _get_context_payloads(self, injection_point: Dict) -> List[Dict]:
        """Probe injection point with canary and generate context-specific payloads"""
        try:
            canary = self.context_analyzer.get_canary()
            url = injection_point['url']
            param = injection_point.get('parameter', '')

            if injection_point['type'] == 'url_parameter':
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [canary]
                new_query = urlencode(params, doseq=True)
                probe_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                response = self.session.get(probe_url, timeout=self.config.timeout)

            elif injection_point['type'] == 'form_input':
                form_action = injection_point.get('form_action', '')
                form_method = injection_point.get('form_method', 'get')
                data = {param: canary}

                if form_method == 'post':
                    response = self.session.post(form_action, data=data, timeout=self.config.timeout)
                else:
                    response = self.session.get(form_action, params=data, timeout=self.config.timeout)
            else:
                return []

            # Analyze where canary landed
            contexts = self.context_analyzer.analyze_context(response.text)

            if contexts:
                # Generate payloads for the first detected context
                return self.context_analyzer.generate_context_payloads(contexts[0])

        except Exception:
            pass

        return []

    def _test_single_injection(self, injection_point: Dict, payload: Dict) -> Dict | None:
        """Test a single injection point with a payload (thread-safe)"""
        vector_id = f"{injection_point['url']}:{injection_point.get('parameter')}:{payload['payload']}"

        with self._vectors_lock:
            if vector_id in self.tested_vectors:
                return None
            self.tested_vectors.add(vector_id)

        with self._stats_lock:
            self.stats['parameters_tested'] += 1

        # Check rate limiter
        if self.rate_limiter and not self.rate_limiter.is_safe_to_continue():
            if self.config.verbose:
                print(f"\n  {Fore.RED}[!] Rate limiter suggests stopping{Style.RESET_ALL}")
            return None

        try:
            if injection_point['type'] == 'url_parameter':
                return self._test_url_parameter(injection_point, payload)
            elif injection_point['type'] == 'form_input':
                return self._test_form_input(injection_point, payload)
        except Exception as e:
            if self.config.verbose:
                print(f"  {Fore.YELLOW}[!] Test exception: {str(e)}{Style.RESET_ALL}")

        if self.rate_limiter:
            self.rate_limiter.wait()
        else:
            time.sleep(self.config.delay)

        return None

    def _test_url_parameter(self, injection_point: Dict, payload: Dict) -> Dict | None:
        """Test URL parameter for XSS"""
        url = injection_point['url']
        param = injection_point['parameter']

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload['payload']]

        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

        start_time = time.time()
        response = self.session.get(new_url, timeout=self.config.timeout, allow_redirects=True)
        response_time = time.time() - start_time

        if self.rate_limiter:
            self.rate_limiter.record_response(response.status_code, response_time)

        is_vulnerable, detection_method = self.detector.detect_xss(
            response.text, response.headers, payload['payload']
        )

        if is_vulnerable:
            return {
                'type': payload['type'],
                'severity': payload['severity'],
                'url': new_url,
                'parameter': param,
                'payload': payload['payload'],
                'method': 'GET',
                'detection_method': detection_method,
                'response_snippet': response.text[:500],
                'timestamp': datetime.now().isoformat()
            }

        return None

    def _test_form_input(self, injection_point: Dict, payload: Dict) -> Dict | None:
        """Test form input for XSS"""
        form_action = injection_point['form_action']
        form_method = injection_point['form_method']
        param = injection_point['parameter']

        data = {param: payload['payload']}

        start_time = time.time()
        if form_method == 'post':
            response = self.session.post(form_action, data=data, timeout=self.config.timeout, allow_redirects=True)
        else:
            response = self.session.get(form_action, params=data, timeout=self.config.timeout, allow_redirects=True)
        response_time = time.time() - start_time

        if self.rate_limiter:
            self.rate_limiter.record_response(response.status_code, response_time)

        is_vulnerable, detection_method = self.detector.detect_xss(
            response.text, response.headers, payload['payload']
        )

        if is_vulnerable:
            return {
                'type': payload['type'],
                'severity': payload['severity'],
                'url': injection_point['url'],
                'form_action': form_action,
                'parameter': param,
                'payload': payload['payload'],
                'method': form_method.upper(),
                'detection_method': detection_method,
                'response_snippet': response.text[:500],
                'timestamp': datetime.now().isoformat()
            }

        return None

    def _build_results(self) -> Dict:
        """Build final scan results"""
        return {
            'target': self.config.target_url,
            'scan_mode': self.config.mode,
            'vulnerabilities': self.vulnerabilities,
            'stats': self.stats,
            'config': {
                'payload_level': self.config.payload_level,
                'depth': self.config.depth,
                'threads': self.config.threads,
                'context_aware': self.config.context_aware,
                'waf_detection': self.config.waf_detection,
                'dom_scan': self.config.dom_scan,
                'stored_xss': self.config.stored_xss,
                'param_discovery': self.config.param_discovery,
                'blind_xss': self.config.blind_xss,
            },
            'rate_limiter_stats': self.rate_limiter.get_stats() if self.rate_limiter else None,
        }
