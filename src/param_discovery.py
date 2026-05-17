"""
Hidden Parameter Discovery Module
Discovers hidden/undocumented parameters by brute-forcing common
parameter names against target endpoints.
"""

import time
import threading
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, urlunparse
from colorama import Fore, Style
import requests


# Common parameter names found in web applications
COMMON_PARAMS = [
    # Search & query
    'q', 'query', 'search', 's', 'keyword', 'term', 'find',
    # User input
    'id', 'uid', 'user', 'username', 'name', 'email', 'login',
    'password', 'pass', 'passwd',
    # Page & navigation
    'page', 'p', 'pg', 'url', 'uri', 'path', 'redirect', 'return',
    'returnurl', 'return_url', 'next', 'goto', 'dest', 'destination',
    'redir', 'redirect_uri', 'continue', 'callback',
    # Content
    'content', 'text', 'title', 'body', 'message', 'msg', 'comment',
    'description', 'desc', 'note', 'data', 'value', 'val',
    # Display
    'view', 'template', 'tpl', 'layout', 'theme', 'style',
    'format', 'type', 'mode', 'action', 'do', 'cmd', 'command',
    # File & resource
    'file', 'filename', 'filepath', 'path', 'dir', 'folder',
    'document', 'doc', 'image', 'img', 'src', 'source',
    'include', 'require', 'load', 'read',
    # API & data
    'api', 'key', 'token', 'auth', 'session', 'sid',
    'lang', 'language', 'locale', 'country', 'region',
    'category', 'cat', 'tag', 'label', 'group',
    # Sorting & filtering
    'sort', 'order', 'orderby', 'sortby', 'filter', 'limit',
    'offset', 'start', 'end', 'from', 'to', 'count', 'size',
    # Debug & admin
    'debug', 'test', 'admin', 'dev', 'verbose', 'trace',
    'log', 'error', 'status', 'info', 'config', 'settings',
    # JSONP & callbacks
    'callback', 'jsonp', 'cb', 'fn', 'func', 'function',
    # Misc
    'ref', 'referrer', 'origin', 'host', 'domain',
    'input', 'output', 'result', 'response', 'request',
    'param', 'args', 'option', 'opt', 'flag',
    'width', 'height', 'color', 'bg', 'font',
    'class', 'className', 'target', 'rel', 'method',
    'submit', 'btn', 'button', 'click',
    'year', 'month', 'day', 'date', 'time', 'timestamp',
    'version', 'v', 'ver', 'rev', 'build',
    'channel', 'source', 'medium', 'campaign', 'utm_source',
    'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
]


class ParamDiscovery:
    """Discovers hidden parameters on web endpoints"""

    def __init__(self, config, session: requests.Session):
        self.config = config
        self.session = session
        self.discovered_params: Dict[str, List[str]] = {}  # url -> [params]
        self._lock = threading.Lock()

    def discover(self, urls: List[str], custom_wordlist: str = None) -> Dict[str, List[str]]:
        """
        Discover hidden parameters for given URLs.
        Returns dict mapping URL -> list of discovered parameter names.
        """
        params_to_test = COMMON_PARAMS
        if custom_wordlist:
            params_to_test = self._load_wordlist(custom_wordlist)

        print(f"  {Fore.CYAN}[Param Discovery] Testing {len(params_to_test)} parameter names on {len(urls)} URLs{Style.RESET_ALL}")

        for url in urls:
            discovered = self._discover_params_for_url(url, params_to_test)
            if discovered:
                with self._lock:
                    self.discovered_params[url] = discovered
                if self.config.verbose:
                    print(f"  {Fore.GREEN}[Param Discovery] Found {len(discovered)} params on {url}: {', '.join(discovered[:5])}{Style.RESET_ALL}")

        total = sum(len(v) for v in self.discovered_params.values())
        print(f"  {Fore.GREEN}[Param Discovery] Discovered {total} hidden parameters across {len(self.discovered_params)} URLs{Style.RESET_ALL}")

        return self.discovered_params

    def _discover_params_for_url(self, url: str, params: List[str]) -> List[str]:
        """Discover which parameters a URL accepts"""
        discovered = []

        # Get baseline response
        try:
            baseline = self.session.get(url, timeout=self.config.timeout)
            baseline_length = len(baseline.text)
            baseline_status = baseline.status_code
        except Exception:
            return discovered

        # Test parameters in batches for efficiency
        batch_size = 10
        for i in range(0, len(params), batch_size):
            batch = params[i:i + batch_size]
            batch_results = self._test_param_batch(url, batch, baseline_length, baseline_status)
            discovered.extend(batch_results)
            time.sleep(self.config.delay)

        return discovered

    def _test_param_batch(self, url: str, params: List[str], baseline_length: int, baseline_status: int) -> List[str]:
        """Test a batch of parameters against a URL"""
        found = []

        # Strategy 1: Add all params at once and check for difference
        test_params = {p: 'xss_test_value' for p in params}
        parsed = urlparse(url)
        query = urlencode(test_params)
        if parsed.query:
            query = parsed.query + '&' + query
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, query, ''
        ))

        try:
            response = self.session.get(test_url, timeout=self.config.timeout)

            # If response differs significantly, test individually
            length_diff = abs(len(response.text) - baseline_length)
            if length_diff > 50 or response.status_code != baseline_status:
                # Test each param individually
                for param in params:
                    if self._test_single_param(url, param, baseline_length, baseline_status):
                        found.append(param)
            else:
                # Try reflection-based detection
                for param in params:
                    if self._test_param_reflection(url, param):
                        found.append(param)

        except Exception:
            pass

        return found

    def _test_single_param(self, url: str, param: str, baseline_length: int, baseline_status: int) -> bool:
        """Test if a single parameter causes a response difference"""
        unique_value = f"paramtest{hash(param) % 9999}"
        parsed = urlparse(url)
        query = f"{param}={unique_value}"
        if parsed.query:
            query = parsed.query + '&' + query
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, query, ''
        ))

        try:
            response = self.session.get(test_url, timeout=self.config.timeout)
            length_diff = abs(len(response.text) - baseline_length)

            # Parameter is accepted if response changes
            if length_diff > 20:
                return True
            if response.status_code != baseline_status:
                return True

        except Exception:
            pass

        return False

    def _test_param_reflection(self, url: str, param: str) -> bool:
        """Test if a parameter value is reflected in the response"""
        unique_value = f"r3fl3ct{hash(param) % 99999}"
        parsed = urlparse(url)
        query = f"{param}={unique_value}"
        if parsed.query:
            query = parsed.query + '&' + query
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, query, ''
        ))

        try:
            response = self.session.get(test_url, timeout=self.config.timeout)
            return unique_value in response.text
        except Exception:
            return False

    def _load_wordlist(self, filepath: str) -> List[str]:
        """Load custom parameter wordlist from file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"  {Fore.YELLOW}[Param Discovery] Wordlist not found: {filepath}, using defaults{Style.RESET_ALL}")
            return COMMON_PARAMS

    def get_injection_points(self) -> List[Dict]:
        """Convert discovered parameters into injection points for the scanner"""
        points = []
        for url, params in self.discovered_params.items():
            for param in params:
                points.append({
                    'type': 'url_parameter',
                    'url': f"{url}?{param}=test",
                    'parameter': param,
                    'method': 'GET',
                    'source': 'param_discovery'
                })
        return points
