"""
Session Handler Module
Supports login sequences with CSRF token extraction to maintain
authenticated sessions throughout the scan.
"""

import re
import time
from typing import Dict, Optional, List, Tuple
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style


class SessionHandler:
    """Manages authenticated sessions with automatic re-login"""

    def __init__(self, config, session: requests.Session):
        self.config = config
        self.session = session
        self.login_url: Optional[str] = None
        self.login_data: Dict[str, str] = {}
        self.csrf_field_name: Optional[str] = None
        self.success_indicator: Optional[str] = None
        self.failure_indicator: Optional[str] = None
        self.is_authenticated = False
        self.login_count = 0
        self.max_relogins = 5

    def configure_login(
        self,
        login_url: str,
        username_field: str,
        username_value: str,
        password_field: str,
        password_value: str,
        extra_fields: Optional[Dict[str, str]] = None,
        csrf_field: Optional[str] = None,
        success_indicator: Optional[str] = None,
        failure_indicator: Optional[str] = None,
    ):
        """Configure the login sequence"""
        self.login_url = login_url
        self.login_data = {
            username_field: username_value,
            password_field: password_value,
        }
        if extra_fields:
            self.login_data.update(extra_fields)

        self.csrf_field_name = csrf_field
        self.success_indicator = success_indicator
        self.failure_indicator = failure_indicator or 'invalid|incorrect|failed|error'

    def login(self) -> bool:
        """Perform login sequence"""
        if not self.login_url:
            return False

        if self.login_count >= self.max_relogins:
            print(f"  {Fore.RED}[Session] Max re-login attempts reached{Style.RESET_ALL}")
            return False

        try:
            # Step 1: GET the login page to extract CSRF token
            login_page = self.session.get(self.login_url, timeout=self.config.timeout)

            # Step 2: Extract CSRF token if configured
            if self.csrf_field_name:
                csrf_token = self._extract_csrf_token(login_page.text)
                if csrf_token:
                    self.login_data[self.csrf_field_name] = csrf_token
                else:
                    if self.config.verbose:
                        print(f"  {Fore.YELLOW}[Session] Could not find CSRF token{Style.RESET_ALL}")

            # Step 3: Submit login form
            response = self.session.post(
                self.login_url,
                data=self.login_data,
                timeout=self.config.timeout,
                allow_redirects=True
            )

            # Step 4: Verify login success
            if self._verify_login(response):
                self.is_authenticated = True
                self.login_count += 1
                if self.config.verbose:
                    print(f"  {Fore.GREEN}[Session] Login successful (attempt #{self.login_count}){Style.RESET_ALL}")
                return True
            else:
                if self.config.verbose:
                    print(f"  {Fore.RED}[Session] Login failed{Style.RESET_ALL}")
                return False

        except Exception as e:
            if self.config.verbose:
                print(f"  {Fore.RED}[Session] Login error: {str(e)}{Style.RESET_ALL}")
            return False

    def _extract_csrf_token(self, html: str) -> Optional[str]:
        """Extract CSRF token from login page"""
        soup = BeautifulSoup(html, 'html.parser')

        # Try common CSRF field names
        csrf_names = [
            self.csrf_field_name,
            'csrf_token', 'csrfmiddlewaretoken', '_token',
            'authenticity_token', '__RequestVerificationToken',
            'csrf', 'token', '_csrf_token', 'nonce',
        ]

        for name in csrf_names:
            if not name:
                continue
            # Check input fields
            field = soup.find('input', {'name': name})
            if field and field.get('value'):
                return field['value']

            # Check meta tags
            meta = soup.find('meta', {'name': name})
            if meta and meta.get('content'):
                return meta['content']

        # Try regex as fallback
        patterns = [
            r'name=["\']csrf[_-]?token["\']\s+value=["\']([^"\']+)["\']',
            r'name=["\']_token["\']\s+value=["\']([^"\']+)["\']',
            r'csrf[_-]?token["\']\s*:\s*["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _verify_login(self, response: requests.Response) -> bool:
        """Verify if login was successful"""
        # Check for success indicator
        if self.success_indicator:
            if re.search(self.success_indicator, response.text, re.IGNORECASE):
                return True

        # Check for failure indicator
        if self.failure_indicator:
            if re.search(self.failure_indicator, response.text, re.IGNORECASE):
                return False

        # Heuristic: check if we got redirected (common after login)
        if response.history and response.status_code == 200:
            return True

        # Heuristic: check for common logged-in indicators
        logged_in_indicators = ['logout', 'sign out', 'dashboard', 'welcome', 'my account']
        for indicator in logged_in_indicators:
            if indicator in response.text.lower():
                return True

        # If no clear signal, assume success if status is 200
        return response.status_code == 200

    def check_session_valid(self, response: requests.Response) -> bool:
        """Check if current session is still valid"""
        # Common session expiry indicators
        expiry_indicators = [
            'login', 'sign in', 'session expired', 'please log in',
            'unauthorized', 'authentication required'
        ]

        # Check if we got redirected to login page
        if response.history:
            for hist in response.history:
                if 'login' in hist.headers.get('Location', '').lower():
                    return False

        # Check response body for expiry indicators
        body_lower = response.text.lower()
        login_score = sum(1 for ind in expiry_indicators if ind in body_lower)

        # If multiple indicators found, session likely expired
        if login_score >= 2:
            return False

        return True

    def ensure_authenticated(self, response: requests.Response) -> bool:
        """
        Check if session is valid, re-login if needed.
        Call this after each request to maintain session.
        Returns True if session is valid (or was refreshed).
        """
        if not self.login_url:
            return True  # No login configured, always "valid"

        if self.check_session_valid(response):
            return True

        # Session expired, try to re-login
        if self.config.verbose:
            print(f"  {Fore.YELLOW}[Session] Session expired, re-authenticating...{Style.RESET_ALL}")

        self.is_authenticated = False
        return self.login()

    def get_session_info(self) -> Dict:
        """Get current session information"""
        return {
            'is_authenticated': self.is_authenticated,
            'login_url': self.login_url,
            'login_count': self.login_count,
            'cookies': dict(self.session.cookies),
        }
