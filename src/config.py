"""
Configuration Manager
Handles all scanner configuration settings
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict


@dataclass
class Config:
    """Scanner configuration"""
    # Target settings
    target_url: str
    mode: str = 'auto'  # 'auto' or 'semi'
    url_list_file: Optional[str] = None

    # Authentication
    cookie: Optional[str] = None
    headers: Optional[List[str]] = None

    # Login sequence
    login_url: Optional[str] = None
    login_username_field: str = 'username'
    login_username: Optional[str] = None
    login_password_field: str = 'password'
    login_password: Optional[str] = None
    login_csrf_field: Optional[str] = None
    login_success_indicator: Optional[str] = None

    # Spider settings
    depth: int = 3
    max_urls: int = 100
    respect_robots: bool = True

    # Payload settings
    payload_file: Optional[str] = None
    payload_level: str = 'intermediate'  # 'basic', 'intermediate', 'advanced', 'all'

    # Performance settings
    threads: int = 5
    timeout: int = 10
    delay: float = 0.5

    # Network settings
    user_agent: Optional[str] = None
    proxy: Optional[str] = None

    # Feature flags
    ml_detection: bool = False
    verbose: bool = False
    context_aware: bool = True
    waf_detection: bool = True
    dom_scan: bool = False
    stored_xss: bool = True
    param_discovery: bool = False
    blind_xss: bool = False
    adaptive_rate_limit: bool = True

    # Blind XSS settings
    callback_url: Optional[str] = None
    callback_port: int = 8888

    # Param discovery settings
    param_wordlist: Optional[str] = None

    # Confidence filtering
    min_confidence: int = 0  # 0 = show all, 50 = medium+, 75 = high+

    def __post_init__(self):
        """Validate configuration"""
        if self.mode not in ['auto', 'semi']:
            raise ValueError("Mode must be 'auto' or 'semi'")

        if self.payload_level not in ['basic', 'intermediate', 'advanced', 'all']:
            raise ValueError("Invalid payload level")

        if self.depth < 1:
            raise ValueError("Depth must be >= 1")

        if self.threads < 1 or self.threads > 20:
            raise ValueError("Threads must be between 1 and 20")

        if self.timeout < 1:
            raise ValueError("Timeout must be >= 1")

        if self.min_confidence < 0 or self.min_confidence > 100:
            raise ValueError("min_confidence must be between 0 and 100")
