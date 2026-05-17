"""
XSS Scanner Package - Professional Edition
"""

from .scanner import XSSScanner
from .config import Config
from .reporter import Reporter
from .context_analyzer import ContextAnalyzer
from .waf_detector import WAFDetector
from .dom_scanner import DOMScanner
from .stored_xss import StoredXSSScanner
from .param_discovery import ParamDiscovery
from .blind_xss import BlindXSSScanner
from .confidence import ConfidenceScorer
from .rate_limiter import AdaptiveRateLimiter
from .session_handler import SessionHandler

__version__ = '2.0.0'
__all__ = [
    'XSSScanner', 'Config', 'Reporter',
    'ContextAnalyzer', 'WAFDetector', 'DOMScanner',
    'StoredXSSScanner', 'ParamDiscovery', 'BlindXSSScanner',
    'ConfidenceScorer', 'AdaptiveRateLimiter', 'SessionHandler',
]
