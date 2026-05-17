"""
Adaptive Rate Limiter
Detects when the target starts throttling or blocking requests
and automatically backs off to avoid IP bans.
"""

import time
import threading
from typing import Optional
from colorama import Fore, Style


class AdaptiveRateLimiter:
    """Adaptive rate limiting with automatic backoff on throttling detection"""

    def __init__(self, config):
        self.config = config
        self.base_delay = config.delay
        self.current_delay = config.delay
        self.max_delay = 30.0  # Maximum backoff delay
        self.backoff_factor = 2.0
        self.recovery_factor = 0.8

        # Tracking
        self.consecutive_errors = 0
        self.consecutive_successes = 0
        self.total_requests = 0
        self.throttled_requests = 0
        self.blocked = False

        self._lock = threading.Lock()

    def wait(self):
        """Wait the appropriate amount of time before next request"""
        time.sleep(self.current_delay)

    def record_response(self, status_code: int, response_time: float = 0):
        """Record a response and adjust rate accordingly"""
        with self._lock:
            self.total_requests += 1

            if self._is_throttled(status_code):
                self._handle_throttle(status_code)
            elif self._is_blocked(status_code):
                self._handle_block(status_code)
            else:
                self._handle_success(response_time)

    def _is_throttled(self, status_code: int) -> bool:
        """Check if response indicates rate limiting"""
        return status_code == 429

    def _is_blocked(self, status_code: int) -> bool:
        """Check if response indicates IP blocking"""
        return status_code in [403, 503] and self.consecutive_errors > 3

    def _handle_throttle(self, status_code: int):
        """Handle rate limiting response"""
        self.consecutive_errors += 1
        self.consecutive_successes = 0
        self.throttled_requests += 1

        # Exponential backoff
        old_delay = self.current_delay
        self.current_delay = min(self.current_delay * self.backoff_factor, self.max_delay)

        if self.config.verbose:
            print(f"\n  {Fore.YELLOW}[Rate Limit] HTTP {status_code} - Backing off: {old_delay:.1f}s -> {self.current_delay:.1f}s{Style.RESET_ALL}")

    def _handle_block(self, status_code: int):
        """Handle potential IP block"""
        self.consecutive_errors += 1
        self.consecutive_successes = 0
        self.blocked = True

        # Aggressive backoff
        old_delay = self.current_delay
        self.current_delay = min(self.current_delay * self.backoff_factor * 2, self.max_delay)

        if self.config.verbose:
            print(f"\n  {Fore.RED}[Rate Limit] Possible block (HTTP {status_code}) - Heavy backoff: {old_delay:.1f}s -> {self.current_delay:.1f}s{Style.RESET_ALL}")

    def _handle_success(self, response_time: float):
        """Handle successful response - gradually recover speed"""
        self.consecutive_successes += 1
        self.consecutive_errors = 0

        # Gradually reduce delay after consecutive successes
        if self.consecutive_successes > 5 and self.current_delay > self.base_delay:
            self.current_delay = max(
                self.current_delay * self.recovery_factor,
                self.base_delay
            )
            self.blocked = False

        # If response time is very slow, slightly increase delay
        if response_time > 5.0:
            self.current_delay = min(self.current_delay * 1.2, self.max_delay)

    def get_stats(self) -> dict:
        """Get rate limiter statistics"""
        with self._lock:
            return {
                'total_requests': self.total_requests,
                'throttled_requests': self.throttled_requests,
                'current_delay': round(self.current_delay, 2),
                'base_delay': self.base_delay,
                'is_blocked': self.blocked,
                'consecutive_errors': self.consecutive_errors,
            }

    def is_safe_to_continue(self) -> bool:
        """Check if it's safe to continue scanning"""
        with self._lock:
            # If we've been blocked too many times, suggest stopping
            if self.consecutive_errors > 10:
                return False
            return True

    def reset(self):
        """Reset rate limiter to initial state"""
        with self._lock:
            self.current_delay = self.base_delay
            self.consecutive_errors = 0
            self.consecutive_successes = 0
            self.blocked = False
