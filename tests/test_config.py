"""
Tests for the Config module.
Validates configuration validation logic.
"""

import pytest
from src.config import Config


class TestConfigValidation:
    """Test configuration validation"""

    def test_valid_config_creates_successfully(self):
        config = Config(target_url="http://example.com")
        assert config.target_url == "http://example.com"
        assert config.mode == 'auto'
        assert config.depth == 3
        assert config.threads == 5

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError, match="Mode must be"):
            Config(target_url="http://example.com", mode='invalid')

    def test_invalid_payload_level_raises(self):
        with pytest.raises(ValueError, match="Invalid payload level"):
            Config(target_url="http://example.com", payload_level='extreme')

    def test_depth_less_than_1_raises(self):
        with pytest.raises(ValueError, match="Depth must be"):
            Config(target_url="http://example.com", depth=0)

    def test_threads_too_high_raises(self):
        with pytest.raises(ValueError, match="Threads must be"):
            Config(target_url="http://example.com", threads=25)

    def test_threads_zero_raises(self):
        with pytest.raises(ValueError, match="Threads must be"):
            Config(target_url="http://example.com", threads=0)

    def test_timeout_zero_raises(self):
        with pytest.raises(ValueError, match="Timeout must be"):
            Config(target_url="http://example.com", timeout=0)

    def test_all_payload_levels_valid(self):
        for level in ['basic', 'intermediate', 'advanced', 'all']:
            config = Config(target_url="http://example.com", payload_level=level)
            assert config.payload_level == level

    def test_respect_robots_default_true(self):
        config = Config(target_url="http://example.com")
        assert config.respect_robots is True

    def test_respect_robots_can_be_disabled(self):
        config = Config(target_url="http://example.com", respect_robots=False)
        assert config.respect_robots is False
