"""
Tests for the Payload Manager.
Validates payload loading and level filtering.
"""

import pytest
import tempfile
import os
from src.payloads import PayloadManager
from src.config import Config


@pytest.fixture
def basic_config():
    return Config(target_url="http://example.com", payload_level='basic')


@pytest.fixture
def intermediate_config():
    return Config(target_url="http://example.com", payload_level='intermediate')


@pytest.fixture
def advanced_config():
    return Config(target_url="http://example.com", payload_level='advanced')


@pytest.fixture
def all_config():
    return Config(target_url="http://example.com", payload_level='all')


class TestPayloadLevels:
    """Test that payload levels load correct number of payloads"""

    def test_basic_payloads_loaded(self, basic_config):
        pm = PayloadManager(basic_config)
        payloads = pm.get_payloads()
        assert len(payloads) > 0
        assert len(payloads) < 20  # Basic should be small set

    def test_intermediate_includes_basic(self, basic_config, intermediate_config):
        basic_pm = PayloadManager(basic_config)
        inter_pm = PayloadManager(intermediate_config)
        assert len(inter_pm.get_payloads()) > len(basic_pm.get_payloads())

    def test_advanced_includes_intermediate(self, intermediate_config, advanced_config):
        inter_pm = PayloadManager(intermediate_config)
        adv_pm = PayloadManager(advanced_config)
        assert len(adv_pm.get_payloads()) > len(inter_pm.get_payloads())

    def test_all_equals_advanced(self, advanced_config, all_config):
        adv_pm = PayloadManager(advanced_config)
        all_pm = PayloadManager(all_config)
        assert len(all_pm.get_payloads()) == len(adv_pm.get_payloads())


class TestPayloadStructure:
    """Test payload dict structure"""

    def test_payload_has_required_keys(self, basic_config):
        pm = PayloadManager(basic_config)
        for payload in pm.get_payloads():
            assert 'payload' in payload
            assert 'type' in payload
            assert 'severity' in payload

    def test_severity_values_are_valid(self, advanced_config):
        pm = PayloadManager(advanced_config)
        valid_severities = {'Critical', 'High', 'Medium', 'Low'}
        for payload in pm.get_payloads():
            assert payload['severity'] in valid_severities


class TestCustomPayloads:
    """Test custom payload file loading"""

    def test_load_custom_payloads_from_file(self):
        # Create a temp file with custom payloads
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write("<script>alert('custom1')</script>\n")
            f.write("<img src=x onerror=alert('custom2')>\n")
            f.write("\n")  # Empty line should be skipped
            f.write("<svg onload=alert('custom3')>\n")
            temp_path = f.name

        try:
            config = Config(target_url="http://example.com", payload_file=temp_path)
            pm = PayloadManager(config)
            payloads = pm.get_payloads()
            assert len(payloads) == 3
            assert payloads[0]['payload'] == "<script>alert('custom1')</script>"
            assert payloads[0]['type'] == 'Custom XSS'
        finally:
            os.unlink(temp_path)

    def test_missing_custom_file_falls_back_to_defaults(self):
        config = Config(target_url="http://example.com", payload_file="nonexistent_file.txt")
        pm = PayloadManager(config)
        # Should fall back to default payloads
        assert len(pm.get_payloads()) > 0


class TestAddPayload:
    """Test dynamic payload addition"""

    def test_add_payload(self, basic_config):
        pm = PayloadManager(basic_config)
        initial_count = len(pm.get_payloads())
        pm.add_payload("<custom>test</custom>", "Custom Type", "High")
        assert len(pm.get_payloads()) == initial_count + 1
        assert pm.get_payloads()[-1]['payload'] == "<custom>test</custom>"
