"""
Confidence Scoring Module
Assigns confidence scores (0-100%) to detected vulnerabilities
based on evidence strength, reducing false positive noise.
"""

from typing import Dict


class ConfidenceScorer:
    """Assigns confidence scores to vulnerability findings"""

    # Base scores by detection method
    METHOD_SCORES = {
        'Unescaped Payload Reflection': 90,
        'Script Context Reflection': 85,
        'Event Handler Injection': 85,
        'JavaScript Protocol Injection': 80,
        'DOM Sink Injection': 70,
        'Headless Browser Alert Detection': 95,
        'Stored XSS Verification (marker found on re-visit)': 95,
        'Out-of-Band Callback Received': 99,
        'Static Source-Sink Analysis': 40,
        'ML-Based Detection': 60,
        'WAF Bypass Confirmed': 80,
        'Context-Aware Payload Confirmed': 85,
    }

    # Modifiers based on additional evidence
    SEVERITY_BONUS = {
        'Critical': 5,
        'High': 3,
        'Medium': 0,
        'Low': -5,
    }

    def score(self, vulnerability: Dict) -> int:
        """
        Calculate confidence score for a vulnerability.
        Returns score from 0-100.
        """
        detection_method = vulnerability.get('detection_method', '')
        severity = vulnerability.get('severity', 'Medium')
        payload = vulnerability.get('payload', '')
        response_snippet = vulnerability.get('response_snippet', '')

        # Start with base score from detection method
        base_score = self._get_base_score(detection_method)

        # Apply severity modifier
        base_score += self.SEVERITY_BONUS.get(severity, 0)

        # Evidence-based modifiers
        base_score += self._payload_complexity_bonus(payload)
        base_score += self._response_evidence_bonus(response_snippet, payload)
        base_score += self._context_bonus(vulnerability)

        # Clamp to 0-100
        return max(0, min(100, base_score))

    def _get_base_score(self, detection_method: str) -> int:
        """Get base score for detection method"""
        # Exact match
        if detection_method in self.METHOD_SCORES:
            return self.METHOD_SCORES[detection_method]

        # Partial match
        for method, score in self.METHOD_SCORES.items():
            if method.lower() in detection_method.lower():
                return score

        return 50  # Default for unknown methods

    def _payload_complexity_bonus(self, payload: str) -> int:
        """Bonus for payloads that are less likely to be false positives"""
        bonus = 0

        # Simple alert(1) payloads are more reliable indicators
        if 'alert(' in payload and len(payload) < 50:
            bonus += 5

        # Complex payloads with encoding are less reliable
        if '%' in payload or '&#' in payload:
            bonus -= 5

        # Template injection payloads need manual verification
        if '{{' in payload:
            bonus -= 10

        return bonus

    def _response_evidence_bonus(self, response_snippet: str, payload: str) -> int:
        """Bonus based on how clearly the payload appears in response"""
        if not response_snippet:
            return -10

        bonus = 0

        # Full payload reflected verbatim
        if payload in response_snippet:
            bonus += 10

        # Payload appears to be inside executable context
        if '<script' in response_snippet.lower() and payload in response_snippet:
            bonus += 5

        return bonus

    def _context_bonus(self, vulnerability: Dict) -> int:
        """Bonus based on vulnerability context"""
        bonus = 0

        # DOM XSS confirmed by browser is very reliable
        if vulnerability.get('method') == 'DOM':
            if 'Alert Detection' in vulnerability.get('detection_method', ''):
                bonus += 5

        # Stored XSS confirmed by re-visit is very reliable
        if 'Stored' in vulnerability.get('type', ''):
            if 'marker found' in vulnerability.get('detection_method', ''):
                bonus += 5

        # Blind XSS with callback is definitive
        if 'Callback' in vulnerability.get('detection_method', ''):
            bonus += 5

        return bonus

    def get_confidence_label(self, score: int) -> str:
        """Get human-readable confidence label"""
        if score >= 90:
            return "Confirmed"
        elif score >= 75:
            return "High Confidence"
        elif score >= 50:
            return "Medium Confidence"
        elif score >= 25:
            return "Low Confidence"
        else:
            return "Needs Verification"

    def filter_by_confidence(self, vulnerabilities: list, min_confidence: int = 50) -> list:
        """Filter vulnerabilities by minimum confidence score"""
        filtered = []
        for vuln in vulnerabilities:
            score = self.score(vuln)
            vuln['confidence_score'] = score
            vuln['confidence_label'] = self.get_confidence_label(score)
            if score >= min_confidence:
                filtered.append(vuln)
        return filtered

    def enrich_all(self, vulnerabilities: list) -> list:
        """Add confidence scores to all vulnerabilities without filtering"""
        for vuln in vulnerabilities:
            score = self.score(vuln)
            vuln['confidence_score'] = score
            vuln['confidence_label'] = self.get_confidence_label(score)
        return vulnerabilities
