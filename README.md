# 🛡️ XSS Vulnerability Scanner

A comprehensive, professional-grade Cross-Site Scripting (XSS) vulnerability scanner built in Python for ethical hacking and security testing purposes.

## ⚠️ Legal Disclaimer

**THIS TOOL IS FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING ONLY**

- Only use this tool on systems you own or have explicit written permission to test
- Unauthorized testing is illegal and unethical
- The authors are not responsible for misuse of this tool
- Always follow responsible disclosure practices

## 🌟 Features

### Core Capabilities
- ✅ **Automated Web Spidering**: Crawls websites automatically to discover all pages and URLs
- ✅ **Form Detection**: Identifies all input forms and parameters
- ✅ **Comprehensive Payload Library**: 50+ XSS payloads covering multiple attack vectors
- ✅ **Multi-threaded Scanning**: Fast concurrent testing with configurable thread count
- ✅ **Smart Detection**: Multiple detection methods including pattern matching and context analysis
- ✅ **Live Progress Reporting**: Real-time updates during scanning
- ✅ **Professional Reports**: Generate HTML, JSON, and PDF reports
- ✅ **Authentication Support**: Test authenticated areas with cookies and custom headers
- ✅ **Proxy Support**: Route traffic through Burp Suite or other proxies

### Scanning Modes
1. **Automated Mode**: Full automated scan with web spider
2. **Semi-Automated Mode**: Test specific URLs from a file or single URL

### XSS Detection Types
- Reflected XSS
- Stored XSS (Basic detection)
- DOM-based XSS indicators
- Event Handler Injection
- JavaScript Protocol Injection
- Template Injection
- Filter Bypass Techniques

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Step 1: Clone the Repository
```bash
git clone https://github.com/yourusername/xss-scanner.git
cd xss-scanner
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Optional: Install PDF Support
```bash
pip install weasyprint
```

## 🚀 Quick Start

### Basic Automated Scan
```bash
python main.py -u https://example.com --mode auto
```

### Semi-Automated Scan with URL List
```bash
python main.py -u https://example.com --mode semi -l urls.txt
```

### Scan with Authentication
```bash
python main.py -u https://example.com --cookie "session=abc123" --mode auto
```

## 📖 Usage Examples

### Example 1: Simple Automated Scan
```bash
python main.py -u https://testsite.com --mode auto
```

### Example 2: Deep Scan with Custom Depth
```bash
python main.py -u https://testsite.com --mode auto --depth 5 --max-urls 200
```

### Example 3: Scan with Custom Headers
```bash
python main.py -u https://testsite.com --mode auto \
  --header "Authorization: Bearer YOUR_TOKEN" \
  --header "X-Custom-Header: value"
```

### Example 4: Advanced Payload Testing
```bash
python main.py -u https://testsite.com --mode auto \
  --payload-level advanced \
  --threads 10
```

### Example 5: Test Specific URLs
Create a file `urls.txt`:
```
https://example.com/search?q=test
https://example.com/profile?id=123
https://example.com/comment?post=456
```

Then run:
```bash
python main.py -u https://example.com --mode semi -l urls.txt
```

### Example 6: Scan Through Proxy (Burp Suite)
```bash
python main.py -u https://testsite.com --mode auto \
  --proxy http://127.0.0.1:8080
```

### Example 7: Custom Payloads
Create `custom_payloads.txt`:
```
<script>alert('Custom XSS')</script>
<img src=x onerror=alert('Custom')>
'><svg onload=alert('Custom')>
```

Then run:
```bash
python main.py -u https://testsite.com --mode semi \
  --payloads custom_payloads.txt
```

### Example 8: Generate All Report Formats
```bash
python main.py -u https://testsite.com --mode auto \
  --format all \
  -o my_scan_report
```

## 🎛️ Command-Line Options

### Required Arguments
```
-u, --url               Target URL (e.g., https://example.com)
```

### Scan Mode
```
--mode                  Scan mode: 'auto' or 'semi' (default: auto)
-l, --url-list          File containing URLs to test (for semi-auto mode)
```

### Authentication
```
--cookie                Cookie string for authentication
--header                Custom headers (can be used multiple times)
```

### Spider Options
```
--depth                 Spider crawl depth (default: 3)
--max-urls              Maximum URLs to crawl (default: 100)
```

### Payload Options
```
--payloads              Custom payload file
--payload-level         Payload complexity: basic/intermediate/advanced/all
```

### Performance
```
--threads               Number of concurrent threads (default: 5)
--timeout               Request timeout in seconds (default: 10)
--delay                 Delay between requests (default: 0.5)
```

### Output
```
-o, --output            Output report filename (default: xss_scan_report)
--format                Report format: html/json/pdf/all (default: html)
```

### Advanced
```
--user-agent            Custom User-Agent string
--proxy                 Proxy URL (e.g., http://127.0.0.1:8080)
--ml-detection          Enable ML-based detection (experimental)
--verbose               Enable verbose output
--examples              Show usage examples
```

## 📊 Understanding Reports

### HTML Report Sections
1. **Executive Summary**: Overview of scan statistics
2. **Severity Breakdown**: Vulnerabilities categorized by severity
3. **Detailed Report**: Complete list of found vulnerabilities with:
   - Severity level
   - XSS type
   - Vulnerable URL
   - Parameter name
   - Payload used
   - Detection method

### Severity Levels
- **Critical**: Immediate risk, allows cookie theft or session hijacking
- **High**: Allows JavaScript execution
- **Medium**: Requires specific conditions
- **Low**: Limited impact or requires user interaction

## 🎯 Best Practices

### 1. Always Get Permission
```bash
# Only test sites you own or have permission for
echo "I confirm I have permission to test this site" > permission.txt
```

### 2. Start with Low Impact
```bash
# Start with basic payloads first
python main.py -u https://site.com --payload-level basic
```

### 3. Use Rate Limiting
```bash
# Don't overwhelm the server
python main.py -u https://site.com --threads 3 --delay 1.0
```

### 4. Test in Stages
```bash
# Stage 1: Single URL test
python main.py -u "https://site.com/search?q=test" --mode semi

# Stage 2: Limited automated scan
python main.py -u https://site.com --mode auto --depth 2 --max-urls 20

# Stage 3: Full scan (if authorized)
python main.py -u https://site.com --mode auto --depth 5
```

### 5. Save Your Work
```bash
# Always generate reports
python main.py -u https://site.com --mode auto --format all -o scan_$(date +%Y%m%d)
```

## 🔧 Troubleshooting

### Issue: "Connection timeout"
**Solution**: Increase timeout or check network connectivity
```bash
python main.py -u https://site.com --timeout 30
```

### Issue: "Too many requests / Rate limited"
**Solution**: Reduce threads and increase delay
```bash
python main.py -u https://site.com --threads 1 --delay 2.0
```

### Issue: "SSL Certificate Error"
**Solution**: This happens when using a proxy like Burp Suite
```bash
# The tool automatically disables SSL verification when using --proxy
python main.py -u https://site.com --proxy http://127.0.0.1:8080
```

### Issue: "No vulnerabilities found on vulnerable site"
**Solution**: Try different payload levels
```bash
python main.py -u https://site.com --payload-level all
```

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Authors

- **Ethical Hacking Tool Development Team**

## 🙏 Acknowledgments

- OWASP for XSS testing methodologies
- Bug bounty community for payload techniques
- Security researchers for vulnerability patterns

## 📚 Additional Resources

### Learning Resources
- [OWASP XSS Guide](https://owasp.org/www-community/attacks/xss/)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [HackerOne XSS Reports](https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPXSS.md)

### Related Tools
- Burp Suite
- OWASP ZAP
- XSStrike
- Dalfox

## ⚡ Performance Tips

1. **Optimize Thread Count**: More threads = faster, but respect server resources
2. **Adjust Depth**: Lower depth = faster scanning
3. **Use Semi-Auto Mode**: For specific testing, skip the spider
4. **Custom Payloads**: Use targeted payloads for known vulnerabilities

## 🔒 Responsible Disclosure

If you find vulnerabilities using this tool:

1. **Document the vulnerability** with screenshots and steps to reproduce
2. **Contact the site owner** privately (not publicly)
3. **Give them time to fix** (typically 90 days)
4. **Follow up** if no response
5. **Disclose publicly** only after fix or 90 days (if appropriate)

## 📞 Support

For questions or issues:
- Open an issue on GitHub
- Check existing issues for solutions
- Read the documentation thoroughly

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**

🛡️ **Happy (Ethical) Hacking!** 🛡️
