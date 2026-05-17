# XSS Scanner - Project Architecture & Summary

## 📋 Project Overview

A professional-grade XSS vulnerability scanner built in Python following your exact specifications:
- ✅ Automated and semi-automated scanning modes
- ✅ Web spider for discovering URLs
- ✅ Form and parameter detection
- ✅ Comprehensive payload testing
- ✅ Live progress reporting
- ✅ ML-based detection support
- ✅ Multiple report formats (HTML, JSON, PDF)

## 🏗️ Project Structure

```
xss_scanner/
│
├── main.py                          # Main entry point with CLI
│
├── src/                             # Core source code
│   ├── __init__.py                  # Package initialization
│   ├── scanner.py                   # Main scanning engine
│   ├── spider.py                    # Web crawler module
│   ├── payloads.py                  # XSS payload manager
│   ├── detector.py                  # Vulnerability detection logic
│   ├── config.py                    # Configuration management
│   └── reporter.py                  # Report generation (HTML/JSON/PDF)
│
├── examples/                        # Example files
│   ├── urls.txt                     # Sample URL list
│   └── custom_payloads.txt          # Custom payload examples
│
├── requirements.txt                 # Python dependencies
├── README.md                        # Comprehensive documentation
├── QUICKSTART.md                    # Quick start guide
└── ARCHITECTURE.md                  # This file
```

## 🔧 Core Components

### 1. Main.py - CLI Interface
**Purpose**: Command-line interface and orchestration
**Features**:
- Argument parsing
- Configuration setup
- Scan orchestration
- Result presentation
- Report generation

**Key Functions**:
```python
def main():
    - Parse command-line arguments
    - Initialize scanner with configuration
    - Execute scan (auto or semi mode)
    - Generate reports
    - Display summary
```

### 2. Scanner.py - Core Engine
**Purpose**: Main scanning logic and coordination
**Features**:
- Automated vs semi-automated scan modes
- Multi-threaded testing
- Injection point discovery
- Vulnerability testing
- Statistics tracking

**Key Classes**:
```python
class XSSScanner:
    - scan(): Main scanning orchestrator
    - _automated_scan(): Full automated scan with spidering
    - _semi_automated_scan(): Targeted URL testing
    - _find_injection_points(): Discover testable parameters
    - _test_injection_points(): Execute XSS tests
    - _test_single_injection(): Test individual injection point
```

### 3. Spider.py - Web Crawler
**Purpose**: Automatically discover URLs and pages
**Features**:
- Recursive crawling with depth control
- Same-domain filtering
- URL deduplication
- Link extraction from HTML

**Key Functions**:
```python
class Spider:
    - crawl(): Start crawling from seed URL
    - _crawl_recursive(): Recursively discover pages
    - _extract_links(): Extract all valid links from page
```

### 4. Payloads.py - Payload Management
**Purpose**: Manage XSS testing payloads
**Features**:
- 50+ built-in XSS payloads
- Multiple payload levels (basic/intermediate/advanced)
- Custom payload support
- Payload categorization by type and severity

**Payload Categories**:
- Reflected XSS
- Event Handler XSS
- JavaScript Protocol
- Filter Bypass
- Encoding Techniques
- Template Injection
- DOM-based patterns
- WAF bypass techniques

### 5. Detector.py - Vulnerability Detection
**Purpose**: Detect XSS vulnerabilities in responses
**Features**:
- Multiple detection methods
- Pattern matching
- Context analysis
- ML-based detection (optional)

**Detection Methods**:
1. Exact payload reflection
2. Script tag detection
3. Event handler detection
4. JavaScript protocol detection
5. DOM manipulation indicators
6. Encoded payload detection
7. Content-Type header analysis
8. ML-based detection (experimental)

### 6. Reporter.py - Report Generation
**Purpose**: Generate professional vulnerability reports
**Features**:
- HTML reports with styling
- JSON reports for automation
- PDF reports (optional)
- Severity classification
- Detailed vulnerability information

**Report Sections**:
- Executive summary
- Scan statistics
- Severity breakdown
- Detailed vulnerability list
- Timestamps and metadata

## 🔄 Workflow Diagrams

### Automated Scan Flow
```
User Input → Configuration → Scanner Initialization
    ↓
Phase 1: Spidering
    ├─> Start URL
    ├─> Extract Links
    ├─> Recursive Crawl
    └─> Discovered URLs List
    ↓
Phase 2: Injection Point Discovery
    ├─> Parse URL Parameters
    ├─> Extract Forms
    ├─> Identify Input Fields
    └─> Injection Points List
    ↓
Phase 3: Vulnerability Testing
    ├─> For Each Injection Point:
    │   ├─> For Each Payload:
    │   │   ├─> Send Request
    │   │   ├─> Analyze Response
    │   │   ├─> Detect XSS
    │   │   └─> Record if Vulnerable
    │   └─> Next Payload
    └─> Next Injection Point
    ↓
Report Generation
    ├─> Compile Results
    ├─> Generate HTML
    ├─> Generate JSON
    └─> Generate PDF (optional)
```

### Semi-Automated Scan Flow
```
User Input (URLs) → Configuration → Scanner Initialization
    ↓
Phase 1: Load URLs
    ├─> Read from File (if provided)
    └─> Use Single URL
    ↓
Phase 2: Injection Point Discovery
    (Same as automated)
    ↓
Phase 3: Vulnerability Testing
    (Same as automated)
    ↓
Report Generation
    (Same as automated)
```

## 🎯 Key Features Implementation

### Multi-Threading
```python
with ThreadPoolExecutor(max_workers=config.threads) as executor:
    futures = [executor.submit(test_func, point, payload) 
               for point in points for payload in payloads]
    for future in as_completed(futures):
        result = future.result()
        if result:
            vulnerabilities.append(result)
```

### Detection Logic
```python
def detect_xss(response, payload):
    # 1. Check exact reflection
    if payload in response:
        return True, "Exact Reflection"
    
    # 2. Check for script execution
    if re.search(r'<script.*?>.*?alert.*?</script>', response):
        return True, "Script Execution"
    
    # 3. Check event handlers
    if re.search(r'on\w+=.*?alert', response):
        return True, "Event Handler"
    
    # ... more detection methods
    return False, None
```

### Live Progress Reporting
```python
total = len(injection_points) * len(payloads)
for i, result in enumerate(results):
    progress = (i / total) * 100
    print(f"Progress: {i}/{total} ({progress:.1f}%)", end='\r')
    if result:
        print(f"\n[!] VULNERABILITY FOUND: {result['url']}")
```

## 📊 Data Flow

### Input Data
```
User → CLI Arguments → Config Object
Config → Scanner → Session Configuration
URLs → Spider → Discovered URLs
Payloads → PayloadManager → Test Payloads
```

### Processing Data
```
URLs → Injection Point Discovery → Injection Points
Injection Points + Payloads → Testing → Test Results
Test Results → Detector → Vulnerability Assessment
```

### Output Data
```
Vulnerabilities → Statistics Compilation
Statistics + Vulnerabilities → Reporter
Reporter → HTML/JSON/PDF Reports
Reports → File System
Summary → Console Output
```

## 🔒 Security Considerations

### Authentication Handling
- Supports cookie-based authentication
- Custom header support (Bearer tokens, API keys)
- Session persistence throughout scan

### Rate Limiting
- Configurable delay between requests
- Thread pool size control
- Respect robots.txt (optional)

### Safe Testing
- Automatic SSL verification disable for proxies
- Timeout handling for hung requests
- Exception handling for network errors

## 🚀 Performance Optimizations

1. **Multi-threading**: Parallel testing of injection points
2. **Connection Pooling**: Reuse HTTP connections
3. **Duplicate Prevention**: Track tested vectors
4. **Early Exit**: Stop after max URLs reached
5. **Efficient Parsing**: Use lxml for HTML parsing

## 🧪 Testing Strategy

### Payload Testing
```python
# Test multiple vectors
payloads = [
    # Basic
    "<script>alert(1)</script>",
    # Event Handler  
    "<img src=x onerror=alert(1)>",
    # Filter Bypass
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    # Advanced
    "{{constructor.constructor('alert(1)')()}}"
]
```

### Detection Validation
```python
# Multiple detection methods ensure accuracy
1. Exact payload match
2. Pattern matching (regex)
3. Context analysis
4. Signature detection
5. ML classification (optional)
```

## 📈 Extensibility

### Adding New Payloads
```python
# In payloads.py
payload_manager.add_payload(
    payload="<custom>payload</custom>",
    xss_type="Custom XSS",
    severity="High"
)
```

### Adding Detection Methods
```python
# In detector.py
def _check_custom_detection(self, response, payload):
    # Your custom detection logic
    if custom_condition:
        return True
    return False
```

### Custom Report Formats
```python
# In reporter.py
def generate_custom_report(self, filename):
    # Your custom report generation
    pass
```

## 🎓 Learning Resources

### For Understanding XSS
- OWASP XSS Guide
- PortSwigger Web Security Academy
- HackerOne XSS Reports

### For Understanding the Code
- Python Threading Documentation
- BeautifulSoup Documentation
- Requests Library Documentation

## 🔮 Future Enhancements

### Planned Features
- [ ] Blind XSS detection with callback server
- [ ] Advanced DOM-based XSS testing
- [ ] Selenium integration for JavaScript rendering
- [ ] Database storage for scan history
- [ ] Web UI for management
- [ ] API for integration
- [ ] Machine learning improvements
- [ ] WebSocket testing support
- [ ] GraphQL injection testing

### Performance Improvements
- [ ] Async/await implementation
- [ ] Redis caching for discovered URLs
- [ ] Distributed scanning support
- [ ] GPU acceleration for ML detection

## 📝 Development Guidelines

### Code Style
- Follow PEP 8
- Use type hints
- Write docstrings
- Keep functions focused

### Testing
```bash
# Run tests
pytest tests/

# Check coverage
pytest --cov=src tests/

# Linting
flake8 src/
black src/
```

### Git Workflow
```bash
# Create feature branch
git checkout -b feature/new-detection-method

# Make changes and commit
git add .
git commit -m "Add new detection method"

# Push and create PR
git push origin feature/new-detection-method
```

## 📞 Support & Contribution

### Getting Help
1. Read documentation
2. Check examples
3. Review issues on GitHub
4. Ask in discussions

### Contributing
1. Fork repository
2. Create feature branch
3. Make changes
4. Write tests
5. Submit pull request

---

**Built with ❤️ for the ethical hacking community**
