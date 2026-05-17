# 🎉 XSS Scanner - Complete Setup Guide

## ✅ What You've Got

A professional, full-featured XSS vulnerability scanner with:
- ✅ **Automated web spidering**
- ✅ **50+ XSS payloads** (basic to advanced)
- ✅ **Multi-threaded scanning**
- ✅ **Live progress updates**
- ✅ **Professional HTML/JSON/PDF reports**
- ✅ **Authentication support**
- ✅ **Proxy integration** (Burp Suite compatible)
- ✅ **ML-based detection** (optional)

## 📦 Installation Steps

### Step 1: Download the Project

All the files have been created. Download them from the links above.

### Step 2: Set Up Python Environment

```bash
# Check Python version (need 3.8+)
python --version

# Create a virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
# Install required packages
pip install -r requirements.txt

# Optional: Install PDF support
pip install weasyprint
```

### Step 4: Verify Installation

```bash
# Test the installation
python main.py --help

# You should see the help menu with all options
```

## 🚀 Your First Scan (5 Minutes)

### Quick Test on a Practice Site

```bash
# Scan a vulnerable test site (legal to test)
python main.py -u http://testphp.vulnweb.com --mode auto --depth 2 --max-urls 20

# This will:
# 1. Spider the website
# 2. Find injection points
# 3. Test for XSS vulnerabilities
# 4. Generate a report (xss_scan_report.html)
```

### View the Report

Open `xss_scan_report.html` in your browser to see:
- Executive summary
- Vulnerability statistics
- Detailed findings with payloads
- Severity classifications

## 📖 Common Usage Patterns

### Pattern 1: Testing Your Own Application

```bash
# Test your local development server
python main.py -u http://localhost:3000 \
  --mode auto \
  --depth 3 \
  --threads 5 \
  --output my_app_scan

# With authentication
python main.py -u http://localhost:3000 \
  --mode auto \
  --cookie "session=your_session_token"
```

### Pattern 2: Testing Specific Endpoints

```bash
# Create urls.txt with your target URLs
echo "http://example.com/search?q=test" > urls.txt
echo "http://example.com/comment?id=123" >> urls.txt

# Test those specific URLs
python main.py -u http://example.com \
  --mode semi \
  -l urls.txt \
  --payload-level advanced
```

### Pattern 3: Testing with Burp Suite

```bash
# Start Burp Suite and configure proxy on 127.0.0.1:8080

# Run scanner through Burp
python main.py -u https://target.com \
  --mode auto \
  --proxy http://127.0.0.1:8080

# Now you can see all requests in Burp!
```

### Pattern 4: Bug Bounty Workflow

```bash
# Step 1: Light reconnaissance
python main.py -u https://target.com \
  --mode auto \
  --depth 2 \
  --max-urls 50 \
  --payload-level basic

# Step 2: Review findings

# Step 3: Deep dive on interesting endpoints
python main.py -u "https://target.com/vulnerable-endpoint?param=value" \
  --mode semi \
  --payload-level all \
  --format all
```

## 🎓 Understanding the Output

### Console Output

```
[*] Phase 1: Spidering target...
[✓] Found 45 URLs

[*] Phase 2: Detecting injection points...
[✓] Found 23 potential injection points

[*] Phase 3: Testing for XSS vulnerabilities...
Progress: 150/230 (65.2%)
[!] VULNERABILITY FOUND: Reflected XSS at http://target.com/search?q=test

📊 Scan Summary:
  • URLs Scanned: 45
  • Forms Tested: 12
  • Parameters Tested: 230
  • Vulnerabilities Found: 3
```

### Report Sections

1. **Executive Summary**
   - Total URLs scanned
   - Forms and parameters tested
   - Vulnerability count

2. **Severity Breakdown**
   - Critical: Immediate action required
   - High: Serious vulnerabilities
   - Medium: Should be fixed
   - Low: Minor issues

3. **Detailed Findings**
   - Each vulnerability with:
     - Type of XSS
     - Affected URL
     - Vulnerable parameter
     - Working payload
     - Detection method

## ⚙️ Configuration Options

### Scanning Depth & Speed

```bash
# Fast scan (shallow)
python main.py -u https://target.com --depth 1 --max-urls 20 --threads 10

# Thorough scan (deep)
python main.py -u https://target.com --depth 5 --max-urls 200 --threads 3

# Balanced (recommended)
python main.py -u https://target.com --depth 3 --max-urls 100 --threads 5
```

### Payload Levels

```bash
# Basic (fast, common payloads)
--payload-level basic

# Intermediate (recommended, balanced)
--payload-level intermediate

# Advanced (thorough, includes filter bypasses)
--payload-level advanced

# All (comprehensive, slowest)
--payload-level all
```

### Authentication Methods

```bash
# Cookie-based
--cookie "session=abc123; user_id=456"

# Bearer token
--header "Authorization: Bearer eyJhbGc..."

# API key
--header "X-API-Key: your_api_key"

# Multiple headers
--header "Authorization: Bearer token" --header "X-Custom: value"
```

## 🎯 Best Practices

### 1. Always Get Permission
```bash
# Document your authorization
echo "I have permission to test target.com" > authorization.txt
echo "Authorized by: security@target.com" >> authorization.txt
echo "Date: $(date)" >> authorization.txt
```

### 2. Start Small, Scale Up
```bash
# Step 1: Single URL test
python main.py -u "https://target.com/search?q=test" --mode semi

# Step 2: Small automated scan
python main.py -u https://target.com --mode auto --depth 2 --max-urls 20

# Step 3: Full scan (if Step 2 looks good)
python main.py -u https://target.com --mode auto --depth 5 --max-urls 200
```

### 3. Respect Rate Limits
```bash
# Be gentle with the server
python main.py -u https://target.com \
  --threads 3 \
  --delay 1.0 \
  --timeout 30
```

### 4. Save Your Work
```bash
# Generate all report formats with timestamped names
python main.py -u https://target.com \
  --mode auto \
  --format all \
  --output scan_$(date +%Y%m%d_%H%M%S)
```

### 5. Use Verbose Mode for Debugging
```bash
# See exactly what's happening
python main.py -u https://target.com --mode auto --verbose
```

## 🐛 Troubleshooting

### Problem: "Connection refused" or "Timeout"

**Solution 1**: Increase timeout
```bash
python main.py -u https://target.com --timeout 30
```

**Solution 2**: Reduce threads
```bash
python main.py -u https://target.com --threads 1 --delay 2.0
```

### Problem: "No vulnerabilities found" but site is vulnerable

**Solution 1**: Try all payload levels
```bash
python main.py -u https://target.com --payload-level all
```

**Solution 2**: Test specific parameter directly
```bash
python main.py -u "https://target.com/page?vulnerable_param=test" --mode semi
```

### Problem: Too many false positives

**Solution**: Review detection methods in report
- Look for "Exact Payload Reflection" (most reliable)
- Check the "Response Snippet" in detailed view
- Manually verify suspicious findings

### Problem: SSL Certificate errors

**Solution**: This usually happens with proxies
```bash
# The tool handles this automatically with --proxy flag
python main.py -u https://target.com --proxy http://127.0.0.1:8080
```

## 📚 Next Steps

### 1. Read the Documentation
- `README.md` - Complete feature documentation
- `QUICKSTART.md` - Quick reference guide
- `ARCHITECTURE.md` - Technical details

### 2. Practice on Legal Test Sites
- http://testphp.vulnweb.com
- http://demo.testfire.net
- https://xss-game.appspot.com

### 3. Customize Your Scanner
- Add custom payloads: `examples/custom_payloads.txt`
- Create URL lists: `examples/urls.txt`
- Modify detection logic: `src/detector.py`

### 4. Join the Community
- Report bugs
- Share your findings
- Contribute improvements

## 🎁 Bonus Tips

### Tip 1: Combine with Other Tools

```bash
# Use with subfinder for subdomain discovery
subfinder -d target.com > subdomains.txt

# Convert to full URLs
cat subdomains.txt | sed 's/^/https:\/\//' > urls.txt

# Scan all subdomains
python main.py -u https://target.com --mode semi -l urls.txt
```

### Tip 2: Automate Regular Scans

```bash
#!/bin/bash
# scan_daily.sh

DATE=$(date +%Y%m%d)
python main.py -u https://myapp.com \
  --mode auto \
  --depth 3 \
  --format all \
  --output "daily_scan_$DATE"

# Add to crontab: 0 2 * * * /path/to/scan_daily.sh
```

### Tip 3: Create Custom Payload Sets

```bash
# For specific frameworks
echo "<%= system('alert(1)') %>" > rails_payloads.txt
echo "{{7*7}}" >> rails_payloads.txt

python main.py -u https://rails-app.com \
  --mode auto \
  --payloads rails_payloads.txt
```

## 🛡️ Ethical Hacking Reminder

**ALWAYS REMEMBER:**
1. ✅ Only test systems you own or have written permission to test
2. ✅ Document your authorization
3. ✅ Test responsibly (don't DoS the server)
4. ✅ Report findings privately to site owners
5. ✅ Give them time to fix (90 days standard)
6. ✅ Follow responsible disclosure guidelines

**NEVER:**
- ❌ Test without permission
- ❌ Use for malicious purposes
- ❌ Expose vulnerabilities publicly before they're fixed
- ❌ Cause damage or disruption

## 📞 Getting Help

1. **Check Documentation**: README.md covers 99% of questions
2. **Run with --verbose**: See what's happening
3. **Check Examples**: Look at example files
4. **Read Error Messages**: They usually tell you what's wrong
5. **Test on Practice Sites**: Verify your setup works

## 🎊 You're Ready!

You now have a professional XSS scanner. Here's your first mission:

```bash
# Test on a practice site
python main.py -u http://testphp.vulnweb.com \
  --mode auto \
  --depth 2 \
  --format html \
  --output my_first_scan

# Open my_first_scan.html and explore!
```

**Good luck and happy (ethical) hacking!** 🛡️

---

*Remember: Great power comes with great responsibility!*
