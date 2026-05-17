# 🚀 Quick Start Guide

## Installation (5 minutes)

### Step 1: Install Python
Make sure you have Python 3.8+ installed:
```bash
python --version
# or
python3 --version
```

### Step 2: Install Dependencies
```bash
cd xss-scanner
pip install -r requirements.txt
```

### Step 3: Verify Installation
```bash
python main.py --help
```

If you see the help menu, you're ready!

## Your First Scan (10 minutes)

### Test 1: Basic Scan
```bash
# Scan a single vulnerable test site (ONLY use test sites!)
python main.py -u http://testphp.vulnweb.com --mode auto --depth 2
```

### Test 2: Scan Specific URL
```bash
# Test a specific search parameter
python main.py -u "http://testphp.vulnweb.com/search.php?test=query" --mode semi
```

### Test 3: View the Report
After the scan completes, open the generated HTML report:
- Windows: Double-click `xss_scan_report.html`
- Mac/Linux: `open xss_scan_report.html` or `xdg-open xss_scan_report.html`

## Common Workflows

### Workflow 1: Testing Your Own Web App
```bash
# Start with low-impact scan
python main.py -u http://localhost:3000 --mode auto --depth 2 --threads 3

# Review the report

# If you find issues, test specific endpoints
python main.py -u "http://localhost:3000/search?q=test" --mode semi --payload-level all
```

### Workflow 2: Bug Bounty Testing
```bash
# Step 1: Spider the site
python main.py -u https://target.com --mode auto --depth 3 --max-urls 50

# Step 2: Collect interesting URLs from the report

# Step 3: Create urls.txt with interesting endpoints

# Step 4: Targeted testing
python main.py -u https://target.com --mode semi -l urls.txt --payload-level all
```

### Workflow 3: API Testing
```bash
# Test API endpoints with authentication
python main.py -u https://api.target.com/v1/search \
  --mode semi \
  --header "Authorization: Bearer YOUR_TOKEN" \
  --header "Content-Type: application/json"
```

## Tips for Beginners

### 1. Always Start Small
Don't scan the entire site immediately:
```bash
python main.py -u https://site.com --mode auto --depth 1 --max-urls 10
```

### 2. Use Verbose Mode to Learn
See what the scanner is doing:
```bash
python main.py -u https://site.com --mode auto --verbose
```

### 3. Test Locally First
Set up a vulnerable test environment:
```bash
# Use DVWA (Damn Vulnerable Web Application)
# Or OWASP WebGoat
# Or create your own test page
```

### 4. Check the Examples
Look at the example files:
- `examples/urls.txt` - Sample URL list
- `examples/custom_payloads.txt` - Custom payload examples

### 5. Generate Multiple Report Formats
```bash
python main.py -u https://site.com --mode auto --format all -o my_scan
# This creates: my_scan.html, my_scan.json, my_scan.pdf
```

## Common Issues & Solutions

### Issue: "No module named 'requests'"
**Solution**: Install dependencies
```bash
pip install -r requirements.txt
```

### Issue: "Permission denied"
**Solution**: Make the script executable
```bash
chmod +x main.py
```

### Issue: Scan is too slow
**Solution**: Adjust performance settings
```bash
python main.py -u https://site.com --threads 10 --depth 2 --max-urls 50
```

### Issue: Too many false positives
**Solution**: Use higher payload levels and check the detection methods
```bash
python main.py -u https://site.com --payload-level advanced
```

## Next Steps

1. ✅ Complete your first scan
2. ✅ Review the HTML report
3. ✅ Try different payload levels
4. ✅ Test with authentication
5. ✅ Create custom payloads
6. ✅ Read the full README.md
7. ✅ Join security communities

## Practice Sites (Legal to Test)

These sites are DESIGNED for security testing:
- http://testphp.vulnweb.com
- http://demo.testfire.net
- https://xss-game.appspot.com
- http://www.itsecgames.com

**NEVER test sites without permission!**

## Getting Help

1. Check `README.md` for detailed documentation
2. Run with `--verbose` to see what's happening
3. Look at the examples in the `examples/` folder
4. Check GitHub issues for common problems

---

Happy (Ethical) Hacking! 🛡️
