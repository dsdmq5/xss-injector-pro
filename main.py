#!/usr/bin/env python3
"""
XSS Vulnerability Scanner - Professional Edition
A comprehensive tool for detecting all types of Cross-Site Scripting vulnerabilities.
Features: Context-aware analysis, WAF detection/bypass, DOM XSS, Stored XSS,
           Blind XSS, Parameter discovery, Confidence scoring, Adaptive rate limiting.

Author: Ethical Hacking Tool
Purpose: Educational and authorized security testing only
"""

import argparse
import sys
from colorama import init, Fore, Style
from src.scanner import XSSScanner
from src.config import Config
from src.reporter import Reporter
import warnings

init(autoreset=True)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


def print_banner():
    """Display tool banner"""
    banner = f"""
{Fore.CYAN}+===============================================================+
|                                                               |
|           XSS VULNERABILITY SCANNER - PRO EDITION             |
|                                                               |
|              Ethical Hacking & Security Testing               |
|                   Version 2.0.0 - 2025                        |
|                                                               |
+===============================================================+{Style.RESET_ALL}

{Fore.YELLOW}WARNING: Use only on systems you own or have permission to test!{Style.RESET_ALL}
{Fore.YELLOW}    Unauthorized testing is illegal and unethical.{Style.RESET_ALL}
"""
    print(banner)


def print_usage_examples():
    """Display usage examples"""
    examples = f"""
{Fore.GREEN}Usage Examples:{Style.RESET_ALL}

  {Fore.CYAN}# Basic automated scan{Style.RESET_ALL}
  python main.py -u https://example.com --mode auto

  {Fore.CYAN}# Full professional scan (all features){Style.RESET_ALL}
  python main.py -u https://example.com --mode auto --dom-scan --param-discovery --blind-xss

  {Fore.CYAN}# Scan with login sequence{Style.RESET_ALL}
  python main.py -u https://example.com --mode auto \\
    --login-url https://example.com/login \\
    --login-user admin --login-pass secret123

  {Fore.CYAN}# Scan with WAF evasion and context analysis{Style.RESET_ALL}
  python main.py -u https://example.com --mode auto --payload-level advanced

  {Fore.CYAN}# DOM XSS scan with headless browser{Style.RESET_ALL}
  python main.py -u https://example.com --mode auto --dom-scan

  {Fore.CYAN}# Blind XSS with callback server{Style.RESET_ALL}
  python main.py -u https://example.com --mode auto --blind-xss \\
    --callback-url http://your-server.com:8888

  {Fore.CYAN}# Hidden parameter discovery{Style.RESET_ALL}
  python main.py -u https://example.com --mode auto --param-discovery

  {Fore.CYAN}# High-confidence results only{Style.RESET_ALL}
  python main.py -u https://example.com --mode auto --min-confidence 75

  {Fore.CYAN}# Ignore robots.txt{Style.RESET_ALL}
  python main.py -u https://example.com --mode auto --no-robots
"""
    print(examples)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='XSS Vulnerability Scanner Pro - Ethical Hacking Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Remember: Only test systems you own or have explicit permission to test!'
    )

    # === Required ===
    parser.add_argument('-u', '--url', required=True, help='Target URL')

    # === Scan Mode ===
    parser.add_argument('--mode', choices=['auto', 'semi'], default='auto',
                        help='Scan mode: auto or semi (default: auto)')
    parser.add_argument('-l', '--url-list', help='File containing URLs (semi mode)')

    # === Authentication ===
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('--cookie', help='Cookie string (e.g., "session=abc123")')
    auth_group.add_argument('--header', action='append', help='Custom header (repeatable)')
    auth_group.add_argument('--login-url', help='Login page URL for session handling')
    auth_group.add_argument('--login-user', help='Login username')
    auth_group.add_argument('--login-pass', help='Login password')
    auth_group.add_argument('--login-user-field', default='username', help='Username field name (default: username)')
    auth_group.add_argument('--login-pass-field', default='password', help='Password field name (default: password)')
    auth_group.add_argument('--login-csrf-field', help='CSRF token field name')
    auth_group.add_argument('--login-success', help='Regex to match on successful login')

    # === Spider ===
    spider_group = parser.add_argument_group('Spider Options')
    spider_group.add_argument('--depth', type=int, default=3, help='Crawl depth (default: 3)')
    spider_group.add_argument('--max-urls', type=int, default=100, help='Max URLs to crawl (default: 100)')
    spider_group.add_argument('--no-robots', action='store_true', help='Ignore robots.txt')

    # === Payloads ===
    payload_group = parser.add_argument_group('Payload Options')
    payload_group.add_argument('--payloads', help='Custom payload file')
    payload_group.add_argument('--payload-level', choices=['basic', 'intermediate', 'advanced', 'all'],
                               default='intermediate', help='Payload level (default: intermediate)')

    # === Advanced Features ===
    feature_group = parser.add_argument_group('Advanced Features')
    feature_group.add_argument('--dom-scan', action='store_true',
                               help='Enable DOM XSS scanning (requires playwright)')
    feature_group.add_argument('--param-discovery', action='store_true',
                               help='Enable hidden parameter discovery')
    feature_group.add_argument('--param-wordlist', help='Custom parameter wordlist file')
    feature_group.add_argument('--blind-xss', action='store_true',
                               help='Enable blind XSS with callback server')
    feature_group.add_argument('--callback-url', help='External callback URL for blind XSS')
    feature_group.add_argument('--callback-port', type=int, default=8888,
                               help='Callback server port (default: 8888)')
    feature_group.add_argument('--no-waf-detect', action='store_true',
                               help='Disable WAF detection')
    feature_group.add_argument('--no-context', action='store_true',
                               help='Disable context-aware payload generation')
    feature_group.add_argument('--no-stored', action='store_true',
                               help='Disable stored XSS verification')
    feature_group.add_argument('--min-confidence', type=int, default=0,
                               help='Minimum confidence score (0-100, default: 0 = show all)')

    # === Performance ===
    perf_group = parser.add_argument_group('Performance')
    perf_group.add_argument('--threads', type=int, default=5, help='Threads (default: 5)')
    perf_group.add_argument('--timeout', type=int, default=10, help='Timeout seconds (default: 10)')
    perf_group.add_argument('--delay', type=float, default=0.5, help='Delay between requests (default: 0.5)')
    perf_group.add_argument('--no-rate-limit', action='store_true',
                            help='Disable adaptive rate limiting')

    # === Output ===
    output_group = parser.add_argument_group('Output')
    output_group.add_argument('-o', '--output', default='xss_scan_report', help='Report filename')
    output_group.add_argument('--format', choices=['html', 'json', 'pdf', 'all'],
                              default='html', help='Report format (default: html)')

    # === Misc ===
    parser.add_argument('--user-agent', help='Custom User-Agent')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--ml-detection', action='store_true', help='Enable ML detection (experimental)')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--examples', action='store_true', help='Show examples and exit')

    args = parser.parse_args()

    if args.examples:
        print_usage_examples()
        sys.exit(0)

    print_banner()

    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[ERROR] URL must start with http:// or https://{Style.RESET_ALL}")
        sys.exit(1)

    if args.mode == 'semi' and not args.url_list:
        print(f"{Fore.YELLOW}[WARNING] Semi-auto mode works best with --url-list{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}          Scanning single URL: {args.url}{Style.RESET_ALL}\n")

    try:
        config = Config(
            target_url=args.url,
            mode=args.mode,
            url_list_file=args.url_list,
            cookie=args.cookie,
            headers=args.header,
            # Login
            login_url=args.login_url,
            login_username_field=args.login_user_field,
            login_username=args.login_user,
            login_password_field=args.login_pass_field,
            login_password=args.login_pass,
            login_csrf_field=args.login_csrf_field,
            login_success_indicator=args.login_success,
            # Spider
            depth=args.depth,
            max_urls=args.max_urls,
            respect_robots=not args.no_robots,
            # Payloads
            payload_file=args.payloads,
            payload_level=args.payload_level,
            # Performance
            threads=args.threads,
            timeout=args.timeout,
            delay=args.delay,
            # Network
            user_agent=args.user_agent,
            proxy=args.proxy,
            # Features
            ml_detection=args.ml_detection,
            verbose=args.verbose,
            context_aware=not args.no_context,
            waf_detection=not args.no_waf_detect,
            dom_scan=args.dom_scan,
            stored_xss=not args.no_stored,
            param_discovery=args.param_discovery,
            blind_xss=args.blind_xss,
            adaptive_rate_limit=not args.no_rate_limit,
            # Blind XSS
            callback_url=args.callback_url,
            callback_port=args.callback_port,
            # Param discovery
            param_wordlist=args.param_wordlist,
            # Confidence
            min_confidence=args.min_confidence,
        )

        # Print active features
        print(f"\n{Fore.CYAN}[*] Active Features:{Style.RESET_ALL}")
        features = []
        if config.context_aware:
            features.append("Context-Aware Payloads")
        if config.waf_detection:
            features.append("WAF Detection")
        if config.dom_scan:
            features.append("DOM XSS (Headless Browser)")
        if config.stored_xss:
            features.append("Stored XSS Verification")
        if config.param_discovery:
            features.append("Parameter Discovery")
        if config.blind_xss:
            features.append("Blind XSS (Callback)")
        if config.adaptive_rate_limit:
            features.append("Adaptive Rate Limiting")
        if config.login_url:
            features.append("Session Handling")
        if config.respect_robots:
            features.append("Robots.txt Compliance")

        for f in features:
            print(f"  {Fore.GREEN}[+] {f}{Style.RESET_ALL}")

        # Initialize and run scanner
        print(f"\n{Fore.CYAN}[*] Initializing XSS Scanner Pro...{Style.RESET_ALL}")
        scanner = XSSScanner(config)

        print(f"{Fore.CYAN}[*] Starting {args.mode.upper()} mode scan on: {args.url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scan started at: {scanner.get_start_time()}{Style.RESET_ALL}\n")

        results = scanner.scan()

        # Generate reports
        print(f"\n{Fore.CYAN}[*] Generating report...{Style.RESET_ALL}")
        reporter = Reporter(results, config)

        report_files = []
        if args.format in ['html', 'all']:
            report_files.append(reporter.generate_html_report(args.output))
        if args.format in ['json', 'all']:
            report_files.append(reporter.generate_json_report(args.output))
        if args.format in ['pdf', 'all']:
            pdf = reporter.generate_pdf_report(args.output)
            if pdf:
                report_files.append(pdf)

        # Print summary
        print(f"\n{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Scan completed successfully!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}\n")

        print(f"{Fore.CYAN}Scan Summary:{Style.RESET_ALL}")
        print(f"  URLs Scanned: {results['stats']['urls_scanned']}")
        print(f"  Forms Tested: {results['stats']['forms_tested']}")
        print(f"  Parameters Tested: {results['stats']['parameters_tested']}")
        print(f"  Vulnerabilities Found: {Fore.RED}{results['stats']['vulnerabilities_found']}{Style.RESET_ALL}")

        if results['stats'].get('waf_detected'):
            print(f"  WAF Detected: {Fore.YELLOW}{results['stats']['waf_detected']}{Style.RESET_ALL}")
        if results['stats'].get('dom_vulns_found'):
            print(f"  DOM XSS Found: {Fore.RED}{results['stats']['dom_vulns_found']}{Style.RESET_ALL}")
        if results['stats'].get('stored_vulns_found'):
            print(f"  Stored XSS Confirmed: {Fore.RED}{results['stats']['stored_vulns_found']}{Style.RESET_ALL}")
        if results['stats'].get('blind_callbacks'):
            print(f"  Blind XSS Callbacks: {Fore.RED}{results['stats']['blind_callbacks']}{Style.RESET_ALL}")
        if results['stats'].get('hidden_params_found'):
            print(f"  Hidden Params Found: {results['stats']['hidden_params_found']}")

        if results['stats']['vulnerabilities_found'] > 0:
            print(f"\n{Fore.RED}VULNERABILITIES DETECTED:{Style.RESET_ALL}")
            for vuln in results['vulnerabilities'][:10]:
                confidence = vuln.get('confidence_label', '')
                conf_str = f" [{confidence}]" if confidence else ""
                print(f"  - {vuln['type']} at {vuln.get('url', 'N/A')}{conf_str}")
            if len(results['vulnerabilities']) > 10:
                print(f"  - ... and {len(results['vulnerabilities']) - 10} more")

        # Rate limiter stats
        if results.get('rate_limiter_stats'):
            rl = results['rate_limiter_stats']
            if rl['throttled_requests'] > 0:
                print(f"\n{Fore.YELLOW}Rate Limiting:{Style.RESET_ALL}")
                print(f"  Throttled Requests: {rl['throttled_requests']}")
                print(f"  Final Delay: {rl['current_delay']}s")

        print(f"\n{Fore.CYAN}Reports generated:{Style.RESET_ALL}")
        for report_file in report_files:
            print(f"  - {report_file}")

        print(f"\n{Fore.CYAN}Duration: {results['stats']['scan_duration']}{Style.RESET_ALL}\n")

    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] {str(e)}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
