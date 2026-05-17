"""
Web Spider Module
Automatically crawls websites to discover URLs and pages.
Uses iterative BFS to avoid recursion limits on large sites.
Optionally respects robots.txt.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser
from colorama import Fore, Style
import time
from collections import deque
from typing import Set, List


class Spider:
    """Web crawler for discovering URLs using iterative BFS"""

    def __init__(self, config, session):
        self.config = config
        self.session = session
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.domain: str = ""
        self.robot_parser: RobotFileParser | None = None

    def crawl(self, start_url: str) -> List[str]:
        """Crawl website starting from start_url using BFS"""
        self.domain = urlparse(start_url).netloc

        # Load robots.txt if configured
        if self.config.respect_robots:
            self._load_robots_txt(start_url)

        self._crawl_bfs(start_url)
        return list(self.discovered_urls)

    def _load_robots_txt(self, start_url: str):
        """Load and parse robots.txt for the target domain"""
        parsed = urlparse(start_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        self.robot_parser = RobotFileParser()
        self.robot_parser.set_url(robots_url)

        try:
            self.robot_parser.read()
            if self.config.verbose:
                print(f"  {Fore.BLUE}[Spider] Loaded robots.txt from {robots_url}{Style.RESET_ALL}")
        except Exception:
            # If robots.txt is unavailable, allow everything
            if self.config.verbose:
                print(f"  {Fore.YELLOW}[Spider] Could not load robots.txt, proceeding without restrictions{Style.RESET_ALL}")
            self.robot_parser = None

    def _is_allowed(self, url: str) -> bool:
        """Check if URL is allowed by robots.txt"""
        if self.robot_parser is None:
            return True

        user_agent = self.config.user_agent or '*'
        try:
            return self.robot_parser.can_fetch(user_agent, url)
        except Exception:
            return True

    def _crawl_bfs(self, start_url: str):
        """Iterative BFS crawl — no recursion limit issues"""
        queue: deque = deque()
        queue.append((start_url, 0))  # (url, depth)

        while queue:
            # Check max URLs limit
            if len(self.discovered_urls) >= self.config.max_urls:
                break

            url, depth = queue.popleft()

            # Check depth limit
            if depth > self.config.depth:
                continue

            # Skip if already visited
            if url in self.visited_urls:
                continue

            # Check robots.txt
            if not self._is_allowed(url):
                if self.config.verbose:
                    print(f"  {Fore.YELLOW}[Spider] Blocked by robots.txt: {url}{Style.RESET_ALL}")
                continue

            # Mark as visited
            self.visited_urls.add(url)

            try:
                if self.config.verbose:
                    print(f"  {Fore.BLUE}[Spider] Crawling: {url} (depth: {depth}){Style.RESET_ALL}")

                # Fetch page
                response = self.session.get(url, timeout=self.config.timeout)

                # Only process HTML pages
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' not in content_type:
                    continue

                # Add to discovered URLs
                self.discovered_urls.add(url)

                # Parse HTML and extract links
                soup = BeautifulSoup(response.text, 'html.parser')
                links = self._extract_links(soup, url)

                # Enqueue child links at depth + 1
                for link in links:
                    if link not in self.visited_urls and len(self.discovered_urls) < self.config.max_urls:
                        queue.append((link, depth + 1))

                time.sleep(self.config.delay)

            except requests.exceptions.RequestException as e:
                if self.config.verbose:
                    print(f"  {Fore.YELLOW}[Spider] Error crawling {url}: {str(e)}{Style.RESET_ALL}")
            except Exception as e:
                if self.config.verbose:
                    print(f"  {Fore.YELLOW}[Spider] Unexpected error: {str(e)}{Style.RESET_ALL}")

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> Set[str]:
        """Extract all valid links from page"""
        links: Set[str] = set()

        # Find all <a> tags with href
        for tag in soup.find_all('a', href=True):
            href = tag['href']

            # Skip empty hrefs, anchors, javascript, and mailto
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue

            # Convert relative URLs to absolute
            absolute_url = urljoin(base_url, href)

            # Parse URL
            parsed = urlparse(absolute_url)

            # Only include URLs from same domain
            if parsed.netloc == self.domain:
                # Remove fragment
                clean_url = parsed.scheme + '://' + parsed.netloc + parsed.path
                if parsed.query:
                    clean_url += '?' + parsed.query

                links.add(clean_url)

        return links
