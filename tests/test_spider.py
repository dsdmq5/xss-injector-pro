"""
Tests for the Web Spider module.
Uses mocked HTTP responses to test crawling logic without network access.
"""

import pytest
from unittest.mock import patch, MagicMock
from src.spider import Spider
from src.config import Config


@pytest.fixture
def config():
    return Config(
        target_url="http://example.com",
        depth=2,
        max_urls=10,
        delay=0,
        timeout=5,
        verbose=False,
        respect_robots=False
    )


@pytest.fixture
def session():
    return MagicMock()


def make_response(html, content_type='text/html'):
    """Helper to create a mock response"""
    resp = MagicMock()
    resp.text = html
    resp.headers = {'Content-Type': content_type}
    return resp


class TestSpiderBFS:
    """Test BFS crawling behavior"""

    def test_discovers_start_url(self, config, session):
        session.get.return_value = make_response('<html><body>Hello</body></html>')
        spider = Spider(config, session)
        urls = spider.crawl("http://example.com")
        assert "http://example.com" in urls

    def test_follows_links_on_same_domain(self, config, session):
        page1 = '<html><body><a href="/page2">Link</a></body></html>'
        page2 = '<html><body>Page 2</body></html>'

        def side_effect(url, **kwargs):
            if 'page2' in url:
                return make_response(page2)
            return make_response(page1)

        session.get.side_effect = side_effect
        spider = Spider(config, session)
        urls = spider.crawl("http://example.com")
        assert "http://example.com/page2" in urls

    def test_does_not_follow_external_links(self, config, session):
        html = '<html><body><a href="http://evil.com/page">External</a></body></html>'
        session.get.return_value = make_response(html)
        spider = Spider(config, session)
        urls = spider.crawl("http://example.com")
        assert "http://evil.com/page" not in urls

    def test_respects_max_urls_limit(self, config, session):
        config.max_urls = 3
        # Page with many links
        links = ''.join(f'<a href="/page{i}">Link {i}</a>' for i in range(20))
        html = f'<html><body>{links}</body></html>'
        session.get.return_value = make_response(html)
        spider = Spider(config, session)
        urls = spider.crawl("http://example.com")
        assert len(urls) <= 3

    def test_respects_depth_limit(self, config, session):
        config.depth = 1
        # Depth 0: start page links to /a
        # Depth 1: /a links to /b
        # Depth 2: /b links to /c (should NOT be crawled)

        def side_effect(url, **kwargs):
            if url == "http://example.com":
                return make_response('<html><a href="/a">A</a></html>')
            elif url == "http://example.com/a":
                return make_response('<html><a href="/b">B</a></html>')
            elif url == "http://example.com/b":
                return make_response('<html><a href="/c">C</a></html>')
            return make_response('<html></html>')

        session.get.side_effect = side_effect
        spider = Spider(config, session)
        urls = spider.crawl("http://example.com")
        assert "http://example.com" in urls
        assert "http://example.com/a" in urls
        # /b is at depth 2, should not be crawled with depth=1
        assert "http://example.com/b" not in urls

    def test_skips_non_html_content(self, config, session):
        def side_effect(url, **kwargs):
            if 'image' in url:
                return make_response('binary data', content_type='image/png')
            return make_response('<html><a href="/image.png">Img</a></html>')

        session.get.side_effect = side_effect
        spider = Spider(config, session)
        urls = spider.crawl("http://example.com")
        # Non-HTML URLs should not be in discovered set
        assert all('image' not in u for u in urls)

    def test_skips_javascript_and_mailto_links(self, config, session):
        html = '''<html><body>
            <a href="javascript:void(0)">JS</a>
            <a href="mailto:test@test.com">Mail</a>
            <a href="tel:123456">Phone</a>
            <a href="/real-page">Real</a>
        </body></html>'''
        session.get.return_value = make_response(html)
        spider = Spider(config, session)
        urls = spider.crawl("http://example.com")
        assert "http://example.com/real-page" in urls
        assert len(urls) == 2  # start + /real-page


class TestRobotsTxt:
    """Test robots.txt handling"""

    def test_robots_disabled_allows_all(self, config, session):
        config.respect_robots = False
        session.get.return_value = make_response('<html><a href="/secret">S</a></html>')
        spider = Spider(config, session)
        urls = spider.crawl("http://example.com")
        assert "http://example.com/secret" in urls

    @patch('src.spider.RobotFileParser')
    def test_robots_blocks_disallowed_url(self, mock_robot_class, session):
        config = Config(
            target_url="http://example.com",
            depth=2, max_urls=10, delay=0, timeout=5,
            verbose=False, respect_robots=True
        )

        # Mock robot parser to block /admin
        mock_parser = MagicMock()
        mock_parser.can_fetch.side_effect = lambda ua, url: '/admin' not in url
        mock_robot_class.return_value = mock_parser

        html = '<html><a href="/admin">Admin</a><a href="/public">Public</a></html>'
        session.get.return_value = make_response(html)

        spider = Spider(config, session)
        urls = spider.crawl("http://example.com")

        assert "http://example.com/public" in urls
        assert "http://example.com/admin" not in urls
