"""Bundled browser dependencies must be served locally with the right MIME types."""
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
import unittest

import server


class AssetParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'script' and 'src' in attrs:
            self.urls.append(attrs['src'])
        if tag == 'link' and attrs.get('rel') == 'stylesheet':
            self.urls.append(attrs['href'])


class StaticAssetTests(unittest.IsolatedAsyncioTestCase):
    async def test_page_dependencies_are_local_and_served_without_login(self):
        parser = AssetParser()
        parser.feed(server.INDEX_HTML)
        self.assertEqual(len(parser.urls), 4)
        for url in parser.urls:
            with self.subTest(url=url):
                self.assertTrue(url.startswith('/static/vendor/'))
                response = await server.process_request(None, SimpleNamespace(path=url, headers={}))
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.body, (Path(__file__).parent / url.lstrip('/')).read_bytes())
                mime = 'text/css' if url.endswith('.css') else 'application/javascript'
                self.assertTrue(response.headers['Content-Type'].startswith(mime))

    async def test_unknown_and_traversal_paths_are_not_served(self):
        for path in ['/static/missing.js', '/static/../server.py', '/static/%2e%2e/.auth.json']:
            response = await server.process_request(None, SimpleNamespace(path=path, headers={}))
            self.assertEqual(response.status_code, 404)
