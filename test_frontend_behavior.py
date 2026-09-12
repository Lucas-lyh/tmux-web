"""Isolated proxy and browser contract regressions; no real hub/node access."""
import asyncio
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
import unittest
from urllib.parse import parse_qs, urlsplit

from aiohttp import ClientSession
from aiohttp.test_utils import TestServer
from websockets.datastructures import Headers
import http_frontend as frontend


class ConservativeRewriteTests(unittest.TestCase):
    def rewrite(self, source, mime):
        return frontend.rewrite_text(source, mime, '/port/5000/', 5000)

    def test_javascript_business_strings_regex_and_templates_are_unchanged(self):
        source = '''const path = "/tmp/data"; const slash = /"/g;
const object = {path:'/home/user', import: '/business'};
const template = `import "/not-a-module"`;
const nested = `outer ${`import '/still-not-a-module'`} tail`;
const regexTemplate = `${/}/.test('x') ? `import '/business'` : ''}`;
// import "/comment.js"
/* export {x} from "/comment.js" */
fetch('/api/data'); JSON.stringify({path: '/tmp/data'}); object.import('/business');'''
        self.assertEqual(self.rewrite(source, 'text/javascript'), source)

    def test_module_imports_and_exports_keep_working(self):
        source = '''import "/side.js";
import {x} from '/module.js';
export * from "http://localhost:5000/export.js";
const lazy = import(/* chunk */ '/lazy.js');
import z from 'https://example.org/external.js';'''
        result = self.rewrite(source, 'application/javascript')
        for path in ('side.js', 'module.js', 'export.js', 'lazy.js'):
            self.assertIn('/port/5000/' + path, result)
        self.assertIn('https://example.org/external.js', result)

    @unittest.skipUnless(shutil.which('node'), 'JavaScript runtime unavailable')
    def test_rewritten_module_remains_valid_javascript(self):
        source = '''import thing from "/module.js";
const expression = /"/g;
const path = "/tmp/data";
const nested = `outer ${`import '/business'`} tail`;
export const lazy = () => import('/lazy.js');'''
        result = subprocess.run(['node', '--input-type=module', '--check'],
                                input=self.rewrite(source, 'text/javascript'), text=True,
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_css_only_rewrites_url_productions(self):
        source = '''/* url(/comment.png) */
a:before {content:"url(/literal.png)";background:url('/actual.png')}
@import "/theme.css"; b {background:url(/second.png)}'''
        result = self.rewrite(source, 'text/css')
        self.assertIn('/* url(/comment.png) */', result)
        self.assertIn('content:"url(/literal.png)"', result)
        for path in ('actual.png', 'theme.css', 'second.png'):
            self.assertIn('/port/5000/' + path, result)

    def test_html_rewrites_real_attributes_not_data_or_json(self):
        source = '''<!DOCTYPE html><html><head></head><body>
<a href="/">home</a><img src=/image.png><p data-path="/tmp/data">"/literal"</p>
<script type="application/json">{"src":"/business","href":"/business"}</script>
<script>const p="/tmp/data"; const re=/"/g; import '/module.js';</script>
<style>a{background:url(/image.png);content:"/literal"}</style></body></html>'''
        result = self.rewrite(source, 'text/html')
        self.assertIn('href="/port/5000/"', result)
        self.assertIn('src=/port/5000/image.png', result)
        self.assertIn('data-path="/tmp/data"', result)
        self.assertIn('{"src":"/business","href":"/business"}', result)
        self.assertIn('const p="/tmp/data"; const re=/"/g;', result)
        self.assertIn("import '/port/5000/module.js'", result)
        self.assertIn('data-tmux-port-proxy', result)

    def test_importmap_and_srcset_are_explicit_url_contexts(self):
        mapping = {'imports': {'app': '/app.js', '/pkg/': '/lib/', 'external': 'https://cdn.example/app.js'},
                   'scopes': {'/admin/': {'app': '/admin/app.js'}}}
        result = json.loads(frontend.rewrite_importmap(json.dumps(mapping), '/port/5000/', 5000))
        self.assertEqual(result['imports']['app'], '/port/5000/app.js')
        self.assertEqual(result['imports']['/port/5000/pkg/'], '/port/5000/lib/')
        self.assertEqual(result['scopes']['/port/5000/admin/']['app'], '/port/5000/admin/app.js')
        self.assertEqual(result['imports']['external'], 'https://cdn.example/app.js')
        source = '<script type="importmap">' + json.dumps(mapping) + '</script>'
        self.assertIn('/port/5000/app.js', self.rewrite(source, 'text/html'))
        source = '<img srcset="/small.png 1x, /large.png 2x"><source srcset="data:image/png;base64,AAAA 1x, /real.png 2x">'
        result = self.rewrite(source, 'text/html')
        self.assertIn('srcset="/port/5000/small.png 1x, /port/5000/large.png 2x"', result)
        self.assertIn('data:image/png;base64,AAAA 1x, /port/5000/real.png 2x', result)

    def test_textarea_contents_are_opaque(self):
        source = '<textarea><img src="/not-an-image"></textarea>'
        self.assertIn(source, self.rewrite(source, 'text/html'))


class PostAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests = []
        async def process(connection, request):
            self.requests.append(request)
            return SimpleNamespace(status_code=200, headers=Headers(), body=b'ok')
        self.hub = TestServer(frontend.create_app(SimpleNamespace(process_request=process)))
        await self.hub.start_server()
        self.addAsyncCleanup(self.hub.close)
        self.client = ClientSession()
        self.addAsyncCleanup(self.client.close)

    async def test_post_scalar_fields_and_method_reach_backend(self):
        for path in ('login', 'passwd', 'node-enroll', 'node-revoke'):
            async with self.client.post(self.hub.make_url('/api/' + path + '?id=old'),
                                        json={'id': 'new', 'password': 'test &+? password'}) as response:
                self.assertEqual(response.status, 200)
            request = self.requests[-1]
            self.assertEqual(request.method, 'POST')
            self.assertEqual(parse_qs(urlsplit(request.path).query),
                             {'id': ['new'], 'password': ['test &+? password']})

    async def test_get_compatibility_and_non_api_post_rejected(self):
        async with self.client.get(self.hub.make_url('/api/login?password=test'),
                                   headers={'Origin': 'https://historical-client.invalid'}) as response:
            self.assertEqual(response.status, 200)
        self.assertEqual(self.requests[-1].method, 'GET')
        async with self.client.post(self.hub.make_url('/api/new'), json={}) as response:
            self.assertEqual(response.status, 405)

    async def test_origin_matches_host_and_missing_origin_still_works(self):
        async with self.client.post(self.hub.make_url('/api/login'), json={},
                                    headers={'Origin': 'http://other.invalid'}) as response:
            self.assertEqual(response.status, 403)
        self.assertEqual(self.requests, [])
        async with self.client.post(self.hub.make_url('/api/login'), json={},
                                    headers={'Origin': str(self.hub.make_url('/')).rstrip('/')}) as response:
            self.assertEqual(response.status, 200)
        async with self.client.post(self.hub.make_url('/api/login'), json={},
                                    headers={'Host': 'dashboard.example', 'Origin': 'https://dashboard.example'}) as response:
            self.assertEqual(response.status, 200, 'HTTPS reverse proxy may talk HTTP to the hub')
        async with self.client.post(self.hub.make_url('/api/login'), json={},
                                    headers={'Host': 'dashboard.example', 'Origin': 'https://attacker.example'}) as response:
            self.assertEqual(response.status, 403)

    async def test_json_must_be_object_of_scalars(self):
        for data in ('[]', '{"x":{}}', '{"x":[]}', '{"x":NaN}', 'invalid'):
            async with self.client.post(self.hub.make_url('/api/login'), data=data) as response:
                self.assertEqual(response.status, 400, data)
        self.assertEqual(self.requests, [])

    async def test_declared_and_chunked_body_limits(self):
        async with self.client.post(self.hub.make_url('/api/login'), data=b'x' * 8193) as response:
            self.assertEqual(response.status, 413)
        async def chunks():
            for size in (4096, 4096, 1):
                yield b'x' * size
                await asyncio.sleep(0)
        async with self.client.post(self.hub.make_url('/api/login'), data=chunks()) as response:
            self.assertEqual(response.status, 413)
        self.assertEqual(self.requests, [])


class BrowserBehaviorTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'JavaScript runtime unavailable')
    def test_browser_regressions(self):
        result = subprocess.run(['node', str(Path(__file__).with_suffix('.js'))],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
