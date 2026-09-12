"""HTTP frontend and authenticated, path-prefixed loopback web proxy."""
import asyncio
import json
import math
from html import escape, unescape
from html.parser import HTMLParser
import re
from http.cookies import CookieError, SimpleCookie
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import aiohttp
from aiohttp import web, WSMsgType
from multidict import CIMultiDict
from yarl import URL

HOP_HEADERS = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
               'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-length'}
CLIENT = web.AppKey('proxy_client', aiohttp.ClientSession)


class WebSocketAdapter:
    """Keep existing terminal/node handlers while serving regular HTTP methods."""
    def __init__(self, socket, request):
        self.socket = socket
        self.request = SimpleNamespace(path=request.raw_path, headers=request.headers)
        self.remote_address = request.transport.get_extra_info('peername') if request.transport else None

    async def send(self, data):
        if isinstance(data, str):
            await self.socket.send_str(data)
        else:
            await self.socket.send_bytes(data)

    async def recv(self):
        msg = await self.socket.receive()
        if msg.type in (WSMsgType.TEXT, WSMsgType.BINARY):
            return msg.data
        raise ConnectionError('websocket closed')

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return await self.recv()
        except ConnectionError:
            raise StopAsyncIteration

    async def close(self, code=1000, reason=''):
        await self.socket.close(code=code, message=reason.encode())


def clean_headers(headers):
    blocked = HOP_HEADERS | {s.strip().lower() for s in headers.get('Connection', '').split(',')}
    return CIMultiDict((k, v) for k, v in headers.items() if k.lower() not in blocked)


def map_url(value, prefix, port):
    """Rewrite root paths and absolute loopback URLs, leaving external URLs alone."""
    if value.startswith(prefix):
        return value
    if value.startswith('/') and not value.startswith('//'):
        return prefix[:-1] + value
    try:
        u = urlsplit(value)
        if u.hostname in ('127.0.0.1', 'localhost', '::1') and (u.port or 80) == port:
            return prefix[:-1] + urlunsplit(('', '', u.path or '/', u.query, u.fragment))
    except ValueError:
        pass
    return value


def browser_shim(prefix, port):
    return r'''<script data-tmux-port-proxy>
(() => {
  const prefix = PREFIX, port = PORT;
  function route(value) {
    const u = new URL(String(value), location.href);
    const local = (['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname) || u.hostname === location.hostname) && Number(u.port || 80) === port;
    if (u.origin === location.origin || local ||
        (['ws:', 'wss:'].includes(u.protocol) && u.host === location.host)) {
      if (!u.pathname.startsWith(prefix)) u.pathname = prefix.slice(0, -1) + u.pathname;
      u.host = location.host;
      u.protocol = ['ws:', 'wss:'].includes(u.protocol) ? (location.protocol === 'https:' ? 'wss:' : 'ws:') : location.protocol;
    }
    return u.href;
  }
  const originalFetch = window.fetch;
  window.fetch = function(input, init) {
    return originalFetch.call(this, input instanceof Request ? new Request(route(input.url), input) : route(input), init);
  };
  const open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) { return open.call(this, method, route(url), ...rest); };
  for (const name of ['WebSocket', 'EventSource', 'Worker', 'SharedWorker']) {
    const Original = window[name];
    if (Original) window[name] = new Proxy(Original, {construct(Target, args) { args[0] = route(args[0]); return Reflect.construct(Target, args); }});
  }
  for (const name of ['pushState', 'replaceState']) {
    const original = history[name];
    history[name] = function(state, title, url) { return original.call(this, state, title, url == null ? url : route(url)); };
  }
  if (navigator.sendBeacon) {
    const beacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = (url, data) => beacon(route(url), data);
  }
})();
</script>'''.replace('PREFIX', json.dumps(prefix)).replace('PORT', str(port))


CSS_TOKENS = re.compile(r'''/\*.*?\*/|(?P<url>\burl\(\s*)(?P<uq>["']?)(?P<uv>(?:\\.|[^\\"')])*?)(?P=uq)\s*\)|(?P<imp>@import\s+)(?P<iq>["'])(?P<iv>(?:\\.|[^\\"'])*)(?P=iq)|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*' ''', re.I | re.S | re.X)


def rewrite_css(text, prefix, port):
    """Only CSS URL productions; quoted content and comments are opaque."""
    def replace(match):
        group = 'uv' if match.group('url') else 'iv' if match.group('imp') else None
        if group is None or '\\' in match[group]:
            return match[0]
        start, end = match.span(group)
        return match[0][:start - match.start()] + map_url(match[group], prefix, port) + match[0][end - match.start():]
    return CSS_TOKENS.sub(replace, text)


def javascript_tokens(text):
    """Conservative module-specifier lexer: never inspect string/comment/regex bodies."""
    def quoted_end(start, quote):
        cursor = start + 1
        while cursor < len(text):
            if text[cursor] == '\\':
                cursor += 2
            elif text[cursor] == quote:
                return cursor + 1
            else:
                cursor += 1
        return cursor

    def template_end(start, nesting=0):
        if nesting > 64:
            return len(text)  # retain unfamiliar/deep syntax verbatim
        cursor = start + 1
        while cursor < len(text):
            if text[cursor] == '\\':
                cursor += 2
            elif text[cursor] == '`':
                return cursor + 1
            elif text.startswith('${', cursor):
                cursor += 2
                depth = 1
                while cursor < len(text) and depth:
                    if text[cursor] in '\'"':
                        cursor = quoted_end(cursor, text[cursor])
                    elif text[cursor] == '`':
                        cursor = template_end(cursor, nesting + 1)
                    elif text.startswith('/*', cursor):
                        end = text.find('*/', cursor + 2)
                        cursor = len(text) if end < 0 else end + 2
                    elif text.startswith('//', cursor):
                        end = text.find('\n', cursor + 2)
                        cursor = len(text) if end < 0 else end
                    elif text[cursor] == '/':
                        # A regex body can contain braces and backticks. Keep
                        # it opaque as well; unmatched division slashes fall
                        # through to ordinary expression scanning.
                        end, in_class = cursor + 1, False
                        while end < len(text) and text[end] not in '\r\n':
                            if text[end] == '\\':
                                end += 2
                                continue
                            if text[end] == '[':
                                in_class = True
                            elif text[end] == ']':
                                in_class = False
                            elif text[end] == '/' and not in_class:
                                break
                            end += 1
                        cursor = end + 1 if end < len(text) and text[end] == '/' else cursor + 1
                    else:
                        depth += (text[cursor] == '{') - (text[cursor] == '}')
                        cursor += 1
            else:
                cursor += 1
        return cursor

    tokens, i = [], 0
    word_pattern = re.compile(r'[\w$]+')
    while i < len(text):
        start, char = i, text[i]
        if char.isspace():
            i += 1
            continue
        if text.startswith('//', i):
            end = text.find('\n', i + 2)
            i = len(text) if end < 0 else end
            continue
        if text.startswith('/*', i):
            end = text.find('*/', i + 2)
            i = len(text) if end < 0 else end + 2
            continue
        if char in '\'"`':
            i = template_end(i) if char == '`' else quoted_end(i, char)
            tokens.append(('string' if char != '`' else 'template', start, i, text[start:i]))
            continue
        previous = tokens[-1][3] if tokens else ''
        regex_possible = (not tokens or tokens[-1][0] == 'punct' and previous != ']' or
                          previous in ('return', 'throw', 'case', 'yield', 'await'))
        if char == '/' and regex_possible:
            end, in_class = i + 1, False
            while end < len(text) and text[end] not in '\r\n':
                if text[end] == '\\':
                    end += 2
                    continue
                if text[end] == '[':
                    in_class = True
                elif text[end] == ']':
                    in_class = False
                elif text[end] == '/' and not in_class:
                    end += 1
                    while end < len(text) and text[end].isalpha():
                        end += 1
                    tokens.append(('regex', start, end, text[start:end]))
                    i = end
                    break
                end += 1
            if i != start:
                continue
        word = word_pattern.match(text, i)
        if word:
            i = word.end()
            tokens.append(('word', start, i, word[0]))
        else:
            i += 1
            tokens.append(('punct', start, i, char))
    return tokens


def rewrite_javascript(text, prefix, port):
    tokens, edits, statement = javascript_tokens(text), [], []
    for index, (kind, start, end, value) in enumerate(tokens):
        previous = tokens[index - 1][3] if index else ''
        before = tokens[index - 2][3] if index > 1 else ''
        dynamic = previous == '(' and before == 'import' and (index < 3 or tokens[index - 3][3] != '.')
        side_effect = previous == 'import' and before != '.'
        from_module = previous == 'from' and any(word in ('import', 'export') for word in statement)
        if kind == 'string' and '\\' not in value and (dynamic or side_effect or from_module):
            mapped = map_url(value[1:-1], prefix, port)
            if mapped != value[1:-1]:
                edits.append((start + 1, end - 1, mapped))
        if value == ';':
            statement = []
        elif kind == 'word':
            statement.append(value)
    parts, previous = [], 0
    for start, end, replacement in edits:
        parts.extend((text[previous:start], replacement))
        previous = end
    parts.append(text[previous:])
    return ''.join(parts)


HTML_ATTRIBUTES = re.compile(r'''\s+(?P<name>[^\s=/>]+)(?:\s*=\s*(?:"(?P<double>[^"]*)"|'(?P<single>[^']*)'|(?P<bare>[^\s>]+)))?''')
URL_ATTRIBUTES = {'src', 'href', 'action', 'formaction', 'poster', 'data', 'cite', 'background'}


def rewrite_srcset(text, prefix, port):
    """Tokenize URL candidates; commas inside a data URL are not separators."""
    parts, previous, cursor = [], 0, 0
    while cursor < len(text):
        while cursor < len(text) and (text[cursor].isspace() or text[cursor] == ','):
            cursor += 1
        start = cursor
        while cursor < len(text) and not text[cursor].isspace():
            cursor += 1
        end = cursor
        while end > start and text[end - 1] == ',':
            end -= 1
        parts.extend((text[previous:start], map_url(text[start:end], prefix, port)))
        previous = end
        if end == cursor:
            # Consume the width/density descriptor before the next candidate.
            while cursor < len(text) and text[cursor] != ',':
                cursor += 1
    parts.append(text[previous:])
    return ''.join(parts)


def rewrite_importmap(text, prefix, port):
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return text
    if not isinstance(data, dict):
        return text
    def specifiers(mapping):
        if not isinstance(mapping, dict):
            return mapping
        return {map_url(key, prefix, port): map_url(value, prefix, port) if isinstance(value, str) else value
                for key, value in mapping.items()}
    result = dict(data)
    if 'imports' in data:
        result['imports'] = specifiers(data['imports'])
    if isinstance(data.get('scopes'), dict):
        result['scopes'] = {map_url(scope, prefix, port): specifiers(mapping)
                            for scope, mapping in data['scopes'].items()}
    return json.dumps(result, ensure_ascii=False).replace('</', '<\\/') if result != data else text


class ProxyHTML(HTMLParser):
    CDATA_CONTENT_ELEMENTS = ('script', 'style', 'textarea', 'title')
    def __init__(self, prefix, port):
        super().__init__(convert_charrefs=False)
        self.prefix, self.port = prefix, port
        self.parts, self.raw_kind, self.injected = [], None, False

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == 'meta' and (attributes.get('http-equiv') or '').lower() == 'content-security-policy':
            return
        def replace(match):
            name = match['name'].lower()
            if name == 'integrity':
                return ''  # rewritten resources cannot retain their original SRI hash
            group = next((g for g in ('double', 'single', 'bare') if match[g] is not None), None)
            if group is None or name not in URL_ATTRIBUTES | {'style', 'srcset', 'imagesrcset'}:
                return match[0]
            original = unescape(match[group])
            if name == 'style':
                mapped = rewrite_css(original, self.prefix, self.port)
            elif name in ('srcset', 'imagesrcset'):
                mapped = rewrite_srcset(original, self.prefix, self.port)
            else:
                mapped = map_url(original, self.prefix, self.port)
            if mapped == original:
                return match[0]
            start, end = match.span(group)
            return match[0][:start - match.start()] + escape(mapped, quote=True) + match[0][end - match.start():]
        self.parts.append(HTML_ATTRIBUTES.sub(replace, self.get_starttag_text()))
        if tag == 'head' and not self.injected:
            self.parts.append(browser_shim(self.prefix, self.port))
            self.injected = True
        if tag == 'script':
            script_type = (attributes.get('type') or '').lower()
            self.raw_kind = ('js' if script_type in ('', 'module', 'text/javascript', 'application/javascript') else
                             'importmap' if script_type == 'importmap' else 'opaque')
        elif tag == 'style':
            self.raw_kind = 'css'
        elif tag in ('textarea', 'title'):
            self.raw_kind = 'opaque'

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.raw_kind = None

    def handle_endtag(self, tag):
        self.parts.append('</' + tag + '>')
        if tag in self.CDATA_CONTENT_ELEMENTS:
            self.raw_kind = None

    def handle_data(self, data):
        if self.raw_kind == 'js':
            data = rewrite_javascript(data, self.prefix, self.port)
        elif self.raw_kind == 'css':
            data = rewrite_css(data, self.prefix, self.port)
        elif self.raw_kind == 'importmap':
            data = rewrite_importmap(data, self.prefix, self.port)
        self.parts.append(data)

    def handle_comment(self, data):
        self.parts.append('<!--' + data + '-->')

    def handle_decl(self, data):
        self.parts.append('<!' + data + '>')

    def handle_entityref(self, name):
        self.parts.append('&' + name + ';')

    def handle_charref(self, name):
        self.parts.append('&#' + name + ';')

    def handle_pi(self, data):
        self.parts.append('<?' + data + '>')


def rewrite_text(text, content_type, prefix, port):
    if 'html' in content_type:
        parser = ProxyHTML(prefix, port)
        parser.feed(text)
        parser.close()
        return ('' if parser.injected else browser_shim(prefix, port)) + ''.join(parser.parts)
    if 'css' in content_type:
        return rewrite_css(text, prefix, port)
    if 'javascript' in content_type:
        return rewrite_javascript(text, prefix, port)
    return text


def response_headers(upstream, prefix, port, auth_cookies=()):
    headers = clean_headers(upstream.headers)
    for key in ('Content-Encoding', 'Set-Cookie', 'Content-Security-Policy',
                'Content-Security-Policy-Report-Only', 'ETag', 'Content-MD5'):
        headers.popall(key, None)
    if 'Location' in headers:
        headers['Location'] = map_url(headers['Location'], prefix, port)
    if 'Refresh' in headers:
        headers['Refresh'] = re.sub(r'(url=)(.+)', lambda m: m[1] + map_url(m[2], prefix, port), headers['Refresh'], flags=re.I)
    for raw in upstream.headers.getall('Set-Cookie', []):
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
            for name, morsel in cookie.items():
                if name in {'tmux_web_token', *auth_cookies}:
                    continue
                morsel['domain'] = ''
                morsel['path'] = map_url(morsel['path'] or '/', prefix, port)
                headers.add('Set-Cookie', morsel.OutputString())
        except (ValueError, TypeError, CookieError):
            continue
    # Proxy content must never be reused across authenticated users.
    headers['Cache-Control'] = 'no-store'
    return headers


async def bridge_websockets(request, client, url, headers):
    protocols = [p.strip() for p in request.headers.get('Sec-WebSocket-Protocol', '').split(',') if p.strip()]
    for key in list(headers):
        if key.lower().startswith('sec-websocket-'):
            headers.popall(key, None)
    async with client.ws_connect(url, headers=headers, protocols=protocols, max_msg_size=0) as upstream:
        downstream = web.WebSocketResponse(protocols=[upstream.protocol] if upstream.protocol else [], max_msg_size=0, heartbeat=30)
        await downstream.prepare(request)

        async def pump(source, target):
            async for msg in source:
                if msg.type == WSMsgType.TEXT:
                    await target.send_str(msg.data)
                elif msg.type == WSMsgType.BINARY:
                    await target.send_bytes(msg.data)
        tasks = [asyncio.create_task(pump(downstream, upstream)), asyncio.create_task(pump(upstream, downstream))]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await downstream.close(code=upstream.close_code or 1000)
        return downstream


async def proxy(request, backend):
    if not backend.request_authed(request):
        return web.Response(status=401, text='请先在 tmux-web 登录，然后重新打开此网页。')
    raw_port = request.match_info['port']
    if not re.fullmatch(r'[0-9]{1,5}', raw_port) or not 1 <= int(raw_port) <= 65535:
        return web.Response(status=400, text='端口号必须在 1–65535 之间。')
    port = int(raw_port)
    if port == backend.PORT or port in getattr(backend, 'BLOCKED_PORTS', ()):
        return web.Response(status=400, text='请填写目标网页的端口，而不是 tmux-web 自身的端口。')
    prefix = f'/port/{raw_port}/'
    if not request.path.startswith(prefix):
        raise web.HTTPTemporaryRedirect(prefix + ('?' + request.query_string if request.query_string else ''))
    # Preserve escaped path/query bytes. The client never controls the upstream host.
    tail = request.raw_path[len(prefix):]
    url = URL(f'http://127.0.0.1:{port}/' + tail, encoded=True)
    headers = clean_headers(request.headers)
    headers['Host'] = f'127.0.0.1:{port}'
    headers['Accept-Encoding'] = 'identity'
    auth_cookies = {'tmux_web_token', getattr(backend, 'COOKIE_NAME', 'tmux_web_token')}
    cookie = '; '.join(part.strip() for part in headers.get('Cookie', '').split(';')
                       if part.strip() and part.strip().partition('=')[0] not in auth_cookies)
    headers.popall('Cookie', None)
    if cookie:
        headers['Cookie'] = cookie
    if headers.get('Authorization') == 'Bearer ' + backend.node_secret():
        headers.popall('Authorization', None)
    if 'Origin' in headers:
        headers['Origin'] = f'http://127.0.0.1:{port}'
    if 'Referer' in headers:
        ref = urlsplit(headers['Referer'])
        headers['Referer'] = f'http://127.0.0.1:{port}/' + ref.path.removeprefix(prefix) + ('?' + ref.query if ref.query else '')
    headers['X-Forwarded-Prefix'] = prefix[:-1]
    headers['X-Forwarded-Host'] = request.host
    headers['X-Forwarded-Proto'] = request.scheme
    client = request.app[CLIENT]
    try:
        if request.headers.get('Upgrade', '').lower() == 'websocket':
            return await bridge_websockets(request, client, url, headers)
        async with client.request(request.method, url, headers=headers,
                                  data=request.content.iter_chunked(65536) if request.can_read_body else None,
                                  allow_redirects=False) as upstream:
            outgoing = response_headers(upstream, prefix, port, auth_cookies)
            mime = upstream.content_type
            rewrite = upstream.status != 206 and (mime in ('text/html', 'application/xhtml+xml', 'text/css',
                                                           'application/javascript', 'text/javascript'))
            if rewrite and request.method != 'HEAD':
                text = await upstream.text(errors='replace')
                body = rewrite_text(text, mime, prefix, port).encode('utf-8')
                outgoing['Content-Type'] = mime + '; charset=utf-8'
                return web.Response(status=upstream.status, headers=outgoing, body=body)
            result = web.StreamResponse(status=upstream.status, headers=outgoing)
            await result.prepare(request)
            async for chunk in upstream.content.iter_chunked(65536):
                await result.write(chunk)
            await result.write_eof()
            return result
    except (aiohttp.ClientError, OSError, asyncio.TimeoutError) as exc:
        return web.Response(status=502, text=f'无法访问本机 http://127.0.0.1:{port}/，请检查网页服务是否已启动。\n{type(exc).__name__}')


def create_app(backend):
    app = web.Application(client_max_size=1024**3)

    async def lifecycle(app):
        async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar(),
                timeout=aiohttp.ClientTimeout(total=None, sock_connect=10, sock_read=None)) as client:
            app[CLIENT] = client
            yield
    app.cleanup_ctx.append(lifecycle)

    async def legacy(request):
        post_paths = {'/api/login', '/api/passwd', '/api/node-enroll', '/api/node-revoke'}
        path = request.raw_path
        if request.method == 'POST' and request.path in post_paths:
            origin = request.headers.get('Origin')
            if origin:
                # TLS may end at a reverse proxy. Host remains the authority;
                # do not require the backend transport scheme to match it.
                try:
                    parsed_origin = urlsplit(origin)
                    same_host = (parsed_origin.scheme in ('http', 'https') and
                                 parsed_origin.netloc.lower() == request.host.lower() and
                                 not (parsed_origin.path or parsed_origin.query or parsed_origin.fragment))
                except ValueError:
                    same_host = False
                if not same_host:
                    return web.Response(status=403, text='cross-origin request denied\n')
            limit = 8192
            if request.content_length is not None and request.content_length > limit:
                return web.Response(status=413, text='request body too large\n')
            body = bytearray()
            while len(body) <= limit:
                chunk = await request.content.read(min(4096, limit + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            if len(body) > limit:
                return web.Response(status=413, text='request body too large\n')
            try:
                values = json.loads(body)
                if not isinstance(values, dict) or any(
                        not isinstance(key, str) or value is not None and
                        (not isinstance(value, (str, int, float, bool)) or
                         isinstance(value, float) and not math.isfinite(value))
                        for key, value in values.items()):
                    raise ValueError('expected scalar fields')
            except (ValueError, UnicodeError):
                return web.Response(status=400, text='expected a JSON object with scalar fields\n')
            parsed = urlsplit(path)
            query = parse_qs(parsed.query, keep_blank_values=True)
            query.update({key: ['' if value is None else str(value)] for key, value in values.items()})
            path = urlunsplit(('', '', parsed.path, urlencode(query, doseq=True), ''))
        elif request.method not in ('GET', 'HEAD'):
            return web.Response(status=405, headers={'Allow': 'GET, HEAD'})
        adapted = SimpleNamespace(path=path, headers=request.headers, secure=request.secure,
                                  method=request.method)
        conn = SimpleNamespace(remote_address=request.transport.get_extra_info('peername') if request.transport else None)
        result = await backend.process_request(conn, adapted)
        if result is not None:
            return web.Response(status=result.status_code, headers=list(result.headers.raw_items()), body=result.body)
        encrypted_node = request.path == '/ws-node' and request.query.get('v') == '2'
        # aiohttp rejects frames >= this limit; Noise permits exactly 65535.
        socket = web.WebSocketResponse(max_msg_size=65536 if encrypted_node else 0, heartbeat=20)
        await socket.prepare(request)
        try:
            await backend.handle_ws(WebSocketAdapter(socket, request))
        except ConnectionError:
            pass
        finally:
            await socket.close()
        return socket

    async def forward(request):
        return await proxy(request, backend)
    app.router.add_route('*', '/port/{port}', forward)
    app.router.add_route('*', '/port/{port}/{tail:.*}', forward)
    app.router.add_route('*', '/{tail:.*}', legacy)
    return app
