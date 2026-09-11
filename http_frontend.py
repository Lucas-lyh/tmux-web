"""HTTP frontend and authenticated, path-prefixed loopback web proxy."""
import asyncio
import json
import re
from http.cookies import CookieError, SimpleCookie
from types import SimpleNamespace
from urllib.parse import urlsplit, urlunsplit

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


def rewrite_text(text, content_type, prefix, port):
    # Handles HTML attributes, JS module imports/root URL literals, and CSS URLs.
    text = re.sub(r'''(["'`])((?:/(?![/\"'`])|https?://(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?/)[^\s"'`<>]*)''',
                  lambda m: m[1] + map_url(m[2], prefix, port), text)
    text = re.sub(r'(url\(\s*)(/[^/\s)]+)',
                  lambda m: m[1] + map_url(m[2], prefix, port), text, flags=re.I)
    if 'html' in content_type:
        text = re.sub(r'''(\b(?:src|href|action|poster)\s*=\s*)(["'])(/)(\2)''',
                      lambda m: m[1] + m[2] + prefix + m[4], text, flags=re.I)
        text = re.sub(r'(\b(?:src|href|action|poster)\s*=\s*)(/[^/\s>]+)',
                      lambda m: m[1] + map_url(m[2], prefix, port), text, flags=re.I)
        # Rewritten JS/CSS no longer match the upstream integrity hash.
        text = re.sub(r'\s+integrity\s*=\s*(["\']).*?\1', '', text, flags=re.I | re.S)
        # The shim must run before application scripts, including with restrictive CSP.
        text = re.sub(r'<meta\b[^>]*http-equiv\s*=\s*["\']?Content-Security-Policy["\']?[^>]*>', '', text, flags=re.I)
        shim = browser_shim(prefix, port)
        head = re.search(r'<head\b[^>]*>', text, re.I)
        text = text[:head.end()] + shim + text[head.end():] if head else shim + text
    return text


def response_headers(upstream, prefix, port):
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
                if name == 'tmux_web_token':
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
    if port == backend.PORT:
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
    cookie = '; '.join(part.strip() for part in headers.get('Cookie', '').split(';')
                       if part.strip() and part.strip().partition('=')[0] != 'tmux_web_token')
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
            outgoing = response_headers(upstream, prefix, port)
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
        if request.method not in ('GET', 'HEAD'):
            return web.Response(status=405, headers={'Allow': 'GET, HEAD'})
        adapted = SimpleNamespace(path=request.raw_path, headers=request.headers, secure=request.secure)
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
