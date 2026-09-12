"""Explicit runtime boundaries for normal and isolated hub instances."""
from dataclasses import dataclass
from pathlib import Path
import os
import re


@dataclass(frozen=True)
class RuntimeConfig:
    source_dir: Path
    state_dir: Path
    host: str
    port: int
    tmux_socket: str
    cookie_name: str
    blocked_ports: frozenset[int]
    isolated_state: bool

    @classmethod
    def from_environment(cls, source_dir):
        source = Path(source_dir).resolve()
        state = Path(os.environ.get('TMUX_WEB_STATE_DIR', str(source))).expanduser().resolve()
        socket = os.environ.get('TMUX_WEB_TMUX_SOCKET', '')
        if socket and not Path(socket).is_absolute():
            raise ValueError('TMUX_WEB_TMUX_SOCKET must be an absolute path')
        cookie = os.environ.get('TMUX_WEB_COOKIE_NAME', 'tmux_web_token')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', cookie):
            raise ValueError('invalid TMUX_WEB_COOKIE_NAME')
        port = int(os.environ.get('TMUX_WEB_PORT', '59999'))
        blocked = frozenset(int(v) for v in os.environ.get('TMUX_WEB_BLOCKED_PORTS', '').split(',') if v)
        if not 0 < port < 65536 or any(not 0 < value < 65536 for value in blocked):
            raise ValueError('invalid runtime port')
        return cls(source, state, os.environ.get('TMUX_WEB_HOST', '0.0.0.0'),
                   port, socket, cookie, blocked, 'TMUX_WEB_STATE_DIR' in os.environ)

    def read_asset(self, name):
        return (self.source_dir / 'static' / name).read_text(encoding='utf-8')

    def tmux_argv(self, *args):
        return ['tmux', *(['-S', self.tmux_socket] if self.tmux_socket else []), *args]

    def tmux_environment(self):
        env = dict(os.environ)
        if self.tmux_socket:
            env.pop('TMUX', None)
            env.pop('TMUX_PANE', None)
        return env

    @property
    def upload_dir(self):
        return str(self.state_dir / 'uploads') if self.isolated_state else '/tmp/tmux-web-uploads'
