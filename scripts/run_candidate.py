#!/usr/bin/env python3
"""Start an isolated B preview without changing the live tmux-web instance."""
from pathlib import Path
import argparse
import json
import os
import subprocess
import sys

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
from hub.storage import atomic_json
from node import ensure_private_upload_root


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=60001)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--state-dir', default='~/.local/state/tmux-web-b')
    parser.add_argument('--auth-from', help='optional read-only copy of an existing password hash file')
    args = parser.parse_args()
    if not 0 < args.port < 65536 or args.port == 59999:
        parser.error('B must use a separate port; port 59999 is reserved for the live instance')
    proposed = Path(os.path.abspath(os.path.expanduser(args.state_dir)))
    if proposed.is_symlink():
        parser.error('B state root must not be a symlink')
    state = proposed.resolve()
    if state == SOURCE or state in SOURCE.parents or SOURCE in state.parents:
        parser.error('B state must be separate from source directories')
    if args.auth_from:
        original = Path(args.auth_from).expanduser().resolve()
        if state == original.parent or original.parent in state.parents:
            parser.error('B state must not be inside the live authentication directory')
    state = Path(ensure_private_upload_root(str(state)))
    for name in ('.auth.json', '.tokens.json', '.node-secret', '.node-credentials.json', 'tmux.sock'):
        if (state / name).is_symlink():
            parser.error('B state files must not be symlinks to another instance')
    if args.auth_from and not (state / '.auth.json').exists():
        with original.open(encoding='utf-8') as stream:
            auth = json.load(stream)
        if not isinstance(auth, dict) or not all(isinstance(auth.get(k), str) for k in ('salt', 'hash')):
            parser.error('auth-from is not a supported password hash file')
        atomic_json(str(state / '.auth.json'), auth)
    tmux_socket = state / 'tmux.sock'
    tmux_config = state / 'tmux.conf'
    tmux_config.write_text("set -s exit-empty off\nset -g default-shell /bin/bash\nset -g default-command '/bin/bash --noprofile --norc'\n")
    env = dict(os.environ)
    for variable in ('TMUX', 'TMUX_PANE', 'BASH_ENV', 'ENV', 'PROMPT_COMMAND', 'CDPATH'):
        env.pop(variable, None)
    probe = subprocess.run(['tmux', '-S', str(tmux_socket), 'display-message', '-p', '#{socket_path}'],
                           env=env, capture_output=True, text=True)
    if probe.returncode:
        subprocess.run(['tmux', '-S', str(tmux_socket), '-f', str(tmux_config),
                        'new-session', '-d', '-s', 'b-review'], env=env, check=True)
        probe = subprocess.run(['tmux', '-S', str(tmux_socket), 'display-message', '-p', '#{socket_path}'],
                               env=env, capture_output=True, text=True, check=True)
    if Path(probe.stdout.strip()).resolve() != tmux_socket.resolve():
        parser.error('unexpected tmux socket; refusing to start B')
    env.update(TMUX_WEB_HOST=args.host, TMUX_WEB_PORT=str(args.port),
               TMUX_WEB_STATE_DIR=str(state), TMUX_WEB_TMUX_SOCKET=str(tmux_socket),
               TMUX_WEB_COOKIE_NAME=f'tmux_web_b_{args.port}_token', TMUX_WEB_BLOCKED_PORTS='59999')
    print(f'B preview: http://{args.host}:{args.port} (isolated state, cookie and tmux socket)', flush=True)
    os.chdir(SOURCE)
    os.execve(sys.executable, [sys.executable, str(SOURCE / 'server.py')], env)


if __name__ == '__main__':
    main()
