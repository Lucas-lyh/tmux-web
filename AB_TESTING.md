# A/B refactoring workflow

The live A instance remains on port 59999. Run candidate B from a separate
checkout/worktree with independent state, tmux socket and browser Cookie name.
Do not replay live mutating requests against both instances.

## Repeatable contract comparison

```bash
python scripts/ab_validate.py --baseline 979cc32 --output /tmp/tmux-web-ab-report
```

Use the repository's existing server Python environment. The harness adds no
runtime packages. It creates two loopback-only fixture servers on random ports,
refuses port 59999, and supplies private source/state/upload directories and
tmux sockets. It never calls the live service. A has the frozen baseline source;
B has the candidate working-tree snapshot, including `hub/` and `static/`.

The report compares successful HTTP behavior and exact login/dashboard HTML.
Expected bug fixes are listed separately instead of silently normalizing them.
Historical node scripts are loaded directly from immutable Git revisions:

| Client | Revision | Authentication |
| --- | --- | --- |
| Original public node | `017c486` | Query token |
| Header-auth node | `b02d477` | Bearer header |
| Current deployed protocol | `979cc32` | Standard-library Noise |
| Candidate node | Working tree | Same Noise protocol plus optional capabilities |

Each client must pass session creation, input/capture, file round trips, kill,
and hub-restart recovery with its node process/session retained. Source hashes,
normalized outcomes and isolation evidence are written to `report.json` and
`report.md`. These reports contain synthetic fixture state, never live secrets.
Full Git history is needed for these developer checks; the deployed node still
needs only its single Python script and the standard library.

## Independent B preview

```bash
python scripts/run_candidate.py --port 60001 \
  --state-dir /path/to/private-b-state \
  --auth-from /path/to/live/.auth.json
```

`--auth-from` optionally makes a one-time **read-only copy of the password hash**,
so the same password can be used to inspect B. It does not copy live login tokens
or node secrets. B generates its own node secret and uses its own Cookie name.
The launcher rejects port 59999 and shared/symlinked state, supplies a private
tmux socket, suppresses user tmux/shell startup hooks in the preview's local
sessions, and prevents its built-in port proxy/relay from targeting port 59999.
Use `--host 0.0.0.0` only when the preview should be reachable from your network.

This is state and routing isolation for a trusted developer preview, not an OS
security sandbox: terminal commands still run as the launching Unix user.

## Compatibility rules

- Keep existing node CLI arguments and the v1 query/Bearer entry points.
- Preserve Noise suite, prologue, PSK derivation, frame encoding and version 2.
- Capability fields in hello are additive. Send new control types only to a
  client which advertised them; use the established protocol otherwise.
- Old nodes keep working without upgrades. Their own internal bugs are not
  magically fixed by a newer hub.
- Keep `node.py` standalone, standard-library-only and compatible with Python 3.8+.
- Do not change the live checkout, authentication, tmux socket, service or routes
  while evaluating B. Promotion is a separate explicit operational action.

## This first refactoring batch

- Extract unchanged login/dashboard assets into `static/` and move runtime
  boundaries, target parsing, atomic persistence and node requests into `hub/`.
- Reject offline remote targets instead of routing them to local tmux.
- Validate upload roots and clean only owned upload directories.
- Buffer PTY input without blocking the event loop and preserve close signals.
- Bind node transfers to their connection and make failed/cancelled uploads close.
- Reject duplicate active node names; clean up failed attach initialization.
- Negotiate metadata-only file checks and transfer cancellation, retaining old
  node fallbacks. Preserve normal endpoint payloads and original UI bytes.

Further UI behavior changes, token-statistics parsing changes, password/token
policy changes, and the rest of the audit should be separate batches with new
regression cases. This branch does not claim all audit findings are resolved.
