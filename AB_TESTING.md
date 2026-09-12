# A/B refactoring workflow

The live A instance remains on port 59999. Run candidate B from a separate
checkout/worktree with independent state, tmux socket and browser Cookie name.
Do not replay live mutating requests against both instances.

## Repeatable contract comparison

```bash
python scripts/ab_validate.py --baseline b041475 --output /tmp/tmux-web-ab-report
```

Use the repository's existing server Python environment. The harness adds no
runtime packages. It creates two loopback-only fixture servers on random ports,
refuses port 59999, and supplies private source/state/upload directories and
tmux sockets. It never calls the live service. A has the frozen baseline source;
B has the candidate working-tree snapshot, including `hub/` and `static/`.

The report compares successful HTTP behavior and records exact login/dashboard HTML hashes.
Expected bug fixes are listed separately instead of silently normalizing them.
Historical node scripts are loaded directly from immutable Git revisions:

| Client | Revision | Authentication |
| --- | --- | --- |
| Original public node | `017c486` | Query token |
| Header-auth node | `b02d477` | Bearer header |
| Current deployed protocol | `979cc32` | Standard-library Noise |
| First runtime refactor | `b041475` | Same Noise protocol, optional capabilities |
| Candidate node | Working tree | Same Noise protocol plus optional capabilities |
| Enrolled candidate | Working tree | One-time grant exchanged for a scoped Noise credential |

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

## Second repair batch

The second batch addresses the remaining CLI, UI, statistics, blocking I/O and
credential-lifecycle findings. Proxy-origin isolation is explicitly excluded.

- Bind asynchronous browser actions to their original connection/session/node;
  scope path caches by node and expire negative results.
- Preserve business strings while rewriting explicit proxy resource URLs; let
  ordinary remote shells scroll locally and respect TUI mouse modes.
- Commit CLI downloads atomically after length validation. Preserve shell state
  and capture command exit status using separated, non-echoed markers.
- Revoke browser tokens on password changes without rotating historical node
  secrets. Use expiring enrollment grants for new one-click commands, then
  persist independently revocable node credentials after an encrypted handoff.
- Move tmux, metrics sampling and file I/O off the event loop; share metric
  snapshots and bound node download encryption messages to 16 KiB.
- Parse appended usage records incrementally, reconcile detail/snapshot overlap
  across counter resets, isolate malformed rows and retire deleted file caches.

Login and dashboard byte differences are expected in this batch and appear as
explicit `approved_fix` observations. The served B page must still match its
snapshotted source asset. Browser interaction regressions run from
`test_frontend_behavior.js` through Python's unittest discovery when Node.js is
available; CI supplies that development runtime. Node.js is not a deployment
requirement. All historical nodes must continue passing actual session/file/
hub-restart checks, alongside a newly enrolled candidate node.

Python 3.8 compatibility checks cover the standalone node, cryptographic vectors,
credential handoff/cache, nonblocking file lifecycle and control-message fairness.
No tests use live nodes, operator credentials or the production tmux socket.
