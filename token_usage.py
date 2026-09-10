"""Read local Codex rollout usage without counting cumulative snapshots twice."""
import datetime
import glob
import json
import os

CODEX_HOME = os.path.expanduser(os.environ.get('CODEX_HOME', '~/.codex'))
TOKEN_KEYS = ('inputOther', 'inputCacheRead', 'inputCacheCreation', 'output')
_cache = {}


def _usage(u):
    read = max(0, int(u.get('cached_input_tokens', 0)))
    write = max(0, int(u.get('cache_write_input_tokens', 0)))
    return dict(zip(TOKEN_KEYS, (max(0, int(u.get('input_tokens', 0)) - read - write),
                                 read, write, max(0, int(u.get('output_tokens', 0))))))


def _read(path, signature):
    if path in _cache and _cache[path][0] == signature:
        return _cache[path][1]
    meta, records, fallback, previous = {}, [], [], {}
    seen_totals, recorded_totals = set(), set()
    with open(path, errors='replace') as f:
        for line in f:
            if not any(k in line for k in ('"session_meta"', '"token_usage_record"', '"token_count"')):
                continue
            try:
                d = json.loads(line)
                p = d.get('payload') or {}
                kind = d.get('type')
                if kind == 'session_meta':
                    if not meta:
                        meta = {k: p.get(k, '') for k in ('id', 'cwd', 'forked_from_id')}
                        meta['timestamp'] = d.get('timestamp', '')
                    continue
                stamp = d['timestamp']
                day = datetime.datetime.fromisoformat(stamp.replace('Z', '+00:00')).astimezone().date().isoformat()
                if kind == 'token_usage_record':
                    # Forks can contain their parent's history. Attribute only this thread.
                    if p.get('thread_id', meta.get('id')) != meta.get('id'):
                        continue
                    u = _usage(p['usage'])
                    key = p.get('response_id') or (meta.get('id'), stamp, tuple(u.values()))
                    records.append((key, day, u))
                    if isinstance(p.get('thread_token_usage'), dict):
                        recorded_totals.add(tuple(sorted(p['thread_token_usage'].items())))
                elif kind == 'event_msg' and p.get('type') == 'token_count':
                    info = p.get('info') or {}
                    total = info.get('total_token_usage')
                    if not isinstance(total, dict):
                        continue
                    sig = tuple(sorted(total.items()))
                    if sig in seen_totals:
                        continue
                    seen_totals.add(sig)
                    # Total input includes cached input; output already includes reasoning.
                    if previous and any(total.get(k, 0) < previous.get(k, 0) for k in ('input_tokens', 'output_tokens')):
                        delta = info.get('last_token_usage') or total
                    else:
                        delta = {k: max(0, v - previous.get(k, 0)) for k, v in total.items()}
                    previous = total
                    if sig in recorded_totals:
                        continue
                    if meta.get('forked_from_id') and stamp < meta.get('timestamp', ''):
                        continue
                    u = _usage(delta)
                    if any(u.values()):
                        fallback.append(((meta.get('id'), stamp, sig), day, u))
            except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
                continue  # Includes incomplete JSON while a live session appends.
    result = (meta, records + fallback)
    _cache[path] = (signature, result)
    return result


def codex_sessions(cutoff):
    """Return daily usage for active and archived sessions, deduplicated by response."""
    paths = sorted({p for folder in ('sessions', 'archived_sessions')
                    for p in glob.glob(os.path.join(CODEX_HOME, folder, '**', '*.jsonl'), recursive=True)})
    seen, sessions = set(), {}
    for path in paths:
        try:
            st = os.stat(path)
            meta, records = _read(path, (st.st_mtime_ns, st.st_size))
        except OSError:
            continue
        sid = meta.get('id') or os.path.basename(path)
        for key, day, usage in records:
            if key in seen:
                continue
            seen.add(key)
            if day < cutoff:
                continue
            s = sessions.setdefault(sid, {'id': sid, 'provider': 'codex',
                'title': os.path.basename(meta.get('cwd', '')) or sid[:8],
                'cwd': meta.get('cwd', ''), 'days': {}})
            a = s['days'].setdefault(day, dict.fromkeys(TOKEN_KEYS, 0) | {'steps': 0})
            for k in TOKEN_KEYS:
                a[k] += usage[k]
            a['steps'] += 1
    for path in set(_cache) - set(paths):
        del _cache[path]
    return list(sessions.values())
