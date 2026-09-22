"""Passive local evidence -> bounded fault confirmation -> existing safe transaction.

No account secrets or request/response bodies are persisted. Python 3.6.
The only external requests are Guard.business/evaluate after fault authorization.
"""
import calendar
import datetime
import json
import os
import re
import sqlite3
import time
import urllib.parse

import clash_common as common
import mihomo_policy as policy

DEFAULTS = {'provider': 'codex', 'min_error_requests': 3, 'error_span_seconds': 120,
            'max_probes_24h': 6, 'max_evaluations_24h': 2}
KINDS = {'StreamUpstreamError', 'StreamUpstreamPrematureClose', 'RequestError', 'UpstreamError'}


def settings(cfg):
    return dict(DEFAULTS, **cfg['activity'])


def stamp(value):
    if not isinstance(value, str):
        return 0
    try:
        base = value[:-1] if value.endswith('Z') else ''
        fmt = '%Y-%m-%dT%H:%M:%S.%f' if '.' in base else '%Y-%m-%dT%H:%M:%S'
        parsed = datetime.datetime.strptime(base, fmt)
        return calendar.timegm(parsed.timetuple()) + parsed.microsecond / 1000000
    except (ValueError, OverflowError):
        return 0


def network_error(row, activity):
    """Explicit provider + request id + network class. Text is never returned."""
    context, error = row.get('context'), row.get('error')
    if not isinstance(context, dict) or not isinstance(error, dict):
        return False
    if context.get('provider') != activity['provider'] or not context.get('requestId'):
        return False
    kind = error.get('name')
    if kind not in KINDS or kind not in activity['error_kinds']:
        return False
    status = str(context.get('upstreamStatus', ''))
    if context.get('kind') in ('client-abort', 'client-write-failed') or re.fullmatch(r'401|403|429|5\d\d', status):
        return False
    message = ' '.join(str(v) for v in (error.get('message', ''), context.get('detail', ''), error.get('code', ''))).lower()
    # These may contain words like timeout/socket too; exclusion takes priority.
    if re.search(r'client.abort|client.write|cancel|server_is_overloaded|server_error|rate.limit|usage.limit|quota|'
                 r'unauthor|forbidden|account.*(?:ban|deactiv)|certificate|cert_|self.signed|\b(?:401|403|429|5\d\d)\b', message):
        return False
    if kind == 'StreamUpstreamPrematureClose':
        return True
    return bool(re.search(r'timed?\s*out|timeout|etimedout|econnreset|econnrefused|ehostunreach|enetunreach|'
                          r'eai_again|enotfound|connection (?:reset|refused|closed)|socket (?:hang up|closed)|'
                          r'tls.*(?:handshake|disconnect|fail)|ssl.*(?:connect|handshake)|unexpected eof', message))


def evidence(cfg, now):
    """Bounded, read-only local sources; both sources must be readable.

    Only SQL timestamp/provider columns are read. Error JSON is inspected in
    memory and only timestamps, hashed request IDs and class names are returned.
    """
    a = settings(cfg)
    start = now - a['window_seconds']
    result = {'available': False, 'success_at': 0, 'faults': [], 'ignored': 0, 'source_error': ''}
    try:
        uri = 'file:' + urllib.parse.quote(a['call_records_path'], safe='/') + '?mode=ro'
        connection = sqlite3.connect(uri, uri=True, timeout=.5)
        try:
            deadline = time.monotonic() + 1
            connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            connection.execute('PRAGMA query_only=ON')
            lower = datetime.datetime.utcfromtimestamp(start).strftime('%Y-%m-%dT%H:%M:%S.000Z')
            upper = datetime.datetime.utcfromtimestamp(now).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            row = connection.execute(
                'SELECT completed_at FROM call_records WHERE completed_at >= ? AND completed_at <= ? '
                # Disqualify the provider-only index: on real multi-GB stores it
                # scans all historical bodies/pages then sorts, even for LIMIT 1.
                # Prefer the existing timestamp index, without DB schema writes.
                'AND +provider = ? ORDER BY completed_at DESC LIMIT 1', (lower, upper, a['provider'])).fetchone()
            result['success_at'] = stamp(row[0]) if row else 0
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        result['source_error'] = 'success-records-unavailable'
        return result
    try:
        # Capture a finite snapshot; do not chase a continuously growing log.
        limit = 8 * 1024 * 1024
        with open(a['error_log_path'], 'rb') as stream:
            size = os.fstat(stream.fileno()).st_size
            offset = max(0, size - limit)
            stream.seek(offset)
            raw = stream.read(min(size, limit))
        if offset:
            raw = raw.partition(b'\n')[2]  # Drop possible partial first line.
        lines = raw.split(b'\n')[:-1]  # An incomplete final append is retried next tick.
        faults, oldest = {}, now
        for line in lines:
            if not line.strip():
                continue
            row = json.loads(line.decode('utf-8'))
            if not isinstance(row, dict):
                raise ValueError('malformed log row')
            at = stamp(row.get('ts'))
            if at:
                oldest = min(oldest, at)
            if not start <= at <= now:
                continue
            if network_error(row, a):
                key = common.fingerprint(str(row['context']['requestId']))
                # Retrying one request must not manufacture multiple request failures.
                if key not in faults or at < faults[key]['at']:
                    faults[key] = {'at': at, 'id': key, 'kind': row['error']['name']}
            else:
                result['ignored'] += 1
        if offset and oldest > start:
            result['source_error'] = 'error-window-exceeds-read-limit'
            return result
        result.update(available=True, faults=sorted(faults.values(), key=lambda r: r['at']))
    except (OSError, ValueError, TypeError, UnicodeError):
        result['source_error'] = 'error-log-unavailable'
    return result


def trace_evidence(previous, report, now, ttl):
    """Evidence is gathered only during an incident, never by idle IP polling."""
    ip = report.get('ip')
    if not ip:
        return {}  # Unknown is not evidence that the previous exit is unchanged.
    same = (previous.get('ip') == ip and 0 <= now - previous.get('at', 0) <= ttl)
    return {'ip': ip, 'at': now, 'samples': min(previous.get('samples', 0) + 1, 10) if same else 1}


def recent_faults(ev, d, now, cfg):
    boundary = max(ev['success_at'], d.get('baseline_at', 0), d.get('recovered_at', 0))
    return [r for r in ev['faults'] if boundary < r['at'] <= now
            and now - r['at'] <= settings(cfg)['window_seconds']]


def run(g, emit, read_journal):
    cfg, now = g.cfg, time.time()
    a = settings(cfg)
    state = common.load_json(g.state_path, {})
    d = state.setdefault('demand', {})
    active_probe = False

    def done(reason, **extra):
        previous = d.get('reason')
        d.update(reason=reason, last_tick=now, **extra)
        g.save(state)
        if reason != previous or now - d.get('last_logged', 0) >= 3600:
            emit('decision' if active_probe else 'passive', reason=reason,
                 success_at=d.get('success_at', 0), network_errors=d.get('network_errors', 0),
                 active_probe=active_probe)
            d['last_logged'] = now
            g.save(state)
        return reason

    def clear_runtime_evidence(mode, reason='runtime-mode-hold'):
        """Drop evidence tied to a previous Clash runtime mode/selection."""
        selector = 'GLOBAL' if mode == 'global' else (g.cfg.get('selector') if mode == 'rule' else None)
        d.update(baseline_at=time.time(), consumed_until=time.time(), confirmations=[], trace={})
        state.update(runtime_mode=mode, runtime_selector=selector,
                     hold_until=time.time() + g.cfg['manual_hold_seconds'], failures=[],
                     last_good={}, last_result={}, token=None)
        g.save(state)
        return reason

    # Clash owns mode selection.  Poll it every local tick, including idle
    # ticks, but never change it from this daemon.
    def monitor_mode():
        try:
            mode = g.runtime_mode()
        except (common.SelectorError, OSError, ValueError):
            return clear_runtime_evidence(None, 'runtime-mode-unavailable')
        if mode not in ('rule', 'global'):
            return clear_runtime_evidence(mode, 'unsupported-mode')
        if state.get('runtime_mode') != mode:
            return clear_runtime_evidence(mode)
        return None

    mode_reason = monitor_mode()

    # Observe journals every LOCAL tick, not only when external probes are allowed.
    logs = read_journal(cfg, state.get('journal_cursor_us', 0), now)
    state.update(journal_cursor_us=logs['cursor_us'], journal_available=logs['available'])
    d['journal_recent'] = [v for v in d.get('journal_recent', []) if now - v['at'] <= a['window_seconds']]
    if logs['errors']:
        d['journal_recent'].append({'at': now, 'count': logs['errors']})
    state['journal_errors'] = sum(v['count'] for v in d['journal_recent'])
    ev = evidence(cfg, now)
    d.update(success_at=ev['success_at'], network_errors=len(ev['faults']),
             sources_available=ev['available'], ignored_errors=ev['ignored'])
    # Initialize the file signature and runtime baseline in the same tick.
    marker = common.load_json(cfg['manual_history'], {}) if cfg['manual_history'] else {}
    signature = common.fingerprint({'text': policy.read(cfg['clash_config']), 'cfg': cfg, 'manual': marker})
    if d.get('signature') != signature or now < d.get('last_tick', 0):
        d.update(signature=signature, baseline_at=now, consumed_until=now, trace={}, confirmations=[])
        state.update(hold_until=now + cfg['manual_hold_seconds'], failures=[], last_good={}, last_result={})
        return done(mode_reason if mode_reason in ('unsupported-mode', 'runtime-mode-unavailable') else 'baseline-hold')
    if mode_reason:
        return done(mode_reason)
    if not ev['available']:
        d.update(confirmations=[], trace={})
        state['failures'] = []
        return done(ev['source_error'])
    if state.get('pending'):
        return done('pending-manual-review')
    if ev['success_at'] > d.get('last_confirmed', 0):
        d.update(confirmations=[], trace={})
        state['failures'] = []
    faults = recent_faults(ev, d, now, cfg)
    # Three NEW distinct requests are required for every diagnostic round.
    consumed = {k: t for k, t in d.get('consumed_ids', {}).items() if now - t < 86400}
    fresh = [r for r in faults if r['at'] > d.get('consumed_until', 0) and r['id'] not in consumed]
    if not faults:
        return done('passive-healthy' if ev['success_at'] else 'idle')
    if len(fresh) < a['min_error_requests'] or fresh[-1]['at'] - fresh[0]['at'] < a['error_span_seconds']:
        return done('insufficient-new-errors')
    if state.get('paused'):
        return done('paused')
    if now < state.get('hold_until', 0):
        return done('manual/config-hold')
    if now - state.get('last_attempt', 0) < cfg['cooldown_seconds']:
        return done('switch-cooldown')
    if len([t for t in state.get('attempts', []) if now - t < 86400]) >= cfg['max_attempts_24h']:
        return done('switch-daily-budget')
    if now - d.get('last_probe', 0) < a['probe_cooldown_seconds']:
        return done('diagnostic-cooldown')
    probes = [t for t in d.get('probes', []) if now - t < 86400]
    if len(probes) >= a['max_probes_24h']:
        return done('diagnostic-daily-budget')
    # Always snapshot before consuming a diagnostic allowance; busy is harmless.
    try:
        with common.locked(cfg['mutation_lock']):
            snap = g.snapshot()
    except common.SelectorError as error:
        if '另一个更新/切换/评估正在进行' in str(error):
            return done('busy')
        raise
    mode_reason = monitor_mode()
    if mode_reason:
        return done(mode_reason)
    if state.get('token') != snap['token']:
        state.update(token=snap['token'], hold_until=now + cfg['manual_hold_seconds'], failures=[])
        d.update(baseline_at=now, consumed_until=now, confirmations=[], trace={})
        return done('runtime-selection-hold')
    d.update(consumed_until=fresh[-1]['at'], last_probe=now, probes=probes + [now])
    consumed.update({r['id']: now for r in fresh})
    d['consumed_ids'] = consumed
    g.save(state)  # Durable budget/consumption before issuing any request.
    active_probe = True
    report = g.business()
    mode_reason = monitor_mode()
    if mode_reason:
        return done(mode_reason)
    emit('fault_confirmation', target=snap['selected'], new_errors=len(fresh), **report)
    state.update(last_check=now, last_result=report)
    if report['ok'] or not report['switchable']:
        d.update(confirmations=[], trace={}, recovered_at=time.time())
        state['failures'] = []
        return done('confirmed-recovered' if report['ok'] else 'ambiguous-response')
    confirmations = d.get('confirmations', [])
    if now - d.get('last_confirmed', 0) > cfg['failure_gap_seconds']:
        confirmations = []
        d['trace'] = {}
    confirmations = (confirmations + [now])[-100:]
    d.update(confirmations=confirmations, last_confirmed=now,
             trace=trace_evidence(d.get('trace', {}), report, now, cfg['same_ip_max_age_seconds']))
    state['failures'] = confirmations
    g.save(state)
    if len(confirmations) < cfg['failure_count'] or now - confirmations[0] < cfg['failure_span_seconds']:
        return done('confirmed-failure-wait-new-demand')
    evaluations = [t for t in d.get('evaluations', []) if now - t < 86400]
    if len(evaluations) >= a['max_evaluations_24h']:
        return done('evaluation-daily-budget')
    if now - state.get('last_evaluation', 0) < cfg['evaluation_interval_seconds']:
        return done('evaluation-cooldown')

    def still_needed():
        current_ev = evidence(cfg, time.time())
        if not current_ev['available']:
            return False
        # Any successful business call after the trigger supersedes synthetic failure.
        if current_ev['success_at'] > ev['success_at']:
            return False
        remaining = recent_faults(current_ev, d, time.time(), cfg)
        return bool(remaining and len(remaining) >= a['min_error_requests'])

    if not still_needed():
        return done('demand-ended-or-recovered')
    mode_reason = monitor_mode()
    if mode_reason:
        return done(mode_reason)
    # Preflight current path before a potentially expensive candidate scan.
    current = g.business()
    mode_reason = monitor_mode()
    if mode_reason:
        return done(mode_reason)
    if current['ok'] or not current['switchable']:
        d.update(confirmations=[], trace={}, recovered_at=time.time())
        state.update(failures=[], last_result=current)
        return done('recovered-before-scan')
    trace = trace_evidence(d.get('trace', {}), current, time.time(), cfg['same_ip_max_age_seconds'])
    d.update(trace=trace, evaluations=evaluations + [time.time()])
    state['last_evaluation'] = time.time()
    g.save(state)
    try:
        results, skipped = g.evaluate(snap)
    except common.SelectorError:
        mode_reason = monitor_mode()
        if mode_reason:
            return done(mode_reason)
        raise
    mode_reason = monitor_mode()
    if mode_reason:
        return done(mode_reason)
    common.save_json(os.path.join(cfg['state_dir'], 'evaluation.json'),
                     {'at': time.time(), 'results': results, 'skipped': skipped, 'trigger': 'business-network-errors'})
    old_ip = trace.get('ip', '') if trace.get('samples', 0) >= 2 else ''
    cross_allowed = cfg['allow_cross_ip'] and now - confirmations[0] >= cfg['cross_ip_failure_span_seconds']
    options = []
    for name, result in results.items():
        if not result['ok'] or result['leaf'] == snap['route']['leaf']:
            continue
        same = bool(old_ip and old_ip == result.get('ip'))
        if not same and not cross_allowed:
            continue
        countries = cfg['preferred_countries']
        rank = countries.index(result['country']) if result.get('country') in countries else len(countries)
        options.append((not same, rank, result['seconds'], name))
    if not options:
        emit('no_candidate', evaluated=len(results), skipped=skipped)
        return done('no-candidate')
    if not still_needed():
        return done('demand-ended-or-recovered')
    if cfg['mode'] != 'auto':
        emit('would_switch', target=sorted(options)[0][-1])
        return done('observe-only')
    target = sorted(options)[0][-1]
    try:
        fresh_result, _ = g.evaluate(snap, only=target)
    except common.SelectorError:
        mode_reason = monitor_mode()
        if mode_reason:
            return done(mode_reason)
        raise
    mode_reason = monitor_mode()
    if mode_reason:
        return done(mode_reason)
    chosen = fresh_result[target]
    if not chosen['ok']:
        return done('candidate-unstable')
    same = bool(old_ip and results[target].get('ip') == old_ip and chosen.get('ip') == old_ip)
    if not same and not cross_allowed:
        return done('candidate-ip-changed')
    with common.locked(cfg['mutation_lock']):
        mode_reason = monitor_mode()
        if mode_reason:
            return done(mode_reason)
        latest = g.snapshot()
        if latest['token'] != snap['token'] or not still_needed():
            return done('changed-or-recovered')
        final = g.business()
        mode_reason = monitor_mode()
        if mode_reason:
            return done(mode_reason)
        if final['ok'] or not final['switchable']:
            d.update(confirmations=[], trace={}, recovered_at=time.time())
            state.update(failures=[], last_result=final)
            return done('recovered-before-switch')
        # Never advertise a stale same-egress comparison after a long scan.
        if same and (final.get('ip') != old_ip or time.time() - trace['at'] > cfg['same_ip_max_age_seconds']):
            return done('current-egress-changed')
        mode_reason = monitor_mode()
        if mode_reason:
            return done(mode_reason)
        if g.snapshot()['token'] != snap['token'] or not still_needed():
            return done('changed-or-recovered')
        g.transaction(latest, target, state, required_ip=old_ip if same else None)
        d.update(confirmations=[], trace={}, recovered_at=time.time())
    return done('switched')
