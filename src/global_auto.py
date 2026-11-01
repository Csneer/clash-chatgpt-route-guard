#!/usr/bin/env python3
"""Opt-in GLOBAL selector: local-to-node TCP quality, isolated relay checks."""
import argparse
import concurrent.futures
import json
import os
import socket
import statistics
import subprocess
import sys
import time
import urllib.parse

import clash_common as common
import mihomo_policy as policy
import global_node_score as scoring

Error = common.SelectorError
DEFAULT_CONFIG = os.path.expanduser('~/.config/clash-guard/global-auto.yaml')
BEGIN = '// BEGIN clash-chatgpt-route-guard global auto'
END = '// END clash-chatgpt-route-guard global auto'
DEFAULTS = dict(version=1, group='GLOBAL Stable Auto', config_source='verge',
                clash_config='', controller_unix='', controller_tcp='',
                binary='', profile_script='', profiles_index='', state_dir='', run_lock='',
                mutation_lock='', probe_lock='', business_proxy='http://127.0.0.1:7890', interval_seconds=30,
                scan_seconds=600, inventory_scan_seconds=60, candidate_max_age_seconds=300, failure_scan_seconds=60, node_cooldown_seconds=600,
                hold_seconds=600, manual_hold_seconds=120, switch_cooldown_seconds=60,
                max_switches_hour=6, batch_size=8, concurrency=2, candidate_rechecks=3, failure_count=2,
                stability_failure_count=3, max_jitter_ms=250, max_tcp_ms=800,
                tcp_samples=3, tcp_timeout_seconds=2, timeout_seconds=5,
                improvement_ms=100, checks=[{'url': 'https://cp.cloudflare.com/generate_204', 'status': 204},
                                          {'url': 'https://www.gstatic.com/generate_204', 'status': 204}])


def load_config(path):
    raw = policy.parse(policy.read(path))
    if set(raw) - set(DEFAULTS):
        raise Error('unknown global-auto configuration fields')
    cfg = dict(DEFAULTS, **raw)
    if cfg['version'] != 1 or cfg['group'] != 'GLOBAL Stable Auto':
        raise Error('unsupported global-auto version or group')
    if cfg['config_source'] not in ('verge', 'static'):
        raise Error('config_source must be verge or static')
    for key in ('clash_config', 'binary', 'state_dir', 'run_lock', 'mutation_lock', 'probe_lock'):
        if not isinstance(cfg[key], str) or not os.path.isabs(cfg[key]):
            raise Error(key + ' must be an absolute path')
    for key in ('profile_script', 'profiles_index'):
        if cfg['config_source'] == 'static' and cfg[key] == '':
            continue
        if not isinstance(cfg[key], str) or not os.path.isabs(cfg[key]):
            raise Error(key + ' must be an absolute path, or empty for a static config')
    if (not isinstance(cfg['controller_unix'], str)
            or (cfg['controller_unix'] and not os.path.isabs(cfg['controller_unix']))):
        raise Error('controller_unix must be empty or an absolute path')
    if not isinstance(cfg['controller_tcp'], str):
        raise Error('controller_tcp must be a string')
    if cfg['controller_tcp']:
        try:
            address = urllib.parse.urlsplit('http://' + cfg['controller_tcp'])
            valid = (address.hostname in ('127.0.0.1', '::1', 'localhost')
                     and address.port is not None and address.port > 0 and not address.username
                     and not address.password and not address.path
                     and not address.query and not address.fragment)
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise Error('controller_tcp must be a loopback host and port')
    elif not os.path.isabs(cfg['controller_unix']):
        raise Error('controller_unix must be an absolute path when controller_tcp is empty')
    limits = dict(interval_seconds=(15, 300), scan_seconds=(300, 3600),
                  inventory_scan_seconds=(15, 300), candidate_max_age_seconds=(60, 1200), failure_scan_seconds=(15, 300),
                  node_cooldown_seconds=(300, 3600), hold_seconds=(300, 3600),
                  manual_hold_seconds=(30, 600), switch_cooldown_seconds=(30, 300),
                  max_switches_hour=(1, 12), batch_size=(2, 16), concurrency=(1, 4), candidate_rechecks=(1, 5),
                  failure_count=(2, 5), stability_failure_count=(2, 6),
                  max_jitter_ms=(50, 5000), max_tcp_ms=(200, 10000),
                  tcp_samples=(3, 5), tcp_timeout_seconds=(1, 5),
                  timeout_seconds=(3, 10), improvement_ms=(100, 5000))
    for key, (low, high) in limits.items():
        if type(cfg[key]) is not int or not low <= cfg[key] <= high:
            raise Error(key + ' outside safe bounds')
    url = urllib.parse.urlsplit(cfg['business_proxy'])
    if (url.scheme != 'http' or url.hostname not in ('127.0.0.1', 'localhost', '::1') or not url.port
            or url.username or url.password or url.path or url.query or url.fragment):
        raise Error('business_proxy must be a credential-free loopback HTTP listener')
    if not isinstance(cfg['checks'], list) or not 1 <= len(cfg['checks']) <= 2:
        raise Error('one or two HTTPS relay checks required')
    for check in cfg['checks']:
        if not isinstance(check, dict) or set(check) != {'url', 'status'} or check['status'] != 204:
            raise Error('relay checks require URL and expected 204')
        url = urllib.parse.urlsplit(check['url'])
        if (url.scheme != 'https' or not url.hostname or url.port not in (None, 443)
                or url.username or url.password or url.fragment):
            raise Error('relay checks must be credential-free HTTPS/443')
    return cfg


def eligible(node):
    # Bound the first version to the ordinary subscription transports on this host.
    return (node.get('type') == 'ss' and not node.get('name', '').startswith('Codex-')
            and not node.get('dialer-proxy') and not node.get('interface-name')
            and not node.get('routing-mark') and not node.get('smux')
            and node.get('plugin') in (None, '', 'obfs'))


def script_block():
    return BEGIN + """
  const autoNodes = (config.proxies || []).filter(p => p.type === 'ss' &&
    !p.name.startsWith('Codex-') && !p['dialer-proxy'] && !p['interface-name'] &&
    !p['routing-mark'] && !p.smux && (!p.plugin || p.plugin === 'obfs')).map(p => p.name);
  config['proxy-groups'] = (config['proxy-groups'] || []).filter(g => g.name !== 'GLOBAL Stable Auto');
  if (autoNodes.length) config['proxy-groups'].push({name: 'GLOBAL Stable Auto', type: 'select',
    proxies: autoNodes, 'interrupt-exist-connections': false});
  config.profile = Object.assign({}, config.profile, {'store-selected': true});
  """ + END


def rewrite_script(source):
    if source.count(BEGIN) != source.count(END) or source.count(BEGIN) > 1:
        raise Error('ambiguous global-auto script markers')
    if BEGIN in source:
        start, end = source.index(BEGIN), source.index(END)
        if end < start:
            raise Error('invalid global-auto script markers')
        return source[:start] + script_block() + source[end + len(END):]
    if source.count('return config;') != 1:
        raise Error('profile script needs one return config')
    return source.replace('return config;', script_block() + '\n  return config;', 1)


def resolve_addresses(node, cfg):
    """Bound libc DNS lookup too; a stuck resolver must not stall recovery."""
    resolver = ('import json,socket,sys; print(json.dumps(socket.getaddrinfo('
                'sys.argv[1],int(sys.argv[2]),socket.AF_UNSPEC,socket.SOCK_STREAM)))')
    try:
        result = subprocess.run([sys.executable, '-I', '-c', resolver,
                                 node['server'], str(node['port'])],
                                capture_output=True, text=True,
                                timeout=2)
        if result.returncode:
            return []
        return list(dict.fromkeys((row[0], tuple(row[4])) for row in json.loads(result.stdout)))
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return []


def tcp_quality(node, cfg):
    """Measure actual upstream TCP handshakes, not target-site latency or ping."""
    values = []
    timeouts = 0
    addresses = resolve_addresses(node, cfg)
    # Bound all address attempts together; a multi-address outage must not
    # monopolize the service and delay the next live-health observation.
    deadline = time.monotonic() + cfg['tcp_samples'] * cfg['tcp_timeout_seconds']
    for index in range(cfg['tcp_samples']):
        sample = []
        # A hostname may publish a dead AAAA or one dead A record.  Try every
        # resolved address for this sample, and score the first working route;
        # one unusable family must not quarantine an otherwise reachable node.
        ordered = addresses[index % len(addresses):] + addresses[:index % len(addresses)] if addresses else []
        for family, address in ordered:
            start = time.monotonic()
            remaining = deadline - start
            if remaining <= 0:
                break
            try:
                with socket.socket(family, socket.SOCK_STREAM) as connection:
                    connection.settimeout(min(cfg['tcp_timeout_seconds'], remaining))
                    connection.connect(address)
                sample.append(round((time.monotonic() - start) * 1000, 2))
                break
            except socket.timeout:
                timeouts += 1
                continue
            except OSError:
                continue
        values.append(min(sample) if sample else None)
        if index + 1 < cfg['tcp_samples'] and time.monotonic() < deadline:
            time.sleep(max(0, min(.2, deadline - time.monotonic())))
    good = [v for v in values if v is not None]
    median = statistics.median(good) if good else None
    jitter = max(good) - min(good) if good else None
    return dict(tcp_ms=median, jitter_ms=jitter, max_tcp_ms=max(good) if good else None,
                tcp_samples=values, tcp_timeouts=timeouts,
                ok=len(good) == cfg['tcp_samples'],
                score_ms=round(median + jitter / 2, 2) if good else None)


def measure(node, cfg, proxy=None):
    quality = tcp_quality(node, cfg)
    # TCP samples describe quality, not end-to-end reachability. The proxy may
    # reach a working address even if a direct sample or local DNS timed out.
    # Test actual relay traffic for candidates too, so outage recovery can use
    # a reachable route while normal preference still requires stable quality.

    def relay(url):
        def fetch(check):
            r = common.fetch(url, check['url'], cfg['timeout_seconds'])
            return dict(ok=r['exit'] == 0 and r['code'] == check['status'],
                        curl_exit=r['exit'], code=r['code'])
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(cfg['checks'])) as pool:
            rows = list(pool.map(fetch, cfg['checks']))
        relay_successes = sum(r['ok'] for r in rows)
        transport_ok = relay_successes > 0
        relay_complete = relay_successes == len(rows)
        switchable = all(r['curl_exit'] in (5, 6, 7, 28, 35, 52, 55, 56) for r in rows)
        stable = (quality['ok'] and relay_complete
                  and quality.get('jitter_ms', 0) <= cfg['max_jitter_ms']
                  and quality.get('max_tcp_ms', 0) <= cfg['max_tcp_ms'])
        if stable:
            reason = 'healthy'
        elif not quality['ok'] and relay_complete:
            reason = 'unstable-tcp'
        elif not transport_ok:
            reason = 'transport-failure' if switchable else 'endpoint-response'
        elif not relay_complete:
            reason = 'unstable-relay'
        else:
            reason = 'unstable-jitter'
        return dict(quality, ok=transport_ok, stable=stable, switchable=switchable and not transport_ok,
                    relay=rows, relay_successes=relay_successes, relay_total=len(rows),
                    reason=reason)
    if proxy:
        return relay(proxy)
    with common.ProbeProcess([node], cfg['binary']) as process:
        return relay(process.proxy(node['name']))


def improvement(current, candidate, cfg):
    return (current.get('stable', current.get('ok')) and candidate.get('stable', candidate.get('ok'))
            and current['tcp_ms'] - candidate['tcp_ms'] >= cfg['improvement_ms']
            and candidate['score_ms'] < current['score_ms'])


def stable(report):
    """Accept old test/state records while making new decisions stability-aware."""
    return bool(report.get('stable', report.get('ok')))


def successful_relays(report):
    """Endpoint indexes with an actual successful expected-204 response."""
    return {index for index, row in enumerate(report.get('relay', []))
            if row.get('ok') and row.get('curl_exit') == 0 and row.get('code') == 204}


def recovery_usable(report):
    """Keep strict quality for preference, but recognize proven partial relay."""
    return stable(report) or bool(report.get('ok') and successful_relays(report))


def recovery_overlap(*reports):
    """Require the same endpoint to keep working across recovery observations."""
    evidence = []
    for report in reports:
        endpoints = successful_relays(report)
        if not endpoints:
            return set()
        evidence.append(endpoints)
    return set.intersection(*evidence) if evidence else set()


class Auto:
    def __init__(self, cfg):
        self.cfg = cfg
        self.path = os.path.join(cfg['state_dir'], 'state.json')

    def state(self):
        return common.load_json(self.path, {})

    def save(self, state):
        common.save_json(self.path, state)

    def snapshot(self):
        cfg = self.cfg
        text = policy.read(cfg['clash_config'])
        config = policy.parse(text)
        api = dict(config, **{'external-controller': cfg['controller_tcp'],
                              'external-controller-unix': cfg['controller_unix']})
        runtime = policy.api(api, '/configs')
        live = policy.api(api, '/proxies')['proxies']
        selected = live.get('GLOBAL', {}).get('now')
        base = dict(active=False, mode=runtime.get('mode'), global_selection=selected)
        group = next((g for g in config.get('proxy-groups', []) if g['name'] == cfg['group']), {})
        actual = live.get(cfg['group'], {})
        if runtime.get('mode') != 'global' or selected != cfg['group']:
            return base
        if (group.get('type') != 'select' or actual.get('type') != 'Selector'
                or actual.get('all') != group.get('proxies') or actual.get('now') not in group.get('proxies', [])):
            raise Error('managed selector differs from local configuration')
        nodes = {n['name']: n for n in config.get('proxies', []) if eligible(n)}
        if any(n not in nodes for n in group['proxies']):
            raise Error('managed selector contains unsupported nodes')
        if (config.get('profile', {}).get('store-selected') is not True
                or urllib.parse.urlsplit(cfg['business_proxy']).port not in (runtime.get('port'), runtime.get('mixed-port'))):
            raise Error('listener or selection persistence mismatch')
        source = dict(text=text, cfg=cfg)
        if cfg['config_source'] == 'verge':
            script = policy.read(cfg['profile_script'])
            index_text = policy.read(cfg['profiles_index'])
            index = policy.parse(index_text)
            profile = next((p for p in index.get('items', []) if p.get('uid') == index.get('current')), {})
            if (profile.get('option', {}).get('script') != os.path.splitext(os.path.basename(cfg['profile_script']))[0]
                    or script.count(BEGIN) != 1 or script.count(END) != 1):
                raise Error('active profile changed; automatic selection paused')
            source.update(script=script, index=index_text)
        generation = common.fingerprint(source)
        return dict(base, active=True, selected=actual['now'], api=api,
                    nodes={n: nodes[n] for n in group['proxies']}, generation=generation,
                    token=common.fingerprint([generation, actual['now']]))

    def probe(self, snap, name, live=False):
        return measure(snap['nodes'][name], self.cfg, self.cfg['business_proxy'] if live else None)

    def record(self, state, snap, name, report, scheduled=True):
        previous = state.setdefault('nodes', {}).get(name, {})
        now = time.time()
        row = dict(report, at=now, identity=common.fingerprint(snap['nodes'][name]))
        measurement_epoch = scoring.epoch(self.cfg)
        compatible = (previous.get('identity') == row['identity']
                      and previous.get('statistics_epoch') == measurement_epoch)
        old_cooldown = previous.get('cooldown_until', 0) if compatible else 0
        row['cooldown_until'] = (old_cooldown if stable(report)
                                 else now + self.cfg['node_cooldown_seconds'])
        row.update(scoring.observe(previous, report, row['identity'], measurement_epoch,
                                   now, scheduled=scheduled))
        state['nodes'][name] = row

    def inventory(self, snap, state):
        now, measurement_epoch = time.time(), scoring.epoch(self.cfg)
        rows = {}
        for name, node in snap.get('nodes', {}).items():
            stored = state.get('nodes', {}).get(name, {})
            measured = (stored.get('identity') == common.fingerprint(node)
                        and stored.get('statistics_epoch') == measurement_epoch)
            row = dict(stored) if measured else {}
            history = [item for item in row.get('history', [])
                       if 0 <= now - item['at'] <= scoring.WINDOW_SECONDS]
            row['ranking'] = scoring.summarize(history, row, now)
            row.update(measured=measured,
                       fresh=measured and 0 <= now - row.get('at', 0) <= self.cfg['candidate_max_age_seconds'],
                       cooling=measured and row.get('cooldown_until', 0) > now)
            rows[name] = row
        return rows

    def scan(self, snap, state, recovery=False):
        now = time.time()
        names = [n for n in snap['nodes'] if n != snap['selected']]
        if not names:
            return {}
        start = state.get('cursor', 0) % len(names)
        ordered = names[start:] + names[:start]
        inventory = self.inventory(snap, state)
        retry_after = max(120, self.cfg['failure_scan_seconds'] * 2)
        eligible_names = [n for n in ordered if not inventory[n]['cooling']
                          or (recovery and now - inventory[n].get('at', now) >= retry_after)]
        recent = []
        if recovery:
            for name in eligible_names:
                row = inventory[name]
                # Expired success can prioritize a new isolated measurement,
                # but never bypass fresh candidate eligibility below.
                priority_age = max(self.cfg['candidate_max_age_seconds'], 600)
                if (row['measured'] and stable(row)
                        and 0 <= now - row.get('at', 0) <= priority_age):
                    recent.append(name)
            recent.sort(key=lambda n: state['nodes'][n]['at'], reverse=True)
        else:
            recent = [n for n in eligible_names if inventory[n]['measured']
                      and stable(inventory[n]) and 0 <= now - inventory[n].get('at', 0) <= 90]
            recent.sort(key=lambda n: -inventory[n]['ranking']['score'])
            # Configuration changes invalidate scores, not the usefulness of a
            # recent successful route as a hint for a new full measurement.
            # Fill a missing backup before repeatedly refreshing the sole one.
            warmup = []
            if len(recent) < 2:
                for name in eligible_names:
                    previous = state.get('nodes', {}).get(name, {})
                    if (name not in recent and stable(previous)
                            and previous.get('identity') == common.fingerprint(snap['nodes'][name])
                            and previous.get('cooldown_until', 0) <= now
                            and 0 <= now - previous.get('at', 0) <= 300):
                        warmup.append(name)
                warmup.sort(key=lambda n: state['nodes'][n]['at'], reverse=True)
            recent = warmup[:1] or sorted(recent[:2], key=lambda n: inventory[n]['at'])[:1]
        # Reserve most of the batch for round-robin exploration, so priority
        # checks cannot starve nodes not yet measured. All candidates are re-probed.
        priority = recent[:min(2, self.cfg['batch_size'] // 2)]
        rotating = [n for n in eligible_names if n not in priority][:self.cfg['batch_size'] - len(priority)]
        batch = priority + rotating
        state['cursor'] = (names.index(rotating[-1]) + 1) % len(names) if rotating else start
        state['last_scan'] = now
        state['evaluation'] = dict(at=now, recovery=recovery, scanned=batch, priority=priority, rechecks=[])
        self.save(state)
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.cfg['concurrency']) as pool:
            jobs = {pool.submit(self.probe, snap, n): n for n in batch}
            for job in concurrent.futures.as_completed(jobs):
                name = jobs[job]
                try:
                    report = job.result()
                except subprocess.TimeoutExpired:
                    report = dict(ok=False, stable=False, switchable=False, reason='probe-timeout')
                except (Error, OSError, ValueError):
                    report = dict(ok=False, switchable=False, reason='probe-unavailable')
                results[name] = report
                self.record(state, snap, name, report)
                if recovery and stable(report):
                    state['nodes'][name]['cooldown_until'] = 0
        state['evaluation']['stable_candidates'] = [n for n, r in results.items() if stable(r)]
        state['evaluation']['usable_candidates'] = [n for n, r in results.items() if recovery_usable(r)]
        self.save(state)
        return results

    def switch(self, snap, target, state, reason, recovery_endpoints=None):
        cfg = self.cfg
        with common.locked(cfg['mutation_lock']):
            if self.snapshot().get('token') != snap['token']:
                return 'selection-changed'
            state['pending'] = dict(old=snap['selected'], target=target, generation=snap['generation'], at=time.time())
            state['attempts'] = [t for t in state.get('attempts', []) if time.time() - t < 3600] + [time.time()]
            state['last_attempt'] = time.time()
            self.save(state)
            # A lost controller reply is ambiguous: retain pending and never blind-retry.
            policy.api(snap['api'], '/proxies/' + urllib.parse.quote(cfg['group'], safe=''), 'PUT', {'name': target})
            current = self.snapshot()
            if not current.get('active') or current.get('generation') != snap['generation'] or current.get('selected') != target:
                return 'pending-selection-changed'
            checked = self.probe(current, target, live=True)
            if self.snapshot().get('token') != current['token']:
                return 'pending-selection-changed'
            self.record(state, current, target, checked, scheduled=False)
            state.setdefault('evaluation', {})['postcheck'] = dict(
                name=target, reason=checked.get('reason'), stable=stable(checked),
                relay_successes=checked.get('relay_successes'), relay_total=checked.get('relay_total'),
                successful_endpoints=sorted(successful_relays(checked)),
                required_endpoints=sorted(recovery_endpoints) if recovery_endpoints is not None else None)
            # Hard-outage recovery must preserve an endpoint demonstrated by
            # both isolated observations; unrelated successes cannot compose a
            # reliable route. Legacy stable records have no endpoint evidence.
            if reason == 'failure' and recovery_endpoints is not None:
                accepted = bool(recovery_endpoints & successful_relays(checked))
            else:
                accepted = stable(checked)
            if not accepted:
                policy.api(snap['api'], '/proxies/' + urllib.parse.quote(cfg['group'], safe=''), 'PUT', {'name': snap['selected']})
                if self.snapshot().get('token') != snap['token']:
                    return 'pending-rollback-uncertain'
                # Returning to the failed old node is not evidence of recovery.
                state.update(pending=None)
                self.save(state)
                return 'rolled-back'
            state.update(pending=None, selected=target, failures=0, health_window=[],
                         degradation_confirmed=False, recovery_samples=0,
                         stability_failures=0 if stable(checked) else 1, last_switch=time.time(),
                         last_change=dict(old=snap['selected'], target=target, reason=reason,
                                          postcheck_reason=checked.get('reason'), at=time.time()),
                         current=checked, token=current['token'])
            self.save(state)
            return 'switched'

    def observe_health(self, state, report, now):
        """Count only interval-separated cycle probes, never in-cycle rechecks."""
        window = [row for row in state.get('health_window', [])
                  if 0 <= now - row['at'] <= 300][-5:]
        if not any(row['bad'] for row in window):
            state.update(degradation_confirmed=False, recovery_samples=0)
        hard = bool(report.get('switchable') and not report.get('ok'))
        bad = hard or (not stable(report) and report.get('reason', '').startswith('unstable-'))
        window.append(dict(at=now, bad=bad))
        state['health_window'] = window
        state['recovery_samples'] = state.get('recovery_samples', 0) + 1 if stable(report) else 0
        confirmed = (state.get('degradation_confirmed', False)
                     or state['failures'] >= self.cfg['failure_count']
                     or state['stability_failures'] >= self.cfg['stability_failure_count']
                     or sum(row['bad'] for row in window) >= 3)
        if state['recovery_samples'] >= 2:
            confirmed = False
            state.update(health_window=[], failures=0, stability_failures=0)
        state['degradation_confirmed'] = confirmed
        return confirmed

    def cycle(self):
        cfg, now, state = self.cfg, time.time(), self.state()
        snap = self.snapshot()
        if not snap['active']:
            if state.get('active'):
                state.update(active=False, failures=0, stability_failures=0, token=None,
                             health_window=[], degradation_confirmed=False, recovery_samples=0)
                self.save(state)
            return dict(action='inactive', mode=snap['mode'], global_selection=snap['global_selection'])
        if state.get('pending'):
            return dict(action='pending-review', pending=state['pending'])
        changed = state.get('token') != snap['token']
        if changed:
            state.update(active=True, token=snap['token'], selected=snap['selected'], failures=0,
                         stability_failures=0, health_window=[], degradation_confirmed=False,
                         recovery_samples=0, hold_until=now + cfg['manual_hold_seconds'],
                         last_scan=0, last_decision=0, last_recovery_decision=0, last_check=0)
        if now - state.get('last_check', 0) < cfg['interval_seconds']:
            return dict(action='waiting', selected=snap['selected'])
        if now - state.get('last_check', 0) > 300:
            state.update(failures=0, stability_failures=0)
        state['last_check'] = now
        self.save(state)
        with common.locked(cfg['probe_lock']):
            report = self.probe(snap, snap['selected'], live=True)
            if self.snapshot().get('token') != snap['token']:
                return dict(action='selection-changed')
            state['current'] = report
            hard_failure = report['switchable'] and not report['ok']
            quality_failure = (not stable(report)
                               and report.get('reason', '').startswith('unstable-'))
            state['failures'] = state.get('failures', 0) + 1 if hard_failure else 0
            state['stability_failures'] = (state.get('stability_failures', 0) + 1
                                           if quality_failure else 0)
            degraded = self.observe_health(state, report, now)
            self.record(state, snap, snap['selected'], report)
            self.save(state)
            failed = state['failures'] >= cfg['failure_count'] or (degraded and hard_failure)
            # The first hard failure must not spend a full inventory scan
            # delaying the second confirmation probe.
            if hard_failure and not degraded:
                return dict(action='failure-confirming')
            interval = cfg['failure_scan_seconds'] if degraded else cfg['inventory_scan_seconds']
            scan_due = now - state.get('last_scan', 0) >= interval
            if scan_due and not degraded:
                self.scan(snap, state, recovery=degraded)
                if self.snapshot().get('token') != snap['token']:
                    return dict(action='selection-changed')
            if degraded and stable(report):
                return dict(action='recovery-confirming')
            if not stable(report) and not degraded:
                return dict(action='stability-confirming' if quality_failure else 'ambiguous-response')
            if degraded and now - state.get('last_recovery_decision', 0) < cfg['failure_scan_seconds']:
                return dict(action='scan-cooldown')
            if not degraded and now - state.get('last_decision', 0) < cfg['scan_seconds']:
                return dict(action='healthy')
            state['last_recovery_decision' if degraded else 'last_decision'] = now
            if degraded:
                state['evaluation'] = dict(at=now, recovery=True, scanned=[], priority=[], rechecks=[])
            else:
                state.setdefault('evaluation', {})['rechecks'] = []
            self.save(state)
            tried = set()
            outcome = 'no-candidate'
            for phase in range(2 if degraded else 1):
                if phase:
                    if not scan_due or len(tried) >= cfg['candidate_rechecks']:
                        break
                    rechecks = state['evaluation']['rechecks']
                    self.scan(snap, state, recovery=True)
                    state['evaluation']['rechecks'] = rechecks
                    self.save(state)
                    if self.snapshot().get('token') != snap['token']:
                        return dict(action='selection-changed')
                inventory = self.inventory(snap, state)
                candidates = {n: r for n, r in inventory.items()
                              if n != snap['selected'] and n not in tried and r['fresh']
                              and ((failed and recovery_usable(r))
                                   or (not r['cooling'] and stable(r)))}
                options = []
                for name, row in candidates.items():
                    rank = row['ranking']
                    if degraded or improvement(report, row, cfg):
                        if degraded:
                            # Fully stable candidates always win; a usable
                            # partial relay is the continuity fallback.
                            options.append((0 if stable(row) else 1,
                                            -rank['score'], row.get('score_ms') or float('inf'), name))
                        else:
                            options.append((-rank['score'], row['score_ms'], name))
                if not options:
                    if not degraded and candidates:
                        return dict(action='below-improvement-threshold')
                    if not tried:
                        outcome = ('no-stable-candidate' if any(r.get('ok') for n, r in inventory.items()
                                   if n != snap['selected'] and r['fresh']) else 'no-candidate')
                    continue
                if now < state.get('hold_until', 0) and not failed:
                    return dict(action='manual-hold')
                cooldown = 30 if failed else cfg['switch_cooldown_seconds']
                if (now - state.get('last_attempt', 0) < cooldown
                        or (not failed and len([t for t in state.get('attempts', []) if now - t < 3600]) >= cfg['max_switches_hour'])):
                    return dict(action='switch-budget')
                if not degraded and now - state.get('last_switch', 0) < cfg['hold_seconds']:
                    return dict(action='stable-hold')
                # Recheck a bounded number of candidates in isolated processes. A
                # flaky fastest candidate must not hide another working alternative.
                outcome = 'candidate-unstable'
                for *_, target in sorted(options)[:cfg['candidate_rechecks'] - len(tried)]:
                    tried.add(target)
                    if self.snapshot().get('token') != snap['token']:
                        return dict(action='selection-changed')
                    try:
                        repeated = self.probe(snap, target)
                    except subprocess.TimeoutExpired:
                        repeated = dict(ok=False, stable=False, switchable=False, reason='probe-timeout')
                    except (Error, OSError, ValueError):
                        repeated = dict(ok=False, stable=False, switchable=False, reason='probe-unavailable')
                    if self.snapshot().get('token') != snap['token']:
                        return dict(action='selection-changed')
                    self.record(state, snap, target, repeated, scheduled=False)
                    state['evaluation']['rechecks'].append(dict(
                        name=target, stable=stable(repeated), reason=repeated.get('reason'),
                        successful_endpoints=sorted(successful_relays(repeated))))
                    self.save(state)
                    recovery_endpoints = None
                    if failed:
                        initial = candidates[target]
                        if not recovery_usable(repeated):
                            continue
                        recovery_endpoints = recovery_overlap(initial, repeated)
                        if not recovery_endpoints:
                            # Only two legacy stable observations may omit relay
                            # evidence. A real repeat cannot borrow a successful
                            # endpoint from a legacy cache; retain it for next round.
                            if (not stable(initial) or not stable(repeated)
                                    or initial.get('relay') or repeated.get('relay')):
                                continue
                            recovery_endpoints = None
                    elif not stable(repeated):
                        continue
                    if not failed:
                        try:
                            latest = self.probe(snap, snap['selected'], live=True)
                        except (Error, OSError, ValueError):
                            outcome = 'candidate-unstable'
                            continue
                        if self.snapshot().get('token') != snap['token']:
                            return dict(action='selection-changed')
                        self.record(state, snap, snap['selected'], latest, scheduled=False)
                        state['current'] = latest
                        self.save(state)
                        # One successful same-round recheck cannot erase confirmed
                        # intermittent failure; recovery needs two scheduled samples.
                        if not degraded and not improvement(latest, repeated, cfg):
                            outcome = 'below-improvement-threshold'
                            continue
                    action = self.switch(snap, target, state,
                                         'failure' if failed else 'stability' if degraded else 'latency',
                                         recovery_endpoints=recovery_endpoints)
                    # Only one live transaction per round, including a rollback.
                    return dict(action=action, selected=state.get('selected'), target=target)
            return dict(action=outcome)

    def status(self):
        snap, state = self.snapshot(), self.state()
        rows = self.inventory(snap, state)
        selected_state = rows.get(snap.get('selected'), {})
        inventory = [dict(name=name, measured=row['measured'], fresh=row['fresh'],
                          stable=row['fresh'] and stable(row), cooling=row['cooling'],
                          available=row['fresh'] and bool(row.get('ok')),
                          eligible=row['fresh'] and stable(row) and not row['cooling'],
                          age_seconds=round(max(0, time.time() - row['at']), 2) if row.get('at') else None,
                          tcp_ms=row.get('tcp_ms'), jitter_ms=row.get('jitter_ms'),
                          at=row.get('at'), reason=row.get('reason'), ranking=row['ranking'])
                     for name, row in rows.items()]
        coverage = dict(total=len(rows), measured=sum(r['measured'] for r in rows.values()),
                        fresh=sum(r['fresh'] for r in rows.values()),
                        stable=sum(r['fresh'] and stable(r) for r in rows.values()),
                        pending=sum(not r['measured'] for r in rows.values()),
                        cooling=sum(r['cooling'] for r in rows.values()),
                        eligible=sum(r['fresh'] and stable(r) and not r['cooling'] for r in rows.values()))
        return dict(active=snap['active'], mode=snap['mode'], global_selection=snap['global_selection'],
                    selected=snap.get('selected'), improvement_ms=self.cfg['improvement_ms'],
                    stability_thresholds=dict(max_jitter_ms=self.cfg['max_jitter_ms'],
                                              max_tcp_ms=self.cfg['max_tcp_ms'],
                                              stability_failure_count=self.cfg['stability_failure_count']),
                    stability=selected_state.get('stability', {}), inventory=inventory, coverage=coverage,
                    state=state)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default=DEFAULT_CONFIG)
    parser.add_argument('action', choices=('check', 'status'))
    args = parser.parse_args(argv)
    cfg = load_config(args.config)
    os.makedirs(cfg['state_dir'], mode=0o700, exist_ok=True)
    auto = Auto(cfg)
    if args.action == 'status':
        result = auto.status()
    else:
        try:
            with common.locked(cfg['run_lock']):
                result = auto.cycle()
                state = auto.state()
                previous = state.get('action')
                state.update(action=result['action'], tick_at=time.time())
                auto.save(state)
                if result['action'] not in ('inactive', 'waiting', 'selection-changed'):
                    result.update(selected=state.get('selected'), failures=state.get('failures', 0),
                                  stability_failures=state.get('stability_failures', 0),
                                  current_reason=state.get('current', {}).get('reason'))
                    if state.get('evaluation', {}).get('at', 0) >= state.get('last_check', 0):
                        result['evaluation'] = state['evaluation']
        except Error as exc:
            if 'another update, switch, or evaluation is already running' in str(exc):
                return 0
            raise
        if previous == result['action'] and result['action'] in ('healthy', 'inactive', 'waiting'):
            return 0
    print(json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
    return 2 if result.get('action', '').startswith('pending') else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Error, OSError, ValueError):
        print(json.dumps(dict(action='error', message='automatic selection paused; inspect local configuration/state')), file=sys.stderr)
        sys.exit(2)
