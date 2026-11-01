#!/usr/bin/env python3
"""Event-driven, persistent entry binding for the user's GLOBAL selection.

Never selects a different logical node. Pinning an upstream entry prevents
DNS rotation; it cannot control NAT rotation inside that upstream server.
"""
import argparse
import copy
import ipaddress
import json
import os
import re
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.parse

import yaml
import clash_common as common
import mihomo_policy as policy

Error = common.SelectorError
BEGIN = '// BEGIN clash-chatgpt-route-guard egress bindings'
END = '// END clash-chatgpt-route-guard egress bindings'
LEGACY_BEGIN = '// BEGIN order-monitor fixed upstream entry'
LEGACY_END = '// END order-monitor fixed upstream entry'
DEFAULT_CONFIG = os.path.expanduser('~/.config/clash-guard/global-egress.yaml')
DEFAULTS = dict(version=1, clash_config='', binary='', controller_unix='',
                profile_script='', profiles_index='', state_dir='', node_binary='/usr/bin/node',
                business_proxy='http://127.0.0.1:7890',
                trace_urls=['https://api.ipify.org', 'https://ifconfig.me/ip'],
                sample_count=3, sample_gap_seconds=1, timeout_seconds=10,
                max_dns_candidates=6, settle_seconds=5, retry_seconds=600, verify_interval_seconds=900,
                mutation_lock='', probe_lock='', unmanaged_global_selections=['GLOBAL Stable Auto'])


def load_config(path):
    raw = policy.parse(policy.read(path))
    if set(raw) - set(DEFAULTS):
        raise Error('unknown egress configuration fields')
    cfg = dict(DEFAULTS, **raw)
    if cfg['version'] != 1:
        raise Error('unsupported egress configuration version')
    if (not isinstance(cfg['unmanaged_global_selections'], list)
            or any(not isinstance(n, str) or not n for n in cfg['unmanaged_global_selections'])):
        raise Error('unmanaged_global_selections must contain selector names')
    for key in ('clash_config', 'binary', 'controller_unix', 'profile_script',
                'state_dir', 'node_binary', 'mutation_lock', 'probe_lock'):
        if not isinstance(cfg[key], str) or not os.path.isabs(cfg[key]):
            raise Error(key + ' must be an absolute path')
    if cfg['profiles_index'] and not os.path.isabs(cfg['profiles_index']):
        raise Error('profiles_index must be an absolute path')
    for key, low, high in (('sample_count', 2, 5), ('sample_gap_seconds', 0, 10),
                           ('timeout_seconds', 5, 20), ('max_dns_candidates', 1, 8),
                           ('settle_seconds', 0, 60), ('retry_seconds', 60, 86400),
                           ('verify_interval_seconds', 300, 86400)):
        if type(cfg[key]) is not int or not low <= cfg[key] <= high:
            raise Error(key + ' outside safe bounds')
    proxy = urllib.parse.urlsplit(cfg['business_proxy'])
    if (proxy.scheme != 'http' or proxy.hostname not in ('127.0.0.1', 'localhost', '::1')
            or not proxy.port or proxy.username or proxy.password or proxy.path or proxy.query or proxy.fragment):
        raise Error('business_proxy must be a credential-free loopback HTTP listener')
    if not isinstance(cfg['trace_urls'], list) or not 2 <= len(cfg['trace_urls']) <= 4:
        raise Error('trace_urls requires 2–4 HTTPS IP endpoints')
    for url in cfg['trace_urls']:
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.fragment or parsed.port not in (None, 443)):
            raise Error('trace URL must be HTTPS/443 without credentials')
    return cfg


def ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ''


def trace_ip(body):
    if ip(body.strip()):
        return ip(body.strip())
    return next((ip(line[3:].strip()) for line in body.splitlines()
                 if line.startswith('ip=') and ip(line[3:].strip())), '')


def samples(cfg, proxy):
    rows = []
    for index in range(cfg['sample_count']):
        for url in cfg['trace_urls']:
            response = common.fetch(proxy, url, cfg['timeout_seconds'])
            address = trace_ip(response['body']) if response['exit'] == 0 and response['code'] == 200 else ''
            rows.append(dict(ip=address, code=response['code'], curl_exit=response['exit'],
                             seconds=response['seconds']))
        if index + 1 < cfg['sample_count']:
            time.sleep(cfg['sample_gap_seconds'])
    unique = sorted(set(r['ip'] for r in rows if r['ip']))
    stable = len(unique) == 1 and all(r['ip'] for r in rows)
    return dict(stable=stable, public_ip=unique[0] if stable else '', unique_ips=unique,
                median_seconds=statistics.median(r['seconds'] for r in rows), samples=rows)


def resolve(server, limit):
    if ip(server):
        return [ip(server)]
    # IPv4 and IPv6 entries are eligible; the actual probe must work end-to-end.
    records = socket.getaddrinfo(server, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(row[4][0] for row in records))
    if not addresses or len(addresses) > limit:
        raise Error('DNS candidate set empty or exceeds configured limit')
    return addresses


def selected_leaf(config, live):
    top = live.get('GLOBAL', {})
    if top.get('type') != 'Selector' or top.get('now') not in top.get('all', []):
        raise Error('invalid GLOBAL selector')
    name = top['now']
    nodes = {n['name']: n for n in config.get('proxies', [])}
    groups = {g['name']: g for g in config.get('proxy-groups', [])}
    if len(nodes) != len(config.get('proxies', [])):
        raise Error('duplicate node names')
    choices, seen = {'GLOBAL': name}, set()
    while name in groups:
        if name in seen:
            raise Error('selector dependency cycle')
        seen.add(name)
        group, actual = groups[name], live.get(name, {})
        if (group.get('type') != 'select' or actual.get('type') != 'Selector'
                or actual.get('now') not in group.get('proxies', [])):
            raise Error('automatic/provider groups are not eligible for entry binding')
        choices[name] = actual['now']
        name = actual['now']
    if name not in nodes:
        raise Error('GLOBAL leaf is not a static proxy node')
    node = nodes[name]
    # Domain-to-IP substitution requires protocol-specific SNI preservation.
    # The supported SS obfs transport keeps plugin-opts.host intact.
    if (node.get('type') not in ('ss', 'socks5') or node.get('dialer-proxy')
            or node.get('tls') or (node.get('type') == 'ss' and node.get('plugin') not in (None, '', 'obfs'))):
        raise Error('unsupported transport or dialer chain; selection left unchanged')
    if node.get('interface-name') or node.get('routing-mark'):
        raise Error('interface-bound transport requires a dedicated probe adapter')
    return name, node, choices


def entry_identity(node):
    value = copy.deepcopy(node)
    value.pop('server', None)
    return common.fingerprint(value)


def block_span(text, begin, end):
    if text.count(begin) != text.count(end) or text.count(begin) > 1:
        raise Error('binding markers ambiguous or damaged')
    if begin not in text:
        return None
    start, stop = text.index(begin), text.index(end)
    if stop < start:
        raise Error('binding marker order invalid')
    return start, stop + len(end)


def bindings_from_script(text):
    span = block_span(text, BEGIN, END)
    if not span:
        legacy = block_span(text, LEGACY_BEGIN, LEGACY_END)
        if not legacy:
            return {}
        body = text[legacy[0]:legacy[1]]
        match = re.search(
            r"proxy\.name\s*===\s*[\"']([^\"']+)[\"'].*?"
            r"proxy\.server\s*=\s*[\"']([^\"']+)[\"']", body, re.S)
        if not match or not ip(match.group(2)):
            raise Error('legacy binding metadata missing; original subscription node required')
        return {match.group(1): {'server': match.group(2), 'origin': '',
                                'type': '', 'port': 0, 'legacy': True}}
    match = re.search(r'const egressBindings = (.+);', text[span[0]:span[1]])
    if not match:
        raise Error('binding metadata missing')
    bindings = json.loads(match.group(1))
    if not isinstance(bindings, dict):
        raise Error('binding metadata invalid')
    for name, binding in bindings.items():
        if (not isinstance(name, str) or not isinstance(binding, dict)
                or not ip(binding.get('server', '')) or not isinstance(binding.get('origin'), str)):
            raise Error('binding metadata invalid')
    return bindings


def rewrite_script(text, bindings):
    literal = json.dumps(bindings, ensure_ascii=True, sort_keys=True, separators=(',', ':'))
    block = (BEGIN + '\n  const egressBindings = ' + literal + ';\n'
             '  for (const proxy of config.proxies || []) {\n'
             '    const pin = Object.prototype.hasOwnProperty.call(egressBindings, proxy.name)\n'
             '      ? egressBindings[proxy.name] : null;\n'
             '    if (pin && proxy.type === pin.type && proxy.port === pin.port &&\n'
             '        (proxy.server === pin.origin || proxy.server === pin.server)) {\n'
             '      proxy.server = pin.server;\n'
             '    }\n'
             '  }\n  ' + END)
    span = block_span(text, BEGIN, END)
    legacy = block_span(text, LEGACY_BEGIN, LEGACY_END)
    if span and legacy:
        raise Error('multiple binding implementations present')
    span = span or legacy
    if span:
        return text[:span[0]] + block + text[span[1]:]
    if text.count('return config;') != 1 or 'function main(' not in text:
        raise Error('profile script requires one unambiguous return config')
    return text.replace('return config;', block + '\n  return config;', 1)


def replace_server(text, leaf, server):
    config = policy.parse(text)
    expected = copy.deepcopy(config)
    found = [n for n in expected.get('proxies', []) if n.get('name') == leaf]
    if len(found) != 1:
        raise Error('target node missing or duplicated')
    found[0]['server'] = server
    root = yaml.compose(text)
    edits = []
    for key, value in root.value:
        if key.value == 'proxies':
            for node in value.value:
                fields = {k.value: v for k, v in node.value}
                if fields.get('name') and fields['name'].value == leaf:
                    scalar = fields.get('server')
                    if not isinstance(scalar, yaml.ScalarNode) or scalar.style not in (None, '"', "'"):
                        raise Error('unsupported server YAML scalar')
                    edits.append((scalar.start_mark.index, scalar.end_mark.index))
    if len(edits) != 1:
        raise Error('ambiguous YAML server position')
    begin, end = edits[0]
    result = text[:begin] + json.dumps(server) + text[end:]
    if policy.parse(result) != expected:
        raise Error('server replacement changed unrelated configuration')
    return result if config != expected else text


def evaluate_script(cfg, source, config):
    # Credentials are stdin-only and errors are intentionally not reflected.
    runner = """const vm=require('vm'),fs=require('fs');
const d=JSON.parse(fs.readFileSync(0,'utf8'));
const c=vm.createContext({config:d.config});
vm.runInContext(d.source+'\\nresult=main(config,"egress-validation");',c,{timeout:3000});
process.stdout.write(JSON.stringify(c.result));"""
    result = subprocess.run([cfg['node_binary'], '-e', runner],
                            input=json.dumps(dict(source=source, config=config)),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=5)
    if result.returncode:
        raise Error('profile JavaScript validation failed (details suppressed)')
    return json.loads(result.stdout)


class Binder:
    def __init__(self, cfg):
        self.cfg = cfg
        self.path = os.path.join(cfg['state_dir'], 'state.json')

    def save(self, state):
        common.save_json(self.path, state)

    def state(self):
        return common.load_json(self.path, {})

    def snapshot(self):
        cfg = self.cfg
        text = policy.read(cfg['clash_config'])
        config = policy.parse(text)
        api_cfg = dict(config, **{'external-controller': '', 'external-controller-unix': cfg['controller_unix']})
        runtime = policy.api(api_cfg, '/configs')
        if runtime.get('mode') != 'global':
            return dict(mode=runtime.get('mode'), api=api_cfg)
        port = urllib.parse.urlsplit(cfg['business_proxy']).port
        if port not in (runtime.get('mixed-port'), runtime.get('port')):
            raise Error('business listener does not match live Mihomo')
        live = policy.api(api_cfg, '/proxies')['proxies']
        if live.get('GLOBAL', {}).get('now') in cfg.get('unmanaged_global_selections', []):
            return dict(mode='global', inactive=True, reason='managed-by-another-selector', api=api_cfg)
        leaf, node, choices = selected_leaf(config, live)
        script = policy.read(cfg['profile_script'])
        index_text, origin_node, origin_nodes = '', None, {}
        if cfg['profiles_index']:
            index_text = policy.read(cfg['profiles_index'])
            index = policy.parse(index_text)
            active = next((p for p in index.get('items', []) if p.get('uid') == index.get('current')), {})
            script_uid = os.path.splitext(os.path.basename(cfg['profile_script']))[0]
            if active.get('option', {}).get('script') != script_uid:
                raise Error('active Verge profile changed; configured script is no longer active')
            filename = active.get('file', '')
            if not filename or os.path.basename(filename) != filename:
                raise Error('invalid active subscription file')
            original = policy.parse(policy.read(os.path.join(os.path.dirname(cfg['profile_script']), filename)))
            origin_nodes = {p.get('name'): p for p in original.get('proxies', []) if p.get('name')}
            origin_node = origin_nodes.get(leaf)
            if origin_node and entry_identity(origin_node) != entry_identity(node):
                raise Error('subscription and live node definitions differ; refusing stale binding')
        if policy.api(api_cfg, '/configs').get('mode') != 'global':
            raise Error('mode changed while reading configuration')
        token = common.fingerprint(dict(text=text, script=script, choices=choices, index=index_text, origin_node=origin_node))
        return dict(mode='global', text=text, config=config, api=api_cfg, script=script,
                    leaf=leaf, node=node, origin_node=origin_node, origin_nodes=origin_nodes, choices=choices, token=token,
                    selections={n: p.get('now') for n, p in live.items() if p.get('type') == 'Selector'})

    def probe(self, snap, address):
        node = copy.deepcopy(snap['node'])
        node['server'] = address
        with common.ProbeProcess([node], self.cfg['binary'], ipv6=snap['config'].get('ipv6', True)) as process:
            return dict(samples(self.cfg, process.proxy(node['name'])), server=address)

    def validate(self, text):
        with tempfile.TemporaryDirectory(prefix='egress-validate-') as directory:
            path = os.path.join(directory, 'config.yaml')
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(text)
            result = subprocess.run([self.cfg['binary'], '-t', '-f', path, '-d',
                                     os.path.dirname(self.cfg['clash_config'])],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
            if result.returncode:
                raise Error('Mihomo rejected candidate config (details suppressed)')

    def commit(self, snap, result, state):
        cfg, leaf = self.cfg, snap['leaf']
        with common.locked(cfg['mutation_lock']):
            if self.snapshot().get('token') != snap['token']:
                raise Error('selection/profile changed during sampling; discarded')
            bindings = bindings_from_script(snap['script'])
            normalized = {}
            live_nodes = {p.get('name'): p for p in snap['config'].get('proxies', [])}
            origin_nodes = snap.get('origin_nodes') or {}
            if not origin_nodes and snap.get('origin_node'):
                origin_nodes = {leaf: snap['origin_node']}
            for name, old in bindings.items():
                if old.get('legacy'):
                    live_old = live_nodes.get(name)
                    origin_old = origin_nodes.get(name)
                    if (not live_old or not origin_old or live_old.get('server') != old.get('server')
                            or entry_identity(live_old) != entry_identity(origin_old)):
                        raise Error('legacy binding target is not present in the active subscription')
                    normalized[name] = dict(server=old['server'], origin=origin_old['server'],
                                            type=live_old.get('type', ''), port=live_old.get('port', 0))
                else:
                    normalized[name] = old
            bindings = normalized
            old = bindings.get(leaf, {})
            origin = old.get('origin', (snap.get('origin_node') or snap['node'])['server'])
            if snap.get('origin_node') and snap['origin_node']['server'] != origin:
                raise Error('subscription origin changed; binding requires review')
            if LEGACY_BEGIN in snap['script'] and not origin_nodes:
                raise Error('legacy adoption requires original subscription nodes')
            bindings[leaf] = dict(server=result['server'], origin=origin,
                                  type=snap['node']['type'], port=snap['node']['port'])
            script = rewrite_script(snap['script'], bindings)
            text = replace_server(snap['text'], leaf, result['server'])
            changed = text != snap['text']
            if changed:
                if snap['config'].get('mode') != 'global':
                    raise Error('disk mode differs from live mode; refusing automatic reload')
                if snap['config'].get('profile', {}).get('store-selected') is not True:
                    raise Error('reload requires profile.store-selected=true')
                self.validate(text)
            before = evaluate_script(cfg, snap['script'], snap['config'])
            after = evaluate_script(cfg, script, snap['config'])
            expected = copy.deepcopy(before)
            next(n for n in expected['proxies'] if n['name'] == leaf)['server'] = result['server']
            if after != expected:
                raise Error('profile script changes unrelated output')
            if self.snapshot().get('token') != snap['token']:
                raise Error('selection/profile changed before commit')
            backup = os.path.join(cfg['state_dir'], 'before-' + str(time.time_ns()) + '.json')
            common.save_json(backup, dict(script=snap['script'], runtime=snap['text']))
            state['pending'] = dict(backup=backup, node=leaf, server=result['server'], at=time.time())
            self.save(state)  # Durable before any config mutation.
            try:
                if script != snap['script']:
                    policy.atomic_write(cfg['profile_script'], script)
                if changed:
                    policy.atomic_write(cfg['clash_config'], text)
                    policy.api(snap['api'], '/configs?force=false', 'PUT', {'path': cfg['clash_config']}, timeout=15)
                current = self.snapshot()
                if (current.get('mode') != 'global' or current.get('choices') != snap['choices']
                        or current['selections'] != snap['selections'] or current['node']['server'] != result['server']):
                    raise Error('selection or server changed after binding')
                checked = samples(cfg, cfg['business_proxy'])
                if not checked['stable'] or checked['public_ip'] != result['public_ip']:
                    raise Error('live egress does not match the isolated candidate')
                if self.snapshot().get('token') != current['token']:
                    raise Error('selection/profile changed during postcheck')
            except BaseException:
                # Do not perform a second global reload after a race or uncertain
                # API result. Keep WAL + backup and stop; never hide partial apply.
                state['last_error'] = 'commit/postcheck uncertain; pending retained; no further writes'
                self.save(state)
                raise
            binding = dict(server=result['server'], origin=origin, public_ip=result['public_ip'],
                           identity=entry_identity(snap['node']), bound_at=time.time())
            state.setdefault('bindings', {})[leaf] = binding
            state.update(pending=None, token=current['token'], last_error='',
                         selected=leaf, last_probe=result, retry_at=0, bound_at=time.time(), verified_at=time.time())
            self.save(state)
            return dict(action='bound', node=leaf, server=result['server'], public_ip=result['public_ip'],
                        reloaded=changed, expires=False)

    def cycle(self, immediate=False):
        state, now = self.state(), time.time()
        if state.get('pending'):
            raise Error('unfinished binding transaction; inspect state and backup before recovery')
        snap = self.snapshot()
        if snap['mode'] != 'global' or snap.get('inactive'):
            if state.get('token'):
                state.update(token=None, observed_token=None)
                self.save(state)
            return dict(action='inactive', mode=snap['mode'])
        leaf, node = snap['leaf'], snap['node']
        saved = state.get('bindings', {}).get(leaf, {})
        pins = bindings_from_script(snap['script'])
        if (state.get('token') == snap['token'] and saved.get('identity') == entry_identity(node)
                and saved.get('server') == node['server'] and pins.get(leaf, {}).get('server') == node['server']):
            if now - state.get('verified_at', state.get('bound_at', now)) >= self.cfg.get('verify_interval_seconds', 900):
                checked = samples(self.cfg, self.cfg['business_proxy'])
                if self.snapshot().get('token') != snap['token']:
                    return dict(action='changed-during-verify')
                ok = checked['stable'] and checked['public_ip'] == saved['public_ip']
                state.update(verified_at=now, last_verification=checked,
                             last_error='' if ok else 'public egress check failed; pin retained, no rotation')
                self.save(state)
                if not ok:
                    return dict(action='egress-check-failed', node=leaf, expected_ip=saved['public_ip'],
                                observed_ips=checked['unique_ips'], ok=False)
            return dict(action='keep', node=leaf, server=node['server'], public_ip=saved['public_ip'])
        if state.get('observed_token') != snap['token']:
            state.update(observed_token=snap['token'], observed_at=now, retry_at=0)
            self.save(state)
        if not immediate and now - state.get('observed_at', now) < self.cfg['settle_seconds']:
            return dict(action='settling', node=leaf)
        if now < state.get('retry_at', 0):
            return dict(action='cooldown', node=leaf, retry_at=state['retry_at'])
        # Budget persisted before starting external probes, including crashes.
        state['retry_at'] = now + self.cfg['retry_seconds']
        self.save(state)
        if saved and node['server'] not in (saved['server'], saved['origin']):
            raise Error('bound node server changed in subscription; refusing stale entry')
        if saved and saved.get('identity') != entry_identity(node):
            raise Error('bound node definition changed; refusing to reuse old entry')
        addresses = [saved['server']] if saved else resolve(node['server'], self.cfg['max_dns_candidates'])
        results = []
        with common.locked(self.cfg['probe_lock']):
            for address in addresses:
                if self.snapshot().get('token') != snap['token']:
                    raise Error('selection changed during candidate sampling')
                results.append(self.probe(snap, address))
        good = [r for r in results if r['stable'] and (not saved or r['public_ip'] == saved['public_ip'])]
        if not good:
            state['last_error'] = 'no stable candidate with the expected public IP; selection unchanged'
            state['last_probe'] = results
            self.save(state)
            raise Error(state['last_error'])
        # If live connections already use a healthy entry, prefer continuity.
        preferred = set()
        for connection in (policy.api(snap['api'], '/connections').get('connections') or []):
            if leaf in connection.get('chains', []):
                remote = connection.get('metadata', {}).get('remoteDestination', '')
                if ip(remote):
                    preferred.add(remote)
        result = min(good, key=lambda r: (r['server'] not in preferred, r['median_seconds']))
        return self.commit(snap, result, state)

    def status(self, verify=False):
        state = self.state()
        try:
            snap = self.snapshot()
        except (Error, OSError, ValueError) as exc:
            return dict(ok=False, mode='unknown', pending=state.get('pending'),
                        bindings=state.get('bindings', {}), last_error=state.get('last_error'),
                        snapshot_error=str(exc) if isinstance(exc, Error) else 'controller/config unavailable')
        leaf = snap.get('leaf')
        if snap.get('inactive'):
            if verify:
                raise Error('GLOBAL automatic group is not managed by the entry binder')
            return dict(mode=snap['mode'], active=False, reason=snap['reason'], pending=state.get('pending'))
        saved = state.get('bindings', {}).get(leaf, {})
        result = dict(mode=snap['mode'], node=leaf, server=snap.get('node', {}).get('server'),
                      binding=saved, pending=state.get('pending'), last_error=state.get('last_error', ''),
                      persistent=False, runtime_entry_matches=False,
                      verified_at=state.get('verified_at'))
        if snap['mode'] == 'global':
            pin = bindings_from_script(snap['script']).get(leaf, {})
            result['persistent'] = bool(saved and pin.get('server') == saved['server'])
            result['runtime_entry_matches'] = bool(saved and snap['node']['server'] == saved['server'])
            peers = []
            for c in (policy.api(snap['api'], '/connections').get('connections') or []):
                if leaf in c.get('chains', []):
                    value = c.get('metadata', {}).get('remoteDestination', '')
                    if ip(value):
                        peers.append(value)
            result['active_remote_entries'] = sorted(set(peers))
        if verify:
            if snap['mode'] != 'global' or not saved:
                raise Error('no active GLOBAL binding to verify')
            checked = samples(self.cfg, self.cfg['business_proxy'])
            result['probe'] = checked
            result['ok'] = (checked['stable'] and checked['public_ip'] == saved['public_ip']
                            and result['persistent'] and result['runtime_entry_matches']
                            and not state.get('pending') and self.snapshot().get('token') == snap['token'])
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default=DEFAULT_CONFIG)
    parser.add_argument('action', choices=('check', 'bind-now', 'status', 'verify'))
    args = parser.parse_args(argv)
    cfg = load_config(args.config)
    os.makedirs(cfg['state_dir'], mode=0o700, exist_ok=True)
    binder = Binder(cfg)
    try:
        with common.locked(os.path.join(cfg['state_dir'], 'run.lock')):
            if args.action in ('status', 'verify'):
                result = binder.status(args.action == 'verify')
            else:
                result = binder.cycle(args.action == 'bind-now')
    except Error as exc:
        if args.action == 'check' and 'another update, switch, or evaluation is already running' in str(exc):
            return 0  # An explicit verification may span several timer ticks.
        raise
    # Routine polling remains quiet; status and meaningful changes are visible.
    if args.action != 'check' or result['action'] in ('bound', 'egress-check-failed'):
        print(json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
    return 2 if result.get('ok') is False else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Error as exc:
        print(json.dumps(dict(action='error', message=str(exc))), file=sys.stderr)
        sys.exit(2)
    except (OSError, ValueError, subprocess.SubprocessError):
        # Controller errors can contain authenticated URLs; do not dump raw exceptions.
        print(json.dumps(dict(action='error', message='binding not completed; inspect local state/status; credentials suppressed')), file=sys.stderr)
        sys.exit(2)
