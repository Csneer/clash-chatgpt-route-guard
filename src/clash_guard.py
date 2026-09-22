#!/usr/bin/env python3
"""Conservative, profile-driven Mihomo guard. Python 3.6, no account secrets."""
import argparse
import concurrent.futures
import copy
import hashlib
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.parse

import clash_common as common
import mihomo_policy as policy
import clash_demand as demand

Error = common.SelectorError
DEFAULT_PROFILE = '/etc/clash-guard/config.yaml'
DEFAULTS = {
    'version': 1, 'mode': 'observe', 'controller': None,
    'state_dir': '/var/lib/clash-guard',
    'run_lock': '/run/lock/clash-guard.lock',
    'mutation_lock': common.LOCK, 'probe_lock': common.PROBE_LOCK,
    'manual_history': '/var/lib/clash-selector/history.json',
    'interval_seconds': 60, 'failure_count': 4, 'failure_span_seconds': 180,
    'failure_gap_seconds': 180, 'cooldown_seconds': 1800,
    'max_attempts_24h': 2,
    'manual_hold_seconds': 1800, 'evaluation_interval_seconds': 600,
    'same_ip_max_age_seconds': 900, 'allow_cross_ip': True,
    'cross_ip_failure_span_seconds': 300,
    'concurrency': 2, 'timeout_seconds': 10, 'max_candidates': 128,
    'include': '.*', 'exclude': '^$', 'preferred_countries': [],
    'switchable_curl_errors': [5, 6, 7, 28, 35, 52, 55, 56],
    'switchable_http_codes': [403],
    'journal_unit': 'clash.service', 'journal_domains': ['chatgpt.com', 'openai.com'],
    'journal_lookback_seconds': 120, 'trace_url': '',
    'activity': {'enabled': False},
}
REQUIRED = {'clash_config', 'binary', 'selector', 'entry', 'business_proxy', 'checks'}


def emit(event, **values):
    print(json.dumps(dict(event=event, **values), ensure_ascii=False, sort_keys=True), flush=True)


def profile(path):
    raw = policy.parse(policy.read(path))
    if set(raw) - (set(DEFAULTS) | REQUIRED) or REQUIRED - set(raw):
        raise Error('守护配置存在未知字段或缺少必要字段。')
    cfg = dict(DEFAULTS, **raw)
    if cfg['version'] != 1 or cfg['mode'] not in ('observe', 'auto'):
        raise Error('仅支持 version=1，mode=observe/auto。')
    for key in ('clash_config', 'binary', 'state_dir', 'run_lock', 'mutation_lock', 'probe_lock'):
        if not isinstance(cfg[key], str) or not os.path.isabs(cfg[key]):
            raise Error(key + ' 必须为绝对路径。')
    if cfg['manual_history'] is not None and not os.path.isabs(cfg['manual_history']):
        raise Error('manual_history 必须为绝对路径或 null。')
    limits = {'interval_seconds': (30, 3600), 'failure_count': (3, 100),
              'failure_span_seconds': (120, 86400), 'failure_gap_seconds': (60, 86400),
              'cooldown_seconds': (300, 86400), 'manual_hold_seconds': (300, 86400),
              'evaluation_interval_seconds': (300, 86400), 'same_ip_max_age_seconds': (60, 3600),
              'cross_ip_failure_span_seconds': (120, 86400), 'concurrency': (1, 4),
              'timeout_seconds': (3, 20), 'max_candidates': (1, 256),
              'journal_lookback_seconds': (30, 600)}
    limits['max_attempts_24h'] = (1, 6)
    for key, (low, high) in limits.items():
        if type(cfg[key]) is not int or not low <= cfg[key] <= high:
            raise Error(key + ' 超出安全范围。')
    if cfg['failure_gap_seconds'] < cfg['interval_seconds'] or cfg['cross_ip_failure_span_seconds'] < cfg['failure_span_seconds']:
        raise Error('异常窗口设置不一致。')
    if type(cfg['allow_cross_ip']) is not bool:
        raise Error('allow_cross_ip 必须为布尔值。')
    for key in ('selector', 'entry'):
        if not isinstance(cfg[key], str) or not cfg[key]:
            raise Error('选择器名称不能为空。')
    for key in ('include', 'exclude'):
        try:
            re.compile(cfg[key])
        except (re.error, TypeError):
            raise Error('无效候选正则。')
    proxy = urllib.parse.urlsplit(cfg['business_proxy'])
    if (proxy.scheme != 'http' or proxy.hostname not in ('127.0.0.1', '::1', 'localhost')
            or not proxy.port or proxy.username or proxy.password or proxy.path or proxy.query or proxy.fragment):
        raise Error('业务探测仅支持无凭据的本机 HTTP/mixed 监听。')
    if not isinstance(cfg['checks'], list) or not 1 <= len(cfg['checks']) <= 4:
        raise Error('checks 需要 1–4 项。')
    for check in cfg['checks']:
        if (not isinstance(check, dict) or set(check) != {'name', 'url', 'status', 'json_contains'}
                or not isinstance(check['name'], str) or type(check['status']) is not int
                or not isinstance(check['json_contains'], dict) or not check['json_contains']):
            raise Error('每个 check 需要 name/url/status/非空 json_contains。')
    for url in [c['url'] for c in cfg['checks']] + ([cfg['trace_url']] if cfg['trace_url'] else []):
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.fragment or parsed.port not in (None, 443)):
            raise Error('探测地址必须是 HTTPS/443，不可含凭据。')
    for key in ('switchable_curl_errors', 'switchable_http_codes'):
        if not isinstance(cfg[key], list) or any(type(v) is not int for v in cfg[key]):
            raise Error('异常类别必须为整数列表。')
    # These responses cannot distinguish a bad exit from account/upstream problems.
    if set(cfg['switchable_http_codes']) - {403} or set(cfg['switchable_curl_errors']) - {5, 6, 7, 28, 35, 52, 55, 56}:
        raise Error('不能把 429/5xx/未知响应/证书错误配置成自动轮换依据。')
    for key in ('preferred_countries', 'journal_domains'):
        if not isinstance(cfg[key], list) or any(not isinstance(v, str) or not v for v in cfg[key]):
            raise Error(key + ' 必须为字符串列表。')
    if cfg['journal_unit'] and not re.match(r'^[A-Za-z0-9_.@-]+\.service$', cfg['journal_unit']):
        raise Error('journal_unit 无效。')
    activity = cfg.get('activity')
    if not isinstance(activity, dict):
        raise Error('activity 必须为 mapping。')
    allowed_activity = {'enabled', 'call_records_path', 'error_log_path', 'window_seconds',
                        'probe_cooldown_seconds', 'error_kinds', 'strategy'} | set(demand.DEFAULTS)
    if set(activity) - allowed_activity:
        raise Error('activity 存在未知字段。')
    if type(activity.get('enabled')) is not bool:
        raise Error('activity.enabled 必须为布尔值。')
    if activity['enabled']:
        if activity.get('strategy') != 'faults-only':
            raise Error('activity.enabled 需要 strategy: faults-only；旧周期活跃探测已停用。')
        a = demand.settings(cfg)
        for key, low, high in (('min_error_requests', 3, 20), ('error_span_seconds', 60, 600),
                              ('max_probes_24h', 3, 12), ('max_evaluations_24h', 1, 3)):
            if type(a[key]) is not int or not low <= a[key] <= high:
                raise Error('activity.' + key + ' 超出安全范围。')
        if not isinstance(a['provider'], str) or not a['provider']:
            raise Error('activity.provider 必须为明确的业务提供者名称。')
        for key in ('call_records_path', 'error_log_path'):
            if not isinstance(activity.get(key), str) or not os.path.isabs(activity[key]):
                raise Error('activity.' + key + ' 必须为绝对路径。')
        for key, low, high in (('window_seconds', 60, 86400), ('probe_cooldown_seconds', 300, 86400)):
            if type(activity.get(key)) is not int or not low <= activity[key] <= high:
                raise Error('activity.' + key + ' 超出安全范围。')
        if not isinstance(activity.get('error_kinds'), list) or any(not isinstance(v, str) or not v for v in activity['error_kinds']):
            raise Error('activity.error_kinds 必须为字符串列表。')
        if set(activity['error_kinds']) - demand.KINDS:
            raise Error('不允许把客户端取消等非网络事件当作触发器。')
        if (activity['window_seconds'] < a['error_span_seconds']
                or cfg['failure_gap_seconds'] < activity['probe_cooldown_seconds'] + 60
                or cfg['same_ip_max_age_seconds'] < activity['probe_cooldown_seconds'] + 60):
            raise Error('证据有效期必须覆盖异常复核间隔，避免永远无法累积。')
    return cfg


def check_proxy(cfg, proxy):
    results = []
    for check in cfg['checks']:
        response = common.fetch(proxy, check['url'], cfg['timeout_seconds'])
        try:
            body = json.loads(response['body'])
        except (ValueError, TypeError):
            body = None
        ok = (response['exit'] == 0 and response['code'] == check['status']
              and 'application/json' in response['content_type'].lower()
              and isinstance(body, dict)
              and all(body.get(k) == v for k, v in check['json_contains'].items()))
        switchable = (response['exit'] in cfg['switchable_curl_errors'] if response['exit']
                      else response['code'] in cfg['switchable_http_codes'])
        results.append({'name': check['name'], 'ok': ok, 'switchable': switchable and not ok,
                        'code': response['code'], 'curl_exit': response['exit'], 'seconds': response['seconds']})
    ip, country = '', ''
    if cfg['trace_url']:
        trace = common.fetch(proxy, cfg['trace_url'], cfg['timeout_seconds'])
        if trace['exit'] == 0 and trace['code'] == 200:
            fields = dict(line.split('=', 1) for line in trace['body'].splitlines() if '=' in line)
            try:
                ip = str(ipaddress.ip_address(fields.get('ip', '')))
                country = fields.get('loc', '')[:3]
            except ValueError:
                pass
    failed = [r for r in results if not r['ok']]
    return {'ok': not failed, 'switchable': bool(failed) and all(r['switchable'] for r in failed),
            'checks': results, 'seconds': sum(r['seconds'] for r in results),
            'ip': ip, 'country': country, 'tested_at': time.time()}




def first_route(rules, host):
    """Fail closed for rules whose match cannot be proven for HTTPS/TCP probes."""
    for rule in rules:
        parts = rule.split(',')
        kind = parts[0].upper()
        if kind == 'MATCH':
            return parts[1]
        if len(parts) < 3:
            raise Error('规则结构不完整。')
        value, target = parts[1], parts[2]
        if kind == 'DOMAIN':
            match = host == value.lower()
        elif kind == 'DOMAIN-SUFFIX':
            value = value.lower().lstrip('.')
            match = host == value or host.endswith('.' + value)
        elif kind == 'DOMAIN-KEYWORD':
            match = value.lower() in host
        elif kind == 'DST-PORT' and value.isdigit():
            match = value == '443'
        elif kind == 'NETWORK':
            match = value.upper() == 'TCP'
        else:
            raise Error('探测域名前存在无法静态核实的规则；需明确前置域名规则。')
        if match:
            return target
    raise Error('探测域名没有明确路由。')


def graph(config, live, target):
    """Flatten fixed selectors in dialer-proxy edges; never flatten auto groups."""
    nodes = {p['name']: p for p in config.get('proxies', [])}
    groups = {g['name']: g for g in config.get('proxy-groups', [])}
    output, choices = {}, {}
    def visit(name, visiting):
        if name in visiting:
            raise Error('代理依赖循环。')
        visiting = visiting | {name}
        if name in groups:
            g, actual = groups[name], live.get(name, {})
            selected = actual.get('now')
            if (g.get('type') != 'select' or actual.get('type') != 'Selector'
                    or selected not in g.get('proxies', []) or selected not in actual.get('all', [])):
                raise Error('依赖自动组选路、动态 provider 或无效选择，跳过。')
            choices[name] = selected
            return visit(selected, visiting)
        if name not in nodes:
            raise Error('缺少静态节点定义（DIRECT/REJECT/provider-only 不参与自动切换）。')
        node = copy.deepcopy(nodes[name])
        if node.get('type') not in ('ss', 'vmess', 'vless', 'trojan', 'http', 'socks5', 'hysteria2', 'tuic'):
            raise Error('该协议尚未完成隔离探测适配。')
        if node.get('type') == 'ss' and node.get('plugin') not in (None, '', 'obfs', 'v2ray-plugin'):
            raise Error('不支持启动外部插件。')
        # File/interface bindings and nested per-transport routes need dedicated adapters.
        def portable(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key in ('certificate', 'private-key', 'ca', 'ca-str', 'interface-name', 'routing-mark', 'smux'):
                        raise Error('节点含暂不支持的外部资源/接口绑定，跳过。')
                    portable(child)
            elif isinstance(value, list):
                for child in value:
                    portable(child)
        portable(node)
        parent = node.get('dialer-proxy')
        if parent:
            node['dialer-proxy'] = visit(parent, visiting)
        output[name] = node
        return name
    leaf = visit(target, set())
    return {'leaf': leaf, 'nodes': output, 'choices': choices,
            'fingerprint': common.fingerprint({'nodes': output, 'choices': choices, 'leaf': leaf})}


def persist(text, selector, target):
    original = policy.parse(text)
    updated = copy.deepcopy(original)
    group = next(g for g in updated['proxy-groups'] if g['name'] == selector)
    if group.get('type') != 'select' or target not in group.get('proxies', []):
        raise Error('只允许保存已有 select 的显式成员。')
    group['proxies'] = [target] + [n for n in group['proxies'] if n != target]
    updated.setdefault('profile', {})['store-selected'] = True
    result = policy.replace_sections(text, {k: updated[k] for k in ('proxy-groups', 'profile')})
    if policy.parse(result) != updated:
        raise Error('保存配置的语义验证失败。')
    # Exact intended change checked above; no arbitrary provider-specific transforms.
    return result


def journal(cfg, since_us, now):
    if not cfg['journal_unit']:
        return {'errors': 0, 'cursor_us': int(now * 1000000), 'available': False}
    start = max(since_us / 1000000, now - cfg['journal_lookback_seconds'])
    args = ['/usr/bin/journalctl', '-u', cfg['journal_unit'], '--since', '@' + str(int(start)),
            '-n', '1000', '-o', 'json', '--no-pager']
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=5)
        if result.returncode:
            raise OSError()
        count, latest = 0, since_us
        for line in result.stdout.splitlines():
            row = json.loads(line)
            stamp = int(row.get('__REALTIME_TIMESTAMP', 0))
            latest = max(latest, stamp)
            message = row.get('MESSAGE', '')
            if not isinstance(message, str) or stamp <= since_us:
                continue
            if (('level=warning' in message or 'level=error' in message)
                    and any(re.search(r'(?<![\w.-])(?:[\w-]+\.)*' + re.escape(d) + r'(?=[:/\s\")]|$)', message)
                            for d in cfg['journal_domains'])):
                count += 1
        return {'errors': count, 'cursor_us': max(latest, int(start * 1000000)), 'available': True}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {'errors': 0, 'cursor_us': since_us, 'available': False}


class Guard:
    def __init__(self, cfg):
        self.cfg = cfg
        self.state_path = os.path.join(cfg['state_dir'], 'state.json')

    def save(self, state):
        common.save_json(self.state_path, state)

    def snapshot(self):
        text = policy.read(self.cfg['clash_config'])
        config = policy.parse(text)
        names = [p['name'] for p in config.get('proxies', []) + config.get('proxy-groups', [])]
        if len(names) != len(set(names)) or not config.get('rules'):
            raise Error('代理名称重复或规则缺失。')
        api_config = dict(config)
        if self.cfg['controller']:
            api_config['external-controller'] = self.cfg['controller']
        runtime = policy.api(api_config, '/configs')
        port = urllib.parse.urlsplit(self.cfg['business_proxy']).port
        if (runtime.get('mode') != 'rule' or config.get('mode', 'rule').lower() != 'rule'
                or port not in (runtime.get('port'), runtime.get('mixed-port'))):
            raise Error('需要 rule 模式及匹配的业务 HTTP/mixed 监听。')
        live = policy.api(api_config, '/proxies')['proxies']
        actual_rules = policy.api(api_config, '/rules')['rules']
        if len(actual_rules) != len(config['rules']):
            raise Error('文件与运行时规则数量不同。')
        urls = [c['url'] for c in self.cfg['checks']] + ([self.cfg['trace_url']] if self.cfg['trace_url'] else [])
        for url in urls:
            host = urllib.parse.urlsplit(url).hostname
            if first_route(config['rules'], host) != self.cfg['entry']:
                raise Error('探测域名未经过配置的业务入口。')
        # Compare the ordered runtime prefix up to every probe domain rule.
        runtime_rules = []
        for rule in actual_rules:
            kind = {'Domain': 'DOMAIN', 'DomainSuffix': 'DOMAIN-SUFFIX', 'DomainKeyword': 'DOMAIN-KEYWORD',
                    'DstPort': 'DST-PORT', 'Network': 'NETWORK', 'Match': 'MATCH'}.get(rule.get('type'), 'UNSUPPORTED')
            runtime_rules.append(','.join([kind] + ([] if kind == 'MATCH' else [str(rule.get('payload', ''))]) + [rule.get('proxy', '')]))
        for url in urls:
            if first_route(runtime_rules, urllib.parse.urlsplit(url).hostname) != self.cfg['entry']:
                raise Error('运行时探测域名路由与预期不符。')
        route = graph(config, live, self.cfg['entry'])
        top = self.cfg['selector']
        if top not in route['choices'] or live[top].get('type') != 'Selector':
            raise Error('业务入口没有经过受管理的手动选择器。')
        marker = common.load_json(self.cfg['manual_history'], {}) if self.cfg['manual_history'] else {}
        selections = {n: p.get('now') for n, p in live.items() if p.get('type') == 'Selector' and n != 'GLOBAL'}
        token = common.fingerprint({'text': text, 'selections': selections, 'manual': marker})
        return {'text': text, 'config': config, 'api': api_config, 'live': live, 'route': route,
                'selected': live[top]['now'], 'token': token}

    def candidates(self, snap):
        top = self.cfg['selector']
        explicit = next(g for g in snap['config']['proxy-groups'] if g['name'] == top).get('proxies', [])
        eligible, skipped, seen = {}, {}, set()
        for name in snap['live'][top]['all']:
            if not re.search(self.cfg['include'], name) or re.search(self.cfg['exclude'], name):
                continue
            try:
                if name not in explicit:
                    raise Error('动态成员未显式列入受管理选择器。')
                g = graph(snap['config'], snap['live'], name)
                # Selecting the top must not change a dialer dependency that refers back to it.
                if top in g['choices']:
                    raise Error('候选出站依赖受管理选择器本身。')
                # Stable config order breaks ties; aliases of one outbound are tested once.
                key = common.fingerprint(g['nodes'])
                if key in seen:
                    continue
                seen.add(key)
                eligible[name] = g
            except Error as error:
                skipped[name] = str(error)
        if len(eligible) > self.cfg['max_candidates']:
            raise Error('候选数量超过 max_candidates；未静默截断。')
        return eligible, skipped

    def evaluate(self, snap, only=None):
        candidates, skipped = self.candidates(snap)
        if only is not None:
            if only not in candidates:
                # Aliases may have been deduplicated in the full inventory.
                if only not in snap['live'][self.cfg['selector']]['all']:
                    raise Error('目标不属于受管理选择器。')
                g = graph(snap['config'], snap['live'], only)
                if self.cfg['selector'] in g['choices']:
                    raise Error('候选依赖受管理选择器。')
                candidates = {only: g}
            else:
                candidates = {only: candidates[only]}
        if not candidates:
            return {}, skipped
        nodes = {}
        for g in candidates.values():
            nodes.update(g['nodes'])
        results = {}
        with common.locked(self.cfg['probe_lock']):
            def probe_one(name):
                candidate = candidates[name]
                with common.ProbeProcess(list(candidate['nodes'].values()), binary=self.cfg['binary'],
                                         client_fingerprint=snap['config'].get('client-fingerprint'),
                                         allow_chains=True, ipv6=snap['config'].get('ipv6', False),
                                         target=candidate['leaf']) as process:
                    return check_proxy(self.cfg, process.proxy(candidate['leaf']))
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.cfg['concurrency']) as pool:
                jobs = {pool.submit(probe_one, name): name for name in candidates}
                for job in concurrent.futures.as_completed(jobs):
                    name = jobs[job]
                    result = job.result()
                    result['graph'] = candidates[name]['fingerprint']
                    result['leaf'] = candidates[name]['leaf']
                    results[name] = result
                    emit('candidate', target=name, **result)
        return results, skipped

    def business(self):
        return check_proxy(self.cfg, self.cfg['business_proxy'])

    def set_choice(self, snap, target):
        policy.api(snap['api'], '/proxies/' + urllib.parse.quote(self.cfg['selector'], safe=''), 'PUT', {'name': target})

    def transaction(self, snap, target, state, required_ip=None, automatic=True):
        """Shared lock held by caller. Pending WAL survives SIGKILL/power failure."""
        original = snap['text']
        candidate = persist(original, self.cfg['selector'], target)
        target_graph = graph(snap['config'], snap['live'], target)
        if self.cfg['selector'] in target_graph['choices']:
            raise Error('切换目标会改变自身依赖。')
        backup = os.path.join(self.cfg['state_dir'], 'pre-switch.yaml')
        # Store the credential-containing backup with the same restrictive JSON writer.
        common.save_json(backup + '.json', {'text': original})
        state['pending'] = {'previous': snap['selected'], 'target': target,
                            'started_at': time.time(), 'backup': backup + '.json'}
        state['last_attempt'] = time.time()
        if automatic:
            state['attempts'] = [t for t in state.get('attempts', []) if time.time() - t < 86400] + [time.time()]
        self.save(state)  # Must be durable BEFORE any mutation.
        try:
            self.set_choice(snap, target)
            after = self.snapshot()
            if after['selected'] != target or after['route']['leaf'] != target_graph['leaf']:
                raise Error('切换后业务链与目标不符。')
            expected_live = copy.deepcopy(snap['live'])
            expected_live[self.cfg['selector']]['now'] = target
            expected_route = graph(snap['config'], expected_live, self.cfg['entry'])
            if after['route']['fingerprint'] != expected_route['fingerprint']:
                raise Error('切换后的依赖链与已测试依赖不符。')
            checked = self.business()
            if not checked['ok']:
                raise Error('切换后业务接口复测失败。')
            if required_ip and checked.get('ip') != required_ip:
                raise Error('切后出口与本次同出口约束不一致。')
            # Re-read after HTTP requests: no silent overwrite of external edits.
            latest = self.snapshot()
            if latest['token'] != after['token'] or policy.read(self.cfg['clash_config']) != original:
                raise Error('切后复测期间发生外部配置/选路修改。')
            policy.atomic_write(self.cfg['clash_config'], candidate)
            completed = self.snapshot()
            if completed['selected'] != target:
                raise Error('保存后选择发生变化。')
            state.update(token=completed['token'], last_switch=time.time(), failures=[], last_result=checked,
                         last_good=checked if checked.get('ip') else {}, pending=None)
            self.save(state)
            emit('switched', previous=snap['selected'], target=target, ip=checked.get('ip'), restart=False)
            return True
        except BaseException:
            try:
                actual = policy.api(snap['api'], '/proxies')['proxies'][self.cfg['selector']]['now']
                if actual not in (target, snap['selected']):
                    raise Error('外部选择已变化；不覆盖。')
                if actual != snap['selected']:
                    self.set_choice(snap, snap['selected'])
                disk = policy.read(self.cfg['clash_config'])
                if disk == candidate:
                    policy.atomic_write(self.cfg['clash_config'], original)
                elif disk != original:
                    raise Error('外部配置已变化；不覆盖。')
                restored = self.snapshot()
                if restored['selected'] != snap['selected'] or restored['route']['fingerprint'] != snap['route']['fingerprint']:
                    raise Error('回退链路核验失败。')
                state.update(pending=None, token=restored['token'], failures=[], last_error='postcheck/commit failed; rolled back')
                self.save(state)
                emit('rolled_back', target=snap['selected'])
            except BaseException:
                emit('CRITICAL', message='回退未确认；保留 pending，禁止后续自动切换，请人工核查。')
            raise

    def cycle(self, readonly=False, activity_gate=True):
        if activity_gate and not readonly and self.cfg.get('activity', {}).get('enabled'):
            return demand.run(self, emit, journal)
        state = common.load_json(self.state_path, {})
        now = time.time()
        try:
            with common.locked(self.cfg['mutation_lock']):
                snap = self.snapshot()
        except Error as error:
            if ('另一个更新/切换/评估正在进行' in str(error)
                    or 'another update, switch, or evaluation is already running' in str(error)):
                emit('busy', reason='shared mutation lock')
                return 'busy'
            raise
        logs = journal(self.cfg, state.get('journal_cursor_us', 0), now)
        report = self.business()
        if logs['errors'] and not report['ok']:
            # Journal error + failed active check gets a second confirmation,
            # but still counts as ONE time-spaced failure, never two.
            report = self.business()
            emit('journal_recheck', errors=logs['errors'], ok=report['ok'])
        emit('health', target=snap['selected'], journal_errors=logs['errors'], **report)
        if readonly:
            return 'readonly'
        if state.get('pending'):
            emit('CRITICAL', message='存在未完成切换记录；仅探测，需人工 acknowledge。')
            return 'pending'
        # Changes to profile/config/manual selection all reset the evidence and hold off.
        cfg_hash = common.fingerprint(self.cfg)
        changed = state.get('token') != snap['token'] or state.get('profile_hash') != cfg_hash
        if changed or now < state.get('last_check', 0):
            state.update(token=snap['token'], profile_hash=cfg_hash, failures=[], last_good={},
                         hold_until=now + self.cfg['manual_hold_seconds'])
            emit('hold', reason='startup/config/manual change', until=state['hold_until'])
        last_check = state.get('last_check', 0)
        state.update(last_check=now, journal_cursor_us=logs['cursor_us'], last_result=report,
                     journal_errors=logs['errors'], journal_available=logs['available'])
        if report['ok']:
            state['failures'] = []
            if report.get('ip'):
                previous = state.get('last_good', {})
                samples = (previous.get('samples', 1) + 1 if previous.get('ip') == report['ip']
                           and now - previous.get('tested_at', 0) <= self.cfg['same_ip_max_age_seconds'] else 1)
                state['last_good'] = dict(report, samples=min(samples, 100))
        elif not report['switchable']:
            state['failures'] = []
        else:
            failures = state.get('failures', [])
            if now - last_check > self.cfg['failure_gap_seconds']:
                failures = []
            if not failures or now - failures[-1] >= self.cfg['interval_seconds']:
                failures.append(now)
            state['failures'] = failures[-100:]
        self.save(state)
        failures = state.get('failures', [])
        reason = ('healthy' if report['ok'] else 'ambiguous-response' if not report['switchable']
                  else 'paused' if state.get('paused') else 'manual/config-hold' if now < state.get('hold_until', 0)
                  else 'switch-cooldown' if now - state.get('last_attempt', 0) < self.cfg['cooldown_seconds']
                  else 'daily-budget' if len([t for t in state.get('attempts', []) if now - t < 86400]) >= self.cfg['max_attempts_24h']
                  else 'insufficient-evidence' if len(failures) < self.cfg['failure_count']
                  or now - failures[0] < self.cfg['failure_span_seconds'] else '')
        if reason:
            emit('decision', action='keep', reason=reason, failures=len(failures))
            return 'hold'
        if now - state.get('last_evaluation', 0) < self.cfg['evaluation_interval_seconds']:
            return 'evaluation-cooldown'
        state['last_evaluation'] = now
        self.save(state)
        results, skipped = self.evaluate(snap)
        common.save_json(os.path.join(self.cfg['state_dir'], 'evaluation.json'),
                         {'at': now, 'results': results, 'skipped': skipped})
        good = state.get('last_good', {})
        old_ip = (good.get('ip', '') if good.get('samples', 0) >= 2
                  and now - good.get('tested_at', 0) <= self.cfg['same_ip_max_age_seconds']
                  and report.get('ip', '') in ('', good.get('ip')) else '')
        options = []
        for name, result in results.items():
            if not result['ok'] or result['leaf'] == snap['route']['leaf']:
                continue
            same = bool(old_ip and result.get('ip') == old_ip)
            if not same and (not self.cfg['allow_cross_ip'] or now - failures[0] < self.cfg['cross_ip_failure_span_seconds']):
                continue
            countries = self.cfg['preferred_countries']
            preference = countries.index(result['country']) if result.get('country') in countries else len(countries)
            options.append((not same, preference, result['seconds'], name))
        if not options:
            # One early same-IP scan may be followed by a single cross-IP scan
            # after the longer outage threshold, not a scan every minute.
            if self.cfg['allow_cross_ip'] and now - failures[0] < self.cfg['cross_ip_failure_span_seconds']:
                state['last_evaluation'] = (failures[0] + self.cfg['cross_ip_failure_span_seconds']
                                            - self.cfg['evaluation_interval_seconds'])
                self.save(state)
            emit('no_candidate', evaluated=len(results), skipped=skipped)
            return 'no-candidate'
        target = sorted(options)[0][-1]
        if self.cfg['mode'] != 'auto':
            emit('would_switch', target=target, reason='observe mode; no mutation')
            return 'observe'
        # Repeat candidate test without using an old full-scan result.
        fresh, _ = self.evaluate(snap, only=target)
        if not fresh[target]['ok']:
            emit('candidate_unstable', target=target)
            return 'unstable'
        same = bool(old_ip and results[target].get('ip') == old_ip and fresh[target].get('ip') == old_ip)
        cross_allowed = self.cfg['allow_cross_ip'] and now - failures[0] >= self.cfg['cross_ip_failure_span_seconds']
        if not same and not cross_allowed:
            return 'ip-changed'
        with common.locked(self.cfg['mutation_lock']):
            latest = self.snapshot()
            if latest['token'] != snap['token']:
                emit('cancelled', reason='configuration or manual selection changed during evaluation')
                return 'changed'
            current = self.business()
            if current['ok'] or not current['switchable']:
                state.update(failures=[], last_result=current)
                self.save(state)
                emit('recovered_or_ambiguous', target=snap['selected'])
                return 'recovered'
            # A manual operation may have modified a file without taking our lock.
            if self.snapshot()['token'] != snap['token']:
                return 'changed'
            self.transaction(latest, target, state, required_ip=None if cross_allowed else old_ip)
        return 'switched'

    def status(self, snap):
        state = common.load_json(self.state_path, {})
        candidates, skipped = self.candidates(snap)
        now = time.time()
        print('守护模式：{}；暂停：{}；未完成事务：{}'.format(self.cfg['mode'], bool(state.get('paused')), bool(state.get('pending'))))
        print('业务入口：{} → {} → {}；物理出站：{}'.format(self.cfg['entry'], self.cfg['selector'], snap['selected'], snap['route']['leaf']))
        print('候选：{}；跳过：{}；连续失败：{}；24h自动尝试：{}/{}'.format(
            len(candidates), len(skipped), len(state.get('failures', [])),
            len([t for t in state.get('attempts', []) if now - t < 86400]), self.cfg['max_attempts_24h']))
        print('保护期剩余：{}秒；切换冷却剩余：{}秒'.format(
            max(0, int(state.get('hold_until', 0) - now)),
            max(0, int(state.get('last_attempt', 0) + self.cfg['cooldown_seconds'] - now))))
        if self.cfg.get('activity', {}).get('enabled'):
            d = state.get('demand', {})
            print('异常驱动：正常调用/空闲不探测；本地判断：{}'.format(d.get('reason', '尚未初始化')))
            print('被动成功调用：{}；窗口网络错误：{}；证据源可读：{}'.format(
                time.strftime('%F %T', time.localtime(d['success_at'])) if d.get('success_at') else '窗口内无成功记录',
                d.get('network_errors', 0), d.get('sources_available', False)))
            print('最近异常复核：{}；24h复核轮次：{}/{}；全量评估：{}/{}'.format(
                time.strftime('%F %T', time.localtime(d['last_probe'])) if d.get('last_probe') else '无',
                len([t for t in d.get('probes', []) if now-t < 86400]), demand.settings(self.cfg)['max_probes_24h'],
                len([t for t in d.get('evaluations', []) if now-t < 86400]), demand.settings(self.cfg)['max_evaluations_24h']))
        result = state.get('last_result', {})
        if result:
            print('最近检查：{}；接口可达(未鉴权)：{}；trace IP：{} / {}'.format(
                time.strftime('%F %T', time.localtime(result.get('tested_at', 0))),
                result.get('ok'), result.get('ip') or '未知', result.get('country') or '未知'))
            for check in result.get('checks', []):
                print('  {} HTTP={} curl={} {:.3f}s'.format(check['name'], check['code'], check['curl_exit'], check['seconds']))
        print('近期日志异常：{}；journal可读：{}'.format(state.get('journal_errors', 0), state.get('journal_available', False)))
        if state.get('pending'):
            print('CRITICAL: 先核查实际选择/业务；确认后 clash-guard acknowledge。不自动盲目回退。')
        for name, reason in skipped.items():
            print('跳过 {}：{}'.format(name, reason))
        print('状态不等于 timer 已启用；查看：systemctl status clash-guard.timer')

    def manual(self, target):
        with common.locked(self.cfg['mutation_lock']):
            snap = self.snapshot()
        if target == snap['selected']:
            emit('unchanged', target=target)
            return
        results, _ = self.evaluate(snap, only=target)
        if not results[target]['ok']:
            raise Error('目标预检失败，未切换。')
        emit('manual_preview', previous=snap['selected'], target=target, **results[target])
        if not common.confirmed('确认切换？'):
            return
        with common.locked(self.cfg['mutation_lock']):
            latest = self.snapshot()
            if latest['token'] != snap['token']:
                raise Error('评估期间选择发生变化，未切换。')
            state = common.load_json(self.state_path, {})
            if state.get('pending'):
                raise Error('先核查并 acknowledge 未完成事务。')
            state['hold_until'] = time.time() + self.cfg['manual_hold_seconds']
            self.transaction(latest, target, state, automatic=False)

    def menu(self):
        if not sys.stdin.isatty():
            raise Error('菜单需要交互终端。')
        while True:
            snap = self.snapshot()
            candidates, skipped = self.candidates(snap)
            names = list(candidates)
            cached = {}
            for filename in ('evaluation.json', 'probe.json'):
                for name, result in common.load_json(os.path.join(self.cfg['state_dir'], filename), {}).get('results', {}).items():
                    if result.get('tested_at', 0) > cached.get(name, {}).get('tested_at', 0):
                        cached[name] = result
            print('\n编号 目标 / 实际节点 / 最近接口检查 / trace IP')
            for i, name in enumerate(names, 1):
                g = candidates[name]
                result = cached.get(name, {})
                if result.get('graph') != g['fingerprint']:
                    result = {}
                status = '未测'
                if result:
                    status = '接口可达(未鉴权)' if result.get('ok') else '探测未通过'
                    if time.time() - result['tested_at'] > 900:
                        status = '已过期:' + status
                    status += ' {:.2f}s'.format(result['seconds'])
                print('{}{} {} → {} / {} / {}'.format(i, '*' if name == snap['selected'] else '', name,
                      g['leaf'], status, result.get('ip') or '未知'))
            print('当前：{}；跳过 {} 个不兼容候选。缓存成功不是长期可用保证。'.format(snap['selected'], len(skipped)))
            answer = input('编号=重新预检并确认切换；t=全量评估并刷新；0/回车=退出：').strip()
            if answer in ('', '0'):
                return
            if answer == 't':
                results, skipped = self.evaluate(snap)
                common.save_json(os.path.join(self.cfg['state_dir'], 'probe.json'),
                                 {'at': time.time(), 'results': results, 'skipped': skipped})
            elif answer.isdigit() and 1 <= int(answer) <= len(names):
                self.manual(names[int(answer) - 1])
                return
            else:
                print('无效选项。')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', default=DEFAULT_PROFILE)
    parser.add_argument('action', choices=('validate', 'status', 'check', 'observe', 'probe', 'pause', 'resume', 'acknowledge', 'use', 'menu'))
    parser.add_argument('target', nargs='?')
    args = parser.parse_args()
    cfg = profile(args.profile)
    guard = Guard(cfg)
    with common.locked(cfg['run_lock']):
        if args.action in ('validate', 'status'):
            snap = guard.snapshot()
            if args.action == 'status':
                guard.status(snap)
            else:
                candidates, skipped = guard.candidates(snap)
                emit('validate', mode=cfg['mode'], target=snap['selected'], leaf=snap['route']['leaf'],
                     eligible=len(candidates), skipped=skipped)
        elif args.action in ('check', 'observe'):
            if args.action == 'check' and not cfg.get('activity', {}).get('enabled'):
                raise Error('自动 check 需要启用 faults-only 本地业务证据；不会退回周期探测。')
            guard.cycle(readonly=args.action == 'observe', activity_gate=args.action != 'observe')
        elif args.action == 'probe':
            snap = guard.snapshot()
            results, skipped = guard.evaluate(snap, args.target)
            # Cache is informational only; automatic decisions always probe anew.
            common.save_json(os.path.join(cfg['state_dir'], 'probe.json'), {'at': time.time(), 'results': results, 'skipped': skipped})
            emit('probe_summary', evaluated=len(results), reachable=sum(r['ok'] for r in results.values()), skipped=skipped)
        elif args.action in ('pause', 'resume', 'acknowledge'):
            state = common.load_json(guard.state_path, {})
            if args.action == 'pause':
                state['paused'] = True
            else:
                if state.get('pending'):
                    if args.action != 'acknowledge' or not guard.business()['ok']:
                        raise Error('需人工核查并在业务探测通过后执行 acknowledge。')
                    # Explicit acknowledgement adopts the observed route; no blind recovery.
                    state['pending'] = None
                state.update(paused=False, failures=[], hold_until=time.time() + cfg['manual_hold_seconds'])
                state['token'] = guard.snapshot()['token']
            guard.save(state)
            emit(args.action, hold_until=state.get('hold_until'))
        elif args.action == 'use':
            if not args.target:
                raise Error('use 需要目标名称。')
            guard.manual(args.target)
        elif args.action == 'menu':
            guard.menu()


if __name__ == '__main__':
    os.umask(0o077)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        sys.exit(130)
    except Exception as error:
        # Do not leak URLs, credentials, YAML snippets or HTTP response bodies.
        emit('error', message=str(error) if isinstance(error, (Error, policy.PolicyError)) else type(error).__name__)
        sys.exit(1)
