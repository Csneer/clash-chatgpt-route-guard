#!/usr/bin/env python3
"""Guard tests: fixtures/fake controllers only. Never mutate production routing."""
import copy
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import yaml
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
import clash_guard as guard
import clash_common as common
import mihomo_policy as policy


def write(path, text):
    with open(path, 'w') as stream:
        stream.write(text)


def report(ok=True, ip='198.51.100.1', switchable=True, country='TW', seconds=1):
    return dict(ok=ok, switchable=not ok and switchable, ip=ip, country=country,
                seconds=seconds, tested_at=time.time(), checks=[])


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='guard-test-')
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, 'clash.yaml')
        self.config = {'mode': 'rule', 'port': 17890, 'external-controller': '127.0.0.1:19090',
                       'proxies': [{'name': n, 'type': 'ss', 'server': '127.0.0.1', 'port': 19091 + i,
                                    'cipher': 'aes-128-gcm', 'password': 'fixture-not-a-secret'} for i, n in enumerate(['A', 'B', 'C'])],
                       'proxy-groups': [{'name': 'Service', 'type': 'select', 'proxies': ['Choice']},
                                        {'name': 'Choice', 'type': 'select', 'proxies': ['A', 'B', 'C']}],
                       'rules': ['DOMAIN-SUFFIX,guard.test,Service', 'MATCH,REJECT'],
                       'profile': {'store-selected': True}}
        self.text = yaml.safe_dump(self.config, default_flow_style=False)
        write(self.path, self.text)
        self.cfg = dict(guard.DEFAULTS, clash_config=self.path,
                        binary=os.environ.get('MIHOMO_BINARY', '/usr/local/bin/mihomo'),
                        state_dir=self.tmp.name, run_lock=os.path.join(self.tmp.name, 'run.lock'),
                        mutation_lock=os.path.join(self.tmp.name, 'mutation.lock'),
                        probe_lock=os.path.join(self.tmp.name, 'probe.lock'), manual_history=None,
                        selector='Choice', entry='Service', business_proxy='http://127.0.0.1:17890',
                        checks=[dict(name='test', url='https://guard.test/api', status=401,
                                     json_contains={'detail': 'Unauthorized'})],
                        mode='auto', journal_unit=None, cross_ip_failure_span_seconds=180)
        self.g = guard.Guard(self.cfg)
        self.live = {p['name']: {'type': 'Shadowsocks'} for p in self.config['proxies']}
        self.live.update({g['name']: dict(type='Selector', now=g['proxies'][0], all=g['proxies'][:]) for g in self.config['proxy-groups']})
        self.requests = []
        self.runtime_mode = 'rule'
        patch = mock.patch.object(policy, 'api', side_effect=self.api)
        patch.start()
        self.addCleanup(patch.stop)
        self.output = io.StringIO()
        patch = mock.patch('sys.stdout', self.output)
        patch.start()
        self.addCleanup(patch.stop)

    def api(self, config, path, method='GET', data=None, timeout=3):
        self.requests.append((method, path, data))
        if path == '/configs':
            return dict(mode=self.runtime_mode, port=17890)
        if path == '/proxies':
            return {'proxies': copy.deepcopy(self.live)}
        if path == '/rules':
            return {'rules': [dict(type='DomainSuffix', payload='guard.test', proxy='Service'),
                              dict(type='Match', payload='', proxy='REJECT')]}
        if method == 'PUT' and path.startswith('/proxies/'):
            name = guard.urllib.parse.unquote(path.split('/proxies/')[1])
            self.live[name]['now'] = data['name']
            return None
        raise AssertionError('unexpected request: ' + path)

    def mutations(self):
        return [r for r in self.requests if r[0] != 'GET']

    def state(self, **kw):
        snap = self.g.snapshot()
        value = dict(token=snap['token'], profile_hash=common.fingerprint(self.cfg),
                     last_check=9940, failures=[9760, 9820, 9880],
                     last_good=dict(ip='198.51.100.1', tested_at=9700, samples=2))
        value.update(kw)
        self.g.save(value)
        return value


class ConfigTests(Base):
    def load(self, **kw):
        cfg = dict(self.cfg, **kw)
        path = os.path.join(self.tmp.name, 'profile.yaml')
        write(path, yaml.safe_dump(cfg, default_flow_style=False))
        return guard.profile(path)

    def test_portable_names_no_provider_assumptions(self):
        self.assertEqual(self.load()['selector'], 'Choice')
        self.assertEqual(self.g.snapshot()['route']['leaf'], 'A')

    def test_unknown_keys_rejected(self):
        with self.assertRaises(guard.Error): self.load(cooldon_seconds=1)

    def test_aggressive_timers_rejected(self):
        for key, value in [('failure_count', 1), ('cooldown_seconds', 10), ('concurrency', 100), ('interval_seconds', 0)]:
            with self.subTest(key=key), self.assertRaises(guard.Error): self.load(**{key: value})

    def test_non_loopback_proxy_rejected(self):
        with self.assertRaises(guard.Error): self.load(business_proxy='http://example.com:7890')

    def test_http_check_and_credentials_rejected(self):
        for url in ['http://guard.test/api', 'https://user:secret@guard.test/api']:
            with self.subTest(url=url), self.assertRaises(guard.Error):
                self.load(checks=[dict(self.cfg['checks'][0], url=url)])

    def test_rate_limit_and_server_errors_cannot_enable_switching(self):
        for code in (401, 429, 500, 200):
            with self.subTest(code=code), self.assertRaises(guard.Error): self.load(switchable_http_codes=[code])

    def test_certificate_errors_do_not_rotate(self):
        with self.assertRaises(guard.Error): self.load(switchable_curl_errors=[60])

    def test_empty_json_expectation_rejected(self):
        with self.assertRaises(guard.Error): self.load(checks=[dict(self.cfg['checks'][0], json_contains={})])

    def test_generic_persistence_preserves_every_other_field(self):
        text = guard.persist(self.text, 'Choice', 'B')
        actual = policy.parse(text)
        expected = copy.deepcopy(self.config)
        expected['proxy-groups'][1]['proxies'] = ['B', 'A', 'C']
        self.assertEqual(actual, expected)
        self.assertEqual(actual['rules'], self.config['rules'])

    def test_missing_member_cannot_be_inserted(self):
        with self.assertRaises(guard.Error): guard.persist(self.text, 'Choice', 'NEW')

    def test_actual_route_checked_not_rule_presence(self):
        self.config['rules'].insert(0, 'DOMAIN,guard.test,REJECT')
        self.assertEqual(guard.first_route(self.config['rules'], 'guard.test'), 'REJECT')

    def test_complex_preceding_rule_rejected(self):
        with self.assertRaises(guard.Error): guard.first_route(['RULE-SET,unknown,DIRECT'] + self.config['rules'], 'guard.test')

    def test_suffix_does_not_match_lookalike(self):
        self.assertEqual(guard.first_route(self.config['rules'], 'notguard.test'), 'REJECT')

    def test_nonmatching_port_allowed_before_domain(self):
        self.assertEqual(guard.first_route(['DST-PORT,8080,DIRECT'] + self.config['rules'], 'guard.test'), 'Service')

    def test_control_ready_but_business_port_not_ready_fails_closed(self):
        original = self.api
        def api(config, path, *args, **kwargs):
            if path == '/configs': return dict(mode='rule', port=0)
            return original(config, path, *args, **kwargs)
        with mock.patch.object(policy, 'api', side_effect=api), mock.patch.object(self.g, 'business') as business:
            with self.assertRaises(guard.Error): self.g.cycle()
        business.assert_not_called()
        self.assertFalse(self.mutations())

    def test_global_without_runtime_selector_rejected(self):
        original = self.api
        def api(config, path, *args, **kwargs):
            if path == '/configs': return dict(mode='global', port=17890)
            return original(config, path, *args, **kwargs)
        with mock.patch.object(policy, 'api', side_effect=api):
            with self.assertRaises(guard.Error): self.g.snapshot()
        self.assertFalse(self.mutations())

    def test_global_snapshot_uses_virtual_global_selector(self):
        self.runtime_mode = 'global'
        self.config['mode'] = 'global'
        self.live['GLOBAL'] = dict(type='Selector', now='A', all=['A', 'B', 'C'])
        snap = self.g.snapshot()
        self.assertEqual(snap['mode'], 'global')
        self.assertEqual(snap['selector'], 'GLOBAL')
        self.assertEqual(snap['selected'], 'A')
        self.assertEqual(snap['route']['leaf'], 'A')
        candidates, skipped = self.g.candidates(snap)
        self.assertEqual(set(candidates), {'A', 'B', 'C'})
        self.assertFalse(skipped)
        self.assertFalse(self.mutations())

    def test_unsupported_runtime_mode_rejected(self):
        self.runtime_mode = 'direct'
        with self.assertRaises(guard.Error):
            self.g.snapshot()

    def test_global_transaction_puts_virtual_selector_without_rewriting_yaml(self):
        self.runtime_mode = 'global'
        self.config['mode'] = 'global'
        self.live['GLOBAL'] = dict(type='Selector', now='A', all=['A', 'B', 'C'])
        snap = self.g.snapshot()
        with mock.patch.object(self.g, 'business', return_value=report()):
            self.g.transaction(snap, 'B', {})
        self.assertEqual(self.live['GLOBAL']['now'], 'B')
        self.assertEqual([r[1] for r in self.mutations()], ['/proxies/GLOBAL'])
        self.assertEqual(policy.read(self.path), self.text)

    def test_wrong_runtime_route_not_silently_adopted(self):
        original = self.api
        def api(config, path, *args, **kwargs):
            if path == '/rules': return {'rules': [dict(type='DomainSuffix', payload='guard.test', proxy='DIRECT'), dict(type='Match', payload='', proxy='REJECT')]}
            return original(config, path, *args, **kwargs)
        with mock.patch.object(policy, 'api', side_effect=api):
            with self.assertRaises(guard.Error): self.g.snapshot()
        self.assertFalse(self.mutations())


class RuntimeModeTests(Base):
    def setUp(self):
        super(RuntimeModeTests, self).setUp()
        self.live['GLOBAL'] = dict(type='Selector', now='A', all=['A', 'B', 'C', 'DIRECT', 'provider-only'])

    def test_global_ignores_rule_entry_and_keeps_file_mode(self):
        self.runtime_mode = 'global'
        self.cfg.update(entry='Missing', selector='Missing')
        self.config.pop('rules')
        write(self.path, yaml.safe_dump(self.config))
        snap = self.g.snapshot()
        self.assertEqual(snap['selector'], 'GLOBAL')
        self.assertIsNone(snap['entry'])
        self.assertFalse(any(r[1] == '/rules' for r in self.requests))
        eligible, skipped = self.g.candidates(snap)
        self.assertEqual(set(eligible), {'A', 'B', 'C'})
        self.assertEqual(set(skipped), {'DIRECT', 'provider-only'})
        self.assertEqual(snap['config']['mode'], 'rule')

    def test_switch_back_to_rule_uses_entry_and_selector(self):
        self.runtime_mode = 'global'
        global_snap = self.g.snapshot()
        self.runtime_mode = 'rule'
        rule_snap = self.g.snapshot()
        self.assertEqual(rule_snap['selector'], 'Choice')
        self.assertEqual(rule_snap['route']['choices'], {'Service': 'Choice', 'Choice': 'A'})
        self.assertNotEqual(global_snap['token'], rule_snap['token'])

    def test_rule_entry_must_actually_traverse_selector(self):
        self.live['Service']['now'] = 'B'
        self.live['Service']['all'].append('B')
        self.config['proxy-groups'][0]['proxies'].append('B')
        write(self.path, yaml.safe_dump(self.config))
        with self.assertRaises(guard.Error):
            self.g.snapshot()

    def test_mode_change_clears_legacy_evidence_and_holds(self):
        self.state()
        self.runtime_mode = 'global'
        with mock.patch.object(self.g, 'business', return_value=report(False)), \
                mock.patch.object(self.g, 'evaluate') as evaluate:
            self.assertEqual(self.g.cycle(), 'hold')
        state = common.load_json(self.g.state_path, {})
        self.assertEqual(state['runtime_mode'], 'global')
        self.assertEqual(state['runtime_selector'], 'GLOBAL')
        self.assertEqual(state['failures'], [])
        self.assertEqual(state['last_good'], {})
        self.assertGreater(state['hold_until'], time.time())
        evaluate.assert_not_called()
        self.assertFalse(self.mutations())

    def test_mode_change_before_transaction_never_puts(self):
        snap = self.g.snapshot()
        self.runtime_mode = 'global'
        with self.assertRaises(guard.Error):
            self.g.transaction(snap, 'B', {})
        self.assertFalse(self.mutations())
        self.assertEqual(policy.read(self.path), self.text)

    def test_mode_change_with_pending_clears_evidence_but_keeps_wal(self):
        self.state(runtime_mode='rule', runtime_selector='Choice', pending={'target': 'B'}, last_result=report())
        self.runtime_mode = 'global'
        with mock.patch.object(self.g, 'business', return_value=report(False)):
            self.assertEqual(self.g.cycle(), 'pending')
        state = common.load_json(self.g.state_path, {})
        self.assertEqual(state['pending'], {'target': 'B'})
        self.assertEqual(state['runtime_mode'], 'global')
        self.assertEqual((state['failures'], state['last_good'], state['last_result']), ([], {}, {}))

    def test_unsupported_mode_clears_old_evidence_without_probe(self):
        self.state(runtime_mode='rule')
        self.runtime_mode = 'direct'
        with mock.patch.object(self.g, 'business') as business:
            with self.assertRaises(guard.Error):
                self.g.cycle()
        state = common.load_json(self.g.state_path, {})
        self.assertEqual(state['runtime_mode'], 'direct')
        self.assertEqual(state['failures'], [])
        self.assertEqual(state['last_good'], {})
        business.assert_not_called()

    def test_candidate_global_dialer_change_invalidates_rule_snapshot(self):
        self.config['proxies'][1]['dialer-proxy'] = 'GLOBAL'
        write(self.path, yaml.safe_dump(self.config))
        snap = self.g.snapshot()
        self.assertIn('B', self.g.candidates(snap)[0])
        self.live['GLOBAL']['now'] = 'C'
        self.assertNotEqual(self.g.snapshot()['token'], snap['token'])

    def test_mode_change_after_put_preserves_pending_without_rollback(self):
        self.runtime_mode = 'global'
        snap = self.g.snapshot()
        setter = self.g.set_choice
        def change_mode(snap, target):
            setter(snap, target)
            self.runtime_mode = 'rule'
        with mock.patch.object(self.g, 'set_choice', side_effect=change_mode):
            with self.assertRaises(guard.Error):
                self.g.transaction(snap, 'B', {})
        self.assertEqual([r[1] for r in self.mutations()], ['/proxies/GLOBAL'])
        self.assertEqual(self.live['Choice']['now'], 'A')
        self.assertEqual(self.live['GLOBAL']['now'], 'B')
        pending = common.load_json(self.g.state_path, {})['pending']
        self.assertEqual((pending['mode'], pending['selector']), ('global', 'GLOBAL'))
        self.assertEqual(policy.read(self.path), self.text)

    def test_mode_change_during_postcheck_preserves_pending(self):
        self.runtime_mode = 'global'
        def business():
            self.runtime_mode = 'rule'
            return report()
        with mock.patch.object(self.g, 'business', side_effect=business):
            with self.assertRaises(guard.Error):
                self.g.transaction(self.g.snapshot(), 'B', {})
        self.assertEqual(len(self.mutations()), 1)
        self.assertIsNotNone(common.load_json(self.g.state_path, {})['pending'])
        self.assertEqual(policy.read(self.path), self.text)

    def test_mode_change_during_wal_never_puts(self):
        snap = self.g.snapshot()
        save = self.g.save
        def save_and_change(state):
            save(state)
            self.runtime_mode = 'global'
        with mock.patch.object(self.g, 'save', side_effect=save_and_change):
            with self.assertRaises(guard.Error):
                self.g.transaction(snap, 'B', {})
        self.assertFalse(self.mutations())

    def test_global_success_does_not_write_generated_file(self):
        self.runtime_mode = 'global'
        with mock.patch.object(self.g, 'business', return_value=report()), \
                mock.patch.object(policy, 'atomic_write') as writer:
            self.g.transaction(self.g.snapshot(), 'B', {})
        writer.assert_not_called()
        self.assertEqual(self.live['Choice']['now'], 'A')
        self.assertEqual(self.live['GLOBAL']['now'], 'B')

    def test_global_without_store_selected_refuses_before_put(self):
        self.runtime_mode = 'global'
        self.config['profile']['store-selected'] = False
        write(self.path, yaml.safe_dump(self.config))
        with self.assertRaises(guard.Error):
            self.g.transaction(self.g.snapshot(), 'B', {})
        self.assertFalse(self.mutations())

    def test_global_explicit_group_persist_preserves_mode_and_other_groups(self):
        self.runtime_mode = 'global'
        self.config['proxy-groups'].append(dict(name='GLOBAL', type='select', proxies=['A', 'B', 'C']))
        write(self.path, yaml.safe_dump(self.config))
        with mock.patch.object(self.g, 'business', return_value=report()):
            self.g.transaction(self.g.snapshot(), 'B', {})
        updated = policy.parse(policy.read(self.path))
        self.assertEqual(updated['proxy-groups'][-1]['proxies'], ['B', 'A', 'C'])
        self.assertEqual(updated['proxy-groups'][:-1], self.config['proxy-groups'][:-1])
        self.assertEqual(updated['mode'], 'rule')

    def test_global_failed_postcheck_rolls_back_once(self):
        self.runtime_mode = 'global'
        with mock.patch.object(self.g, 'business', return_value=report(False)):
            with self.assertRaises(guard.Error):
                self.g.transaction(self.g.snapshot(), 'B', {})
        self.assertEqual(self.live['GLOBAL']['now'], 'A')
        self.assertEqual([r[1] for r in self.mutations()], ['/proxies/GLOBAL', '/proxies/GLOBAL'])
        self.assertIsNone(common.load_json(self.g.state_path, {})['pending'])

    def test_global_dependency_cannot_reenter_global(self):
        self.runtime_mode = 'global'
        self.config['proxies'][1]['dialer-proxy'] = 'GLOBAL'
        write(self.path, yaml.safe_dump(self.config))
        eligible, skipped = self.g.candidates(self.g.snapshot())
        self.assertNotIn('B', eligible)
        self.assertIn('B', skipped)

    def test_global_manual_selection_invalidates_token(self):
        self.runtime_mode = 'global'
        snap = self.g.snapshot()
        self.live['GLOBAL']['now'] = 'B'
        self.assertNotEqual(self.g.snapshot()['token'], snap['token'])

    def test_global_selection_invalidates_rule_candidate_evidence(self):
        snap = self.g.snapshot()
        self.live['GLOBAL']['now'] = 'B'
        self.assertNotEqual(self.g.snapshot()['token'], snap['token'])

    def test_global_in_rule_dependency_invalidates_token(self):
        self.config['proxy-groups'][1]['proxies'].append('GLOBAL')
        self.live['Choice']['all'].append('GLOBAL')
        self.live['Choice']['now'] = 'GLOBAL'
        write(self.path, yaml.safe_dump(self.config))
        before = self.g.snapshot()
        self.live['GLOBAL']['now'] = 'B'
        after = self.g.snapshot()
        self.assertNotEqual(before['route']['leaf'], after['route']['leaf'])
        self.assertNotEqual(before['token'], after['token'])

    def test_evaluation_exception_after_mode_change_clears_evidence(self):
        self.state()
        def evaluate(*args, **kwargs):
            self.runtime_mode = 'global'
            raise guard.Error('runtime changed')
        with mock.patch.object(guard.time, 'time', return_value=10000), \
                mock.patch.object(self.g, 'business', return_value=report(False)), \
                mock.patch.object(self.g, 'evaluate', side_effect=evaluate):
            self.assertEqual(self.g.cycle(), 'changed')
        state = common.load_json(self.g.state_path, {})
        self.assertEqual(state['failures'], [])
        self.assertEqual(state['last_good'], {})
        self.assertEqual(state['runtime_mode'], 'global')
        self.assertGreater(state['hold_until'], 10000)
        self.assertFalse(self.mutations())


class GraphTests(Base):
    def graph(self, target='B'):
        return guard.graph(self.config, self.live, target)

    def test_explicit_chain_dependencies_included(self):
        self.config['proxies'][1]['dialer-proxy'] = 'A'
        g = self.graph()
        self.assertEqual(set(g['nodes']), {'A', 'B'})
        self.assertEqual(g['nodes']['B']['dialer-proxy'], 'A')

    def test_selector_in_dialer_chain_is_frozen(self):
        self.config['proxy-groups'].append(dict(name='FirstHop', type='select', proxies=['A', 'C']))
        self.live['FirstHop'] = dict(type='Selector', now='A', all=['A', 'C'])
        self.config['proxies'][1]['dialer-proxy'] = 'FirstHop'
        self.assertEqual(self.graph()['nodes']['B']['dialer-proxy'], 'A')

    def test_auto_dialer_group_rejected(self):
        self.config['proxy-groups'][1]['type'] = 'url-test'
        self.config['proxies'][1]['dialer-proxy'] = 'Choice'
        with self.assertRaises(guard.Error): self.graph()

    def test_node_cycle_rejected(self):
        self.config['proxies'][0]['dialer-proxy'] = 'B'
        self.config['proxies'][1]['dialer-proxy'] = 'A'
        with self.assertRaises(guard.Error): self.graph()

    def test_group_cycle_rejected(self):
        self.live['Choice']['now'] = 'Service'
        self.live['Choice']['all'].append('Service')
        self.config['proxy-groups'][1]['proxies'].append('Service')
        with self.assertRaises(guard.Error): self.graph('Choice')

    def test_missing_dependency_rejected(self):
        self.config['proxies'][1]['dialer-proxy'] = 'Missing'
        with self.assertRaises(guard.Error): self.graph()

    def test_external_files_rejected(self):
        self.config['proxies'][1]['certificate'] = 'server.pem'
        with self.assertRaises(guard.Error): self.graph()

    def test_provider_only_rejected_without_secret_inventory(self):
        with self.assertRaises(guard.Error): self.graph('provider-node')

    def test_fingerprint_changes_with_dependency_credentials(self):
        self.config['proxies'][1]['dialer-proxy'] = 'A'
        before = self.graph()['fingerprint']
        self.config['proxies'][0]['password'] = 'changed'
        self.assertNotEqual(before, self.graph()['fingerprint'])

    def test_no_dependency_mutation_in_original_config(self):
        before = copy.deepcopy(self.config)
        self.graph()
        self.assertEqual(before, self.config)

    def test_direct_reject_not_candidates(self):
        for n in ['DIRECT', 'REJECT']:
            with self.subTest(n=n), self.assertRaises(guard.Error): self.graph(n)

    def test_full_inventory_limit_never_silently_truncates(self):
        self.cfg['max_candidates'] = 2
        with self.assertRaises(guard.Error): self.g.candidates(self.g.snapshot())


class HealthTests(Base):
    def health(self, code=401, exit=0, body='{"detail":"Unauthorized"}', content_type='application/json'):
        with mock.patch.object(common, 'fetch', return_value=dict(exit=exit, code=code, body=body, content_type=content_type, seconds=1)):
            return guard.check_proxy(self.cfg, self.cfg['business_proxy'])

    def test_expected_401_is_reachable(self): self.assertTrue(self.health()['ok'])
    def test_200_html_is_not_reachable(self): self.assertFalse(self.health(200, body='<html/>', content_type='text/html')['ok'])
    def test_random_401_is_not_reachable(self): self.assertFalse(self.health(body='{"error":"no"}')['ok'])
    def test_403_is_switchable(self): self.assertTrue(self.health(403)['switchable'])
    def test_429_never_triggers_rotation(self): self.assertFalse(self.health(429)['switchable'])
    def test_503_never_triggers_rotation(self): self.assertFalse(self.health(503)['switchable'])
    def test_certificate_error_never_triggers_rotation(self): self.assertFalse(self.health(exit=60)['switchable'])
    def test_tls_failure_switchable(self): self.assertTrue(self.health(exit=35)['switchable'])
    def test_timeout_switchable(self): self.assertTrue(self.health(exit=28)['switchable'])
    def test_unexpected_json_not_logged(self): self.assertNotIn('body', self.health(body='{"secret":"private"}'))

    def test_trace_success_cannot_mask_backend_failure(self):
        self.cfg['trace_url'] = 'https://guard.test/trace'
        values = [dict(exit=35, code=0, body='', content_type='', seconds=1),
                  dict(exit=0, code=200, body='ip=198.51.100.1\nloc=TW', content_type='text/plain', seconds=1)]
        with mock.patch.object(common, 'fetch', side_effect=values):
            r = guard.check_proxy(self.cfg, 'http://127.0.0.1:1')
        self.assertFalse(r['ok'])
        self.assertEqual(r['ip'], '198.51.100.1')


class CycleTests(Base):
    def run_cycle(self, health=None, options=None, readonly=False, **state):
        self.state(**state)
        values = options if options is not None else {'B': dict(report(), leaf='B')}
        with mock.patch.object(guard.time, 'time', return_value=10000), \
                mock.patch.object(self.g, 'business', return_value=health or report(False)), \
                mock.patch.object(self.g, 'evaluate', return_value=(values, {})) as evaluate, \
                mock.patch.object(self.g, 'transaction') as transaction:
            result = self.g.cycle(readonly)
        return result, evaluate, transaction

    def test_healthy_never_evaluates_or_switches(self):
        _, e, t = self.run_cycle(health=report())
        e.assert_not_called(); t.assert_not_called()

    def test_one_failure_does_not_switch(self):
        _, e, t = self.run_cycle(failures=[])
        e.assert_not_called(); t.assert_not_called()

    def test_failure_minimum_span_enforced(self):
        _, e, t = self.run_cycle(failures=[9900, 9920, 9940])
        e.assert_not_called(); t.assert_not_called()

    def test_eligible_failure_evaluates_and_switches(self):
        result, e, t = self.run_cycle()
        self.assertEqual(result, 'switched'); self.assertEqual(e.call_count, 2); t.assert_called_once()

    def test_unknown_or_upstream_error_does_not_switch(self):
        _, e, t = self.run_cycle(health=report(False, switchable=False))
        e.assert_not_called(); t.assert_not_called()

    def test_switch_cooldown_enforced(self):
        _, e, t = self.run_cycle(last_attempt=9900)
        e.assert_not_called(); t.assert_not_called()

    def test_manual_hold_enforced(self):
        _, e, t = self.run_cycle(hold_until=11000)
        e.assert_not_called(); t.assert_not_called()

    def test_pause_enforced(self):
        _, e, t = self.run_cycle(paused=True)
        e.assert_not_called(); t.assert_not_called()

    def test_readonly_observe_does_not_write_state(self):
        self.state()
        before = policy.read(self.g.state_path)
        with mock.patch.object(self.g, 'business', return_value=report(False)):
            self.g.cycle(readonly=True)
        self.assertEqual(before, policy.read(self.g.state_path)); self.assertFalse(self.mutations())

    def test_observe_mode_never_puts(self):
        self.cfg['mode'] = 'observe'
        result, _, t = self.run_cycle()
        self.assertEqual(result, 'observe'); t.assert_not_called(); self.assertFalse(self.mutations())

    def test_pending_crash_latches_no_switch(self):
        result, e, t = self.run_cycle(pending={'target': 'B'})
        self.assertEqual(result, 'pending'); e.assert_not_called(); t.assert_not_called()

    def test_all_candidates_bad_holds_route(self):
        result, _, t = self.run_cycle(options={'B': dict(report(False), leaf='B')})
        self.assertEqual(result, 'no-candidate'); t.assert_not_called()

    def test_evaluation_cooldown_enforced(self):
        _, e, t = self.run_cycle(last_evaluation=9900)
        e.assert_not_called(); t.assert_not_called()

    def test_gap_resets_streak(self):
        _, e, t = self.run_cycle(last_check=9000)
        e.assert_not_called(); t.assert_not_called()

    def test_repeated_command_does_not_inflate_streak(self):
        self.run_cycle(failures=[9990], last_check=9990)
        self.assertEqual(common.load_json(self.g.state_path, {})['failures'], [9990])

    def test_clock_backwards_starts_hold(self):
        _, e, t = self.run_cycle(last_check=10001)
        e.assert_not_called(); t.assert_not_called()

    def test_external_selection_resets_evidence(self):
        self.state()
        self.live['Choice']['now'] = 'B'
        with mock.patch.object(guard.time, 'time', return_value=10000), mock.patch.object(self.g, 'business', return_value=report(False)), mock.patch.object(self.g, 'evaluate') as e:
            self.g.cycle()
        e.assert_not_called()
        self.assertGreater(common.load_json(self.g.state_path, {})['hold_until'], 10000)

    def test_current_recovery_aborts_switch(self):
        self.state()
        with mock.patch.object(guard.time, 'time', return_value=10000), mock.patch.object(self.g, 'business', side_effect=[report(False), report()]), mock.patch.object(self.g, 'evaluate', return_value=({'B': dict(report(), leaf='B')}, {})), mock.patch.object(self.g, 'transaction') as t:
            self.assertEqual(self.g.cycle(), 'recovered')
        t.assert_not_called()

    def test_candidate_second_probe_failure_aborts(self):
        self.state()
        evaluations = [({'B': dict(report(), leaf='B')}, {}), ({'B': dict(report(False), leaf='B')}, {})]
        with mock.patch.object(guard.time, 'time', return_value=10000), mock.patch.object(self.g, 'business', return_value=report(False)), mock.patch.object(self.g, 'evaluate', side_effect=evaluations), mock.patch.object(self.g, 'transaction') as t:
            self.assertEqual(self.g.cycle(), 'unstable')
        t.assert_not_called()

    def test_same_ip_preferred_over_faster_different_ip(self):
        options = {'B': dict(report(seconds=5), leaf='B'), 'C': dict(report(ip='198.51.100.2', seconds=1), leaf='C')}
        _, _, t = self.run_cycle(options=options)
        self.assertEqual(t.call_args[0][1], 'B')

    def test_cross_ip_disabled_no_compatible_candidate(self):
        self.cfg['allow_cross_ip'] = False
        _, _, t = self.run_cycle(options={'B': dict(report(ip='198.51.100.2'), leaf='B')})
        t.assert_not_called()

    def test_concurrent_manual_change_during_evaluation_not_overwritten(self):
        self.state()
        def evaluate(*args, **kwargs):
            self.live['Choice']['now'] = 'C'
            return {'B': dict(report(), leaf='B')}, {}
        with mock.patch.object(guard.time, 'time', return_value=10000), mock.patch.object(self.g, 'business', return_value=report(False)), mock.patch.object(self.g, 'evaluate', side_effect=evaluate), mock.patch.object(self.g, 'transaction') as t:
            self.assertEqual(self.g.cycle(), 'changed')
        t.assert_not_called()

    def test_daily_attempt_budget_includes_failures(self):
        _, e, t = self.run_cycle(attempts=[5000, 8000])
        e.assert_not_called(); t.assert_not_called()

    def test_one_ip_sample_cannot_claim_same_exit(self):
        self.cfg['allow_cross_ip'] = False
        _, _, t = self.run_cycle(last_good=dict(ip='198.51.100.1', tested_at=9700, samples=1))
        t.assert_not_called()

    def test_stale_ip_cannot_claim_same_exit(self):
        self.cfg['allow_cross_ip'] = False
        _, _, t = self.run_cycle(last_good=dict(ip='198.51.100.1', tested_at=1000, samples=2))
        t.assert_not_called()

    def test_changed_ip_on_repeat_probe_respects_cross_ip_delay(self):
        self.cfg['cross_ip_failure_span_seconds'] = 300
        self.state()
        values = [({'B': dict(report(), leaf='B')}, {}), ({'B': dict(report(ip='198.51.100.2'), leaf='B')}, {})]
        with mock.patch.object(guard.time, 'time', return_value=10000), mock.patch.object(self.g, 'business', return_value=report(False)), mock.patch.object(self.g, 'evaluate', side_effect=values), mock.patch.object(self.g, 'transaction') as t:
            self.assertEqual(self.g.cycle(), 'ip-changed')
        t.assert_not_called()

    def test_healthy_resets_failure_streak(self):
        self.run_cycle(health=report())
        self.assertEqual(common.load_json(self.g.state_path, {})['failures'], [])

    def test_ambiguous_resets_failure_streak(self):
        self.run_cycle(health=report(False, switchable=False))
        self.assertEqual(common.load_json(self.g.state_path, {})['failures'], [])

    def test_journal_recheck_counts_only_one_failure(self):
        self.state(failures=[])
        with mock.patch.object(guard.time, 'time', return_value=10000), mock.patch.object(guard, 'journal', return_value=dict(errors=3, cursor_us=1, available=True)), mock.patch.object(self.g, 'business', return_value=report(False)) as business:
            self.g.cycle()
        self.assertEqual(business.call_count, 2)
        self.assertEqual(len(common.load_json(self.g.state_path, {})['failures']), 1)

    def test_journal_cannot_override_healthy_probe(self):
        with mock.patch.object(guard, 'journal', return_value=dict(errors=30, cursor_us=1, available=True)):
            _, e, t = self.run_cycle(health=report())
        e.assert_not_called(); t.assert_not_called()

    def test_cross_ip_scan_follows_longer_threshold(self):
        self.cfg['cross_ip_failure_span_seconds'] = 300
        self.run_cycle(options={'B': dict(report(ip='198.51.100.2'), leaf='B')})
        state = common.load_json(self.g.state_path, {})
        self.assertEqual(state['last_evaluation'] + self.cfg['evaluation_interval_seconds'], 10060)

    def test_profile_edit_resets_evidence(self):
        _, e, t = self.run_cycle(profile_hash='different')
        e.assert_not_called(); t.assert_not_called()

    def test_shared_mutation_lock_blocks_cycle_without_probe(self):
        with common.locked(self.cfg['mutation_lock']), mock.patch.object(self.g, 'business') as business:
            self.assertEqual(self.g.cycle(), 'busy')
        business.assert_not_called()


class TransactionTests(Base):
    def transaction(self, business=None):
        snap = self.g.snapshot()
        with mock.patch.object(self.g, 'business', return_value=business or report()):
            self.g.transaction(snap, 'B', {})

    def test_success_changes_one_selector_and_preserves_rules(self):
        self.transaction()
        self.assertEqual(self.live['Choice']['now'], 'B')
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(policy.parse(policy.read(self.path))['rules'], self.config['rules'])
        self.assertIsNone(common.load_json(self.g.state_path, {})['pending'])

    def test_failed_business_probe_rolls_back_once(self):
        with self.assertRaises(guard.Error): self.transaction(report(False))
        self.assertEqual(self.live['Choice']['now'], 'A')
        self.assertEqual(len(self.mutations()), 2)
        self.assertEqual(policy.read(self.path), self.text)

    def test_pending_written_before_put(self):
        original = self.g.set_choice
        def set_choice(*args):
            self.assertEqual(common.load_json(self.g.state_path, {})['pending']['target'], 'B')
            return original(*args)
        with mock.patch.object(self.g, 'set_choice', side_effect=set_choice): self.transaction()

    def test_wal_write_failure_never_mutates_live(self):
        with mock.patch.object(self.g, 'save', side_effect=OSError('disk full')):
            with self.assertRaises(OSError): self.transaction()
        self.assertFalse(self.mutations())

    def test_file_write_failure_rolls_back(self):
        with mock.patch.object(policy, 'atomic_write', side_effect=OSError('disk full')):
            with self.assertRaises(OSError): self.transaction()
        self.assertEqual(self.live['Choice']['now'], 'A')

    def test_lost_put_reply_rolls_back(self):
        original = self.g.set_choice
        def setter(snap, target):
            original(snap, target)
            if target == 'B': raise OSError('lost reply')
        with mock.patch.object(self.g, 'set_choice', side_effect=setter):
            with self.assertRaises(OSError): self.transaction()
        self.assertEqual(self.live['Choice']['now'], 'A')

    def test_failed_rollback_keeps_pending_and_logs_critical(self):
        original = self.g.set_choice
        def setter(snap, target):
            if target == 'A': raise OSError('controller gone')
            return original(snap, target)
        with mock.patch.object(self.g, 'set_choice', side_effect=setter):
            with self.assertRaises(guard.Error): self.transaction(report(False))
        self.assertIsNotNone(common.load_json(self.g.state_path, {})['pending'])
        self.assertIn('CRITICAL', self.output.getvalue())

    def test_sigterm_rolls_back(self):
        snap = self.g.snapshot()
        with mock.patch.object(self.g, 'business', side_effect=SystemExit(143)):
            with self.assertRaises(SystemExit): self.g.transaction(snap, 'B', {})
        self.assertEqual(self.live['Choice']['now'], 'A')

    def test_third_party_choice_not_overwritten(self):
        def business():
            self.live['Choice']['now'] = 'C'
            return report(False)
        with mock.patch.object(self.g, 'business', side_effect=business):
            with self.assertRaises(guard.Error): self.g.transaction(self.g.snapshot(), 'B', {})
        self.assertEqual(self.live['Choice']['now'], 'C')
        self.assertIsNotNone(common.load_json(self.g.state_path, {})['pending'])

    def test_corrupt_state_fails_closed(self):
        write(self.g.state_path, '{broken')
        with self.assertRaises(guard.Error): self.g.cycle()
        self.assertFalse(self.mutations())

    def test_ip_constraint_failure_rolls_back(self):
        snap = self.g.snapshot()
        with mock.patch.object(self.g, 'business', return_value=report(ip='198.51.100.2')):
            with self.assertRaises(guard.Error): self.g.transaction(snap, 'B', {}, required_ip='198.51.100.1')
        self.assertEqual(self.live['Choice']['now'], 'A')

    def test_failed_switch_consumes_attempt_and_cooldown(self):
        with self.assertRaises(guard.Error): self.transaction(report(False))
        state = common.load_json(self.g.state_path, {})
        self.assertEqual(len(state['attempts']), 1)
        self.assertGreater(state['last_attempt'], 0)

    def test_state_commit_failure_rolls_back_file_and_live(self):
        original = self.g.save
        calls = []
        def save(state):
            calls.append(1)
            if len(calls) == 2: raise OSError('disk full during commit')
            original(state)
        with mock.patch.object(self.g, 'save', side_effect=save):
            with self.assertRaises(OSError): self.transaction()
        self.assertEqual(policy.read(self.path), self.text)
        self.assertEqual(self.live['Choice']['now'], 'A')

    def test_third_party_file_edit_not_overwritten(self):
        def business():
            write(self.path, self.text + '\n# external edit\n')
            return report()
        with mock.patch.object(self.g, 'business', side_effect=business):
            with self.assertRaises(guard.Error): self.g.transaction(self.g.snapshot(), 'B', {})
        self.assertTrue(policy.read(self.path).endswith('# external edit\n'))
        self.assertIsNotNone(common.load_json(self.g.state_path, {})['pending'])

    def test_manual_cancel_never_changes_live(self):
        with mock.patch.object(self.g, 'evaluate', return_value=({'B': report()}, {})), mock.patch.object(common, 'confirmed', return_value=False):
            self.g.manual('B')
        self.assertFalse(self.mutations())

    def test_manual_uses_same_safety_transaction_and_hold(self):
        with mock.patch.object(self.g, 'evaluate', return_value=({'B': report()}, {})), mock.patch.object(common, 'confirmed', return_value=True), mock.patch.object(self.g, 'business', return_value=report()):
            self.g.manual('B')
        state = common.load_json(self.g.state_path, {})
        self.assertGreater(state['hold_until'], time.time())
        self.assertFalse(state.get('attempts'))

    def test_menu_cancel_no_probe_or_mutation(self):
        with mock.patch('sys.stdin.isatty', return_value=True), mock.patch('builtins.input', return_value='0'), mock.patch.object(self.g, 'evaluate') as evaluate:
            self.g.menu()
        evaluate.assert_not_called()
        self.assertFalse(self.mutations())

    def test_menu_evaluation_refreshes_without_switch(self):
        with mock.patch('sys.stdin.isatty', return_value=True), mock.patch('builtins.input', side_effect=['t', '0']), mock.patch.object(self.g, 'evaluate', return_value=({'B': report()}, {})) as evaluate:
            self.g.menu()
        evaluate.assert_called_once()
        self.assertTrue(os.path.isfile(os.path.join(self.cfg['state_dir'], 'probe.json')))
        self.assertFalse(self.mutations())

    def test_menu_eof_no_mutation(self):
        with mock.patch('sys.stdin.isatty', return_value=True), mock.patch('builtins.input', side_effect=EOFError()):
            with self.assertRaises(EOFError): self.g.menu()
        self.assertFalse(self.mutations())


class JournalTests(Base):
    def test_errors_are_domain_scoped_and_not_replayed(self):
        cfg = dict(self.cfg, journal_unit='clash.service', journal_domains=['chatgpt.com'])
        rows = [dict(__REALTIME_TIMESTAMP=str(i), MESSAGE=m) for i, m in [
            (1000000, 'level=warning chatgpt.com:443 error'),
            (2000000, 'level=info chatgpt.com:443'),
            (3000000, 'level=warning evilchatgpt.com:443 error'),
            (4000000, 'level=warning chatgpt.com:443 error'),
            (5000000, 'level=warning api.chatgpt.com:443 error')]]
        result = subprocess.CompletedProcess([], 0, '\n'.join(json.dumps(r) for r in rows), '')
        with mock.patch.object(guard.subprocess, 'run', return_value=result):
            actual = guard.journal(cfg, 1000000, 10)
            again = guard.journal(cfg, actual['cursor_us'], 10)
        self.assertEqual(actual['errors'], 2)
        self.assertEqual(again['errors'], 0)

    def test_missing_journal_is_not_network_failure(self):
        cfg = dict(self.cfg, journal_unit='clash.service')
        with mock.patch.object(guard.subprocess, 'run', side_effect=OSError()):
            self.assertFalse(guard.journal(cfg, 0, 10)['available'])




if __name__ == '__main__':
    unittest.main(verbosity=2)
