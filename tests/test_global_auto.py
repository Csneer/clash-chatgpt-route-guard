import copy
import os
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import global_auto as auto
import yaml


def node(name='A', server='a.example'):
    return {'name': name, 'type': 'ss', 'server': server, 'port': 2377,
            'cipher': 'aes-128-gcm', 'password': 'secret', 'plugin': 'obfs',
            'plugin-opts': {'mode': 'tls', 'host': 'transport.example'}}


class ConfigAndScriptTests(unittest.TestCase):
    def load_settings(self, changes=None, omit=()):
        with tempfile.TemporaryDirectory() as directory:
            values = dict(auto.DEFAULTS)
            for key in ('clash_config', 'binary', 'profile_script', 'profiles_index',
                        'controller_unix', 'state_dir', 'run_lock', 'mutation_lock', 'probe_lock'):
                values[key] = os.path.join(directory, key)
            values.update(changes or {})
            for key in omit:
                values.pop(key, None)
            path = os.path.join(directory, 'global-auto.yaml')
            with open(path, 'w', encoding='utf-8') as stream:
                yaml.safe_dump(values, stream)
            return auto.load_config(path)

    def test_load_config_accepts_tcp_controller(self):
        result = self.load_settings(dict(controller_tcp='127.0.0.1:9090', controller_unix=''))
        self.assertEqual(result['controller_tcp'], '127.0.0.1:9090')

    def test_legacy_config_defaults_to_verge_and_unix_controller(self):
        result = self.load_settings(omit=('config_source', 'controller_tcp'))
        self.assertEqual(result['config_source'], 'verge')
        self.assertEqual(result['controller_tcp'], '')
        self.assertTrue(os.path.isabs(result['controller_unix']))

    def test_static_config_needs_no_verge_profile_files(self):
        for controller in (dict(controller_tcp='127.0.0.1:9090', controller_unix=''),
                           dict(controller_tcp='', controller_unix='/run/test-controller.sock')):
            with self.subTest(controller=controller):
                result = self.load_settings(dict(config_source='static', **controller),
                                            omit=('profile_script', 'profiles_index'))
                self.assertEqual(result['profile_script'], '')
                self.assertEqual(result['profiles_index'], '')

    def test_verge_config_still_requires_profile_paths(self):
        for key in ('profile_script', 'profiles_index'):
            with self.subTest(key=key), self.assertRaises(auto.Error):
                self.load_settings(omit=(key,))

    def test_rejects_unknown_config_source(self):
        for source in ('desktop', '', None, []):
            with self.subTest(source=source), self.assertRaises(auto.Error):
                self.load_settings(dict(config_source=source))

    def test_tcp_controller_rejects_remote_credentials_and_url_components(self):
        for controller in ('192.0.2.1:9090', '0.0.0.0:9090', 'user:secret@127.0.0.1:9090',
                           '127.0.0.1:9090/path', '127.0.0.1:9090?query=1',
                           '127.0.0.1:9090#fragment', '127.0.0.1', '127.0.0.1:0',
                           '127.0.0.1:65536', '127.0.0.1:bad', None):
            with self.subTest(controller=controller), self.assertRaises(auto.Error):
                self.load_settings(dict(controller_tcp=controller))

    def test_static_config_still_requires_absolute_runtime_paths_and_controller(self):
        for key in ('clash_config', 'binary', 'state_dir', 'run_lock', 'mutation_lock',
                    'probe_lock', 'controller_unix'):
            with self.subTest(key=key), self.assertRaises(auto.Error):
                self.load_settings(dict(config_source='static', **{key: 'relative/path'}))
        with self.assertRaises(auto.Error):
            self.load_settings(dict(config_source='static', controller_tcp='', controller_unix=''))

    def test_rewrite_preserves_existing_chain_and_is_idempotent(self):
        source = 'function main(config) {\n  config.chain = true;\n  return config;\n}\n'
        result = auto.rewrite_script(source)
        self.assertIn('config.chain = true;', result)
        self.assertEqual(result.count(auto.BEGIN), 1)
        self.assertEqual(auto.rewrite_script(result), result)

    def test_eligible_excludes_chain_and_unsafe_nodes(self):
        self.assertTrue(auto.eligible(node()))
        for change in ({'name': 'Codex-ChatGPT-B2'}, {'dialer-proxy': 'FirstHop'},
                       {'type': 'trojan'}, {'plugin': 'v2ray-plugin'}):
            candidate = node()
            candidate.update(change)
            self.assertFalse(auto.eligible(candidate))


class ThresholdTests(unittest.TestCase):
    def setUp(self):
        self.cfg = dict(auto.DEFAULTS, improvement_ms=100)

    def report(self, tcp, score=None, ok=True):
        return {'ok': ok, 'tcp_ms': tcp, 'score_ms': score if score is not None else tcp}

    def test_active_preference_requires_at_least_100ms(self):
        current = self.report(180)
        self.assertFalse(auto.improvement(current, self.report(81), self.cfg))
        self.assertTrue(auto.improvement(current, self.report(79), self.cfg))

    def test_failure_recovery_does_not_require_latency_margin(self):
        current = self.report(180, ok=False)
        self.assertFalse(auto.improvement(current, self.report(1), self.cfg))


class LocalMeasureTests(unittest.TestCase):
    def test_relay_accepts_one_of_two_probe_endpoints(self):
        cfg = dict(auto.DEFAULTS, tcp_samples=3, sample_gap_seconds=0)
        n = node()
        tcp = {'tcp_ms': 50, 'jitter_ms': 5, 'tcp_samples': [50, 55, 48],
               'ok': True, 'score_ms': 52.5}
        responses = [dict(exit=0, code=204, seconds=.1),
                     dict(exit=28, code=0, seconds=5)]
        with patch.object(auto, 'tcp_quality', return_value=tcp), \
                patch.object(auto.common, 'fetch', side_effect=responses):
            result = auto.measure(n, cfg, 'http://127.0.0.1:1')
        self.assertTrue(result['ok'])
        self.assertFalse(result['stable'])
        self.assertEqual(result['reason'], 'unstable-relay')

    def test_high_jitter_is_not_stable_even_when_relay_works(self):
        cfg = dict(auto.DEFAULTS, tcp_samples=3, max_jitter_ms=100)
        tcp = {'tcp_ms': 100, 'jitter_ms': 400, 'max_tcp_ms': 300,
               'tcp_samples': [50, 100, 450], 'ok': True, 'score_ms': 300}
        responses = [dict(exit=0, code=204, seconds=.1), dict(exit=0, code=204, seconds=.1)]
        with patch.object(auto, 'tcp_quality', return_value=tcp), \
                patch.object(auto.common, 'fetch', side_effect=responses):
            result = auto.measure(node(), cfg, 'http://127.0.0.1:1')
        self.assertTrue(result['ok'])
        self.assertFalse(result['stable'])
        self.assertEqual(result['reason'], 'unstable-jitter')

    def test_one_dead_resolved_address_does_not_fail_node(self):
        cfg = dict(auto.DEFAULTS, tcp_samples=3, sample_gap_seconds=0)
        n = node()
        addresses = [(2, 1, 6, '', ('192.0.2.1', 2377)),
                     (2, 1, 6, '', ('192.0.2.2', 2377))]
        calls = []
        class Sock:
            def __init__(self, family, kind): pass
            def __enter__(self): return self
            def __exit__(self, *unused): pass
            def settimeout(self, value): pass
            def connect(self, address):
                calls.append(address)
                if address[0] == '192.0.2.1': raise OSError('dead family')
        with patch.object(auto, 'resolve_addresses', return_value=[(row[0], row[4]) for row in addresses]), \
                patch.object(auto.socket, 'socket', side_effect=lambda family, kind: Sock(family, kind)), \
                patch.object(auto.time, 'sleep'):
            result = auto.tcp_quality(n, cfg)
        self.assertTrue(result['ok'])
        self.assertEqual(len(calls), 5)

    def test_isolated_tcp_failure_still_proves_real_relay_availability(self):
        cfg = dict(auto.DEFAULTS, tcp_samples=3)
        tcp = {'tcp_ms': None, 'jitter_ms': None, 'max_tcp_ms': None,
               'tcp_samples': [None, None, None], 'ok': False, 'score_ms': None}
        with patch.object(auto, 'tcp_quality', return_value=tcp), \
                patch.object(auto.common, 'fetch', return_value=dict(exit=0, code=204)) as fetch, \
                patch.object(auto.common, 'ProbeProcess') as process:
            process.return_value.__enter__.return_value.proxy.return_value = 'http://127.0.0.1:1'
            result = auto.measure(node(), cfg)
        self.assertEqual(fetch.call_count, 2)
        process.assert_called_once()
        self.assertTrue(result['ok'])
        self.assertFalse(result['stable'])
        self.assertFalse(result['switchable'])
        self.assertEqual(result['reason'], 'unstable-tcp')
        self.assertEqual(auto.successful_relays(result), {0, 1})

    def test_isolated_tcp_failure_and_failed_relays_remain_unusable(self):
        tcp = dict(ok=False, tcp_ms=None, jitter_ms=None, max_tcp_ms=None,
                   tcp_samples=[None] * 3, score_ms=None)
        with patch.object(auto, 'tcp_quality', return_value=tcp), \
                patch.object(auto.common, 'fetch', return_value=dict(exit=28, code=0)), \
                patch.object(auto.common, 'ProbeProcess') as process:
            process.return_value.__enter__.return_value.proxy.return_value = 'http://127.0.0.1:1'
            result = auto.measure(node(), auto.DEFAULTS)
        self.assertFalse(result['ok'])
        self.assertTrue(result['switchable'])
        self.assertEqual(result['reason'], 'transport-failure')
        self.assertFalse(auto.recovery_usable(result))

    def test_partial_recovery_requires_actual_204_not_counters_or_arbitrary_http(self):
        unproven = dict(ok=True, stable=False, relay_successes=1, relay_total=2)
        self.assertFalse(auto.recovery_usable(unproven))
        for row in [dict(ok=True, curl_exit=0, code=403),
                    dict(ok=True, curl_exit=28, code=204),
                    dict(ok=False, curl_exit=0, code=204)]:
            self.assertFalse(auto.recovery_usable(dict(unproven, relay=[row])))
        valid = dict(unproven, relay=[dict(ok=True, curl_exit=0, code=204)])
        self.assertTrue(auto.recovery_usable(valid))

    def test_live_relay_success_overrides_partial_or_total_tcp_failure(self):
        cfg = dict(auto.DEFAULTS)
        proxy = 'http://127.0.0.1:1'
        for samples in ([50, None, 60], [None, None, None]):
            with self.subTest(samples=samples):
                tcp = dict(ok=False, tcp_samples=samples, tcp_ms=None,
                           jitter_ms=None, max_tcp_ms=None, score_ms=None)
                responses = [dict(exit=0, code=204)] * 2
                with patch.object(auto, 'tcp_quality', return_value=tcp), \
                        patch.object(auto.common, 'fetch', side_effect=responses) as fetch, \
                        patch.object(auto.common, 'ProbeProcess') as process:
                    result = auto.measure(node(), cfg, proxy)
                self.assertEqual(fetch.call_count, 2)
                self.assertEqual([call.args[0] for call in fetch.call_args_list], [proxy, proxy])
                process.assert_not_called()
                self.assertTrue(result['ok'])
                self.assertFalse(result['stable'])
                self.assertFalse(result['switchable'])
                self.assertEqual(result['reason'], 'unstable-tcp')
                self.assertEqual(result['relay_successes'], 2)
                self.assertIsNone(result['tcp_ms'])

    def test_live_tcp_failure_still_measures_relay_network_failure(self):
        cfg = dict(auto.DEFAULTS)
        tcp = dict(ok=False, tcp_samples=[None] * 3, tcp_ms=None,
                   jitter_ms=None, max_tcp_ms=None, score_ms=None)
        with patch.object(auto, 'tcp_quality', return_value=tcp), \
                patch.object(auto.common, 'fetch', side_effect=[
                    dict(exit=28, code=0), dict(exit=35, code=0)]) as fetch:
            result = auto.measure(node(), cfg, 'http://127.0.0.1:1')
        self.assertEqual(fetch.call_count, 2)
        self.assertFalse(result['ok'])
        self.assertFalse(result['stable'])
        self.assertTrue(result['switchable'])
        self.assertEqual(result['reason'], 'transport-failure')
        self.assertEqual(result['relay_successes'], 0)

    def test_live_tcp_failure_does_not_turn_endpoint_response_into_transport_failure(self):
        cfg = dict(auto.DEFAULTS)
        tcp = dict(ok=False, tcp_samples=[None] * 3, tcp_ms=None,
                   jitter_ms=None, max_tcp_ms=None, score_ms=None)
        with patch.object(auto, 'tcp_quality', return_value=tcp), \
                patch.object(auto.common, 'fetch', return_value=dict(exit=0, code=403)) as fetch:
            result = auto.measure(node(), cfg, 'http://127.0.0.1:1')
        self.assertEqual(fetch.call_count, 2)
        self.assertFalse(result['ok'])
        self.assertFalse(result['stable'])
        self.assertFalse(result['switchable'])
        self.assertEqual(result['reason'], 'endpoint-response')



def quality(ms=200, *, ok=True, switchable=False, score=None):
    return dict(ok=ok, switchable=switchable, tcp_ms=ms, score_ms=ms if score is None else score,
                jitter_ms=0, max_tcp_ms=ms, tcp_samples=[ms] * 3, relay=[],
                stable=ok, reason='healthy' if ok else 'tcp-failure')


class AutoCycleTests(unittest.TestCase):
    """Persistent decision loop with controlled probes and controller mutations."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = dict(auto.DEFAULTS, state_dir=self.tmp.name,
                        mutation_lock=self.tmp.name + '/mutation.lock',
                        probe_lock=self.tmp.name + '/probe.lock')
        self.agent = auto.Auto(self.cfg)
        self.now = 100000
        self.selected, self.generation = 'A', 'generation-1'
        self.mode, self.global_selection = 'global', self.cfg['group']
        self.reports = {'A': quality(200), 'B': quality(100)}
        self.probes, self.writes = [], []
        self.patch(auto.time, 'time', side_effect=lambda: self.now)
        self.patch(self.agent, 'snapshot', side_effect=self.snapshot)
        self.patch(self.agent, 'probe', side_effect=self.probe)
        self.patch(auto.policy, 'api', side_effect=self.api)
        self.agent.save(dict(active=True, token=self.snapshot()['token'], selected='A',
                             failures=0, last_scan=0, last_check=0, hold_until=0))
        state = self.agent.state()
        for at in (self.now - 180, self.now - 120, self.now - 60):
            with patch.object(auto.time, 'time', return_value=at):
                for name, report in self.reports.items():
                    self.agent.record(state, self.snapshot(), name, report)
        self.agent.save(state)

    def patch(self, obj, key, **kwargs):
        patcher = patch.object(obj, key, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def snapshot(self):
        active = self.mode == 'global' and self.global_selection == self.cfg['group']
        return dict(active=active,
                    mode=self.mode, global_selection=self.global_selection, selected=self.selected,
                    generation=self.generation, token=self.generation + ':' + self.selected if active else None,
                    api={}, nodes={name: node(name) for name in self.reports})

    def probe(self, snap, name, live=False):
        self.probes.append((name, live))
        value = self.reports[name]
        if callable(value):
            return value(live)
        return copy.deepcopy(value)

    def api(self, cfg, path, method='GET', body=None):
        self.writes.append((path, method, body))
        self.assertEqual(path, '/proxies/GLOBAL%20Stable%20Auto')
        self.assertEqual(method, 'PUT')
        self.selected = body['name']
        return {}

    def tick(self, seconds=30):
        self.now += seconds
        return self.agent.cycle()

    @staticmethod
    def relay_report(*successful, ms=160):
        rows = [dict(ok=i in successful, curl_exit=0 if i in successful else 28,
                     code=204 if i in successful else 0) for i in range(2)]
        return dict(quality(ms, ok=bool(successful), switchable=not successful),
                    stable=len(successful) == 2, relay=rows,
                    relay_successes=len(successful), relay_total=2,
                    reason='healthy' if len(successful) == 2 else
                           'unstable-relay' if successful else 'transport-failure')

    def cache_report(self, name, report):
        state = self.agent.state()
        self.agent.record(state, self.snapshot(), name, report)
        self.agent.save(state)

    def test_99ms_improvement_keeps_current(self):
        self.reports['B'] = quality(101)
        self.assertEqual(self.tick()['action'], 'below-improvement-threshold')
        self.assertEqual(self.writes, [])

    def test_exactly_100ms_improvement_switches_only_managed_group(self):
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertEqual(self.selected, 'B')
        self.assertEqual(self.writes, [('/proxies/GLOBAL%20Stable%20Auto', 'PUT', {'name': 'B'})])
        self.assertEqual(self.probes.count(('B', False)), 2)
        self.assertIn(('B', True), self.probes)
        state = self.agent.state()
        self.assertIsNone(state['pending'])
        self.assertEqual(state['last_change']['reason'], 'latency')

    def test_lower_latency_with_worse_jitter_score_does_not_switch(self):
        self.reports['B'] = quality(100, score=201)
        self.assertEqual(self.tick()['action'], 'below-improvement-threshold')
        self.assertEqual(self.writes, [])

    def test_three_stability_degradations_trigger_scan_but_only_stable_candidate_is_allowed(self):
        self.cfg['stability_failure_count'] = 2
        self.reports['A'] = quality(200, score=300)
        self.reports['A'].update(ok=True, stable=False, reason='unstable-jitter', jitter_ms=500)
        self.reports['B'] = quality(180, score=200)
        self.assertEqual(self.tick()['action'], 'stability-confirming')
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertEqual(self.agent.state()['last_change']['reason'], 'stability')

    def test_two_failures_switch_to_slower_working_node_without_100ms_margin(self):
        self.reports['A'] = quality(50, ok=False, switchable=True)
        self.reports['B'] = quality(200)
        self.assertEqual(self.tick()['action'], 'failure-confirming')
        self.assertEqual(self.writes, [])
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertEqual(self.agent.state()['last_change']['reason'], 'failure')

    def test_failed_node_cannot_immediately_return_even_after_recovery(self):
        self.reports['A'] = quality(50, ok=False, switchable=True)
        self.reports['B'] = quality(200)
        self.tick()
        self.assertEqual(self.tick()['action'], 'switched')
        self.reports['A'] = quality(1)
        self.reports['B'] = quality(200, ok=False, switchable=True)
        self.assertEqual(self.tick()['action'], 'failure-confirming')
        self.probes.clear()
        self.assertEqual(self.tick()['action'], 'no-candidate')
        self.assertNotIn(('A', False), self.probes)
        self.assertEqual(len(self.writes), 1)

    def test_repeated_candidate_failure_does_not_switch(self):
        reports = iter([quality(100), quality(100, ok=False, switchable=True)])
        self.reports['B'] = lambda live: next(reports)
        self.assertEqual(self.tick()['action'], 'candidate-unstable')
        self.assertEqual(self.writes, [])
        self.assertGreater(self.agent.state()['nodes']['B']['cooldown_until'], self.now)

    def test_failure_tries_next_candidate_after_fastest_repeat_fails(self):
        # This case exercises newly discovered candidates, with no cached backup.
        state = self.agent.state()
        state['nodes'].pop('B')
        self.agent.save(state)
        self.reports['A'] = quality(50, ok=False, switchable=True)
        reports = iter([quality(100), quality(100, ok=False, switchable=True)])
        self.reports['B'] = lambda live: next(reports)
        self.reports['C'] = quality(200)
        self.assertEqual(self.tick()['action'], 'failure-confirming')
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertEqual(self.selected, 'C')
        self.assertEqual([call[2]['name'] for call in self.writes], ['C'])
        self.assertGreater(self.agent.state()['nodes']['B']['cooldown_until'], self.now)

    def test_candidate_repeat_error_does_not_hide_next_working_candidate(self):
        # This case exercises newly discovered candidates, with no cached backup.
        state = self.agent.state()
        state['nodes'].pop('B')
        self.agent.save(state)
        self.reports['A'] = quality(50, ok=False, switchable=True)
        calls = []
        def unavailable(live):
            calls.append(live)
            if len(calls) > 1:
                raise OSError('isolated probe unavailable')
            return quality(100)
        self.reports.update(B=unavailable, C=quality(200))
        self.tick()
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertEqual(self.selected, 'C')

    def test_cached_candidate_process_timeout_does_not_hide_working_backup(self):
        self.reports.update(A=quality(50, ok=False, switchable=True), C=quality(200))
        state, snap = self.agent.state(), self.snapshot()
        self.agent.record(state, snap, 'B', quality(100))
        self.agent.record(state, snap, 'C', quality(200))
        self.agent.save(state)

        def timeout(live):
            raise subprocess.TimeoutExpired(['mihomo', '-t'], 15)

        self.reports['B'] = timeout
        self.assertEqual(self.tick()['action'], 'failure-confirming')
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertEqual(self.selected, 'C')
        self.assertEqual([write[2]['name'] for write in self.writes], ['C'])
        state = self.agent.state()
        self.assertEqual([row['name'] for row in state['evaluation']['rechecks']], ['B', 'C'])
        self.assertEqual(state['nodes']['B']['reason'], 'probe-timeout')
        self.assertFalse(state['nodes']['B']['ok'])
        self.assertFalse(state['nodes']['B']['stable'])
        self.assertGreater(state['nodes']['B']['cooldown_until'], self.now)

    def test_inventory_process_timeout_is_recorded_without_losing_other_results(self):
        def timeout(live):
            raise subprocess.TimeoutExpired(['mihomo', '-t'], 15)

        self.reports.update(B=timeout, C=quality(200))
        state, snap = self.agent.state(), self.snapshot()
        self.assertTrue(state['nodes']['B']['ok'])
        results = self.agent.scan(snap, state)
        self.assertEqual(set(results), {'B', 'C'})
        self.assertEqual(results['B']['reason'], 'probe-timeout')
        self.assertFalse(results['B']['ok'])
        self.assertTrue(results['C']['ok'])
        state = self.agent.state()
        self.assertEqual(state['evaluation']['stable_candidates'], ['C'])
        self.assertEqual(state['evaluation']['usable_candidates'], ['C'])
        self.assertEqual(state['nodes']['B']['reason'], 'probe-timeout')
        self.assertFalse(state['nodes']['B']['ok'])
        self.assertGreater(state['nodes']['B']['cooldown_until'], self.now)
        self.assertEqual(self.writes, [])

    def test_candidate_rechecks_are_bounded(self):
        # This case exercises newly discovered candidates, with no cached backup.
        state = self.agent.state()
        state['nodes'].pop('B')
        self.agent.save(state)
        self.reports['A'] = quality(50, ok=False, switchable=True)
        self.cfg['candidate_rechecks'] = 3
        for name, delay in [('B', 100), ('C', 200), ('D', 300)]:
            reports = iter([quality(delay), quality(delay, ok=False, switchable=True)])
            self.reports[name] = lambda live, reports=reports: next(reports)
        self.reports['E'] = quality(400)
        self.tick()
        self.assertEqual(self.tick()['action'], 'candidate-unstable')
        self.assertEqual(self.probes.count(('E', False)), 1)
        self.assertEqual(len(self.agent.state()['evaluation']['rechecks']), 3)
        self.assertEqual(self.writes, [])

    def test_manual_change_during_failed_repeat_stops_further_probes(self):
        # This case exercises newly discovered candidates, with no cached backup.
        state = self.agent.state()
        state['nodes'].pop('B')
        self.agent.save(state)
        self.reports['A'] = quality(50, ok=False, switchable=True)
        calls = []
        def changed(live):
            calls.append(live)
            if len(calls) > 1:
                self.global_selection = 'DIRECT'
                return quality(100, ok=False, switchable=True)
            return quality(100)
        self.reports.update(B=changed, C=quality(200))
        self.tick()
        self.assertEqual(self.tick()['action'], 'selection-changed')
        self.assertEqual(self.probes.count(('C', False)), 1)
        self.assertEqual(self.writes, [])

    def test_failure_scan_prioritizes_recent_good_nodes_and_advances_rotation(self):
        self.cfg['batch_size'] = 2
        self.reports.update(C=quality(200), D=quality(300), E=quality(400))
        state, snap = self.agent.state(), self.snapshot()
        self.agent.record(state, snap, 'E', quality(400))
        self.agent.save(state)
        self.agent.scan(snap, state, recovery=True)
        self.assertEqual(set(name for name, _ in self.probes), {'B', 'E'})
        self.assertEqual(state['cursor'], 1)

    def test_failure_priority_respects_cooldown_age_and_identity(self):
        self.cfg['batch_size'] = 2
        self.reports.update(C=quality(200), D=quality(300), E=quality(400))
        for change in ('cooldown', 'stale', 'identity'):
            with self.subTest(change=change):
                state, snap = self.agent.state(), self.snapshot()
                self.agent.record(state, snap, 'E', quality(400))
                row = state['nodes']['E']
                if change == 'cooldown': row['cooldown_until'] = self.now + 600
                if change == 'stale': row['at'] = self.now - 1201
                if change == 'identity': row['identity'] = 'old-subscription'
                state['cursor'] = 0
                self.probes.clear()
                self.agent.scan(snap, state, recovery=True)
                self.assertEqual(set(name for name, _ in self.probes), {'B', 'C'})

    def test_no_stable_candidates_is_not_reported_as_latency_threshold(self):
        self.cfg['stability_failure_count'] = 2
        unstable = dict(quality(), stable=False, reason='unstable-jitter', jitter_ms=1000)
        self.reports = {'A': unstable, 'B': unstable}
        self.tick()
        self.assertEqual(self.tick()['action'], 'no-stable-candidate')

    def test_failed_postcheck_preserves_outage_confirmation_after_rollback(self):
        self.reports['A'] = quality(50, ok=False, switchable=True)
        self.reports['B'] = lambda live: quality(100, ok=not live, switchable=live)
        self.tick()
        self.assertEqual(self.tick()['action'], 'rolled-back')
        self.assertEqual(self.agent.state()['failures'], 2)

    def test_full_transport_recovery_with_postcheck_jitter_does_not_return_to_dead_node(self):
        self.cache_report('B', self.relay_report(0, 1))
        self.reports['A'] = quality(50, ok=False, switchable=True)
        def measured(live):
            result = self.relay_report(0, 1)
            if live:
                result.update(stable=False, reason='unstable-jitter', jitter_ms=1030,
                              max_tcp_ms=1190, relay_successes=2, relay_total=2)
            return result
        self.reports['B'] = measured
        self.tick()
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertEqual([w[2]['name'] for w in self.writes], ['B'])
        state = self.agent.state()
        self.assertEqual(state['stability_failures'], 1)
        self.assertEqual(state['failures'], 0)
        self.assertFalse(state['current']['stable'])
        self.assertEqual(state['evaluation']['postcheck']['reason'], 'unstable-jitter')
        self.assertIsNone(state['pending'])

    def test_failure_postcheck_tcp_loss_with_complete_relay_keeps_new_node(self):
        self.cache_report('B', self.relay_report(0, 1))
        self.reports['A'] = quality(ok=False, switchable=True)
        self.reports['B'] = lambda live: (dict(self.relay_report(0, 1), stable=False, reason='unstable-tcp',
            tcp_ms=None, score_ms=None) if live else self.relay_report(0, 1))
        self.tick()
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertEqual([w[2]['name'] for w in self.writes], ['B'])
        self.assertEqual(self.agent.state()['last_change']['reason'], 'failure')

    def test_mixed_window_current_hard_failure_uses_transport_recovery(self):
        self.reports['B'] = self.relay_report(0, 1)
        self.cache_report('B', self.reports['B'])
        self.reports['A'] = quality(ok=False, switchable=True)
        self.tick()
        self.reports['A'] = dict(quality(), stable=False, reason='unstable-jitter')
        self.tick()
        self.reports['A'] = quality(ok=False, switchable=True)
        self.reports['B'] = lambda live: (dict(self.relay_report(0, 1), stable=False, reason='unstable-tcp',
            tcp_ms=None, score_ms=None) if live else self.relay_report(0, 1))
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertEqual(self.agent.state()['last_change']['reason'], 'failure')
        self.assertEqual([w[2]['name'] for w in self.writes], ['B'])

    def test_quality_and_latency_switches_reject_unstable_tcp_postcheck(self):
        for reason in ('stability', 'latency'):
            with self.subTest(reason=reason):
                self.reports['B'] = dict(quality(), stable=False, reason='unstable-tcp',
                                        tcp_ms=None, score_ms=None, relay_successes=2, relay_total=2)
                result = self.agent.switch(self.snapshot(), 'B', self.agent.state(), reason)
                self.assertEqual(result, 'rolled-back')
                self.assertEqual(self.selected, 'A')

    def test_partial_relay_recovery_still_rolls_back(self):
        self.reports['A'] = quality(50, ok=False, switchable=True)
        def measured(live):
            result = quality(160)
            if live:
                result.update(stable=False, reason='unstable-relay', relay_successes=1, relay_total=2)
            return result
        self.reports['B'] = measured
        self.tick()
        self.assertEqual(self.tick()['action'], 'rolled-back')
        self.assertEqual(self.selected, 'A')

    def test_hard_outage_uses_cooling_partial_with_same_endpoint_three_times(self):
        self.reports['A'] = quality(ok=False, switchable=True)
        self.reports['B'] = self.relay_report(0)
        self.cache_report('B', self.reports['B'])
        self.tick()
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertEqual(self.selected, 'B')
        self.assertEqual([w[2]['name'] for w in self.writes], ['B'])
        self.assertEqual(self.agent.state()['stability_failures'], 1)

    def test_legacy_cache_cannot_prove_partial_recovery_until_next_real_observation(self):
        self.reports['A'] = quality(ok=False, switchable=True)
        self.reports['B'] = self.relay_report(0)
        # setUp cached only legacy stable quality, with no actual endpoint evidence.
        self.assertEqual(self.agent.state()['nodes']['B']['relay'], [])
        self.assertEqual(self.tick()['action'], 'failure-confirming')
        self.assertEqual(self.tick()['action'], 'candidate-unstable')
        self.assertEqual(self.writes, [])
        self.assertEqual(self.probes.count(('B', False)), 1)
        # The failed decision retained its genuine partial observation. It can
        # serve as the initial endpoint evidence for a later independent repeat.
        self.assertEqual(self.tick(60)['action'], 'switched')
        self.assertEqual(self.probes.count(('B', False)), 2)
        self.assertEqual(self.probes.count(('B', True)), 1)
        self.assertEqual([w[2]['name'] for w in self.writes], ['B'])

    def test_hard_outage_rejects_alternating_isolated_endpoints(self):
        self.reports['A'] = quality(ok=False, switchable=True)
        self.cache_report('B', self.relay_report(0))
        self.reports['B'] = self.relay_report(1)
        self.tick()
        self.assertEqual(self.tick()['action'], 'candidate-unstable')
        self.assertEqual(self.writes, [])

    def test_hard_outage_postcheck_requires_previously_verified_endpoint(self):
        for successful in ((), (1,)):
            with self.subTest(successful=successful):
                self.reports['A'] = quality(ok=False, switchable=True)
                self.cache_report('B', self.relay_report(0))
                self.reports['B'] = lambda live: self.relay_report(*successful) if live else self.relay_report(0)
                self.tick(60)
                self.assertEqual(self.tick(60)['action'], 'rolled-back')
                self.assertEqual(self.selected, 'A')
                self.assertIsNone(self.agent.state()['pending'])
                self.assertEqual([w[2]['name'] for w in self.writes[-2:]], ['B', 'A'])
                state = self.agent.state()
                state.update(failures=0, health_window=[], degradation_confirmed=False)
                self.agent.save(state)

    def test_hard_outage_partial_lost_put_keeps_pending_and_stops(self):
        self.reports['A'] = quality(ok=False, switchable=True)
        self.reports['B'] = self.relay_report(0)
        self.cache_report('B', self.reports['B'])
        def lost(*args, **kwargs):
            self.api(*args, **kwargs)
            raise OSError('lost reply')
        auto.policy.api.side_effect = lost
        self.tick()
        with self.assertRaises(OSError):
            self.tick()
        self.assertEqual(self.agent.state()['pending']['target'], 'B')
        self.assertEqual(self.tick()['action'], 'pending-review')
        self.assertEqual(len(self.writes), 1)

    def test_quality_degradation_does_not_use_partial_candidate(self):
        self.cfg['stability_failure_count'] = 2
        self.reports['A'] = dict(quality(), stable=False, reason='unstable-jitter')
        self.reports['B'] = self.relay_report(0)
        self.cache_report('B', self.reports['B'])
        self.tick()
        self.assertEqual(self.tick()['action'], 'no-stable-candidate')
        self.assertEqual(self.writes, [])

    def test_hard_outage_does_not_accept_ok_without_real_relay_evidence(self):
        self.reports['A'] = quality(ok=False, switchable=True)
        self.reports['B'] = dict(quality(), stable=False, reason='unstable-relay')
        self.cache_report('B', self.reports['B'])
        self.tick()
        self.assertEqual(self.tick()['action'], 'no-stable-candidate')
        self.assertEqual(self.writes, [])

    def test_hard_outage_prefers_stable_over_faster_partial_candidate(self):
        self.reports['A'] = quality(ok=False, switchable=True)
        self.reports['B'] = self.relay_report(0, ms=1)
        self.reports['C'] = self.relay_report(0, 1, ms=200)
        self.cache_report('B', self.reports['B'])
        self.cache_report('C', self.reports['C'])
        self.tick()
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertEqual(self.selected, 'C')
        self.assertNotIn(('B', False), self.probes)

    def test_latency_switch_with_postcheck_jitter_still_rolls_back(self):
        def measured(live):
            result = quality(100)
            if live:
                result.update(stable=False, reason='unstable-jitter', jitter_ms=1030,
                              max_tcp_ms=1130, relay_successes=2, relay_total=2)
            return result
        self.reports['B'] = measured
        self.assertEqual(self.tick()['action'], 'rolled-back')
        self.assertEqual(self.selected, 'A')

    def test_repeated_candidate_must_still_meet_threshold(self):
        reports = iter([quality(100), quality(101)])
        self.reports['B'] = lambda live: next(reports)
        self.assertEqual(self.tick()['action'], 'below-improvement-threshold')
        self.assertEqual(self.writes, [])

    def test_all_candidates_fail_keeps_current(self):
        self.reports = {name: quality(ok=False, switchable=True) for name in ('A', 'B')}
        self.tick()
        self.assertEqual(self.tick()['action'], 'candidate-unstable')
        self.assertEqual(self.selected, 'A')
        self.assertEqual(self.writes, [])

    def test_inactive_modes_and_other_global_selection_never_probe_or_write(self):
        for mode, selection in [('rule', self.cfg['group']), ('direct', self.cfg['group']),
                                ('global', 'A'), ('global', 'DIRECT')]:
            with self.subTest(mode=mode, selection=selection):
                self.mode, self.global_selection = mode, selection
                self.assertEqual(self.tick()['action'], 'inactive')
        self.assertEqual(self.probes, [])
        self.assertEqual(self.writes, [])

    def test_manual_selection_during_probe_aborts(self):
        def changed(live):
            self.selected = 'B'
            return quality(200)
        self.reports['A'] = changed
        self.assertEqual(self.tick()['action'], 'selection-changed')
        self.assertEqual(self.writes, [])

    def test_config_change_during_candidate_scan_aborts(self):
        def changed(live):
            self.generation = 'generation-2'
            return quality(100)
        self.reports['B'] = changed
        self.assertEqual(self.tick()['action'], 'selection-changed')
        self.assertEqual(self.writes, [])

    def test_snapshot_change_just_before_switch_aborts(self):
        snap = self.snapshot()
        self.generation = 'changed'
        self.assertEqual(self.agent.switch(snap, 'B', self.agent.state(), 'latency'), 'selection-changed')
        self.assertEqual(self.writes, [])
        self.assertNotIn('pending', self.agent.state())

    def test_ambiguous_endpoint_failure_does_not_trigger_failover(self):
        self.reports['A'] = quality(ok=False, switchable=False)
        for _ in range(3):
            self.assertEqual(self.tick()['action'], 'ambiguous-response')
        self.assertEqual(self.writes, [])
        self.assertEqual(self.agent.state()['failures'], 0)

    def test_same_round_recovery_does_not_clear_confirmed_failure(self):
        reports = iter([quality(ok=False, switchable=True), quality(ok=False, switchable=True), quality()])
        self.reports['A'] = lambda live: next(reports)
        self.tick()
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertEqual(self.selected, 'B')

    def test_mixed_failures_in_short_window_trigger_switch(self):
        self.reports['A'] = quality(ok=False, switchable=True)
        self.assertEqual(self.tick()['action'], 'failure-confirming')
        self.reports['A'] = dict(quality(), stable=False, reason='unstable-tcp')
        self.assertEqual(self.tick()['action'], 'stability-confirming')
        self.reports['A'] = quality(ok=False, switchable=True)
        self.assertEqual(self.tick()['action'], 'switched')

    def test_one_success_does_not_erase_mixed_bad_samples(self):
        self.reports['B'] = quality(150)
        self.reports['A'] = quality(ok=False, switchable=True)
        self.tick()
        self.reports['A'] = quality()
        self.tick()
        self.reports['A'] = dict(quality(), stable=False, reason='unstable-jitter')
        self.tick()
        self.reports['A'] = quality(ok=False, switchable=True)
        self.assertEqual(self.tick()['action'], 'switched')

    def test_expired_bad_samples_do_not_confirm_degradation(self):
        self.reports['A'] = quality(ok=False, switchable=True)
        self.tick()
        self.reports['A'] = dict(quality(), stable=False, reason='unstable-jitter')
        self.tick()
        self.reports['A'] = quality(ok=False, switchable=True)
        self.assertEqual(self.tick(301)['action'], 'failure-confirming')
        self.assertFalse(self.agent.state()['degradation_confirmed'])

    def test_expired_consecutive_failure_does_not_count_as_fast_recovery(self):
        self.reports['A'] = quality(ok=False, switchable=True)
        self.tick()
        self.assertEqual(self.tick(301)['action'], 'failure-confirming')
        self.assertEqual(self.agent.state()['failures'], 1)

    def test_health_window_is_bounded_to_six_scheduled_samples(self):
        self.reports['A'] = quality(ok=False, switchable=False)
        for _ in range(8):
            self.tick()
        self.assertEqual(len(self.agent.state()['health_window']), 6)
        self.assertFalse(self.agent.state()['degradation_confirmed'])

    def test_inactive_mode_clears_confirmed_health_evidence(self):
        state = self.agent.state()
        state.update(degradation_confirmed=True, recovery_samples=1,
                     health_window=[dict(at=self.now, bad=True)])
        self.agent.save(state)
        self.mode = 'rule'
        self.assertEqual(self.tick()['action'], 'inactive')
        state = self.agent.state()
        self.assertFalse(state['degradation_confirmed'])
        self.assertEqual(state['health_window'], [])
        self.assertEqual(state['recovery_samples'], 0)

    def test_two_separate_stable_samples_clear_confirmed_failure(self):
        self.reports['B'] = quality(ok=False, switchable=True)
        self.reports['A'] = quality(ok=False, switchable=True)
        self.tick()
        self.assertEqual(self.tick()['action'], 'candidate-unstable')
        self.reports['A'] = quality()
        self.assertEqual(self.tick()['action'], 'recovery-confirming')
        self.assertTrue(self.agent.state()['degradation_confirmed'])
        self.tick()
        self.assertFalse(self.agent.state()['degradation_confirmed'])
        self.assertEqual(self.agent.state()['health_window'], [])

    def test_generation_and_manual_changes_clear_failure_evidence(self):
        for change in ('generation', 'manual'):
            with self.subTest(change=change):
                state = self.agent.state()
                state.update(degradation_confirmed=True, recovery_samples=1,
                             health_window=[dict(at=self.now, bad=True)], failures=1)
                self.agent.save(state)
                if change == 'generation':
                    self.generation += '-new'
                else:
                    self.selected = 'B'
                self.reports[self.selected] = quality(ok=False, switchable=True)
                self.assertEqual(self.tick()['action'], 'failure-confirming')
                self.assertFalse(self.agent.state()['degradation_confirmed'])
                self.assertEqual(len(self.agent.state()['health_window']), 1)
                self.assertEqual(self.agent.state()['recovery_samples'], 0)

    def test_post_switch_failure_rolls_back_and_cools_down_candidate(self):
        self.reports['B'] = lambda live: quality(100, ok=not live, switchable=live)
        self.assertEqual(self.tick()['action'], 'rolled-back')
        self.assertEqual(self.selected, 'A')
        self.assertEqual([call[2]['name'] for call in self.writes], ['B', 'A'])
        state = self.agent.state()
        self.assertIsNone(state['pending'])
        self.assertGreater(state['nodes']['B']['cooldown_until'], self.now)

    def test_lost_controller_reply_retains_pending_and_never_blind_retries(self):
        def lost_reply(*args, **kwargs):
            self.api(*args, **kwargs)
            raise OSError('controller response lost')
        auto.policy.api.side_effect = lost_reply
        with self.assertRaises(OSError):
            self.tick()
        self.assertEqual(self.selected, 'B')
        self.assertEqual(self.agent.state()['pending']['target'], 'B')
        self.probes.clear()
        self.assertEqual(self.tick()['action'], 'pending-review')
        self.assertEqual(self.probes, [])
        self.assertEqual(len(self.writes), 1)

    def test_manual_change_after_put_retains_pending_without_rollback(self):
        def changed(*args, **kwargs):
            self.api(*args, **kwargs)
            self.global_selection = 'DIRECT'
        auto.policy.api.side_effect = changed
        self.assertEqual(self.tick()['action'], 'pending-selection-changed')
        self.assertIsNotNone(self.agent.state()['pending'])
        self.assertEqual(len(self.writes), 1)

    def test_uncertain_rollback_retains_pending(self):
        self.reports['B'] = lambda live: quality(100, ok=not live, switchable=live)
        def changed(*args, **kwargs):
            self.api(*args, **kwargs)
            if len(self.writes) == 2:
                self.generation = 'changed-during-rollback'
        auto.policy.api.side_effect = changed
        self.assertEqual(self.tick()['action'], 'pending-rollback-uncertain')
        self.assertIsNotNone(self.agent.state()['pending'])


class RealTcpTests(unittest.TestCase):
    def test_loopback_tcp_handshakes_and_closed_port_failure(self):
        cfg = dict(auto.DEFAULTS, tcp_samples=3, tcp_timeout_seconds=1)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(8)
            target = node(server='127.0.0.1')
            target['port'] = listener.getsockname()[1]
            measured = auto.tcp_quality(target, cfg)
            self.assertTrue(measured['ok'])
            self.assertEqual(len(measured['tcp_samples']), 3)
            self.assertTrue(all(ms >= 0 for ms in measured['tcp_samples']))
            self.assertGreaterEqual(measured['score_ms'], measured['tcp_ms'])
        measured = auto.tcp_quality(target, cfg)
        self.assertFalse(measured['ok'])
        self.assertEqual(measured['tcp_samples'], [None] * 3)
        self.assertIsNone(measured['tcp_ms'])


if __name__ == '__main__':
    unittest.main()
