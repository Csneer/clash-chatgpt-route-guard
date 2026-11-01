"""Disposable Mihomo controller/persistence regression; no external network probes."""
import os
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
from unittest.mock import patch

import yaml
import global_auto as auto
import mihomo_policy as policy


MIHOMO_BINARY = os.environ.get('MIHOMO_BINARY', '/usr/bin/verge-mihomo')


@unittest.skipUnless(os.path.isfile(MIHOMO_BINARY), 'set MIHOMO_BINARY for native selector tests')
class GlobalAutoNativeTests(unittest.TestCase):
    config_source = 'verge'

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='global-auto-native-')
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.process = None
        self.addCleanup(self.stop)
        reservation = socket.socket()
        self.addCleanup(reservation.close)
        reservation.bind(('127.0.0.1', 0))
        self.port = reservation.getsockname()[1]
        self.config = {
            'mode': 'global', 'mixed-port': self.port, 'allow-lan': False,
            'bind-address': '127.0.0.1', 'external-controller': '',
            'external-controller-unix': self.root + '/controller.sock',
            'ipv6': False, 'log-level': 'silent', 'geo-auto-update': False,
            'dns': {'enable': False}, 'tun': {'enable': False},
            'profile': {'store-selected': True},
            'proxies': [dict(name=name, type='ss', server='127.0.0.1', port=1,
                             cipher='aes-128-gcm', password='local-test-password')
                        for name in ('A', 'B', 'C')],
            'proxy-groups': [
                {'name': 'GLOBAL Stable Auto', 'type': 'select', 'proxies': ['A', 'B', 'C'],
                 'interrupt-exist-connections': False},
                {'name': 'Unrelated', 'type': 'select', 'proxies': ['A', 'B']},
                {'name': 'Codex-ChatGPT-Chain', 'type': 'select', 'proxies': ['B', 'A']}],
            'rules': ['MATCH,REJECT']}
        if self.config_source == 'static':
            controller = socket.socket()
            self.addCleanup(controller.close)
            controller.bind(('127.0.0.1', 0))
            self.config['external-controller'] = '127.0.0.1:' + str(controller.getsockname()[1])
            self.config['secret'] = 'local-controller-test-secret'
            del self.config['external-controller-unix']
            controller.close()
        self.path = self.root + '/live.yaml'
        self.script = self.root + '/profile.js'
        self.index = self.root + '/profiles.yaml'
        with open(self.path, 'w') as stream:
            yaml.safe_dump(self.config, stream)
        if self.config_source == 'verge':
            with open(self.script, 'w') as stream:
                stream.write(auto.rewrite_script('function main(config) { return config; }'))
            with open(self.index, 'w') as stream:
                yaml.safe_dump({'current': 'local-test', 'items': [
                    {'uid': 'local-test', 'option': {'script': 'profile'}}]}, stream)
        self.cfg = dict(auto.DEFAULTS, config_source=self.config_source,
                        clash_config=self.path, binary=MIHOMO_BINARY,
                        interval_seconds=15, failure_scan_seconds=15,
                        controller_tcp=self.config['external-controller'],
                        controller_unix=self.config.get('external-controller-unix', ''),
                        profile_script=self.script if self.config_source == 'verge' else '',
                        profiles_index=self.index if self.config_source == 'verge' else '',
                        state_dir=self.root + '/state', mutation_lock=self.root + '/mutation.lock',
                        run_lock=self.root + '/run.lock',
                        probe_lock=self.root + '/probe.lock',
                        business_proxy='http://127.0.0.1:' + str(self.port))
        self.agent = auto.Auto(self.cfg)
        reservation.close()
        self.start()
        policy.api(self.config, '/proxies/GLOBAL', 'PUT', {'name': self.cfg['group']})
        policy.api(self.config, '/proxies/Unrelated', 'PUT', {'name': 'B'})
        policy.api(self.config, '/proxies/Codex-ChatGPT-Chain', 'PUT', {'name': 'A'})
        snap = self.agent.snapshot()
        self.assertTrue(snap['active'])
        self.assertEqual(snap['selected'], 'A')
        self.agent.save(dict(active=True, token=snap['token'], selected='A',
                             failures=0, last_scan=0, last_check=0, hold_until=0))

    def start(self):
        log = open(self.root + '/mihomo.log', 'ab')
        try:
            self.process = subprocess.Popen([MIHOMO_BINARY, '-f', self.path, '-d', self.root],
                                            stdout=log, stderr=subprocess.STDOUT)
        finally:
            log.close()
        for _ in range(80):
            try:
                runtime = policy.api(self.config, '/configs')
                live = policy.api(self.config, '/proxies')['proxies']
                if runtime.get('mixed-port') == self.port and self.cfg['group'] in live:
                    return
            except OSError:
                pass
            if self.process.poll() is not None:
                self.fail('disposable Mihomo exited during startup')
            time.sleep(.05)
        self.fail('disposable Mihomo controller did not initialize')

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

    def choices(self):
        return {name: row['now'] for name, row in policy.api(self.config, '/proxies')['proxies'].items()
                if row.get('type') == 'Selector'}

    def _partial_relay(self, endpoint=0, successes=1):
        relay = [dict(ok=(index == endpoint and successes > 0),
                       curl_exit=0 if index == endpoint and successes > 0 else 28,
                       code=204 if index == endpoint and successes > 0 else 0)
                 for index in range(2)]
        return dict(ok=successes > 0, stable=False, switchable=False,
                    tcp_ms=120, score_ms=120, jitter_ms=0,
                    tcp_samples=[120] * 3, relay=relay,
                    relay_successes=successes, relay_total=2,
                    reason='unstable-relay')

    def _prime_partial_candidate(self, name, at, report):
        state, snap = self.agent.state(), self.agent.snapshot()
        with patch.object(auto.time, 'time', return_value=at - 5):
            self.agent.record(state, snap, name, report)
        # Cache a recent partial observation, including its quality cooldown.
        state['last_scan'] = at
        self.agent.save(state)
        self.assertGreater(state['nodes'][name]['cooldown_until'], at + 15)

    @staticmethod
    def measured(node, cfg, proxy=None):
        # Selection orchestration is real; deterministic measurements avoid all egress traffic.
        ms = {'A': 200, 'B': 100, 'C': 150}[node['name']]
        return dict(ok=True, switchable=False, tcp_ms=ms, score_ms=ms, jitter_ms=0,
                    tcp_samples=[ms] * 3, reason='healthy', relay=[])

    def test_real_selector_put_persists_and_preserves_other_choices(self):
        state, snap, now = self.agent.state(), self.agent.snapshot(), time.time()
        for at in (now - 180, now - 120, now - 60):
            with patch.object(auto.time, 'time', return_value=at):
                for name, node in snap['nodes'].items():
                    self.agent.record(state, snap, name, self.measured(node, self.cfg))
        self.agent.save(state)
        before = self.choices()
        original_api = policy.api
        calls = []

        def recorded(config, path, method='GET', body=None):
            calls.append((path, method, body))
            return original_api(config, path, method, body)

        with patch.object(auto, 'measure', side_effect=self.measured), \
                patch.object(policy, 'api', side_effect=recorded):
            result = self.agent.cycle()
        self.assertEqual(result['action'], 'switched')
        self.assertEqual(result['target'], 'B')
        writes = [(path, method, body) for path, method, body in calls if method != 'GET']
        self.assertEqual(writes, [('/proxies/GLOBAL%20Stable%20Auto', 'PUT', {'name': 'B'})])
        expected = dict(before, **{self.cfg['group']: 'B'})
        self.assertEqual(self.choices(), expected)
        self.assertEqual(policy.api(self.config, '/configs')['mode'], 'global')
        self.assertIsNone(self.agent.state()['pending'])
        # A genuine core restart, using the same disposable home/cache, proves store-selected.
        self.stop()
        self.start()
        self.assertEqual(self.choices(), expected)
        restarted = auto.Auto(self.cfg)
        self.assertEqual(restarted.snapshot()['selected'], 'B')
        self.assertEqual(restarted.state()['selected'], 'B')
        self.assertEqual(restarted.state()['last_change']['reason'], 'latency')

    def test_real_mode_exit_and_other_global_selection_do_not_probe_or_mutate(self):
        original_api = policy.api
        for mode, selection in [('rule', self.cfg['group']), ('direct', self.cfg['group']),
                                ('global', 'A')]:
            with self.subTest(mode=mode, selection=selection):
                original_api(self.config, '/configs', 'PATCH', {'mode': mode})
                original_api(self.config, '/proxies/GLOBAL', 'PUT', {'name': selection})
                before = self.choices()
                calls = []

                def recorded(config, path, method='GET', body=None):
                    calls.append((path, method))
                    return original_api(config, path, method, body)

                with patch.object(auto, 'measure', side_effect=AssertionError('inactive probe')), \
                        patch.object(policy, 'api', side_effect=recorded):
                    result = self.agent.cycle()
                self.assertEqual(result['action'], 'inactive')
                self.assertTrue(all(method == 'GET' for _, method in calls))
                self.assertEqual(self.choices(), before)
                self.assertEqual(original_api(self.config, '/configs')['mode'], mode)

    def test_real_controller_recovers_with_second_candidate_after_first_repeat_fails(self):
        before = self.choices()
        probes = []
        def measured(node, cfg, proxy=None):
            name = node['name']
            probes.append(name)
            result = self.measured(node, cfg, proxy)
            if name == 'A' or (name == 'B' and probes.count('B') > 1):
                result.update(ok=False, stable=False, switchable=True, reason='transport-failure')
            return result
        with patch.object(auto, 'measure', side_effect=measured):
            self.assertEqual(self.agent.cycle()['action'], 'failure-confirming')
            state = self.agent.state()
            state['last_check'] -= self.cfg['interval_seconds']
            self.agent.save(state)
            self.assertEqual(self.agent.cycle()['action'], 'switched')
        self.assertEqual(self.choices(), dict(before, **{self.cfg['group']: 'C'}))
        state = self.agent.state()
        self.assertEqual(state['last_change']['reason'], 'failure')
        self.assertEqual([r['name'] for r in state['evaluation']['rechecks']], ['B', 'C'])
        self.assertIsNone(state['pending'])

    def test_real_manual_selection_during_failed_repeat_cancels_recovery(self):
        before = self.choices()
        probes = []
        def measured(node, cfg, proxy=None):
            name = node['name']
            probes.append(name)
            result = self.measured(node, cfg, proxy)
            if name == 'A' or (name == 'B' and probes.count('B') > 1):
                result.update(ok=False, stable=False, switchable=True, reason='transport-failure')
            if name == 'B' and probes.count('B') > 1:
                policy.api(self.config, '/proxies/GLOBAL', 'PUT', {'name': 'C'})
            return result
        with patch.object(auto, 'measure', side_effect=measured):
            self.agent.cycle()
            state = self.agent.state()
            state['last_check'] -= self.cfg['interval_seconds']
            self.agent.save(state)
            self.assertEqual(self.agent.cycle()['action'], 'selection-changed')
        self.assertEqual(self.choices(), dict(before, GLOBAL='C'))
        self.assertEqual(probes.count('C'), 1)
        self.assertIsNone(self.agent.state().get('pending'))

    def test_real_partial_recovery_switches_with_cooling_candidate_within_one_minute(self):
        """A 1/2 relay candidate is sufficient for hard-outage continuity.

        The candidate is deliberately cooling because its cached observation is
        partial.  A second observation and the post-switch check must prove the
        same endpoint before the real Mihomo selector PUT is accepted.
        """
        base = 1_000_000.0
        self._prime_partial_candidate('B', base, self._partial_relay(0, 1))
        calls = {'A': 0, 'B': 0}

        def measured(node, cfg, proxy=None):
            name = node['name']
            calls[name] = calls.get(name, 0) + 1
            if name == 'A':
                return dict(ok=False, stable=False, switchable=True,
                            tcp_ms=None, score_ms=None, relay=[],
                            reason='transport-failure')
            if name == 'B':
                return self._partial_relay(0, 1)
            return dict(ok=False, stable=False, switchable=True,
                        tcp_ms=None, score_ms=None, relay=[],
                        reason='transport-failure')

        before = self.choices()
        with patch.object(auto, 'measure', side_effect=measured), \
                patch.object(auto.time, 'time', return_value=base):
            self.assertEqual(self.agent.cycle()['action'], 'failure-confirming')
        with patch.object(auto, 'measure', side_effect=measured), \
                patch.object(auto.time, 'time', return_value=base + 15), \
                patch.object(policy, 'api', wraps=policy.api) as controller:
            result = self.agent.cycle()

        self.assertEqual(result['action'], 'switched')
        self.assertEqual([call.args[3] for call in controller.call_args_list
                          if len(call.args) > 2 and call.args[2] == 'PUT'], [{'name': 'B'}])
        self.assertEqual(result['target'], 'B')
        self.assertEqual(self.choices(), dict(before, **{self.cfg['group']: 'B'}))
        self.assertEqual(self.choices()['Unrelated'], before['Unrelated'])
        self.assertEqual(self.choices()['Codex-ChatGPT-Chain'], before['Codex-ChatGPT-Chain'])
        self.assertIsNone(self.agent.state()['pending'])
        self.assertEqual(self.agent.state()['last_change']['reason'], 'failure')
        self.assertEqual(calls['B'], 2)  # recheck and postcheck

    def test_real_partial_recovery_rejects_alternating_endpoint(self):
        base = 1_100_000.0
        self._prime_partial_candidate('B', base, self._partial_relay(0, 1))

        def measured(node, cfg, proxy=None):
            if node['name'] == 'A':
                return dict(ok=False, stable=False, switchable=True,
                            tcp_ms=None, score_ms=None, relay=[],
                            reason='transport-failure')
            if node['name'] == 'B':
                return self._partial_relay(1, 1)
            return dict(ok=False, stable=False, switchable=True,
                        tcp_ms=None, score_ms=None, relay=[],
                        reason='transport-failure')
        before = self.choices()
        with patch.object(auto, 'measure', side_effect=measured), \
                patch.object(auto.time, 'time', return_value=base):
            self.agent.cycle()
        with patch.object(auto, 'measure', side_effect=measured), \
                patch.object(auto.time, 'time', return_value=base + 15), \
                patch.object(policy, 'api', wraps=policy.api) as controller:
            result = self.agent.cycle()

        self.assertEqual(result['action'], 'candidate-unstable')
        self.assertFalse(any(len(call.args) > 2 and call.args[2] != 'GET'
                             for call in controller.call_args_list))
        self.assertEqual(self.choices(), before)
        self.assertIsNone(self.agent.state().get('pending'))

    def test_real_partial_recovery_rolls_back_when_postcheck_has_no_endpoint_success(self):
        base = 1_200_000.0
        self._prime_partial_candidate('B', base, self._partial_relay(0, 1))
        calls = {'B': 0}

        def measured(node, cfg, proxy=None):
            if node['name'] == 'A':
                return dict(ok=False, stable=False, switchable=True,
                            tcp_ms=None, score_ms=None, relay=[],
                            reason='transport-failure')
            if node['name'] == 'B':
                calls['B'] += 1
                return self._partial_relay(0, 1) if calls['B'] == 1 else self._partial_relay(0, 0)
            return dict(ok=False, stable=False, switchable=True,
                        tcp_ms=None, score_ms=None, relay=[],
                        reason='transport-failure')

        before = self.choices()
        with patch.object(auto, 'measure', side_effect=measured), \
                patch.object(auto.time, 'time', return_value=base):
            self.agent.cycle()
        with patch.object(auto, 'measure', side_effect=measured), \
                patch.object(auto.time, 'time', return_value=base + 15), \
                patch.object(policy, 'api', wraps=policy.api) as controller:
            result = self.agent.cycle()

        self.assertEqual(result['action'], 'rolled-back')
        self.assertEqual([call.args[3] for call in controller.call_args_list
                          if len(call.args) > 2 and call.args[2] == 'PUT'],
                         [{'name': 'B'}, {'name': 'A'}])
        self.assertEqual(self.choices(), before)
        self.assertIsNone(self.agent.state()['pending'])
        self.assertNotIn('last_change', self.agent.state())


class GlobalAutoStaticNativeTests(GlobalAutoNativeTests):
    """Run the same selection/recovery contract over a static YAML + TCP API."""
    config_source = 'static'

    def test_static_source_without_profile_files_uses_real_tcp_authentication(self):
        self.assertFalse(os.path.exists(self.script))
        self.assertFalse(os.path.exists(self.index))
        settings = self.root + '/global-auto.yaml'
        with open(settings, 'w') as stream:
            yaml.safe_dump(self.cfg, stream)
        loaded = auto.load_config(settings)
        self.assertTrue(auto.Auto(loaded).snapshot()['active'])
        changed = dict(self.config, secret='wrong-test-secret')
        with open(self.path, 'w') as stream:
            yaml.safe_dump(changed, stream)
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.agent.snapshot()
        try:
            self.assertEqual(error.exception.code, 401)
        finally:
            error.exception.close()

    def test_static_source_retains_config_and_runtime_consistency_checks(self):
        before = self.choices()
        for mismatch in ('members', 'node-type', 'persistence', 'listener'):
            with self.subTest(mismatch=mismatch):
                changed = yaml.safe_load(yaml.safe_dump(self.config))
                cfg = dict(self.cfg)
                if mismatch == 'members':
                    changed['proxy-groups'][0]['proxies'] = ['A', 'B']
                elif mismatch == 'node-type':
                    changed['proxies'][0]['type'] = 'socks5'
                elif mismatch == 'persistence':
                    changed['profile']['store-selected'] = False
                else:
                    cfg['business_proxy'] = 'http://127.0.0.1:1'
                with open(self.path, 'w') as stream:
                    yaml.safe_dump(changed, stream)
                with self.assertRaises(auto.Error):
                    auto.Auto(cfg).snapshot()
                self.assertEqual(self.choices(), before)

    def test_static_config_change_during_probe_cancels_switch(self):
        before = self.choices()
        initial = self.agent.snapshot()

        def measured(node, cfg, proxy=None):
            if proxy is not None:
                changed = dict(self.config, **{'log-level': 'warning'})
                with open(self.path, 'w') as stream:
                    yaml.safe_dump(changed, stream)
            return self.measured(node, cfg, proxy)

        with patch.object(auto, 'measure', side_effect=measured), \
                patch.object(policy, 'api', wraps=policy.api) as controller:
            result = self.agent.cycle()
        self.assertEqual(result['action'], 'selection-changed')
        self.assertFalse(any(len(call.args) > 2 and call.args[2] != 'GET'
                             for call in controller.call_args_list))
        self.assertEqual(self.choices(), before)
        self.assertNotEqual(self.agent.snapshot()['generation'], initial['generation'])


if __name__ == '__main__':
    unittest.main()
