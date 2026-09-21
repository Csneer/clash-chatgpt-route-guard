#!/usr/bin/env python3
"""Real Mihomo + real curl/TLS + local proxy chain. No external/prod traffic."""
import copy
import json
import os
import select
import sqlite3
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import shutil
from unittest import mock

import yaml
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
import clash_guard as guard
import clash_common as common
import mihomo_policy as policy
import clash_demand as demand

MIHOMO_BINARY = os.environ.get('MIHOMO_BINARY', '/usr/local/bin/mihomo')
if not os.path.isfile(MIHOMO_BINARY):
    MIHOMO_BINARY = shutil.which('mihomo') or MIHOMO_BINARY


def headers(sock):
    data = b''
    while b'\r\n\r\n' not in data and len(data) < 32768:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            request = headers(self.request)
            if not request.startswith(b'CONNECT '):
                return
            if self.server.kind == 'bad':
                self.request.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
                return
            if self.server.kind == 'relay':
                destination = request.split()[1].decode().split(':')
                # Do not allow test code to connect outside loopback.
                if destination[0] != '127.0.0.1':
                    return
                with socket.create_connection((destination[0], int(destination[1])), timeout=5) as upstream:
                    self.server.hops += 1
                    self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
                    sockets = [self.request, upstream]
                    while True:
                        ready, _, _ = select.select(sockets, [], [], 5)
                        if not ready:
                            return
                        for source in ready:
                            chunk = source.recv(32768)
                            if not chunk:
                                return
                            (upstream if source is self.request else self.request).sendall(chunk)
            else:
                self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
                with self.server.tls.wrap_socket(self.request, server_side=True) as wrapped:
                    headers(wrapped)
                    self.server.calls += 1
                    body = b'{"detail":"Unauthorized"}'
                    wrapped.sendall(b'HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
        except (OSError, ValueError, ssl.SSLError):
            return


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


@unittest.skipUnless(os.path.isfile(MIHOMO_BINARY), 'set MIHOMO_BINARY to run real Mihomo integration tests')
class NativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='guard-native-')
        self.addCleanup(self.tmp.cleanup)
        self.cert = os.path.join(self.tmp.name, 'ca.pem')
        key = os.path.join(self.tmp.name, 'key.pem')
        checked = subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                                  '-keyout', key, '-out', self.cert, '-days', '1', '-subj', '/CN=guard.test'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        self.assertEqual(checked.returncode, 0)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.load_cert_chain(self.cert, key)
        self.servers = {}
        for kind in ['good', 'bad', 'relay']:
            server = Server(('127.0.0.1', 0), Proxy)
            server.kind, server.tls, server.calls, server.hops = kind, context, 0, 0
            thread = threading.Thread(target=server.serve_forever)
            thread.daemon = True
            thread.start()
            self.servers[kind] = server
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
        reservations = []
        ports = []
        for _ in range(2):
            sock = socket.socket()
            sock.bind(('127.0.0.1', 0))
            reservations.append(sock)
            ports.append(sock.getsockname()[1])
        self.path = os.path.join(self.tmp.name, 'live.yaml')
        nodes = [dict(name=kind, type='http', server='127.0.0.1', port=s.server_address[1]) for kind, s in self.servers.items()]
        next(p for p in nodes if p['name'] == 'good')['dialer-proxy'] = 'relay'
        self.config = dict(mode='rule', port=ports[0], **{
            'external-controller': '127.0.0.1:' + str(ports[1]), 'allow-lan': False, 'log-level': 'silent',
            'ipv6': False, 'proxies': nodes, 'proxy-groups': [
                dict(name='App', type='select', proxies=['Selection']),
                dict(name='Selection', type='select', proxies=['bad', 'good'])],
            'rules': ['DOMAIN,guard.test,App', 'MATCH,REJECT'], 'profile': {'store-selected': True},
            'dns': {'enable': False}, 'tun': {'enable': False}, 'geo-auto-update': False})
        with open(self.path, 'w') as stream:
            yaml.safe_dump(self.config, stream, default_flow_style=False)
        for sock in reservations:
            sock.close()
        self.log = open(os.path.join(self.tmp.name, 'mihomo.log'), 'wb')
        self.addCleanup(self.log.close)
        self.process = subprocess.Popen([MIHOMO_BINARY, '-f', self.path, '-d', self.tmp.name], stdout=self.log, stderr=subprocess.STDOUT)
        self.addCleanup(self.stop)
        for _ in range(50):
            try:
                runtime = policy.api(self.config, '/configs')
                live = policy.api(self.config, '/proxies')['proxies']
                if runtime.get('port') != ports[0] or runtime.get('mode') != 'rule' or 'Selection' not in live:
                    raise OSError('control API is up before runtime initialization completes')
                if len(policy.api(self.config, '/rules')['rules']) != 2:
                    raise OSError('runtime rules not ready')
                with socket.create_connection(('127.0.0.1', ports[0]), timeout=.1):
                    pass
                break
            except Exception:
                if self.process.poll() is not None:
                    self.fail('isolated mihomo exited')
                time.sleep(.1)
        else:
            self.fail('isolated runtime did not become ready')
        self.cfg = dict(guard.DEFAULTS, mode='auto', clash_config=self.path, binary=MIHOMO_BINARY,
                        selector='Selection', entry='App', business_proxy='http://127.0.0.1:' + str(ports[0]),
                        state_dir=os.path.join(self.tmp.name, 'state'), mutation_lock=os.path.join(self.tmp.name, 'mutation.lock'),
                        probe_lock=os.path.join(self.tmp.name, 'probe.lock'), run_lock=os.path.join(self.tmp.name, 'run.lock'),
                        journal_unit=None, manual_history=None, timeout_seconds=4,
                        checks=[dict(name='local-tls-backend', url='https://guard.test/api', status=401,
                                     json_contains={'detail': 'Unauthorized'})])
        self.g = guard.Guard(self.cfg)
        patch = mock.patch.dict(os.environ, CURL_CA_BUNDLE=self.cert)
        patch.start()
        self.addCleanup(patch.stop)

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=5)

    def test_full_eval_does_not_touch_live_and_chain_really_used(self):
        original = policy.read(self.path)
        snap = self.g.snapshot()
        self.assertFalse(self.g.business()['ok'])
        results, skipped = self.g.evaluate(snap)
        self.assertTrue(results['good']['ok'])
        self.assertFalse(results['bad']['ok'])
        self.assertFalse(skipped)
        self.assertGreater(self.servers['relay'].hops, 0)
        self.assertEqual(self.g.snapshot()['selected'], 'bad')
        self.assertEqual(policy.read(self.path), original)

    def test_real_switch_postcheck_pin_and_hot_reload(self):
        pid = self.process.pid
        snap = self.g.snapshot()
        with common.locked(self.cfg['mutation_lock']):
            self.g.transaction(snap, 'good', {})
        self.assertTrue(self.g.business()['ok'])
        self.assertEqual(self.g.snapshot()['selected'], 'good')
        self.assertEqual(self.process.pid, pid)
        current = policy.parse(policy.read(self.path))
        self.assertEqual(current['rules'], self.config['rules'])
        self.assertEqual(current['proxy-groups'][1]['proxies'][0], 'good')
        policy.api(current, '/configs?force=false', 'PUT', {'path': self.path})
        self.assertEqual(self.g.snapshot()['selected'], 'good')
        self.assertTrue(self.g.business()['ok'])

    def test_real_failed_postcheck_rolls_back_to_working_chain(self):
        with common.locked(self.cfg['mutation_lock']):
            self.g.transaction(self.g.snapshot(), 'good', {})
        working = policy.read(self.path)
        with common.locked(self.cfg['mutation_lock']):
            with self.assertRaises(guard.Error):
                self.g.transaction(self.g.snapshot(), 'bad', {})
        self.assertEqual(self.g.snapshot()['selected'], 'good')
        self.assertTrue(self.g.business()['ok'])
        self.assertEqual(policy.read(self.path), working)

    def test_real_automatic_cycle_recovers_outage_only_after_evidence(self):
        now = time.time()
        self.g.save(dict(token=self.g.snapshot()['token'], profile_hash=common.fingerprint(self.cfg),
                         failures=[now - 400, now - 300, now - 200], last_check=now - 70))
        self.assertEqual(self.g.cycle(), 'switched')
        self.assertTrue(self.g.business()['ok'])
        self.assertEqual(self.g.snapshot()['selected'], 'good')
        # Healthy next cycle does not switch back to the original route.
        self.assertEqual(self.g.cycle(), 'hold')
        self.assertEqual(self.g.snapshot()['selected'], 'good')

    def test_real_demand_guard_idle_success_then_network_fault_recovery(self):
        import datetime
        path=os.path.join(self.tmp.name,'calls.sqlite')
        log=os.path.join(self.tmp.name,'errors.jsonl')
        def iso(t): return datetime.datetime.utcfromtimestamp(t).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE call_records (completed_at TEXT, provider TEXT)')
        with open(log,'w') as stream: stream.write('')
        self.cfg.update(failure_count=3,failure_span_seconds=1200,cross_ip_failure_span_seconds=1200,
                        failure_gap_seconds=1800,same_ip_max_age_seconds=1800)
        self.cfg['activity']=dict(enabled=True,strategy='faults-only',provider='codex',
                                  call_records_path=path,error_log_path=log,window_seconds=900,
                                  probe_cooldown_seconds=600,error_kinds=sorted(demand.KINDS))
        with mock.patch.object(self.g,'business',side_effect=AssertionError('idle external request')):
            self.assertEqual(self.g.cycle(),'baseline-hold')
            self.assertEqual(self.g.cycle(),'idle')
            with sqlite3.connect(path) as db:
                db.execute('INSERT INTO call_records VALUES (?,?)',(iso(time.time()-500),'codex'))
            self.assertEqual(self.g.cycle(),'passive-healthy')
        # Feed recent local failures and prior spaced confirmations; real requests
        # then verify the failed current proxy and the working two-hop candidate.
        now=time.time()
        with open(log,'w') as stream:
            for i,at in enumerate((now-150,now-80,now-1)):
                stream.write(json.dumps(dict(ts=iso(at),error=dict(name='StreamUpstreamPrematureClose',
                                   message='Upstream stream closed before terminal event'),
                                   context=dict(provider='codex',requestId='native-'+str(i))))+'\n')
        state=common.load_json(self.g.state_path,{})
        state.update(token=self.g.snapshot()['token'],hold_until=0)
        state['demand'].update(baseline_at=now-2000,consumed_until=now-700,confirmations=[now-1300,now-650],last_confirmed=now-650)
        self.g.save(state)
        with sqlite3.connect(path) as db:
            db.execute('DELETE FROM call_records') # Local disposable fixture only.
        self.assertEqual(self.g.cycle(),'switched')
        self.assertEqual(self.g.snapshot()['selected'],'good')
        self.assertTrue(self.g.business()['ok'])
        with mock.patch.object(self.g,'business',side_effect=AssertionError('recovered external request')):
            self.g.cycle()
        self.assertEqual(self.g.snapshot()['selected'], 'good')


if __name__ == '__main__':
    unittest.main(verbosity=2)
