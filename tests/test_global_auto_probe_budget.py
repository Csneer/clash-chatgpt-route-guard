import json
import subprocess
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import global_auto as auto


class ProbeBudgetTests(unittest.TestCase):
    def test_dns_timeout_returns_no_addresses_without_unbounded_wait(self):
        cfg = dict(auto.DEFAULTS, tcp_timeout_seconds=1)
        with patch.object(auto.subprocess, 'run', side_effect=subprocess.TimeoutExpired('resolver', 2)) as run:
            self.assertEqual(auto.resolve_addresses(dict(server='unreachable.test', port=443), cfg), [])
        self.assertEqual(run.call_args.kwargs['timeout'], 2)
        self.assertIn('-I', run.call_args.args[0])

    def test_dns_addresses_are_tuples_and_deduplicated(self):
        addresses = [[2, 1, 6, '', ['127.0.0.1', 443]]] * 2
        with patch.object(auto.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(addresses))):
            self.assertEqual(auto.resolve_addresses(dict(server='localhost', port=443), auto.DEFAULTS), [(2, ('127.0.0.1', 443))])

    def test_two_relay_checks_run_concurrently_in_one_timeout_window(self):
        cfg = dict(auto.DEFAULTS, timeout_seconds=3)
        quality = dict(ok=True, tcp_ms=20, jitter_ms=1, max_tcp_ms=21, score_ms=20.5)
        barrier = threading.Barrier(2)
        def fetch(proxy, url, timeout):
            self.assertEqual(timeout, 3)
            barrier.wait(timeout=1)
            return dict(exit=0, code=204)
        with patch.object(auto, 'tcp_quality', return_value=quality), patch.object(auto.common, 'fetch', side_effect=fetch):
            report = auto.measure(dict(name='test'), cfg, 'http://127.0.0.1:7890')
        self.assertTrue(report['stable'])
        self.assertEqual(report['relay_successes'], 2)
