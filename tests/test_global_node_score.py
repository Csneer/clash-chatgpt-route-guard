import unittest
from unittest.mock import patch

import global_auto as auto
import global_node_score as scoring


class ScoreTests(unittest.TestCase):
    def setUp(self):
        self.now = 10000
        self.identity = 'node-1'
        self.epoch = scoring.epoch(auto.DEFAULTS)
        self.good = dict(ok=True, stable=True, tcp_ms=100, jitter_ms=10,
                         max_tcp_ms=110, relay=[dict(curl_exit=0), dict(curl_exit=0)])

    def add(self, row, report=None, delta=60, scheduled=True):
        self.now += delta
        report = self.good if report is None else report
        stats = scoring.observe(row, report, self.identity, self.epoch, self.now, scheduled)
        return dict(report, identity=self.identity, at=self.now, **stats)

    def series(self, reports):
        row = {}
        for report in reports:
            row = self.add(row, report)
        return row

    def test_current_good_probe_beats_old_reputation(self):
        proven = self.series([self.good] * 8)
        current_failure = self.add(proven, dict(self.good, ok=False, stable=False))
        newcomer = self.add({}, dict(self.good, tcp_ms=1, jitter_ms=0))
        self.assertGreater(newcomer['ranking']['score'], current_failure['ranking']['score'])
        self.assertEqual(current_failure['ranking']['score'], 0)
        self.assertFalse(newcomer['ranking']['sustained'])

    def test_older_than_five_minutes_has_no_score_influence(self):
        original = self.series([dict(self.good, ok=False, stable=False)] * 8)
        updated = self.add(original, delta=301)
        clean = scoring.observe({}, self.good, self.identity, self.epoch, self.now)
        self.assertEqual(updated['ranking'], clean['ranking'])

    def test_recent_failure_loses_weight_with_time_and_fresh_success(self):
        row = self.add({}, dict(self.good, ok=False, stable=False))
        first = self.add(row)
        second = self.add(first, delta=120)
        self.assertGreater(second['ranking']['score'], first['ranking']['score'])
        self.assertGreater(second['ranking']['success_rate'], first['ranking']['success_rate'])

    def test_sampling_frequency_alone_does_not_make_current_unbeatable(self):
        sparse = self.series([self.good] * 6)
        dense = self.series([self.good] * 40)
        self.assertEqual(sparse['ranking']['score'], dense['ranking']['score'])

    def test_instant_rechecks_and_close_scheduled_samples_are_not_independent(self):
        row = self.add({})
        for scheduled in (False, False, True, False):
            row = self.add(row, delta=10, scheduled=scheduled)
        self.assertEqual(row['ranking']['observations'], 1)
        self.assertFalse(row['ranking']['sustained'])
        row = self.add(row, delta=20)
        self.assertEqual(row['ranking']['observations'], 2)

    def test_late_recheck_alone_cannot_add_independent_evidence(self):
        row = self.add({})
        row = self.add(row, delta=300, scheduled=False)
        self.assertEqual(row['ranking']['observations'], 1)

    def test_failure_in_recheck_cannot_be_erased_by_same_round_success(self):
        row = self.add({})
        row = self.add(row, dict(self.good, ok=False, stable=False,
                                relay=[dict(curl_exit=28)]), delta=1, scheduled=False)
        row = self.add(row, delta=1, scheduled=False)
        self.assertEqual(row['ranking']['stable_rate'], 0)
        self.assertEqual(row['ranking']['success_rate'], 0)
        self.assertEqual(row['ranking']['timeout_rate'], 1)
        self.assertEqual(row['ranking']['stable_streak'], 0)
        row = self.add(row)
        self.assertEqual(row['ranking']['observations'], 2)
        self.assertEqual(row['ranking']['stable_streak'], 1)

    def test_time_identity_and_policy_do_not_reuse_stale_success(self):
        original = self.series([self.good] * 4)
        stale = self.add(original, delta=3601)
        self.assertEqual(stale['ranking']['observations'], 1)
        self.identity = 'node-new'
        changed = self.add(original)
        self.assertEqual(changed['ranking']['observations'], 1)
        self.identity = 'node-1'
        self.epoch = 'new-policy'
        changed = self.add(original)
        self.assertEqual(changed['ranking']['observations'], 1)

    def test_legacy_history_is_not_assumed_independent(self):
        row = self.series([self.good] * 4)
        del row['statistics_epoch']
        row = self.add(row)
        self.assertEqual(row['ranking']['observations'], 1)

    def test_timeout_and_tail_jitter_penalize_equal_availability(self):
        good = self.series([self.good] * 8)
        jittered = self.series([self.good] * 6 + [dict(self.good, jitter_ms=240)] * 2)
        timeout = self.series([dict(self.good, tcp_timeouts=1)] * 8)
        self.assertGreater(good['ranking']['score'], jittered['ranking']['score'])
        self.assertGreater(good['ranking']['score'], timeout['ranking']['score'])
        self.assertEqual(jittered['ranking']['jitter_ms'], 240)
        self.assertEqual(timeout['ranking']['timeout_rate'], 1)

    def test_sparse_good_samples_are_not_called_sustained(self):
        row = self.series([self.good] * 2)
        self.assertFalse(row['ranking']['sustained'])
        row = self.add(row)
        self.assertTrue(row['ranking']['sustained'])
        self.assertEqual(row['ranking']['span_seconds'], 120)
        self.assertLessEqual(row['ranking']['score'], 100)

    def test_measurement_policy_epoch_ignores_scheduling_but_tracks_checks(self):
        cfg = dict(auto.DEFAULTS, hold_seconds=300, inventory_scan_seconds=30)
        self.assertEqual(scoring.epoch(cfg), self.epoch)
        cfg['timeout_seconds'] += 1
        self.assertNotEqual(scoring.epoch(cfg), self.epoch)

    def test_history_storage_is_bounded(self):
        row = self.series([self.good] * 80)
        self.assertLessEqual(len(row['history']), 60)
        self.assertGreaterEqual(row['history'][0]['at'], self.now - 3600)


class TcpBudgetTests(unittest.TestCase):
    def test_all_resolved_addresses_share_one_connection_budget(self):
        cfg = dict(auto.DEFAULTS, tcp_samples=3, tcp_timeout_seconds=2)
        clock = [0.0]
        calls = []
        class Sock:
            def __init__(self, *args): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def settimeout(self, value): self.timeout = value
            def connect(self, address):
                calls.append(address)
                clock[0] += self.timeout
                raise auto.socket.timeout()
        addresses = [(2, 1, 6, '', ('192.0.2.' + str(i), 2377)) for i in range(1, 21)]
        with patch.object(auto, 'resolve_addresses', return_value=[(row[0], row[4]) for row in addresses]), \
             patch.object(auto.socket, 'socket', side_effect=Sock), \
             patch.object(auto.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(auto.time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            report = auto.tcp_quality(dict(server='unreachable.example', port=2377), cfg)
        self.assertLessEqual(clock[0], 6)
        self.assertEqual(len(calls), 3)
        self.assertFalse(report['ok'])
        self.assertEqual(report['tcp_timeouts'], 3)
        self.assertEqual(report['tcp_samples'], [None, None, None])
