import unittest
from unittest.mock import patch

import global_auto as auto
from test_global_auto import AutoCycleTests as Fixture, quality


class InventoryTests(unittest.TestCase):
    setUp = Fixture.setUp
    patch = Fixture.patch
    snapshot = Fixture.snapshot
    probe = Fixture.probe
    api = Fixture.api
    tick = Fixture.tick
    relay_report = staticmethod(Fixture.relay_report)
    cache_report = Fixture.cache_report

    def seed(self, name, report, count=3, age=0):
        state = self.agent.state()
        for index in range(count):
            at = self.now - age - (count - index) * 60
            with patch.object(auto.time, 'time', return_value=at):
                self.agent.record(state, self.snapshot(), name, report)
        self.agent.save(state)

    def test_healthy_inventory_rotates_despite_hold_and_decision_cooldown(self):
        self.cfg['batch_size'] = 2
        self.reports.update(C=quality(190), D=quality(190), E=quality(190), F=quality(190))
        state = self.agent.state()
        state.update(last_decision=self.now, hold_until=self.now + 600, last_attempt=self.now)
        self.agent.save(state)
        for _ in range(5):
            self.assertEqual(self.tick(60)['action'], 'healthy')
        measured = {name for name, live in self.probes if not live}
        self.assertEqual(measured, {'B', 'C', 'D', 'E', 'F'})
        self.assertEqual(self.writes, [])

    def test_current_hard_failure_first_round_does_not_scan(self):
        self.reports['A'] = quality(ok=False, switchable=True)
        self.assertEqual(self.tick()['action'], 'failure-confirming')
        self.assertEqual(self.probes, [('A', True)])

    def test_cached_candidate_outside_current_batch_is_rechecked(self):
        self.cfg['batch_size'] = 2
        self.reports.update(B=quality(180), C=quality(180), D=quality(80))
        self.seed('D', self.reports['D'], count=5, age=40)
        state = self.agent.state()
        state['last_scan'] = self.now
        state['evaluation'] = dict(scanned=[])
        self.agent.save(state)
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertEqual(self.selected, 'D')
        self.assertNotIn('D', self.agent.state()['evaluation']['scanned'])
        self.assertIn(('D', False), self.probes)

    def test_normal_preference_can_use_new_currently_better_node(self):
        state = self.agent.state()
        state['nodes'].pop('B')
        self.agent.save(state)
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertEqual(self.selected, 'B')

    def test_current_latency_improvement_can_beat_long_current_history(self):
        self.seed('A', quality(200), count=12)
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertEqual(self.selected, 'B')

    def test_failure_can_use_new_candidate_without_sustained_history(self):
        state = self.agent.state()
        state['nodes'].pop('B')
        self.agent.save(state)
        self.reports['A'] = quality(ok=False, switchable=True)
        self.tick()
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertFalse(self.agent.state()['nodes']['B']['ranking']['sustained'])

    def test_newly_scanned_partial_candidate_is_rechecked_despite_quality_cooldown(self):
        state = self.agent.state()
        state['nodes'].pop('B')
        self.agent.save(state)
        self.reports['A'] = quality(ok=False, switchable=True)
        self.reports['B'] = self.relay_report(0)
        self.tick()
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertEqual(self.selected, 'B')
        self.assertEqual(self.probes.count(('B', False)), 2)
        self.assertGreater(self.agent.state()['nodes']['B']['cooldown_until'], self.now)

    def test_zero_relay_candidate_remains_ineligible_during_hard_outage(self):
        self.reports['A'] = quality(ok=False, switchable=True)
        self.reports['B'] = self.relay_report()
        self.cache_report('B', self.reports['B'])
        self.tick()
        self.assertEqual(self.tick()['action'], 'no-candidate')
        self.assertEqual(self.writes, [])

    def test_currently_better_new_candidate_precedes_sustained_slower_candidate(self):
        self.reports.update(C=quality(1))
        self.seed('C', self.reports['C'], count=1)
        self.reports['A'] = quality(ok=False, switchable=True)
        self.tick()
        self.assertEqual(self.tick()['action'], 'switched')
        self.assertEqual(self.selected, 'C')

    def test_inventory_rejects_old_identity_epoch_and_age(self):
        self.reports.update(C=quality(100), D=quality(100))
        self.seed('C', quality(100))
        self.seed('D', quality(100))
        state = self.agent.state()
        state['nodes']['B']['at'] = self.now - 301
        state['nodes']['C']['statistics_epoch'] = 'old'
        state['nodes']['D']['identity'] = 'changed'
        rows = self.agent.inventory(self.snapshot(), state)
        self.assertFalse(rows['B']['fresh'])
        self.assertFalse(rows['C']['measured'])
        self.assertFalse(rows['D']['measured'])
        self.assertEqual(rows['C']['ranking']['observations'], 0)

    def test_new_epoch_does_not_inherit_old_node_cooldown(self):
        state = self.agent.state()
        state['nodes']['B'].update(statistics_epoch='old', cooldown_until=self.now + 500)
        self.agent.record(state, self.snapshot(), 'B', quality(100))
        self.assertEqual(state['nodes']['B']['cooldown_until'], 0)
        self.assertEqual(state['nodes']['B']['ranking']['observations'], 1)

    def test_rechecks_do_not_inflate_independent_statistics(self):
        self.assertEqual(self.tick()['action'], 'switched')
        state = self.agent.state()
        self.assertEqual(state['nodes']['B']['ranking']['observations'], 4)
        self.assertEqual(state['nodes']['A']['ranking']['observations'], 4)

    def test_status_coverage_has_all_nodes_without_probing_or_writing(self):
        self.reports.update(C=quality(100))
        before = self.agent.state()
        result = self.agent.status()
        self.assertEqual(result['coverage'], dict(total=3, measured=2, fresh=2, stable=2, pending=1, cooling=0, eligible=2))
        self.assertEqual({r['name'] for r in result['inventory']}, {'A', 'B', 'C'})
        row = next(r for r in result['inventory'] if r['name'] == 'B')
        self.assertTrue(row['available'])
        self.assertTrue(row['eligible'])
        self.assertEqual(row['age_seconds'], 60)
        self.assertEqual(row['tcp_ms'], 100)
        self.assertEqual(row['jitter_ms'], 0)
        self.assertEqual(before, self.agent.state())
        self.assertEqual(self.probes, [])
        self.assertEqual(self.writes, [])

    def test_coverage_distinguishes_stable_from_eligible_cooling_node(self):
        state = self.agent.state()
        state['nodes']['B']['cooldown_until'] = self.now + 100
        self.agent.save(state)
        result = self.agent.status()
        self.assertEqual(result['coverage']['stable'], 2)
        self.assertEqual(result['coverage']['eligible'], 1)
        row = next(r for r in result['inventory'] if r['name'] == 'B')
        self.assertTrue(row['available'])
        self.assertFalse(row['eligible'])

    def test_recovery_retries_cooling_node_only_after_120_seconds(self):
        state, snap = self.agent.state(), self.snapshot()
        self.agent.record(state, snap, 'B', quality(ok=False, switchable=True))
        self.now += 119
        self.assertEqual(self.agent.scan(snap, state, recovery=True), {})
        self.now += 1
        self.assertEqual(set(self.agent.scan(snap, state, recovery=True)), {'B'})
        self.assertEqual(state['nodes']['B']['cooldown_until'], 0)

    def test_healthy_scan_does_not_retry_cooling_node(self):
        state, snap = self.agent.state(), self.snapshot()
        self.agent.record(state, snap, 'B', quality(ok=False, switchable=True))
        self.now += 120
        self.assertEqual(self.agent.scan(snap, state, recovery=False), {})

    def test_failed_recovery_retry_extends_cooldown(self):
        state, snap = self.agent.state(), self.snapshot()
        self.reports['B'] = quality(ok=False, switchable=True)
        self.agent.record(state, snap, 'B', self.reports['B'])
        old = state['nodes']['B']['cooldown_until']
        self.now += 120
        self.agent.scan(snap, state, recovery=True)
        self.assertGreater(state['nodes']['B']['cooldown_until'], old)
        self.assertEqual(state['nodes']['B']['at'], self.now)

    def test_expired_success_is_not_displayed_as_currently_available(self):
        state = self.agent.state()
        state['nodes']['B']['at'] = self.now - 301
        self.agent.save(state)
        row = next(row for row in self.agent.status()['inventory'] if row['name'] == 'B')
        self.assertFalse(row['available'])
        self.assertFalse(row['stable'])
        self.assertFalse(row['eligible'])

    def test_recovery_prioritizes_expired_recent_success_only_for_reprobe(self):
        self.cfg['batch_size'] = 2
        self.reports.update(C=quality(150), D=quality(80))
        state, snap = self.agent.state(), self.snapshot()
        self.agent.record(state, snap, 'D', quality(80))
        state['nodes']['D']['at'] = self.now - 450
        state['nodes'].pop('B')
        self.assertFalse(self.agent.inventory(snap, state)['D']['fresh'])
        self.agent.scan(snap, state, recovery=True)
        self.assertEqual(state['evaluation']['priority'], ['D'])
        self.assertIn(('D', False), self.probes)
        self.assertTrue(self.agent.inventory(snap, state)['D']['fresh'])
        self.assertEqual(state['nodes']['D']['at'], self.now)

    def test_expired_recent_success_failed_reprobe_cannot_become_candidate(self):
        self.cfg['batch_size'] = 2
        self.reports.update(C=quality(150), D=quality(ok=False, switchable=True))
        state, snap = self.agent.state(), self.snapshot()
        self.agent.record(state, snap, 'D', quality(80))
        state['nodes']['D']['at'] = self.now - 450
        state['nodes'].pop('B')
        self.agent.scan(snap, state, recovery=True)
        self.assertEqual(state['evaluation']['priority'], ['D'])
        self.assertFalse(auto.stable(self.agent.inventory(snap, state)['D']))
        self.assertNotIn('D', state['evaluation']['stable_candidates'])
        self.assertEqual(self.writes, [])

    def test_success_older_than_ten_minutes_does_not_get_recovery_priority(self):
        self.cfg['batch_size'] = 2
        self.reports.update(C=quality(150), D=quality(80))
        state, snap = self.agent.state(), self.snapshot()
        self.agent.record(state, snap, 'D', quality(80))
        state['nodes']['D']['at'] = self.now - 601
        state['nodes'].pop('B')
        self.agent.scan(snap, state, recovery=True)
        self.assertEqual(state['evaluation']['priority'], [])
        self.assertNotIn(('D', False), self.probes)
        self.assertFalse(self.agent.inventory(snap, state)['D']['fresh'])

    def test_inactive_mode_never_scans_or_changes_selection(self):
        self.mode = 'rule'
        self.assertEqual(self.tick()['action'], 'inactive')
        self.assertEqual(self.probes, [])
        self.assertEqual(self.writes, [])

    def test_confirmed_outage_uses_cached_backup_before_inventory(self):
        self.cfg.update(interval_seconds=15, failure_scan_seconds=15, inventory_scan_seconds=15, batch_size=2)
        self.reports['A'] = quality(ok=False, switchable=True)
        self.reports.update(C=quality(50), D=quality(60))
        with patch.object(self.agent, 'scan', wraps=self.agent.scan) as scan:
            self.assertEqual(self.tick(15)['action'], 'failure-confirming')
            self.assertEqual(self.tick(15)['action'], 'switched')
        scan.assert_not_called()
        self.assertEqual(self.probes, [('A', True), ('A', True), ('B', False), ('B', True)])

    def test_failed_cached_backup_then_scan_shares_repeat_budget(self):
        self.cfg.update(candidate_rechecks=2, batch_size=2)
        self.reports['A'] = quality(ok=False, switchable=True)
        self.reports['B'] = quality(ok=False, switchable=True)
        calls = []
        def candidate(live):
            calls.append(live)
            return quality(100) if len(calls) == 1 else quality(ok=False, switchable=True)
        self.reports.update(C=candidate, D=quality(150))
        self.tick()
        self.assertEqual(self.tick()['action'], 'candidate-unstable')
        checks = self.agent.state()['evaluation']['rechecks']
        self.assertEqual([row['name'] for row in checks], ['B', 'C'])
        self.assertEqual(self.probes.count(('D', False)), 1)
        self.assertEqual(self.writes, [])

    def test_hard_recovery_bypasses_hour_and_manual_hold_but_attempts_are_spaced(self):
        self.reports['A'] = quality(ok=False, switchable=True)
        state = self.agent.state()
        state.update(hold_until=self.now + 600, attempts=[self.now] * 6,
                     last_attempt=self.now + 10)
        self.agent.save(state)
        self.assertEqual(self.tick(15)['action'], 'failure-confirming')
        self.assertEqual(self.tick(30)['action'], 'switched')

    def test_hard_recovery_attempt_spacing_is_thirty_seconds(self):
        self.cfg.update(interval_seconds=15, failure_scan_seconds=15)
        self.reports['A'] = quality(ok=False, switchable=True)
        state = self.agent.state()
        state.update(last_attempt=self.now + 10)
        self.agent.save(state)
        self.assertEqual(self.tick(15)['action'], 'failure-confirming')
        self.assertEqual(self.tick(15)['action'], 'switch-budget')
        self.assertEqual(self.tick(15)['action'], 'switched')

    def test_healthy_backup_refresh_does_not_starve_round_robin(self):
        self.cfg.update(batch_size=2, interval_seconds=15, inventory_scan_seconds=15)
        self.reports.update(C=quality(150), D=quality(150), E=quality(150), F=quality(150))
        state = self.agent.state()
        state['last_decision'] = self.now
        self.agent.save(state)
        batches = []
        for _ in range(6):
            self.tick(15)
            batches.append(self.agent.state()['evaluation']['scanned'])
        self.assertTrue(all(len(batch) == 2 for batch in batches))
        self.assertEqual(set().union(*map(set, batches)), {'B', 'C', 'D', 'E', 'F'})
        self.assertEqual(self.writes, [])

    def test_cached_outage_recovery_finishes_within_minute_probe_budget_model(self):
        self.cfg.update(interval_seconds=15, failure_scan_seconds=15, inventory_scan_seconds=15, batch_size=2)
        self.reports['A'] = quality(ok=False, switchable=True)
        start = self.now
        original = self.probe
        def timed_probe(snap, name, live=False):
            # DNS 2s + TCP 3s + parallel HTTPS 3s, plus isolated startup 1s.
            self.now += 8 if live else 9
            return original(snap, name, live)
        self.agent.probe.side_effect = timed_probe
        self.assertEqual(self.tick(15)['action'], 'failure-confirming')
        self.assertEqual(self.tick(15)['action'], 'switched')
        self.assertLessEqual(self.now - start, 65)
        self.assertEqual(len(self.writes), 1)

    def test_epoch_warmup_remeasures_recent_success_without_inheriting_score(self):
        self.cfg['batch_size'] = 2
        self.reports.update(C=quality(ok=False, switchable=True), D=quality(80))
        self.seed('D', quality(80), age=90)
        state = self.agent.state()
        for row in state['nodes'].values():
            row['statistics_epoch'] = 'previous-configuration'
        snap = self.snapshot()
        before = self.agent.inventory(snap, state)['D']
        self.assertFalse(before['measured'])
        self.assertFalse(before['fresh'])
        self.assertEqual(before['ranking']['observations'], 0)
        # B is newer, so it fills the first backup slot; then D fills the second.
        self.agent.scan(snap, state)
        self.assertEqual(state['evaluation']['priority'], ['B'])
        self.agent.scan(snap, state)
        self.assertEqual(state['evaluation']['priority'], ['D'])
        row = self.agent.inventory(snap, state)['D']
        self.assertTrue(row['measured'])
        self.assertTrue(row['fresh'])
        self.assertEqual(row['ranking']['observations'], 1)
        self.assertEqual(self.writes, [])

    def test_warmup_prioritizes_second_backup_over_refreshing_only_backup(self):
        self.cfg['batch_size'] = 2
        self.reports.update(C=quality(150), D=quality(80))
        self.seed('D', quality(80), age=90)
        state, snap = self.agent.state(), self.snapshot()
        self.agent.scan(snap, state)
        self.assertEqual(state['evaluation']['priority'], ['D'])
        self.assertEqual(set(state['evaluation']['scanned']), {'B', 'D'})

    def test_warmup_rejects_failed_changed_old_and_cooling_hints(self):
        self.cfg['batch_size'] = 2
        self.reports.update(C=quality(150), D=quality(80))
        self.seed('D', quality(80))
        for invalid in ('failed', 'identity', 'age', 'cooldown'):
            with self.subTest(invalid=invalid):
                state, snap = self.agent.state(), self.snapshot()
                row = state['nodes']['D']
                row['statistics_epoch'] = 'old'
                if invalid == 'failed': row.update(ok=False, stable=False)
                if invalid == 'identity': row['identity'] = 'changed-node'
                if invalid == 'age': row['at'] = self.now - 301
                if invalid == 'cooldown': row['cooldown_until'] = self.now + 100
                self.agent.scan(snap, state)
                self.assertNotIn('D', state['evaluation']['priority'])

    def test_failed_warmup_loses_priority_and_rotation_keeps_advancing(self):
        self.cfg['batch_size'] = 2
        self.reports.update(C=quality(150), D=quality(ok=False, switchable=True), E=quality(170))
        self.seed('D', quality(80), age=90)
        state, snap = self.agent.state(), self.snapshot()
        state['nodes']['D']['statistics_epoch'] = 'old'
        self.agent.scan(snap, state)
        self.assertEqual(state['evaluation']['priority'], ['D'])
        self.assertFalse(auto.stable(state['nodes']['D']))
        batches = [state['evaluation']['scanned']]
        for _ in range(4):
            self.agent.scan(snap, state)
            self.assertNotIn('D', state['evaluation']['priority'])
            batches.append(state['evaluation']['scanned'])
        self.assertEqual(set().union(*map(set, batches)), {'B', 'C', 'D', 'E'})
        self.assertEqual(self.writes, [])


# Do not rediscover the imported fixture as a second test class.
del Fixture
