#!/usr/bin/env python3
"""Demand guard tests; no external traffic and no production mutation."""
import datetime
import json
import os
import sqlite3
import sys
import time
import unittest
from unittest import mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
import clash_demand as d
import clash_guard as guard
import clash_common as common
import mihomo_policy as policy
from test_clash_guard import Base, report, write


def iso(t):
    return datetime.datetime.utcfromtimestamp(t).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def error_row(t=10000, rid='a', kind='StreamUpstreamError', message='socket hang up', provider='codex', **kw):
    return dict(ts=iso(t), error=dict(name=kind, message=message),
                context=dict(requestId=rid, provider=provider, **kw))


class DemandBase(Base):
    def setUp(self):
        super(DemandBase, self).setUp()
        self.db, self.log = [os.path.join(self.tmp.name, v) for v in ('calls.sqlite', 'error.jsonl')]
        with sqlite3.connect(self.db) as c:
            c.execute('CREATE TABLE call_records (completed_at TEXT, provider TEXT)')
        write(self.log, '')
        self.cfg.update(failure_count=3, failure_span_seconds=1200, failure_gap_seconds=1800,
                        same_ip_max_age_seconds=1800, cross_ip_failure_span_seconds=1200)
        self.cfg['activity'] = dict(enabled=True, strategy='faults-only', call_records_path=self.db,
                                    error_log_path=self.log, window_seconds=900, probe_cooldown_seconds=600,
                                    error_kinds=sorted(d.KINDS), **d.DEFAULTS)
        self.now = 10000
        p=mock.patch.object(guard.time, 'time', side_effect=lambda: self.now)
        p.start(); self.addCleanup(p.stop)
        # Initialize once, then advance past startup/manual hold without traffic.
        self.g.cycle()
        state=common.load_json(self.g.state_path,{})
        state.update(token=self.g.snapshot()['token'], hold_until=0)
        state['demand'].update(baseline_at=9000, consumed_until=9000)
        self.g.save(state)

    def errors(self, rows):
        write(self.log, ''.join(json.dumps(r)+'\n' for r in rows))

    def success(self, at, provider='codex'):
        with sqlite3.connect(self.db) as c:
            c.execute('INSERT INTO call_records VALUES (?,?)',(iso(at),provider))

    def batch(self, at, prefix='a'):
        self.errors([error_row(at-150,prefix+'1'),error_row(at-80,prefix+'2'),error_row(at-1,prefix+'3')])

    def run_cycle(self, value=None):
        with mock.patch.object(self.g,'business',return_value=value or report(False)) as b, \
                mock.patch.object(self.g,'evaluate') as e:
            result=self.g.cycle()
        return result,b,e

    def state(self):
        return common.load_json(self.g.state_path,{})


class EvidenceTests(DemandBase):
    def test_reader_avoids_historical_provider_scan(self):
        with sqlite3.connect(self.db) as db:
            db.execute('CREATE INDEX idx_provider ON call_records(provider)')
            db.execute('CREATE INDEX idx_completed ON call_records(completed_at)')
            db.executemany('INSERT INTO call_records VALUES (?,?)',
                           ((iso(self.now-5000-i),'codex') for i in range(3000)))
        self.success(self.now-1)
        original=sqlite3.connect
        statements=[]
        def connect(*args,**kw):
            connection=original(*args,**kw)
            connection.set_trace_callback(lambda sql: statements.append(sql))
            return connection
        with mock.patch.object(d.sqlite3,'connect',side_effect=connect):
            ev=d.evidence(self.cfg,self.now)
        self.assertTrue(ev['available']); self.assertAlmostEqual(ev['success_at'],self.now-1)
        query=next(s for s in statements if s.startswith('SELECT completed_at'))
        with original(self.db) as db:
            plan=' '.join(str(r) for r in db.execute('EXPLAIN QUERY PLAN '+query))
        self.assertIn('idx_completed',plan)
        self.assertNotIn('idx_provider',plan)
        self.assertNotIn('TEMP B-TREE',plan)

    def test_success_only_is_not_network_probe(self):
        self.success(self.now-1)
        r,b,e=self.run_cycle()
        self.assertEqual(r,'passive-healthy'); b.assert_not_called(); e.assert_not_called()

    def test_idle_skips_controller_and_business(self):
        with mock.patch.object(self.g,'snapshot') as s:
            r,b,e=self.run_cycle()
        self.assertEqual(r,'idle'); s.assert_not_called(); b.assert_not_called()

    def test_continuous_success_for_hours_never_probes(self):
        with mock.patch.object(self.g,'business') as b:
            for _ in range(10):
                self.now+=1800
                self.success(self.now-1)
                self.assertEqual(self.g.cycle(),'passive-healthy')
        b.assert_not_called()

    def test_client_abort_not_network_failure(self):
        self.errors([error_row(kind='StreamClientAbort',message='Client aborted stream')])
        self.assertFalse(d.evidence(self.cfg,self.now)['faults'])

    def test_upstream_overload_and_account_errors_excluded(self):
        for text in ('server_is_overloaded timeout','server_error socket closed','429 timeout','quota timeout',
                     'Unauthorized TLS handshake failed','certificate handshake failure','client aborted socket closed'):
            with self.subTest(text=text):
                self.assertFalse(d.network_error(error_row(message=text),d.settings(self.cfg)))

    def test_structured_status_beats_network_word(self):
        for status in (401,403,429,500,502,503,504,599,'502','504'):
            with self.subTest(status=status):
                self.assertFalse(d.network_error(error_row(message='socket closed',upstreamStatus=status),d.settings(self.cfg)))

    def test_server_error_text_never_becomes_network_evidence(self):
        for status in range(500,600):
            self.assertFalse(d.network_error(error_row(message='HTTP {} socket timeout'.format(status)),d.settings(self.cfg)))

    def test_unknown_message_does_not_trigger(self):
        self.assertFalse(d.network_error(error_row(message='unknown application error'),d.settings(self.cfg)))

    def test_missing_provider_does_not_trigger(self):
        r=error_row(); del r['context']['provider']
        self.assertFalse(d.network_error(r,d.settings(self.cfg)))

    def test_non_codex_provider_filtered(self):
        self.errors([error_row(provider='custom')]); self.success(self.now-1,'custom')
        ev=d.evidence(self.cfg,self.now)
        self.assertFalse(ev['faults']); self.assertEqual(ev['success_at'],0)

    def test_missing_request_id_filtered(self):
        r=error_row(); del r['context']['requestId']
        self.assertFalse(d.network_error(r,d.settings(self.cfg)))

    def test_network_kinds_recognized(self):
        for text in ('ETIMEDOUT','ECONNRESET','ECONNREFUSED','TLS handshake failed','unexpected EOF','socket hang up','connection reset','EAI_AGAIN'):
            with self.subTest(text=text): self.assertTrue(d.network_error(error_row(message=text),d.settings(self.cfg)))

    def test_premature_close_recognized(self):
        self.assertTrue(d.network_error(error_row(kind='StreamUpstreamPrematureClose',message='Upstream stream closed before terminal event'),d.settings(self.cfg)))

    def test_error_ids_hashed_no_raw_sensitive_fields(self):
        self.errors([error_row(rid='private-request',message='TLS handshake failed private string')])
        serialized=json.dumps(d.evidence(self.cfg,self.now))
        self.assertNotIn('private',serialized)
        self.assertNotIn('message',serialized)

    def test_database_missing_fail_closed_and_no_create(self):
        self.cfg['activity']['call_records_path']=os.path.join(self.tmp.name,'missing.db')
        # Update signature to ensure testing reader failure, not baseline.
        self.g.cycle()
        r,b,e=self.run_cycle()
        self.assertEqual(r,'success-records-unavailable'); b.assert_not_called()
        self.assertFalse(os.path.exists(self.cfg['activity']['call_records_path']))

    def test_missing_error_log_fail_closed_even_with_success(self):
        self.success(self.now-1)
        os.rename(self.log,self.log+'.backup')
        r,b,e=self.run_cycle(); self.assertEqual(r,'error-log-unavailable'); b.assert_not_called()

    def test_invalid_json_fail_closed(self):
        write(self.log,'{bad json}\n')
        self.assertFalse(d.evidence(self.cfg,self.now)['available'])

    def test_corrupt_existing_database_fail_closed(self):
        write(self.db,'not a database')
        self.batch(self.now)
        r,b,e=self.run_cycle()
        self.assertEqual(r,'success-records-unavailable'); b.assert_not_called(); e.assert_not_called()

    def test_incomplete_error_window_fail_closed(self):
        line=json.dumps(error_row(self.now-1))+'\n'
        write(self.log,line*((8*1024*1024)//len(line)+100))
        ev=d.evidence(self.cfg,self.now)
        self.assertFalse(ev['available'])
        self.assertEqual(ev['source_error'],'error-window-exceeds-read-limit')

    def test_partial_append_deferred(self):
        write(self.log,json.dumps(error_row())+'\n{"ts":')
        ev=d.evidence(self.cfg,self.now)
        self.assertTrue(ev['available']); self.assertEqual(len(ev['faults']),1)

    def test_log_rotation_does_not_keep_old_error(self):
        self.batch(self.now); self.run_cycle()
        os.rename(self.log,self.log+'.old'); write(self.log,'')
        r,b,e=self.run_cycle(); self.assertEqual(r,'idle'); b.assert_not_called()

    def test_future_and_expired_events_ignored(self):
        self.errors([error_row(self.now+10),error_row(self.now-901,'b')])
        self.success(self.now+100)
        ev=d.evidence(self.cfg,self.now)
        self.assertFalse(ev['faults']); self.assertEqual(ev['success_at'],0)

    def test_duplicate_retry_same_request_counts_once(self):
        self.errors([error_row(self.now-t,'same') for t in (200,100,1)])
        self.assertEqual(len(d.evidence(self.cfg,self.now)['faults']),1)

    def test_impossible_iso_date_ignored(self):
        self.assertEqual(d.stamp('2026-02-30T00:00:00.000Z'),0)


class TriggerTests(DemandBase):
    def test_three_errors_over_two_minutes_confirm_once(self):
        self.batch(self.now)
        r,b,e=self.run_cycle()
        self.assertEqual(r,'confirmed-failure-wait-new-demand'); b.assert_called_once(); e.assert_not_called()

    def test_two_errors_no_probe(self):
        self.errors([error_row(self.now-200,'a'),error_row(self.now-1,'b')])
        r,b,e=self.run_cycle(); b.assert_not_called()

    def test_three_errors_burst_not_enough_span(self):
        self.errors([error_row(self.now-t,str(t)) for t in (10,5,1)])
        r,b,e=self.run_cycle(); b.assert_not_called()

    def test_success_after_errors_suppresses_probe(self):
        self.batch(self.now); self.success(self.now)
        r,b,e=self.run_cycle(); self.assertEqual(r,'passive-healthy'); b.assert_not_called()

    def test_no_replaying_consumed_errors_even_after_cooldown(self):
        self.batch(self.now); self.run_cycle(); self.now+=650
        r,b,e=self.run_cycle(); self.assertEqual(r,'insufficient-new-errors'); b.assert_not_called()

    def test_retried_request_id_next_batch_not_new(self):
        self.batch(self.now,'same'); self.run_cycle(); self.now+=650
        self.batch(self.now,'same')
        r,b,e=self.run_cycle(); b.assert_not_called()

    def test_new_errors_cannot_bypass_diagnostic_cooldown(self):
        self.batch(self.now,'a'); self.run_cycle(); self.now+=200; self.batch(self.now,'b')
        r,b,e=self.run_cycle(); self.assertEqual(r,'diagnostic-cooldown'); b.assert_not_called()

    def test_new_batch_after_cooldown_can_confirm(self):
        self.batch(self.now,'a'); self.run_cycle(); self.now+=650; self.batch(self.now,'b')
        r,b,e=self.run_cycle(); b.assert_called_once()
        self.assertEqual(len(self.state()['failures']),2)

    def test_stopping_use_stops_diagnostics(self):
        self.batch(self.now); self.run_cycle(); self.now+=901
        r,b,e=self.run_cycle(); self.assertEqual(r,'idle'); b.assert_not_called()

    def test_confirmation_success_clears_old_errors(self):
        self.batch(self.now)
        r,b,e=self.run_cycle(report(True))
        self.assertEqual(r,'confirmed-recovered'); self.assertFalse(self.state()['failures'])
        self.now+=650
        r,b,e=self.run_cycle(); b.assert_not_called()

    def test_ambiguous_probe_no_switch(self):
        self.batch(self.now)
        r,b,e=self.run_cycle(report(False,switchable=False))
        self.assertEqual(r,'ambiguous-response'); e.assert_not_called()

    def test_pause_hold_pending_and_budget_all_prevent_probe(self):
        for update in ({'paused':True},{'pending':{'target':'B'}},{'hold_until':11000},
                       {'last_attempt':9990},{'attempts':[9500,9600]}):
            before=self.state(); st=dict(before,**update); self.g.save(st); self.batch(self.now)
            with self.subTest(update=update):
                r,b,e=self.run_cycle(); b.assert_not_called()
            self.g.save(before)

    def test_diagnostic_daily_budget(self):
        st=self.state(); st['demand']['probes']=[self.now-5000]*6; self.g.save(st)
        self.batch(self.now)
        r,b,e=self.run_cycle(); self.assertEqual(r,'diagnostic-daily-budget'); b.assert_not_called()

    def test_log_consumption_and_budget_written_before_probe(self):
        self.batch(self.now)
        def business():
            self.assertEqual(len(self.state()['demand']['probes']),1)
            self.assertEqual(len(self.state()['demand']['consumed_ids']),3)
            raise OSError('injected')
        with mock.patch.object(self.g,'business',side_effect=business):
            with self.assertRaises(OSError): self.g.cycle()
        self.now+=650
        r,b,e=self.run_cycle(); b.assert_not_called()

    def test_business_success_resets_old_failure_confirmations(self):
        self.batch(self.now); self.run_cycle(); self.now+=700; self.success(self.now-1)
        r,b,e=self.run_cycle(); self.assertFalse(self.state()['failures']); b.assert_not_called()

    def test_clash_logs_alone_never_trigger_and_are_read_each_tick(self):
        logs=dict(errors=20,cursor_us=1,available=True)
        with mock.patch.object(guard,'journal',return_value=logs) as j:
            r,b,e=self.run_cycle(); b.assert_not_called(); j.assert_called_once()
        self.assertEqual(self.state()['journal_errors'],20)

    def test_lock_busy_does_not_consume_probe_budget(self):
        self.batch(self.now)
        with common.locked(self.cfg['mutation_lock']):
            r,b,e=self.run_cycle()
        self.assertEqual(r,'busy'); b.assert_not_called(); self.assertFalse(self.state()['demand'].get('probes'))

    def test_manual_runtime_change_holds_before_probe(self):
        self.batch(self.now); self.live['Choice']['now']='C'
        r,b,e=self.run_cycle(); self.assertEqual(r,'runtime-selection-hold'); b.assert_not_called()

    def test_config_change_never_probes(self):
        self.batch(self.now); write(self.path,policy.read(self.path)+'\n# edit\n')
        r,b,e=self.run_cycle(); self.assertEqual(r,'baseline-hold'); b.assert_not_called()

    def test_time_backwards_resets_baseline(self):
        self.now-=100
        r,b,e=self.run_cycle(); self.assertEqual(r,'baseline-hold'); b.assert_not_called()


class EscalationTests(DemandBase):
    def prepare(self):
        st=self.state()
        st['demand'].update(confirmations=[8700,9350], last_confirmed=9350,
                            trace={'ip':'198.51.100.1','at':9350,'samples':1})
        self.g.save(st); self.batch(self.now)

    def test_full_escalation_same_ip_required(self):
        self.prepare()
        with mock.patch.object(self.g,'business',return_value=report(False)), \
                mock.patch.object(self.g,'evaluate',return_value=({'B':dict(report(),leaf='B')},{})) as e, \
                mock.patch.object(self.g,'transaction') as t:
            self.assertEqual(self.g.cycle(),'switched')
        self.assertEqual(e.call_count,2); self.assertEqual(t.call_args[1]['required_ip'],'198.51.100.1')

    def test_real_success_during_scan_cancels_without_switch(self):
        self.prepare()
        def evaluate(*args,**kw):
            self.success(self.now)
            return {'B':dict(report(),leaf='B')},{}
        with mock.patch.object(self.g,'business',return_value=report(False)), mock.patch.object(self.g,'evaluate',side_effect=evaluate), mock.patch.object(self.g,'transaction') as t:
            self.assertEqual(self.g.cycle(),'demand-ended-or-recovered')
        t.assert_not_called()

    def test_demand_expires_during_scan_cancels(self):
        self.prepare()
        def evaluate(*args,**kw):
            self.now+=901
            return {'B':dict(report(),leaf='B')},{}
        with mock.patch.object(self.g,'business',return_value=report(False)), mock.patch.object(self.g,'evaluate',side_effect=evaluate), mock.patch.object(self.g,'transaction') as t:
            self.assertEqual(self.g.cycle(),'demand-ended-or-recovered')
        t.assert_not_called()

    def test_same_ip_slow_candidate_beats_fast_different_exit(self):
        self.prepare()
        results={'B':dict(report(seconds=4),leaf='B'),'C':dict(report(ip='198.51.100.2',seconds=1),leaf='C')}
        with mock.patch.object(self.g,'business',return_value=report(False)),mock.patch.object(self.g,'evaluate',return_value=(results,{})),mock.patch.object(self.g,'transaction') as t:
            self.g.cycle()
        self.assertEqual(t.call_args[0][1],'B')

    def test_unknown_exit_can_cross_only_with_explicit_policy(self):
        import copy
        initial=copy.deepcopy(self.state())
        for allowed in (False,True):
            self.g.save(copy.deepcopy(initial))
            self.prepare(); self.cfg['allow_cross_ip']=allowed
            st=self.state(); st['demand']['signature']=common.fingerprint({'text':policy.read(self.path),'cfg':self.cfg,'manual':{}}); self.g.save(st)
            with mock.patch.object(self.g,'business',return_value=report(False,ip='')),mock.patch.object(self.g,'evaluate',return_value=({'B':dict(report(ip=''),leaf='B')},{})),mock.patch.object(self.g,'transaction') as t:
                self.g.cycle()
            self.assertEqual(t.called,allowed)

    def test_evaluation_daily_budget(self):
        self.prepare(); st=self.state(); st['demand']['evaluations']=[8000,8100]; self.g.save(st)
        r,b,e=self.run_cycle(); self.assertEqual(r,'evaluation-daily-budget'); e.assert_not_called()

    def test_recovered_before_scan_never_scans(self):
        self.prepare()
        with mock.patch.object(self.g,'business',side_effect=[report(False),report()]),mock.patch.object(self.g,'evaluate') as e:
            self.assertEqual(self.g.cycle(),'recovered-before-scan')
        e.assert_not_called()

    def test_changed_current_ip_before_switch_cancels(self):
        self.prepare()
        with mock.patch.object(self.g,'business',side_effect=[report(False),report(False),report(False,ip='198.51.100.2')]),mock.patch.object(self.g,'evaluate',return_value=({'B':dict(report(),leaf='B')},{})),mock.patch.object(self.g,'transaction') as t:
            self.assertEqual(self.g.cycle(),'current-egress-changed')
        t.assert_not_called()

    def test_observe_mode_never_transactions(self):
        self.cfg['mode']='observe'; self.prepare()
        st=self.state(); st['demand']['signature']=common.fingerprint({'text':policy.read(self.path),'cfg':self.cfg,'manual':{}}); self.g.save(st)
        with mock.patch.object(self.g,'business',return_value=report(False)),mock.patch.object(self.g,'evaluate',return_value=({'B':dict(report(),leaf='B')},{})),mock.patch.object(self.g,'transaction') as t:
            self.assertEqual(self.g.cycle(),'observe-only')
        t.assert_not_called()


class ProfileAndTraceTests(DemandBase):
    def test_cli_disabled_evidence_cannot_restore_periodic_polling(self):
        import yaml
        self.cfg['activity']={'enabled':False}
        path=os.path.join(self.tmp.name,'disabled.yaml'); write(path,yaml.safe_dump(self.cfg))
        with mock.patch.object(sys,'argv',['clash-guard','--profile',path,'check']), \
                mock.patch.object(guard.Guard,'cycle') as cycle:
            with self.assertRaises(guard.Error): guard.main()
        cycle.assert_not_called()

    def test_profile_rejects_old_strategy(self):
        import yaml
        self.cfg['activity'].pop('strategy')
        path=os.path.join(self.tmp.name,'profile.yaml'); write(path,yaml.safe_dump(self.cfg))
        with self.assertRaises(guard.Error): guard.profile(path)

    def test_profile_rejects_incompatible_ip_ttl(self):
        import yaml
        self.cfg['same_ip_max_age_seconds']=300
        path=os.path.join(self.tmp.name,'profile.yaml'); write(path,yaml.safe_dump(self.cfg))
        with self.assertRaises(guard.Error): guard.profile(path)

    def test_evidence_accumulates_across_diagnostic_interval(self):
        before=d.trace_evidence({},report(False),10000,1800)
        after=d.trace_evidence(before,report(False),10610,1800)
        self.assertEqual(after['samples'],2)

    def test_unknown_or_changed_ip_clears_old_evidence(self):
        before=d.trace_evidence({},report(False),10000,1800)
        self.assertFalse(d.trace_evidence(before,report(False,ip=''),10610,1800))
        self.assertEqual(d.trace_evidence(before,report(False,ip='198.51.100.2'),10610,1800)['samples'],1)

    def test_expired_trace_does_not_count(self):
        before=d.trace_evidence({},report(False),10000,1800)
        self.assertEqual(d.trace_evidence(before,report(False),12000,1800)['samples'],1)


if __name__=='__main__': unittest.main(verbosity=2)
