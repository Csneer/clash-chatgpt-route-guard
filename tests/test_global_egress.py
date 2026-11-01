import copy
import json
import os
import tempfile
import unittest
from unittest.mock import patch

import global_egress as egress


SCRIPT = "function main(config) { return config; }\n"


class MainLockTests(unittest.TestCase):
    def test_timer_tick_skips_active_manual_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = dict(egress.DEFAULTS, state_dir=directory)
            with patch.object(egress, "load_config", return_value=cfg), \
                    patch.object(egress.Binder, "cycle") as cycle, \
                    egress.common.locked(os.path.join(directory, "run.lock")):
                self.assertEqual(egress.main(["check"]), 0)
                cycle.assert_not_called()
                with self.assertRaises(egress.Error):
                    egress.main(["bind-now"])


def node(server="pool.example", name="US"):
    return dict(name=name, type="ss", server=server, port=2377,
                cipher="aes-128-gcm", password="test-secret", plugin="obfs",
                **{"plugin-opts": {"mode": "tls", "host": "transport.example"}})


def stable(server="192.0.2.1", public_ip="198.51.100.1", latency=1):
    return dict(server=server, stable=True, public_ip=public_ip,
                median_seconds=latency, unique_ips=[public_ip], samples=[])


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.config = {"proxies": [node()], "proxy-groups": []}
        self.live = {"GLOBAL": {"type": "Selector", "now": "US", "all": ["US"]}}

    def test_direct_and_nested_static_selection(self):
        self.assertEqual(egress.selected_leaf(self.config, self.live)[2], {"GLOBAL": "US"})
        self.config["proxy-groups"] = [{"name": "Manual", "type": "select", "proxies": ["US"]}]
        self.live["GLOBAL"].update(now="Manual", all=["Manual"])
        self.live["Manual"] = {"type": "Selector", "now": "US"}
        leaf, selected, choices = egress.selected_leaf(self.config, self.live)
        self.assertEqual((leaf, selected["server"], choices),
                         ("US", "pool.example", {"GLOBAL": "Manual", "Manual": "US"}))

    def test_dynamic_groups_and_unsafe_transports_are_rejected(self):
        for kind in ("fallback", "url-test", "load-balance"):
            with self.subTest(kind=kind):
                cfg = copy.deepcopy(self.config)
                cfg["proxy-groups"] = [{"name": "Auto", "type": kind, "proxies": ["US"]}]
                live = {"GLOBAL": {"type": "Selector", "now": "Auto", "all": ["Auto"]},
                        "Auto": {"type": "Selector", "now": "US"}}
                with self.assertRaises(egress.Error):
                    egress.selected_leaf(cfg, live)
        for change in ({"dialer-proxy": "FirstHop"}, {"tls": True},
                       {"plugin": "v2ray-plugin"}, {"type": "trojan"}):
            with self.subTest(change=change):
                cfg = copy.deepcopy(self.config)
                cfg["proxies"][0].update(change)
                with self.assertRaises(egress.Error):
                    egress.selected_leaf(cfg, self.live)


class RewriteTests(unittest.TestCase):
    def test_yaml_only_replaces_server_scalar(self):
        source = ("# preserved comment\nproxies:\n  - name: US\n    type: ss\n"
                  "    server: 'pool.example' # entry\n    port: 2377\n"
                  "    password: 'secret:#value'\n    plugin: obfs\n"
                  "    plugin-opts: {mode: tls, host: transport.example}\n"
                  "rules: [MATCH, US]\n")
        result = egress.replace_server(source, "US", "192.0.2.1")
        self.assertEqual(result, source.replace("'pool.example'", '\"192.0.2.1\"'))
        self.assertEqual(egress.replace_server(result, "US", "192.0.2.1"), result)

    @unittest.skipUnless(os.path.exists("/usr/bin/node"), "Node required for real script validation")
    def test_script_executes_after_subscription_regeneration_without_cross_origin_binding(self):
        pins = {"US": dict(origin="pool.example", server="192.0.2.1", type="ss", port=2377)}
        script = egress.rewrite_script(SCRIPT, pins)
        self.assertEqual(egress.bindings_from_script(script), pins)
        self.assertEqual(egress.rewrite_script(script, pins), script)
        for server, expected in (("pool.example", "192.0.2.1"), ("192.0.2.1", "192.0.2.1"),
                                 ("new-supplier.example", "new-supplier.example")):
            with self.subTest(server=server):
                original = {"proxies": [node(server)], "mode": "global"}
                desired = copy.deepcopy(original)
                desired["proxies"][0]["server"] = expected
                self.assertEqual(egress.evaluate_script({"node_binary": "/usr/bin/node"}, script, original), desired)
        for key, value in (("port", 1234), ("type", "socks5")):
            original = {"proxies": [node()]}
            original["proxies"][0][key] = value
            self.assertEqual(egress.evaluate_script({"node_binary": "/usr/bin/node"}, script, original), original)

    def test_ambiguous_script_is_rejected(self):
        with self.assertRaises(egress.Error):
            egress.rewrite_script(SCRIPT + SCRIPT, {})
        with self.assertRaises(egress.Error):
            egress.bindings_from_script(egress.BEGIN)


class SampleTests(unittest.TestCase):
    def test_all_samples_must_succeed_and_agree(self):
        cfg = dict(egress.DEFAULTS, sample_count=2, sample_gap_seconds=0)
        good = dict(body="198.51.100.1", code=200, exit=0, seconds=0.2)
        variations = [({}, True), ({"body": "198.51.100.2"}, False),
                      ({"exit": 35}, False), ({"code": 403}, False),
                      ({"body": "not an IP"}, False)]
        for change, expected in variations:
            with self.subTest(change=change):
                replies = [good, good, dict(good, **change), good]
                with patch.object(egress.common, "fetch", side_effect=replies) as fetch:
                    result = egress.samples(cfg, "http://127.0.0.1:1234")
                self.assertEqual(result["stable"], expected)
                self.assertEqual(result["public_ip"], "198.51.100.1" if expected else "")
                self.assertEqual(fetch.call_count, 4)


class BinderTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = self.directory.name
        self.cfg = dict(egress.DEFAULTS, state_dir=root, profile_script=root + "/profile.js",
                        clash_config=root + "/config.yaml", mutation_lock=root + "/mutation.lock",
                        probe_lock=root + "/probe.lock")
        self.binder = egress.Binder(self.cfg)
        self.snap = self.make_snapshot()
        self.snapshot = patch.object(self.binder, "snapshot", return_value=self.snap).start()
        self.addCleanup(patch.stopall)
        self.clock = patch.object(egress.time, "time", return_value=1000).start()
        self.probe = patch.object(self.binder, "probe", return_value=stable()).start()
        self.api = patch.object(egress.policy, "api", return_value={"connections": []}).start()
        self.resolve = patch.object(egress, "resolve", return_value=["192.0.2.1"]).start()

    def make_snapshot(self, name="US", server="pool.example", token="first", script=SCRIPT):
        selected = node(server, name)
        config = {"proxies": [selected], "mode": "global", "profile": {"store-selected": True}}
        return dict(mode="global", leaf=name, node=selected, choices={"GLOBAL": name},
                    selections={"GLOBAL": name}, token=token, script=script,
                    config=config, text=json.dumps(config), api={})

    def test_selection_change_restarts_settle_then_binds_new_node(self):
        with patch.object(self.binder, "commit", return_value={"action": "bound"}) as commit:
            self.assertEqual(self.binder.cycle()["action"], "settling")
            self.clock.return_value = 1004
            self.snapshot.return_value = self.make_snapshot(name="JP", token="second")
            self.assertEqual(self.binder.cycle()["action"], "settling")
            self.clock.return_value = 1008
            self.assertEqual(self.binder.cycle()["action"], "settling")
            self.probe.assert_not_called()
            self.clock.return_value = 1009
            self.assertEqual(self.binder.cycle()["action"], "bound")
            self.assertEqual(commit.call_args.args[0]["leaf"], "JP")

    def test_remembered_unchanged_binding_needs_no_probe(self):
        pins = {"US": dict(origin="pool.example", server="192.0.2.1", type="ss", port=2377)}
        snap = self.make_snapshot(server="192.0.2.1", script=egress.rewrite_script(SCRIPT, pins))
        self.snapshot.return_value = snap
        self.binder.save({"token": snap["token"], "bindings": {"US": dict(
            server="192.0.2.1", public_ip="198.51.100.1", identity=egress.entry_identity(snap["node"]))}})
        self.assertEqual(self.binder.cycle()["action"], "keep")
        self.probe.assert_not_called()
        self.api.assert_not_called()
        self.resolve.assert_not_called()

    def test_periodic_verification_retains_pin_on_success_failure_and_selection_race(self):
        pins = {"US": dict(origin="pool.example", server="192.0.2.1", type="ss", port=2377)}
        snap = self.make_snapshot(server="192.0.2.1", script=egress.rewrite_script(SCRIPT, pins))
        initial = {"token": snap["token"], "verified_at": 0, "bindings": {"US": dict(
            server="192.0.2.1", origin="pool.example", public_ip="198.51.100.1",
            identity=egress.entry_identity(snap["node"]))}}
        for scenario, checked, action in (("healthy", stable(), "keep"),
                ("drift", stable(public_ip="198.51.100.2"), "egress-check-failed"),
                ("race", stable(), "changed-during-verify")):
            with self.subTest(scenario=scenario):
                self.binder.save(copy.deepcopy(initial))
                self.snapshot.side_effect = [snap, dict(snap, token="changed") if scenario == "race" else snap]
                with patch.object(egress, "samples", return_value=checked) as sample, \
                        patch.object(egress.policy, "atomic_write") as write:
                    result = self.binder.cycle()
                self.assertEqual(result["action"], action)
                sample.assert_called_once_with(self.cfg, self.cfg["business_proxy"])
                write.assert_not_called()
                self.assertEqual(self.binder.state()["bindings"], initial["bindings"])
                self.assertEqual(self.binder.state()["verified_at"], 0 if scenario == "race" else 1000)
        self.probe.assert_not_called()
        self.api.assert_not_called()

    def test_rule_mode_never_writes_configuration(self):
        self.snapshot.return_value = {"mode": "rule"}
        self.binder.save({"token": "old"})
        with patch.object(egress.policy, "atomic_write") as write:
            self.assertEqual(self.binder.cycle(), {"action": "inactive", "mode": "rule"})
        write.assert_not_called()
        self.probe.assert_not_called()
        self.api.assert_not_called()
        self.assertIsNone(self.binder.state()["token"])

    def test_auto_group_is_inactive_for_binder(self):
        self.snapshot.return_value = {"mode": "global", "inactive": True,
                                      "reason": "managed-by-another-selector"}
        self.binder.save({"token": "old"})
        with patch.object(egress.policy, "atomic_write") as write:
            self.assertEqual(self.binder.cycle()["action"], "inactive")
        write.assert_not_called()
        self.probe.assert_not_called()
        self.assertFalse(self.binder.status()["active"])
        with self.assertRaises(egress.Error):
            self.binder.status(verify=True)

    def test_failure_enforces_cooldown(self):
        self.probe.return_value = dict(stable(), stable=False)
        with self.assertRaisesRegex(egress.Error, "no stable candidate"):
            self.binder.cycle(immediate=True)
        self.clock.return_value = 1001
        self.assertEqual(self.binder.cycle(immediate=True)["action"], "cooldown")
        self.assertEqual(self.probe.call_count, 1)

    def test_selection_race_discards_before_probe(self):
        self.snapshot.side_effect = [self.snap, self.make_snapshot(name="JP", token="changed")]
        with patch.object(self.binder, "commit") as commit:
            with self.assertRaisesRegex(egress.Error, "selection changed"):
                self.binder.cycle(immediate=True)
        commit.assert_not_called()
        self.probe.assert_not_called()

    def test_pending_transaction_blocks_even_snapshot(self):
        self.binder.save({"pending": {"backup": "existing-backup"}})
        with self.assertRaisesRegex(egress.Error, "unfinished binding"):
            self.binder.cycle(immediate=True)
        self.snapshot.assert_not_called()
        self.probe.assert_not_called()

    @unittest.skipUnless(os.path.exists("/usr/bin/node"), "Node required for commit validation")
    def test_adopting_same_server_updates_script_without_reload(self):
        snap = self.make_snapshot(server="192.0.2.1")
        current = dict(snap, token="bound")
        self.snapshot.side_effect = [snap, snap, current, current]
        with open(self.cfg["clash_config"], "w") as stream:
            stream.write(snap["text"])
        with open(self.cfg["profile_script"], "w") as stream:
            stream.write(SCRIPT)
        with patch.object(egress, "samples", return_value=stable()), \
                patch.object(self.binder, "validate") as validate:
            result = self.binder.commit(snap, stable(), {})
        self.assertEqual(result["action"], "bound")
        self.assertFalse(result["reloaded"])
        self.api.assert_not_called()
        validate.assert_not_called()
        with open(self.cfg["clash_config"]) as stream:
            self.assertEqual(stream.read(), snap["text"])
        with open(self.cfg["profile_script"]) as stream:
            self.assertEqual(egress.bindings_from_script(stream.read())["US"]["server"], "192.0.2.1")
        self.assertIsNone(self.binder.state()["pending"])
        self.assertEqual(self.binder.state()["bindings"]["US"]["public_ip"], "198.51.100.1")

    def test_returning_to_saved_node_only_tests_saved_entry_and_requires_same_public_ip(self):
        self.binder.save({"bindings": {"US": dict(server="192.0.2.8", origin="pool.example",
            public_ip="198.51.100.8", identity=egress.entry_identity(self.snap["node"]))}})
        self.probe.return_value = stable(server="192.0.2.8", public_ip="198.51.100.9")
        with patch.object(self.binder, "commit") as commit:
            with self.assertRaisesRegex(egress.Error, "expected public IP"):
                self.binder.cycle(immediate=True)
        self.resolve.assert_not_called()
        self.probe.assert_called_once_with(self.snap, "192.0.2.8")
        commit.assert_not_called()

    def test_existing_live_entry_preferred_over_faster_candidate(self):
        self.resolve.return_value = ["192.0.2.1", "192.0.2.2"]
        self.probe.side_effect = [stable(latency=0.1), stable(server="192.0.2.2", latency=0.8)]
        self.api.return_value = {"connections": [{"chains": ["US", "GLOBAL"],
            "metadata": {"remoteDestination": "192.0.2.2"}}]}
        with patch.object(self.binder, "commit", return_value={"action": "bound"}) as commit:
            self.binder.cycle(immediate=True)
        self.assertEqual(commit.call_args.args[1]["server"], "192.0.2.2")

    @unittest.skipUnless(os.path.exists("/usr/bin/node"), "Node required for commit validation")
    def test_failed_postcheck_keeps_backup_and_blocks_future_writes(self):
        snap = self.make_snapshot(server="192.0.2.1")
        current = dict(snap, token="bound")
        self.snapshot.side_effect = [snap, snap, current]
        with open(self.cfg["profile_script"], "w") as stream:
            stream.write(SCRIPT)
        with patch.object(egress, "samples", return_value=stable(public_ip="198.51.100.9")):
            with self.assertRaisesRegex(egress.Error, "does not match"):
                self.binder.commit(snap, stable(), {})
        state = self.binder.state()
        self.assertTrue(state["pending"])
        with open(state["pending"]["backup"]) as stream:
            backup = json.load(stream)
        self.assertEqual(backup, {"script": SCRIPT, "runtime": snap["text"]})
        self.api.assert_not_called()
        self.snapshot.reset_mock()
        with self.assertRaisesRegex(egress.Error, "unfinished binding"):
            self.binder.cycle(immediate=True)
        self.snapshot.assert_not_called()

    @unittest.skipUnless(os.path.exists("/usr/bin/node"), "Node required for legacy adoption validation")
    def test_legacy_adoption_preserves_subscription_domain_binding(self):
        legacy = ("function main(config) {\n" + egress.LEGACY_BEGIN + "\n"
                  "for (const proxy of config.proxies || []) {\n"
                  "  if (proxy.name === 'US' && proxy.server === 'pool.example') {\n"
                  "    proxy.server = '192.0.2.1';\n"
                  "  }\n}\n" + egress.LEGACY_END + "\nreturn config; }\n")
        snap = self.make_snapshot(server="192.0.2.1", script=legacy)
        snap["origin_node"] = node("pool.example")
        current = dict(snap, token="adopted")
        self.snapshot.side_effect = [snap, snap, current, current]
        with open(self.cfg["profile_script"], "w") as stream:
            stream.write(legacy)
        with open(self.cfg["clash_config"], "w") as stream:
            stream.write(snap["text"])
        with patch.object(egress, "samples", return_value=stable()):
            result = self.binder.commit(snap, stable(), {})
        self.assertFalse(result["reloaded"])
        self.api.assert_not_called()
        with open(self.cfg["profile_script"]) as stream:
            adopted = stream.read()
        self.assertNotIn(egress.LEGACY_BEGIN, adopted)
        binding = egress.bindings_from_script(adopted)["US"]
        self.assertEqual(binding["origin"], "pool.example")
        self.assertEqual(binding["server"], "192.0.2.1")
        regenerated = copy.deepcopy(snap["config"])
        regenerated["proxies"] = [node("pool.example")]
        output = egress.evaluate_script(self.cfg, adopted, regenerated)
        self.assertEqual(output, snap["config"])
        self.assertEqual(self.binder.state()["bindings"]["US"]["origin"], "pool.example")

    @unittest.skipUnless(os.path.exists("/usr/bin/node"), "Node required for multi-node legacy adoption")
    def test_legacy_a_is_preserved_when_current_selection_b_is_bound(self):
        legacy = ("function main(config) {\n" + egress.LEGACY_BEGIN + "\n"
                  "for (const proxy of config.proxies || []) {\n"
                  "  if (proxy.name === 'A') proxy.server = '192.0.2.1';\n"
                  "}\n" + egress.LEGACY_END + "\nreturn config; }\n")
        snap = self.make_snapshot(name="B", server="b.example", script=legacy)
        snap["config"]["proxies"].insert(0, node("192.0.2.1", "A"))
        snap["config"]["proxies"].append(node("untouched.example", "C"))
        snap["config"]["rules"] = ["DOMAIN,private.example,DIRECT", "MATCH,B"]
        snap["config"]["dns"] = {"enable": False}
        snap["text"] = json.dumps(snap["config"])
        snap["origin_nodes"] = {"A": node("a.example", "A"), "B": node("b.example", "B"),
                                "C": node("untouched.example", "C")}
        snap["origin_node"] = snap["origin_nodes"]["B"]
        expected = copy.deepcopy(snap["config"])
        expected["proxies"][1]["server"] = "192.0.2.2"
        current = dict(snap, token="both-bound", config=expected, node=expected["proxies"][1])
        self.snapshot.side_effect = [snap, snap, current, current]
        candidate = stable(server="192.0.2.2")
        with open(self.cfg["profile_script"], "w") as stream:
            stream.write(legacy)
        with open(self.cfg["clash_config"], "w") as stream:
            stream.write(snap["text"])
        with patch.object(egress, "samples", return_value=candidate), \
                patch.object(self.binder, "validate"):
            result = self.binder.commit(snap, candidate, {})
        self.assertTrue(result["reloaded"])
        self.api.assert_called_once_with({}, "/configs?force=false", "PUT",
                                         {"path": self.cfg["clash_config"]}, timeout=15)
        with open(self.cfg["profile_script"]) as stream:
            adopted = stream.read()
        self.assertEqual(egress.bindings_from_script(adopted), {
            "A": dict(origin="a.example", server="192.0.2.1", type="ss", port=2377),
            "B": dict(origin="b.example", server="192.0.2.2", type="ss", port=2377)})
        regenerated = copy.deepcopy(snap["config"])
        regenerated["proxies"] = list(snap["origin_nodes"].values())
        self.assertEqual(egress.evaluate_script(self.cfg, adopted, regenerated), expected)
        with open(self.cfg["clash_config"]) as stream:
            self.assertEqual(egress.policy.parse(stream.read()), expected)
        self.assertEqual(current["choices"], {"GLOBAL": "B"})

    def test_legacy_adoption_without_original_node_refuses_all_writes(self):
        legacy = ("function main(config) {\n" + egress.LEGACY_BEGIN + "\n"
                  + egress.LEGACY_END + "\nreturn config; }\n")
        snap = self.make_snapshot(server="192.0.2.1", script=legacy)
        self.snapshot.return_value = snap
        with patch.object(egress.policy, "atomic_write") as write, \
                patch.object(self.binder, "save") as save:
            with self.assertRaisesRegex(egress.Error, "original subscription node"):
                self.binder.commit(snap, stable(), {})
        write.assert_not_called()
        save.assert_not_called()
        self.api.assert_not_called()

    def test_commit_race_never_mutates_files(self):
        self.snapshot.return_value = dict(self.snap, token="changed")
        with patch.object(egress.policy, "atomic_write") as write:
            with self.assertRaisesRegex(egress.Error, "changed during sampling"):
                self.binder.commit(self.snap, stable(), {})
        write.assert_not_called()
        self.api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
