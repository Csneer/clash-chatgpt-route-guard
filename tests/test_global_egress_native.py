"""Real isolated Mihomo + SOCKS5 + authenticated local TLS; no external traffic."""
import ipaddress
import os
import shutil
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

import yaml
import global_egress as egress
import mihomo_policy as policy


MIHOMO_BINARY = os.environ.get("MIHOMO_BINARY", shutil.which("mihomo") or "/usr/local/bin/mihomo")


def receive(sock, length):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise OSError("short SOCKS handshake")
        data += chunk
    return data


class LocalSocks(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            version, count = receive(self.request, 2)
            methods = receive(self.request, count)
            if version != 5 or 0 not in methods:
                raise OSError("unexpected SOCKS authentication")
            self.request.sendall(b"\x05\x00")
            version, command, reserved, kind = receive(self.request, 4)
            if (version, command, reserved, kind) != (5, 1, 0, 3):
                raise OSError("expected domain SOCKS CONNECT")
            host = receive(self.request, receive(self.request, 1)[0]).decode()
            port = int.from_bytes(receive(self.request, 2), "big")
            if host != "guard.test" or port != 443:
                raise OSError("test rejects unexpected destination")
            # Terminate the tunnel locally; never dial the requested destination.
            self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb")
            with self.server.tls.wrap_socket(self.request, server_side=True) as wrapped:
                request = b""
                while b"\r\n\r\n" not in request and len(request) < 32768:
                    chunk = wrapped.recv(4096)
                    if not chunk:
                        return
                    request += chunk
                path = request.split(b" ")[1]
                if path not in (b"/ip-a", b"/ip-b"):
                    raise OSError("unexpected trace endpoint")
                self.server.requests.append(path)
                body = self.server.public_ip.encode()
                wrapped.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                                b"Connection: close\r\nContent-Length: " + str(len(body)).encode()
                                + b"\r\n\r\n" + body)
        except (OSError, ValueError, IndexError) as error:
            self.server.errors.append(type(error).__name__)


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


@unittest.skipUnless(os.path.isfile(MIHOMO_BINARY) and os.path.isfile("/usr/bin/node"),
                     "set MIHOMO_BINARY and install Node for native egress regression")
class GlobalEgressNativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="egress-native-")
        self.addCleanup(self.tmp.cleanup)
        root = self.tmp.name
        cert, key = root + "/ca.pem", root + "/key.pem"
        result = subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048",
                                 "-nodes", "-keyout", key, "-out", cert, "-days", "1",
                                 "-subj", "/CN=guard.test", "-addext", "subjectAltName=DNS:guard.test"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        self.assertEqual(result.returncode, 0)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        self.servers = {}
        nodes = []
        for name, public_ip in (("A", "203.0.113.9"), ("B", "203.0.113.10")):
            server = Server(("127.0.0.1", 0), LocalSocks)
            server.tls, server.public_ip = tls, public_ip
            server.requests, server.errors = [], []
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            self.servers[name] = server
            nodes.append(dict(name=name, type="socks5", server="localhost", port=server.server_address[1]))
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        self.path, self.script = root + "/live.yaml", root + "/profile.js"
        self.config = {"mode": "global", "mixed-port": port, "allow-lan": False,
                       "bind-address": "127.0.0.1", "external-controller": "",
                       "external-controller-unix": root + "/controller.sock",
                       "ipv6": False, "log-level": "silent", "geo-auto-update": False,
                       "dns": {"enable": False}, "tun": {"enable": False},
                       "profile": {"store-selected": True}, "proxies": nodes,
                       "rules": ["MATCH,REJECT"]}
        with open(self.path, "w") as stream:
            yaml.safe_dump(self.config, stream)
        with open(self.script, "w") as stream:
            stream.write("function main(config) { return config; }\n")
        reservation.close()
        log = open(root + "/mihomo.log", "wb")
        self.addCleanup(log.close)
        self.process = subprocess.Popen([MIHOMO_BINARY, "-f", self.path, "-d", root],
                                        stdout=log, stderr=subprocess.STDOUT)
        self.addCleanup(self.stop)
        for _ in range(60):
            try:
                runtime = policy.api(self.config, "/configs")
                live = policy.api(self.config, "/proxies")["proxies"]
                if runtime.get("mode") == "global" and runtime.get("mixed-port") == port and "B" in live:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
            except OSError:
                pass
            if self.process.poll() is not None:
                self.fail("disposable Mihomo exited before initialization")
            time.sleep(.1)
        else:
            self.fail("disposable Mihomo did not initialize")
        self.cfg = dict(egress.DEFAULTS, clash_config=self.path, binary=MIHOMO_BINARY,
                        controller_unix=self.config["external-controller-unix"], profile_script=self.script,
                        state_dir=root + "/state", mutation_lock=root + "/mutation.lock",
                        probe_lock=root + "/probe.lock", business_proxy="http://127.0.0.1:" + str(port),
                        trace_urls=["https://guard.test/ip-a", "https://guard.test/ip-b"],
                        settle_seconds=0, sample_count=2, sample_gap_seconds=0, timeout_seconds=5)
        self.binder = egress.Binder(self.cfg)
        patcher = mock.patch.dict(os.environ, CURL_CA_BUNDLE=cert)
        patcher.start()
        self.addCleanup(patcher.stop)

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

    def test_user_switch_auto_binds_and_remembers_without_changing_global(self):
        original_pid = self.process.pid
        observed = {}
        original_probe = egress.common.ProbeProcess
        candidate_servers = []

        def local_probe(nodes, *args, **kwargs):
            # Fail before launching any candidate process if its upstream escapes loopback.
            for candidate in nodes:
                self.assertTrue(ipaddress.ip_address(candidate["server"]).is_loopback)
                self.assertIn(candidate["port"], [s.server_address[1] for s in self.servers.values()])
                candidate_servers.append(candidate["server"])
            return original_probe(nodes, *args, **kwargs)

        probe_guard = mock.patch.object(egress.common, "ProbeProcess", side_effect=local_probe)
        probe_guard.start()
        self.addCleanup(probe_guard.stop)
        for selected in ("A", "B", "A"):
            policy.api(self.config, "/proxies/GLOBAL", "PUT", {"name": selected})
            result = self.binder.cycle(immediate=True)
            self.assertEqual(result["action"], "bound")
            self.assertEqual(result["node"], selected)
            self.assertEqual(result["public_ip"], self.servers[selected].public_ip)
            self.assertTrue(ipaddress.ip_address(result["server"]).is_loopback)
            snap = self.binder.snapshot()
            self.assertEqual(snap["mode"], "global")
            self.assertEqual(snap["choices"], {"GLOBAL": selected})
            self.assertEqual(snap["node"]["server"], result["server"])
            self.assertEqual(self.process.pid, original_pid)
            if selected in observed:
                self.assertEqual(result["server"], observed[selected])
                self.assertFalse(result["reloaded"])
            else:
                self.assertTrue(result["reloaded"])
                observed[selected] = result["server"]
            # Restarting the binder and advancing time cannot expire the entry.
            restarted = egress.Binder(self.cfg)
            with mock.patch.object(restarted, "probe", side_effect=AssertionError("unexpected probe")), \
                    mock.patch.object(egress, "samples", side_effect=AssertionError("unexpected trace")):
                self.assertEqual(restarted.cycle()["action"], "keep")
            # A due health verification uses the existing route, never a new candidate.
            with mock.patch.object(restarted, "probe", side_effect=AssertionError("unexpected probe")), \
                    mock.patch.object(egress.time, "time", return_value=time.time() + 30 * 86400):
                self.assertEqual(restarted.cycle()["action"], "keep")
                self.assertEqual(restarted.snapshot()["node"]["server"], result["server"])
        self.assertTrue(candidate_servers)
        pins = egress.bindings_from_script(policy.read(self.script))
        self.assertEqual(set(pins), {"A", "B"})
        self.assertEqual({p["origin"] for p in pins.values()}, {"localhost"})
        self.assertEqual(set(self.binder.state()["bindings"]), {"A", "B"})
        for server in self.servers.values():
            self.assertGreaterEqual(len(server.requests), 8)
            self.assertEqual(set(server.requests), {b"/ip-a", b"/ip-b"})
            self.assertEqual(server.errors, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
