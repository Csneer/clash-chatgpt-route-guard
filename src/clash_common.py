"""Shared, provider-neutral safety primitives for the route guard."""
import contextlib
import fcntl
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import time

import yaml

LOCK = os.environ.get('CLASH_MUTATION_LOCK', '/run/lock/clash-config-update.lock')
PROBE_LOCK = os.environ.get('CLASH_PROBE_LOCK', '/run/lock/clash-selector-probe.lock')


class SelectorError(RuntimeError):
    pass


@contextlib.contextmanager
def locked(path):
    with open(path, 'a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SelectorError('another update, switch, or evaluation is already running '
                                '(另一个更新/切换/评估正在进行)')
        yield


def save_json(path, value):
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.state-', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_json(path, default):
    try:
        with open(path, encoding='utf-8') as stream:
            return json.load(stream)
    except FileNotFoundError:
        return default
    except (ValueError, OSError):
        raise SelectorError('state file is damaged or unreadable: ' + path)


def fingerprint(node):
    return hashlib.sha256(json.dumps(node, sort_keys=True).encode('utf-8')).hexdigest()


def fetch(proxy, url, timeout=10):
    # -q must come first: do not inherit .curlrc cookies, auth or flags.
    args = ['/usr/bin/curl', '-q', '--noproxy', '', '--proxy', proxy,
            '--proto', '=https', '--connect-timeout', '4', '--max-time', str(timeout),
            '--max-filesize', '262144', '--silent', '--show-error',
            '--write-out', '\n__CLASH_METRICS__%{http_code}\t%{time_total}\t%{content_type}', url]
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=timeout + 3)
    except subprocess.TimeoutExpired:
        return {'exit': 28, 'code': 0, 'seconds': 0, 'content_type': '', 'body': ''}
    body, _, metrics = result.stdout.rpartition('\n__CLASH_METRICS__')
    try:
        code, elapsed, content_type = metrics.split('\t', 2)
        code, elapsed = int(code), float(elapsed)
    except (ValueError, TypeError):
        code, elapsed, content_type = 0, 0, ''
    return {'exit': result.returncode, 'code': code, 'seconds': elapsed,
            'content_type': content_type, 'body': body}


class ProbeProcess:
    """One isolated Mihomo with loopback listeners pinned to candidates."""
    def __init__(self, nodes, binary, client_fingerprint=None, allow_chains=False, ipv6=True):
        self.nodes, self.binary = nodes, binary
        self.client_fingerprint = client_fingerprint
        self.allow_chains, self.ipv6 = allow_chains, ipv6
        self.temp = self.process = self.log = None
        self.ports = {}

    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='clash-probe-')
        reservations = []
        try:
            lookup = {node['name']: node for node in self.nodes}

            def dependency(name, visiting):
                if name in visiting or name not in lookup:
                    raise SelectorError('candidate dependency is missing or cyclic')
                parent = lookup[name].get('dialer-proxy')
                if parent:
                    dependency(parent, visiting | {name})

            for name in lookup:
                dependency(name, set())
            listeners = []
            for index, node in enumerate(self.nodes):
                if node.get('dialer-proxy') and not self.allow_chains:
                    raise SelectorError('candidate depends on another outbound; chain probing is disabled')
                sock = socket.socket()
                sock.bind(('127.0.0.1', 0))
                reservations.append(sock)
                port = sock.getsockname()[1]
                self.ports[node['name']] = port
                listeners.append({'name': 'probe-' + str(index), 'type': 'http',
                                  'listen': '127.0.0.1', 'port': port, 'proxy': node['name']})
            config = {'mode': 'rule', 'allow-lan': False, 'bind-address': '127.0.0.1',
                      'port': 0, 'socks-port': 0, 'mixed-port': 0, 'redir-port': 0, 'tproxy-port': 0,
                      'ipv6': self.ipv6, 'log-level': 'silent', 'geo-auto-update': False,
                      'dns': {'enable': False}, 'tun': {'enable': False},
                      'profile': {'store-selected': False, 'store-fake-ip': False},
                      'proxies': self.nodes, 'listeners': listeners, 'rules': ['MATCH,REJECT']}
            if self.client_fingerprint:
                config['client-fingerprint'] = self.client_fingerprint
            path = os.path.join(self.temp.name, 'probe.yaml')
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                yaml.safe_dump(config, stream, allow_unicode=True, default_flow_style=False)
            args = [self.binary, '-f', path, '-d', self.temp.name]
            checked = subprocess.run(args + ['-t'], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, timeout=15)
            if checked.returncode:
                raise SelectorError('isolated probe configuration was rejected')
            for sock in reservations:
                sock.close()
            self.log = open(os.path.join(self.temp.name, 'probe.log'), 'wb')
            self.process = subprocess.Popen(args, stdout=self.log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 8
            pending = set(self.ports.values())
            while pending and time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise SelectorError('isolated probe process did not start')
                for port in list(pending):
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                            pending.remove(port)
                    except OSError:
                        pass
                if pending:
                    time.sleep(0.1)
            if pending:
                raise SelectorError('isolated probe listener did not become ready')
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise
        finally:
            for sock in reservations:
                sock.close()

    def proxy(self, name):
        return 'http://127.0.0.1:' + str(self.ports[name])

    def __exit__(self, *unused):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=4)
        if self.log:
            self.log.close()
        if self.temp:
            self.temp.cleanup()


def confirmed(message, yes=False):
    if yes:
        return True
    import sys
    if not sys.stdin.isatty():
        raise SelectorError('non-interactive changes require explicit confirmation')
    return input(message + ' [y/N] ').strip().lower() in ('y', 'yes')
