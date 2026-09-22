import http.server
import json
import os
import socket
import socketserver
import tempfile
import threading
import time
import unittest
import urllib.error
from unittest.mock import patch

from mihomo_policy import PolicyError, api


class ControllerHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append((self.command, self.path, dict(self.headers), None))
        self.respond()

    def do_PUT(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.server.requests.append((self.command, self.path, dict(self.headers), json.loads(body)))
        self.respond()

    def respond(self):
        time.sleep(self.server.delay)
        payload = self.server.payload
        self.send_response(self.server.status)
        self.send_header('Content-Length', str(len(payload)))
        if self.server.status == 302:
            self.send_header('Location', 'https://example.invalid/escape')
        try:
            self.end_headers()
            self.wfile.write(payload)
        except BrokenPipeError:
            pass  # The timeout test disconnects before the response.

    def log_message(self, *_args):
        pass


class PolicyApiTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = os.path.join(self.directory.name, 'mihomo.sock')
        self.server = self.start_server(socketserver.UnixStreamServer(self.path, ControllerHandler))
        self.config = {'external-controller': '', 'external-controller-unix': self.path,
                       'secret': 'test-controller-secret'}

    def start_server(self, server):
        server.requests, server.payload, server.status, server.delay = [], b'{"mode":"global"}', 200, 0
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={'poll_interval': .01}, daemon=True)
        thread.start()

        def close():
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.addCleanup(close)
        return server

    def test_unix_get_authentication_and_no_environment_proxy(self):
        with patch.dict(os.environ, {'http_proxy': 'http://127.0.0.1:1', 'HTTP_PROXY': 'http://127.0.0.1:1', 'no_proxy': ''}):
            self.assertEqual(api(self.config, '/configs'), {'mode': 'global'})
        method, path, headers, body = self.server.requests[0]
        self.assertEqual((method, path, body), ('GET', '/configs', None))
        self.assertEqual(headers['Authorization'], 'Bearer test-controller-secret')

    def test_unix_put_json_and_empty_response(self):
        self.server.payload, self.server.status = b'', 204
        self.assertIsNone(api(self.config, '/proxies/GLOBAL', 'PUT', {'name': 'node'}))
        method, path, headers, body = self.server.requests[0]
        self.assertEqual((method, path, body), ('PUT', '/proxies/GLOBAL', {'name': 'node'}))
        self.assertEqual(headers['Content-Type'], 'application/json')

    def test_unix_http_error_and_timeout(self):
        self.server.status = 403
        with self.assertRaises(urllib.error.HTTPError) as caught:
            api(self.config, '/configs')
        self.assertEqual(caught.exception.code, 403)
        caught.exception.close()
        self.server.status, self.server.delay = 200, .1
        with self.assertRaises(socket.timeout):
            api(self.config, '/configs', timeout=.01)

    def test_unix_with_absent_tcp_controller(self):
        del self.config['external-controller']
        self.assertEqual(api(self.config, '/configs'), {'mode': 'global'})

    def test_unix_redirect_cannot_escape_to_another_controller(self):
        self.server.status = 302
        with self.assertRaises(urllib.error.HTTPError) as caught:
            api(self.config, '/configs')
        self.assertEqual(caught.exception.code, 302)
        caught.exception.close()

    def test_unix_path_and_socket_validation(self):
        self.config['external-controller-unix'] += '.missing'
        with self.assertRaises(urllib.error.URLError):
            api(self.config, '/configs')
        for path in ('relative.sock', '', '/tmp/bad\0socket', 12, []):
            with self.subTest(path=path):
                self.config['external-controller-unix'] = path
                with self.assertRaisesRegex(PolicyError, 'absolute local socket'):
                    api(self.config, '/configs')

    def test_explicit_tcp_controller_takes_precedence(self):
        tcp = self.start_server(http.server.HTTPServer(('127.0.0.1', 0), ControllerHandler))
        tcp.payload = b'{"source":"tcp"}'
        self.config['external-controller'] = '127.0.0.1:%d' % tcp.server_port
        self.config['external-controller-unix'] = 'invalid-and-unused'
        self.assertEqual(api(self.config, '/configs'), {'source': 'tcp'})
        self.assertEqual(self.server.requests, [])

    def test_non_loopback_tcp_is_not_bypassed_by_unix(self):
        self.config['external-controller'] = '192.0.2.1:9090'
        with self.assertRaisesRegex(PolicyError, 'loopback'):
            api(self.config, '/configs')

    def test_original_tcp_default_is_preserved(self):
        with patch('urllib.request.build_opener') as factory:
            factory.return_value.open.return_value.__enter__.return_value.read.return_value = b'{}'
            self.assertEqual(api({}, '/configs'), {})
        self.assertEqual(factory.return_value.open.call_args.args[0].full_url, 'http://127.0.0.1:9090/configs')


if __name__ == '__main__':
    unittest.main()
