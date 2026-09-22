"""Provider-neutral YAML/controller helpers used by the guard."""
import http.client
import json
import os
import socket
import stat
import tempfile
import urllib.parse
import urllib.request

import yaml


class PolicyError(ValueError):
    pass


class UniqueLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        keys = set()
        for key, _ in node.value:
            if key.tag == 'tag:yaml.org,2002:merge':
                continue
            name = self.construct_object(key, deep=deep)
            try:
                if name in keys:
                    raise PolicyError('duplicate YAML mapping key')
                keys.add(name)
            except TypeError:
                raise PolicyError('non-scalar YAML mapping key')
        return super().construct_mapping(node, deep=deep)


def parse(text):
    try:
        value = yaml.load(text, Loader=UniqueLoader)
    except (yaml.YAMLError, TypeError, RecursionError):
        raise PolicyError('invalid YAML (details suppressed to protect credentials)')
    if not isinstance(value, dict):
        raise PolicyError('configuration must be a YAML mapping')
    if any(not isinstance(key, str) for key in value):
        raise PolicyError('top-level keys must be strings')
    return value


def read(path):
    with open(path, encoding='utf-8') as stream:
        return stream.read()


def replace_sections(text, changes):
    """Replace complete top-level YAML sections without regex rewriting."""
    root = yaml.compose(text)
    edits, found = [], set()
    for index, (key, value) in enumerate(root.value):
        if key.value not in changes:
            continue
        if key.start_mark.column != 0 or (key.value == 'proxy-groups' and value.flow_style):
            raise PolicyError('unsupported top-level section layout; refusing to rewrite')
        end = root.value[index + 1][0].start_mark.index if index + 1 < len(root.value) else len(text)
        replacement = yaml.safe_dump({key.value: changes[key.value]}, allow_unicode=True,
                                     default_flow_style=False, width=120)
        edits.append((key.start_mark.index, end, replacement + '\n'))
        found.add(key.value)
    for begin, end, replacement in sorted(edits, reverse=True):
        text = text[:begin] + replacement + text[end:]
    missing = {key: value for key, value in changes.items() if key not in found}
    if missing:
        offset = yaml.compose(text).value[0][0].start_mark.index
        text = text[:offset] + yaml.safe_dump(missing, allow_unicode=True,
                                               default_flow_style=False) + '\n' + text[offset:]
    return text


def atomic_write(path, text):
    info = os.stat(path)
    fd, temporary = tempfile.mkstemp(prefix='.policy-', dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
            os.fchown(stream.fileno(), info.st_uid, info.st_gid)
        os.replace(temporary, path)
        directory_fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        try:
            self.sock.connect(self.socket_path)
        except OSError:
            self.sock.close()
            self.sock = None
            raise


class UnixHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, socket_path):
        super().__init__()
        self.socket_path = socket_path

    def http_open(self, request):
        return self.do_open(lambda *args, **kwargs: UnixHTTPConnection(
            self.socket_path, *args, **kwargs), request)


class NoControllerRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def api(config, path, method='GET', data=None, timeout=3):
    """Call a loopback TCP controller, or an explicitly configured Unix socket."""
    controller = config.get('external-controller', '127.0.0.1:9090')
    socket_path = config.get('external-controller-unix')
    handlers = [urllib.request.ProxyHandler({})]
    if not config.get('external-controller') and socket_path is not None:
        if (not isinstance(socket_path, str) or not os.path.isabs(socket_path)
                or '\0' in socket_path):
            raise PolicyError('Unix controller must be an absolute local socket path')
        controller = 'localhost'
        handlers.extend([UnixHTTPHandler(socket_path), NoControllerRedirect()])
    else:
        try:
            address = urllib.parse.urlsplit('http://' + controller)
            valid = (address.hostname in ('127.0.0.1', '::1', 'localhost')
                     and address.port is not None and not address.username
                     and not address.password and not address.path
                     and not address.query and not address.fragment)
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise PolicyError('controller must be a loopback address')
    body = json.dumps(data).encode('utf-8') if data is not None else None
    request = urllib.request.Request('http://' + controller + path, data=body, method=method)
    if body is not None:
        request.add_header('Content-Type', 'application/json')
    if config.get('secret'):
        request.add_header('Authorization', 'Bearer ' + str(config['secret']))
    opener = urllib.request.build_opener(*handlers)
    with opener.open(request, timeout=timeout) as response:
        raw = response.read()
        return json.loads(raw) if raw else None
