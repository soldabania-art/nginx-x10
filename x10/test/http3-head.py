#!/usr/bin/env python3
"""Independent libcurl/ngtcp2 HTTP/3 HEAD interoperability; loopback only."""
import argparse
import datetime
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
LOCK = Path(__file__).with_suffix('.requirements.txt')
SOURCE_FILES = ['src/http/v3/ngx_http_v3_module.c', 'src/http/v3/ngx_http_v3_request.c',
                'src/http/v3/ngx_http_v3_filter_module.c', 'src/event/quic/ngx_event_quic_ssl.c',
                'src/event/quic/ngx_event_quic_transport.c']
REQUEST_TIMEOUT = 3
CAP = 2 * 1024 * 1024
ACTIVE = None
INTERRUPTED = None


class FixtureInterrupted(RuntimeError):
    # selectors treats InterruptedError as EINTR and can swallow it.
    pass


def check_interrupted():
    if INTERRUPTED is not None:
        raise FixtureInterrupted(f'Fixture interrupted by {INTERRUPTED}')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(value, message):
    if not value:
        raise AssertionError(message)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sources():
    return {p: digest((ROOT / p).read_bytes()) for p in SOURCE_FILES}


def identity():
    import curl_cffi
    text = LOCK.read_text()
    expected = {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([A-Za-z0-9_-]+)==([^\s]+) --hash=sha256:([a-f0-9]{64})', line)
        require(match is not None, 'Invalid independent HTTP3 client lock')
        require(match[1] not in expected, 'Duplicate dependency in lock')
        expected[match[1]] = match[2]
    require(set(expected) == {'curl_cffi', 'certifi', 'cffi', 'pycparser'}, 'Incomplete independent client lock')
    require(expected['curl_cffi'] == '0.16.3', 'Unexpected curl_cffi version in lock')
    actual = {name: importlib.metadata.version(name) for name in expected}
    require(actual == expected, 'Installed independent HTTP3 dependencies differ from lock')
    package = Path(curl_cffi.__file__).parent
    files = ['__init__.py', 'curl.py', 'const.py', '_wrapper.abi3.so']
    return {'versions': actual, 'lockSha256': digest(text.encode()),
            'clientFilesSha256': {name: digest((package / name).read_bytes()) for name in files}}


def sockets():
    result = []
    for p in Path('/proc/self/fd').iterdir():
        if int(p.name) <= 2:  # Node may supply socket-backed standard streams.
            continue
        try:
            target = os.readlink(p)
            if target.startswith('socket:['):
                result.append(target)
        except FileNotFoundError:
            pass
    return sorted(result)


def resolve_child(pid, binary):
    # /proc can be mounted from an ancestor PID namespace in Work mode.
    own_status = Path('/proc/self/status').read_text()
    parent = int(re.search(r'^Pid:\s+(\d+)$', own_status, re.M)[1])
    pid_namespace = os.readlink('/proc/self/ns/pid')
    matches = []
    entries = [p for p in Path('/proc').iterdir() if p.name.isdecimal()]
    require(len(entries) <= 10000, 'Too many processes for bounded native identity resolution')
    for proc in entries:
        try:
            text = (proc / 'status').read_text()
            pids = [int(x) for x in re.search(r'^NSpid:\s+([0-9\t ]+)$', text, re.M)[1].split()]
            ppid = int(re.search(r'^PPid:\s+(\d+)$', text, re.M)[1])
            uid = int(re.search(r'^Uid:\s+(\d+)', text, re.M)[1])
            if pids[-1] == pid and ppid == parent and uid == os.getuid() and os.readlink(proc / 'ns/pid') == pid_namespace:
                require(os.readlink(proc / 'exe') == str(binary), 'Native child executable differs')
                stat = (proc / 'stat').read_text().rsplit(') ', 1)[1].split()
                require(stat[0] != 'Z', 'Native child is a zombie')
                matches.append({'procPid': int(proc.name), 'pidNamespace': pid_namespace, 'startTicks': stat[19]})
        except (FileNotFoundError, PermissionError, TypeError):
            continue
    require(len(matches) <= 1, 'Ambiguous native child process identity')
    return matches[0] if matches else None


def request_worker(spec):
    from curl_cffi import Curl, CurlOpt, CurlInfo, CurlHttpVersion, CurlError
    require(spec['host'] in ('localhost', 'wrong.invalid'), 'Worker destination is not a fixture host')
    require(isinstance(spec['port'], int) and 1 <= spec['port'] <= 65535, 'Invalid fixture port')
    require(spec['method'] in ('GET', 'HEAD'), 'Invalid fixture method')
    require(spec['target'] == '/payload.bin', 'Invalid fixture target')
    require(not sockets(), 'Worker inherited an unexpected socket')
    body, headers = bytearray(), bytearray()
    def collect(target, cap):
        def append(data):
            if len(target) + len(data) > cap:
                return 0xffffffff  # CURL_WRITEFUNC_ERROR; no unbounded response buffers.
            target.extend(data)
            return len(data)
        return append
    c = Curl(cacert=spec['ca'])
    result = {'method': spec['method'], 'requestedHttpVersion': 'V3ONLY',
              'verifyPeer': True, 'verifyHost': 2, 'bodyBytes': 0,
              'clientVersion': c.version().decode()}
    try:
        opts = {CurlOpt.URL: f"https://{spec['host']}:{spec['port']}{spec['target']}",
                CurlOpt.HTTP_VERSION: CurlHttpVersion.V3ONLY, CurlOpt.SSL_VERIFYPEER: 1,
                CurlOpt.SSL_VERIFYHOST: 2, CurlOpt.CAINFO: spec['ca'],
                CurlOpt.PROXY: '', CurlOpt.NOPROXY: '*',
                CurlOpt.RESOLVE: [f"{spec['host']}:{spec['port']}:127.0.0.1".encode()],
                CurlOpt.CONNECTTIMEOUT_MS: 1500, CurlOpt.TIMEOUT_MS: REQUEST_TIMEOUT * 1000,
                CurlOpt.FOLLOWLOCATION: 0, CurlOpt.NOSIGNAL: 1,
                CurlOpt.WRITEFUNCTION: collect(body, 128 * 1024),
                CurlOpt.HEADERFUNCTION: collect(headers, 64 * 1024)}
        if spec['method'] == 'HEAD':
            opts[CurlOpt.NOBODY] = 1
        else:
            opts[CurlOpt.HTTPGET] = 1
        for opt, value in opts.items():
            c.setopt(opt, value)
        try:
            c.perform()
            result['curlCode'] = 0
        except CurlError as exc:
            result['curlCode'] = int(exc.code)
            result['error'] = str(exc)[:4096]
        result.update(status=c.getinfo(CurlInfo.RESPONSE_CODE), httpVersion=c.getinfo(CurlInfo.HTTP_VERSION),
                      sslVerifyResult=c.getinfo(CurlInfo.SSL_VERIFYRESULT), primaryIp=c.getinfo(CurlInfo.PRIMARY_IP).decode(),
                      primaryPort=c.getinfo(CurlInfo.PRIMARY_PORT), bodyBytes=len(body), bodySha256=digest(body),
                      rawHeaders=headers.decode('iso-8859-1'))
        result['socketCountBeforeHandleClose'] = len(sockets())
    finally:
        c.close()
        result['socketCountAfterHandleClose'] = len(sockets())
    require(result['socketCountAfterHandleClose'] == 0, 'Curl close left a live socket')
    return result


def command(args, *, input_bytes=None, timeout=5):
    global ACTIVE
    check_interrupted()
    process = subprocess.Popen([str(x) for x in args], stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    ACTIVE = process
    output = {process.stdout: bytearray(), process.stderr: bytearray()}
    deadline = time.monotonic() + timeout
    try:
        if input_bytes is not None:
            require(len(input_bytes) <= 4096, 'Worker request exceeds cap')
            process.stdin.write(input_bytes)
            process.stdin.close()
        with selectors.DefaultSelector() as selector:
            for stream in output:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                check_interrupted()
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'Fixture command timed out')
                for key, _ in selector.select(min(0.05, remaining)):
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    output[key.fileobj].extend(data)
                    require(sum(map(len, output.values())) <= CAP, 'Child output exceeds fixture cap')
        process.wait(timeout=max(0.001, deadline-time.monotonic()))
        return process.returncode, bytes(output[process.stdout]), bytes(output[process.stderr])
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        raise
    finally:
        if process.stdin is not None:
            process.stdin.close()
        process.stdout.close()
        process.stderr.close()
        ACTIVE = None


def checked(args):
    code, stdout, stderr = command(args)
    require(code == 0, f'Fixture command exited {code}: {stderr.decode(errors="replace")[-4096:]}')
    return stdout.decode(), stderr.decode()


def certify(prefix):
    # All private keys remain in the private temporary fixture prefix.
    for name in ['ca', 'wrong-ca']:
        checked(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                 '-nodes', '-keyout', prefix / f'{name}.key', '-out', prefix / f'{name}.pem',
                 '-subj', f'/CN=X10 independent HTTP3 {name}', '-days', '1',
                 '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
    checked(['openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
             '-nodes', '-keyout', prefix / 'server.key', '-out', prefix / 'server.csr', '-subj', '/CN=localhost'])
    (prefix / 'server.ext').write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n')
    checked(['openssl', 'x509', '-req', '-in', prefix / 'server.csr', '-CA', prefix / 'ca.pem',
             '-CAkey', prefix / 'ca.key', '-CAcreateserial', '-out', prefix / 'server.pem',
             '-days', '1', '-extfile', prefix / 'server.ext'])
    for p in prefix.iterdir():
        p.chmod(0o600)


def fields(response):
    headers = {}
    lines = response['rawHeaders'].split('\r\n')
    require(lines[0].startswith('HTTP/3 '), 'Client did not expose HTTP3 status headers')
    for line in lines[1:]:
        if not line:
            continue
        name, value = line.split(':', 1)
        name = name.lower()
        require(name not in headers, f'Duplicate response field {name}')
        headers[name] = value.strip()
    return headers


def run(binary):
    global INTERRUPTED
    report = {'schemaVersion': 1, 'suite': 'native-http3-head-interop', 'startedAt': now(),
              'success': False, 'tests': [], 'skips': [], 'identity': {}, 'fixtureErrors': [],
              'limitations': ['Independent libcurl/ngtcp2 client on loopback; no browser/loss/migration/platform matrix.',
                              'HEAD body is the zero bytes exposed by libcurl; this is interoperability, not a packet-level proof of absent DATA.',
                              'Separate from unchanged aioquic HEAD diagnostic; no claim that aioquic HEAD is fixed.',
                              'Local hashes and build records are consistency checks, not signed build attestations.']}
    prefix, native = None, None
    before_binary, before_source, before_deps = None, None, None
    before_harness = digest(Path(__file__).read_bytes())
    before_launcher = digest(Path(__file__).with_suffix('.mjs').read_bytes())
    child_results, cleanup_errors = [], []
    native_exit = None
    try:
        require(sys.platform == 'linux', 'Independent HTTP3 fixture requires Linux /proc socket checks')
        before_deps = identity()
        binary = binary.resolve(strict=True)
        require(binary.is_file() and os.access(binary, os.X_OK), 'Selected native binary is not executable')
        before_binary, before_source = digest(binary.read_bytes()), sources()
        _, version = checked([binary, '-V'])
        require('--with-http_v3_module' in version, 'Selected binary lacks HTTP3 build module')
        report['identity'] = {'binary': str(binary), 'binarySha256': before_binary, 'versionOutput': version,
                              'sourceFilesSha256': before_source, 'harnessSha256': before_harness, 'launcherSha256': before_launcher,
                              'observedSourceCheckout': str(ROOT),
                              'python': sys.version, 'platform': platform.platform(), 'interpreter': str(Path(sys.executable).absolute()),
                              'client': {'name': 'curl_cffi', 'version': '0.16.3'}, **before_deps}
        report['dependencyLockSha256'] = before_deps['lockSha256']
        prefix = Path(tempfile.mkdtemp(prefix='x10-http3-head-'))
        prefix.chmod(0o700)
        certify(prefix)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]; sock.close()
        payload = bytes(range(256)) * 257 + b'independent-head\0\xff'
        (prefix / 'payload.bin').write_bytes(payload)
        (prefix / 'payload.bin').chmod(0o600)
        user = f"user {__import__('pwd').getpwuid(os.getuid()).pw_name};" if os.getuid() == 0 else ''
        config = f'''{user}
daemon off; master_process off; pid {prefix}/nginx.pid;
error_log {prefix}/error.log info;
events {{ worker_connections 128; }}
http {{ access_log off;
client_body_temp_path {prefix}/body;
server {{ listen 127.0.0.1:{port} quic; server_name localhost;
ssl_certificate {prefix}/server.pem; ssl_certificate_key {prefix}/server.key;
ssl_protocols TLSv1.3; http3 on; quic_retry on; quic_gso off;
add_header X-Native-HTTP3 $http3 always;
add_header X-Native-Protocol $server_protocol always;
add_header X-Native-Method $request_method always;
location = /payload.bin {{ root {prefix}; }}
}} }}
'''
        (prefix / 'nginx.conf').write_text(config)
        checked([binary, '-p', f'{prefix}/', '-c', prefix / 'nginx.conf', '-t'])
        native = subprocess.Popen([str(binary), '-p', f'{prefix}/', '-c', str(prefix / 'nginx.conf')],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        report['identity']['nativePid'] = native.pid
        deadline = time.monotonic() + 3
        listener = None
        proc_identity = None
        while listener is None:
            require(native.poll() is None and time.monotonic() < deadline, 'Native did not become ready')
            pidfile = prefix / 'nginx.pid'
            if pidfile.exists() and pidfile.read_text().strip() == str(native.pid):
                proc_identity = resolve_child(native.pid, binary)
                if proc_identity is None:
                    time.sleep(0.01)
                    continue
                proc_pid = proc_identity['procPid']
                owned = set()
                try:
                    for fd in Path(f'/proc/{proc_pid}/fd').iterdir():
                        try:
                            owned.add(os.readlink(fd))
                        except FileNotFoundError:
                            pass
                    for line in Path(f'/proc/{proc_pid}/net/udp').read_text().splitlines()[1:]:
                        values = line.split()
                        if values[1] == f'0100007F:{port:04X}' and f'socket:[{values[9]}]' in owned:
                            listener = {'address': '127.0.0.1', 'port': port, 'socketInode': values[9]}
                except FileNotFoundError:
                    pass
            if listener is None:
                time.sleep(0.01)
        require(resolve_child(native.pid, binary) == proc_identity, 'Native child identity changed during readiness')
        report['identity']['nativeProcIdentity'] = proc_identity
        report['identity']['nativeUdpListener'] = listener
        print(f'HTTP3 HEAD native started: pid={native.pid} prefix={prefix}', file=sys.stderr, flush=True)
        report['scope'] = {'network': 'loopback UDP QUIC', 'processMode': 'single-native-process',
                           'requestedHttpVersion': 'V3ONLY', 'tls': 'TLS1.3', 'quicRetry': True}
        def request(method, *, ca='ca.pem', host='localhost'):
            spec = {'port': port, 'method': method, 'ca': str(prefix / ca), 'host': host, 'target': '/payload.bin'}
            code, stdout, stderr = command([sys.executable, Path(__file__), '--request-worker'],
                                           input_bytes=json.dumps(spec).encode(), timeout=REQUEST_TIMEOUT+2)
            require(code == 0, f'Independent client worker exited {code}: {stderr.decode(errors="replace")[-4096:]}')
            require(not stderr, f'Unexpected client stderr: {stderr.decode(errors="replace")[-4096:]}')
            result = json.loads(stdout)
            require(result.get('socketCountAfterHandleClose') == 0, 'Independent client sockets not closed')
            child_results.append(result)
            return result
        def positive(method):
            r = request(method)
            require(r['curlCode'] == 0, f'Independent {method} failed: {r.get("error")}')
            require(r['status'] == 200 and r['httpVersion'] == 30 and r['sslVerifyResult'] == 0,
                    f'Unexpected verified H3 result: {r}')
            require(r['primaryIp'] == '127.0.0.1' and r['primaryPort'] == port, 'Client left the loopback fixture')
            h = fields(r)
            require(h.get('x-native-http3') == 'h3' and h.get('x-native-protocol') == 'HTTP/3.0', 'Native did not confirm H3')
            require(h.get('x-native-method') == method, 'Native method differs')
            require(h.get('content-length') == str(len(payload)), 'Content-Length differs from GET representation')
            body = payload if method == 'GET' else b''
            require(r['bodyBytes'] == len(body) and r['bodySha256'] == digest(body), f'{method} body differs')
            report['protocol'] = {'nativeHttp3': h['x-native-http3'], 'nativeRequestProtocol': h['x-native-protocol'],
                                  'clientHttpVersion': r['httpVersion'], 'requestedHttpVersion': 'V3ONLY'}
            return r
        def negative(**kwargs):
            r = request('HEAD', **kwargs)
            require(r['curlCode'] == 60 and r['status'] == 0 and r['bodyBytes'] == 0, 'Expected certificate-specific rejection')
            reason = r.get('error', '').lower()
            if 'ca' in kwargs:
                require('certificate' in reason and ('issuer' in reason or 'verify failed' in reason), 'Not an issuer-verification failure')
            else:
                require('certificate' in reason and ('subject name' in reason or 'hostname' in reason), 'Not a hostname-verification failure')
            return r
        cases = [('independent-verified-h3-get-exact-representation', lambda: positive('GET')),
                 ('independent-verified-h3-head-status-headers-empty-api-body', lambda: positive('HEAD')),
                 ('independent-h3-head-wrong-ca-rejected', lambda: negative(ca='wrong-ca.pem')),
                 ('independent-h3-head-wrong-hostname-rejected', lambda: negative(host='wrong.invalid'))]
        for name, operation in cases:
            check_interrupted()
            started = time.monotonic()
            try:
                detail = operation()
                report['tests'].append({'name': name, 'status': 'passed', 'elapsedMs': round((time.monotonic()-started)*1000), 'detail': detail})
            except BaseException as exc:
                report['tests'].append({'name': name, 'status': 'failed', 'error': f'{type(exc).__name__}: {exc}'})
                raise
        report['success'] = True
    except BaseException as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'
    finally:
        if ACTIVE is not None and ACTIVE.poll() is None:
            ACTIVE.kill(); ACTIVE.wait(timeout=2)
        if native is not None:
            try:
                if native.poll() is None:
                    native.send_signal(signal.SIGQUIT)
                native_exit = native.wait(timeout=3)
                require(native_exit == 0, f'Native exited {native_exit}')
            except BaseException as exc:
                cleanup_errors.append(str(exc))
                if native.poll() is None:
                    native.kill(); native.wait(timeout=2)
        if prefix is not None:
            try:
                log = (prefix / 'error.log').read_text() if (prefix / 'error.log').exists() else ''
                report['nativeErrorLogTail'] = log[-8192:]
                report['unexpectedNativeErrors'] = [line for line in log.splitlines() if re.search(r'\[(emerg|alert|crit)\]', line)]
                require(not report['unexpectedNativeErrors'], 'Native logged critical errors')
                shutil.rmtree(prefix)
            except BaseException as exc:
                cleanup_errors.append(str(exc))
        try:
            report['sourceUnchangedDuringTest'] = before_source is not None and sources() == before_source
            report['identity']['binaryUnchangedDuringTest'] = before_binary is not None and digest(binary.read_bytes()) == before_binary
            report['identity']['clientUnchangedDuringTest'] = before_deps is not None and identity() == before_deps
        except BaseException as exc:
            cleanup_errors.append(str(exc))
        report['cleanup'] = {'nativeStopped': native is not None and native.poll() is not None,
                             'nativeExit': native_exit, 'fixturesStopped': ACTIVE is None,
                             'clientProcessesCompleted': len(child_results),
                             'clientSocketsClosed': bool(child_results) and all(r['socketCountAfterHandleClose'] == 0 for r in child_results),
                             'openSockets': len(sockets()), 'temporaryRootRemoved': prefix is not None and not prefix.exists(),
                             'errors': cleanup_errors}
        report['identity']['harnessUnchangedDuringTest'] = digest(Path(__file__).read_bytes()) == before_harness
        report['identity']['launcherUnchangedDuringTest'] = digest(Path(__file__).with_suffix('.mjs').read_bytes()) == before_launcher
        report['interruptedSignal'] = INTERRUPTED
        if cleanup_errors or not report['cleanup']['nativeStopped'] or report['cleanup']['openSockets'] != 0 or INTERRUPTED is not None:
            report['success'] = False
        if not report.get('sourceUnchangedDuringTest') or not report['identity'].get('binaryUnchangedDuringTest') or not report['identity'].get('clientUnchangedDuringTest') or not report['identity']['harnessUnchangedDuringTest'] or not report['identity']['launcherUnchangedDuringTest']:
            report['success'] = False
        report['finishedAt'] = now()
    return report


def interrupted(number, _frame):
    global INTERRUPTED
    if INTERRUPTED is not None:
        return
    INTERRUPTED = signal.Signals(number).name
    raise FixtureInterrupted(f'Fixture interrupted by {INTERRUPTED}')


def main():
    if sys.argv[1:] == ['--request-worker']:
        result = request_worker(json.loads(sys.stdin.buffer.read(4096)))
        print(json.dumps(result))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path(os.environ.get('X10_NGINX_BINARY', ROOT / 'x10/.build/objs/nginx')))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    report = run(args.binary)
    text = json.dumps(report, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text, end='')
    return 0 if report['success'] else 1


if __name__ == '__main__':
    sys.exit(main())
