#!/usr/bin/env python3
"""Real loopback QUIC/TLS/HTTP3 fixtures. No TCP/HTTP2 fallback."""
import argparse
import asyncio
from contextlib import asynccontextmanager
import datetime
import hashlib
import importlib.metadata
import json
import logging
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import ssl
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCE_FILES = ["src/http/v3/ngx_http_v3_module.c", "src/http/v3/ngx_http_v3_request.c",
                "src/http/v3/ngx_http_v3_filter_module.c", "src/event/quic/ngx_event_quic_ssl.c",
                "src/event/quic/ngx_event_quic_openssl_compat.c", "src/event/quic/ngx_event_quic_transport.c"]
LIMIT = 2 * 1024 * 1024
TIMEOUT = 5
CLIENTS = []


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(value, message):
    if not value:
        raise AssertionError(message)


def source_hashes():
    return {name: digest((ROOT / name).read_bytes()) for name in SOURCE_FILES}


def dependency_identity():
    import aioquic
    lock = Path(__file__).with_suffix(".requirements.txt").read_text()
    expected = {}
    for line in lock.splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_-]+)==([^\s]+) --hash=sha256:([a-f0-9]{64})", line)
        require(match is not None, "Unsupported HTTP3 dependency lock line")
        expected[match[1]] = match[2]
    require(len(expected) == 10, "Incomplete HTTP3 client dependency lock")
    actual = {name: importlib.metadata.version(name) for name in expected}
    require(actual == expected, "Installed HTTP3 dependencies differ from the test lock; reinstall with --require-hashes")
    package = Path(aioquic.__file__).parent
    files = ["__init__.py", "asyncio/client.py", "asyncio/protocol.py", "h3/connection.py", "quic/connection.py", "tls.py"]
    return {"versions": actual, "lockSha256": digest(lock.encode()),
            "clientFilesSha256": {name: digest((package/name).read_bytes()) for name in files}}


def certify(prefix):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    now = datetime.datetime.now(datetime.timezone.utc)
    def make_ca(label):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1))
                .not_valid_after(now+datetime.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False, key_agreement=False,
                    key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
                .sign(key, hashes.SHA256()))
        return key, cert
    ca_key, ca = make_ca("X10 HTTP3 synthetic trusted CA")
    _, wrong_ca = make_ca("X10 HTTP3 synthetic unrelated CA")
    server_key = ec.generate_private_key(ec.SECP256R1())
    server = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
              .issuer_name(ca.subject).public_key(server_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=1))
              .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
              .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
              .sign(ca_key, hashes.SHA256()))
    for name, cert in [("ca.pem", ca), ("wrong-ca.pem", wrong_ca), ("server.pem", server)]:
        (prefix/name).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (prefix/name).chmod(0o600)
    key_path = prefix/"server.key"
    key_path.write_bytes(server_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600)


async def command(*args):
    process = await asyncio.create_subprocess_exec(*map(str, args), stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), TIMEOUT)
    except BaseException:
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise
    require(process.returncode == 0, f"Command failed ({process.returncode}): {stderr.decode(errors='replace')[-4096:]}")
    return stdout.decode(), stderr.decode()


def client_class():
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived, DataReceived
    from aioquic.quic.events import HandshakeCompleted, ConnectionTerminated, StreamReset
    class Client(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.http = H3Connection(self._quic)
            self.responses = {}
            self.handshakes = []
            self.terminated = None
            self.datagrams_received = 0
            self.transport_lost = False
            CLIENTS.append(self)

        def datagram_received(self, data, addr):
            self.datagrams_received += 1
            super().datagram_received(data, addr)

        def connection_lost(self, exc):
            self.transport_lost = True

        def quic_event_received(self, event):
            if isinstance(event, HandshakeCompleted):
                self.handshakes.append({"alpn": event.alpn_protocol, "earlyData": event.early_data_accepted,
                    "resumed": event.session_resumed})
            if isinstance(event, ConnectionTerminated):
                self.terminated = {"errorCode": event.error_code, "reason": event.reason_phrase}
                for response in self.responses.values():
                    if not response["done"].done():
                        response["done"].set_exception(ConnectionError(str(self.terminated)))
            if isinstance(event, StreamReset) and event.stream_id in self.responses:
                response = self.responses[event.stream_id]
                if not response["done"].done():
                    response["done"].set_exception(ConnectionError(f"Stream reset {event.error_code}"))
            for item in self.http.handle_event(event):
                if isinstance(item, (HeadersReceived, DataReceived)) and item.stream_id in self.responses:
                    response = self.responses[item.stream_id]
                    if isinstance(item, HeadersReceived):
                        response["headers"].extend(item.headers)
                    else:
                        response["body"].extend(item.data)
                        if item.data:
                            response["firstData"].set()
                        if len(response["body"]) > LIMIT:
                            if not response["done"].done():
                                response["done"].set_exception(RuntimeError("Response exceeded cap"))
                    if item.stream_ended and not response["done"].done():
                        response["done"].set_result(response)

        def begin(self, target, method="GET", body=b"", headers=()):
            stream = self._quic.get_next_available_stream_id()
            response = {"stream": stream, "headers": [], "body": bytearray(),
                "done": asyncio.get_running_loop().create_future(), "firstData": asyncio.Event()}
            self.responses[stream] = response
            fields = [(b":method", method.encode()), (b":scheme", b"https"),
                (b":authority", b"localhost"), (b":path", target.encode())] + list(headers)
            if body:
                fields.append((b"content-length", str(len(body)).encode()))
            self.http.send_headers(stream_id=stream, headers=fields, end_stream=not body)
            if body:
                for offset in range(0, len(body), 4093):
                    self.http.send_data(stream_id=stream, data=body[offset:offset+4093],
                        end_stream=offset+4093 >= len(body))
            self.transmit()
            return response

        async def request(self, *args, **kwargs):
            response = self.begin(*args, **kwargs)
            return await asyncio.wait_for(asyncio.shield(response["done"]), TIMEOUT)

        def cancel(self, response):
            # RFC9114 H3_REQUEST_CANCELLED (0x10c), both directions of this stream.
            self._quic.stop_stream(response["stream"], 0x10c)
            self._quic.reset_stream(response["stream"], 0x10c)
            response["done"].cancel()
            self.transmit()
    return Client


@asynccontextmanager
async def connected(port, ca, hostname="localhost", versions=None, factory=None):
    from aioquic.asyncio import connect
    from aioquic.quic.configuration import QuicConfiguration
    configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"], server_name=hostname,
        verify_mode=ssl.CERT_REQUIRED, cafile=str(ca), idle_timeout=1.5,
        max_data=4*LIMIT, max_stream_data=LIMIT)
    if versions is not None:
        configuration.supported_versions = versions
    async with connect("127.0.0.1", port, configuration=configuration,
                       create_protocol=factory or client_class()) as client:
        require(len(client.handshakes) == 1 and client.handshakes[0]["alpn"] == "h3", "QUIC did not negotiate ALPN h3")
        yield client


def response_check(response, status, body):
    fields = dict(response["headers"])
    require(fields.get(b":status") == str(status).encode(), f"Unexpected H3 status {fields!r}")
    require(fields.get(b"x-native-http3") == b"h3", "Native $http3 did not confirm h3")
    require(fields.get(b"x-native-protocol") == b"HTTP/3.0", "Native protocol is not HTTP/3.0")
    require(bytes(response["body"]) == body, "Response bytes differ")
    return {"streamId": response["stream"], "bytes": len(body), "sha256": digest(body)}


async def run(binary):
    report = {"schemaVersion": 1, "suite": "native-http3-interop", "startedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "identity": {}, "tests": [], "skips": [], "success": False, "fixtureErrors": [],
        "limitations": ["Synthetic loopback UDP QUIC/TLS1.3/H3, not full packet-loss/migration/fuzz/load or platform matrix.",
            "Single native process; no master/worker reload guarantee, HEAD, 0-RTT, resumption, client certificates or browser interoperability.",
            "Client package/module hashes identify this test dependency installation, not a signed attestation."]}
    prefix = None
    native = None
    backend = None
    backend_writers = set()
    backend_tasks = set()
    receipts = []
    barrier_seen = asyncio.Event()
    barrier_release = asyncio.Event()
    slow_closed = asyncio.Event()
    survivor_seen = asyncio.Event()
    survivor_release = asyncio.Event()
    cleanup_errors = []
    cancelled = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, cancelled.set)
    current = asyncio.current_task()
    async def monitor():
        await cancelled.wait()
        current.cancel()
    cancellation = asyncio.create_task(monitor())
    async def test(name, callback):
        if cancelled.is_set():
            raise asyncio.CancelledError()
        started = time.monotonic()
        try:
            detail = await asyncio.wait_for(callback(), 9)
            report["tests"].append({"name": name, "status": "passed", "elapsedMs": round((time.monotonic()-started)*1000), "detail": detail})
        except Exception as error:
            report["tests"].append({"name": name, "status": "failed", "error": f"{type(error).__name__}: {error}"})
            raise
    async def origin(reader, writer):
        backend_tasks.add(asyncio.current_task())
        backend_writers.add(writer)
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), TIMEOUT)
            require(len(head) <= 32768, "Backend header cap")
            lines = head[:-4].split(b"\r\n")
            method, target, protocol = lines[0].split(b" ")
            require(protocol == b"HTTP/1.1", "Unexpected backend protocol")
            headers = {}
            for line in lines[1:]:
                name, value = line.split(b":", 1)
                headers[name.lower()] = value.strip()
            require(b"transfer-encoding" not in headers, "Unexpected backend chunking")
            length = int(headers.get(b"content-length", b"0"))
            require(0 <= length <= LIMIT, "Backend body cap")
            body = await asyncio.wait_for(reader.readexactly(length), TIMEOUT)
            receipt = {"method": method.decode(), "target": target.decode(), "bytes": len(body), "sha256": digest(body),
                "token": headers.get(b"x-fixture-token", b"").decode()}
            receipts.append(receipt)
            if target.startswith(b"/barrier/"):
                if sum(r["target"].startswith("/barrier/") for r in receipts) == 6:
                    barrier_seen.set()
                await asyncio.wait_for(barrier_release.wait(), TIMEOUT)
                response_body = b"barrier:" + target + b"\0binary"
            elif target == b"/survive":
                survivor_seen.set()
                await asyncio.wait_for(survivor_release.wait(), TIMEOUT)
                response_body = b"unrelated-stream-survives-cancellation"
            elif target == b"/slow":
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n" + b"first"*1024)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1), TIMEOUT)
                require(data == b"", "Expected native upstream close after stream cancellation")
                slow_closed.set()
                return
            else:
                response_body = body
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: "
                + str(len(response_body)).encode() + b"\r\nConnection: close\r\n\r\n" + response_body)
            await writer.drain()
        except Exception as error:
            if not cancelled.is_set():
                report["fixtureErrors"].append(f"{type(error).__name__}: {error}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            backend_writers.discard(writer)
            backend_tasks.discard(asyncio.current_task())
    try:
        import aioquic
        require(aioquic.__version__ == "1.3.0", "Install the pinned HTTP3 test client lock")
        dependencies = dependency_identity()
        binary = binary.resolve(strict=True)
        require(binary.is_file() and os.access(binary, os.X_OK), "Selected native binary is not executable")
        before_binary = digest(binary.read_bytes())
        before_sources = source_hashes()
        _, version = await command(binary, "-V")
        require("--with-http_v3_module" in version, "Selected binary lacks required HTTP3 build module")
        report["identity"] = {"binary": str(binary), "binarySha256": before_binary, "versionOutput": version,
            "sourceFilesSha256": before_sources, "harnessSha256": digest(Path(__file__).read_bytes()),
            "python": sys.version, "platform": platform.platform(), "client": {"name": "aioquic", "version": aioquic.__version__},
            "dependencyVersions": dependencies["versions"], "clientFilesSha256": dependencies["clientFilesSha256"],
            "dependencyLockSha256": dependencies["lockSha256"], "interpreter": str(Path(sys.executable).absolute())}
        report["dependencyLockSha256"] = dependencies["lockSha256"]
        prefix = Path(tempfile.mkdtemp(prefix="x10-http3-"))
        prefix.chmod(0o700)
        (prefix/"logs").mkdir()
        certify(prefix)
        backend = await asyncio.start_server(origin, "127.0.0.1", 0, limit=32768)
        origin_port = backend.sockets[0].getsockname()[1]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        payload = bytes(range(256)) * 257 + b"native-http3\0\xff"
        (prefix/"payload.bin").write_bytes(payload)
        (prefix/"payload.bin").chmod(0o600)
        user = f"user {__import__('pwd').getpwuid(os.getuid()).pw_name};" if os.getuid() == 0 else ""
        config = f"""{user}
daemon off; master_process off; pid {prefix}/nginx.pid;
error_log {prefix}/error.log info;
events {{ worker_connections 256; }}
http {{ access_log off;
client_body_temp_path {prefix}/body;
proxy_temp_path {prefix}/proxy;
server {{ listen 127.0.0.1:{port} quic; server_name localhost;
ssl_certificate {prefix}/server.pem; ssl_certificate_key {prefix}/server.key;
ssl_protocols TLSv1.3; http3 on; quic_retry on; quic_gso off;
add_header X-Native-HTTP3 $http3 always;
add_header X-Native-Protocol $server_protocol always;
location = /payload.bin {{ root {prefix}; }}
location / {{ proxy_pass http://127.0.0.1:{origin_port}; proxy_http_version 1.1;
proxy_set_header Connection close; proxy_buffering off; proxy_ignore_client_abort off;
proxy_connect_timeout 1s; proxy_read_timeout 10s; proxy_send_timeout 2s;
}}
}} }}
"""
        (prefix/"nginx.conf").write_text(config)
        await command(binary, "-p", f"{prefix}/", "-c", prefix/"nginx.conf", "-t")
        native = await asyncio.create_subprocess_exec(str(binary), "-p", f"{prefix}/", "-c", str(prefix/"nginx.conf"),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        for _ in range(100):
            if (prefix/"nginx.pid").exists():
                break
            require(native.returncode is None, "Native exited before readiness")
            await asyncio.sleep(0.02)
        require((prefix/"nginx.pid").exists(), "Native PID file not created")
        report["identity"]["nativePid"] = native.pid
        report["scope"] = {"network": "loopback UDP QUIC", "tls": "TLS1.3", "alpn": "h3", "processMode": "single-native-process", "quicRetry": True}
        async def static():
            async with connected(port, prefix/"ca.pem") as client:
                response = await client.request("/payload.bin")
                result = response_check(response, 200, payload)
                headers = dict(response["headers"])
                report["protocol"] = {"negotiatedAlpn": client.handshakes[0]["alpn"],
                    "nativeHttp3": headers[b"x-native-http3"].decode(),
                    "nativeRequestProtocol": headers[b"x-native-protocol"].decode(),
                    "quicVersionHex": hex(client._quic._version)}
                return {**result, "handshake": client.handshakes[0], "receivedDatagrams": client.datagrams_received}
        await test("verified-quic-tls13-alpn-h3-exact-binary-response", static)
        async def range_case():
            async with connected(port, prefix/"ca.pem") as client:
                response = await client.request("/payload.bin", headers=[(b"range", b"bytes=127-4222")])
                result = response_check(response, 206, payload[127:4223])
                require(dict(response["headers"]).get(b"content-range") == f"bytes 127-4222/{len(payload)}".encode(), "Wrong native content range")
                return result
        await test("get-range-exact-bytes-and-content-range-over-h3", range_case)
        async def post():
            async with connected(port, prefix/"ca.pem") as client:
                before = len(receipts)
                response = await client.request("/echo?binary=1", method="POST", body=payload,
                    headers=[(b"x-fixture-token", b"h3-post")])
                result = response_check(response, 200, payload)
                require(len(receipts) == before+1 and receipts[-1] == {"method": "POST", "target": "/echo?binary=1",
                    "bytes": len(payload), "sha256": digest(payload), "token": "h3-post"}, "Native backend receipt differs")
                return {**result, "backendReceipt": receipts[-1]}
        await test("fragmented-h3-data-post-exact-native-backend-receipt", post)
        async def concurrent():
            async with connected(port, prefix/"ca.pem") as client:
                responses = [client.begin(f"/barrier/{i}") for i in range(6)]
                try:
                    await asyncio.wait_for(barrier_seen.wait(), TIMEOUT)
                    observed = [r for r in receipts if r["target"].startswith("/barrier/")]
                    require(len(observed) == 6 and {r["target"] for r in observed} == {f"/barrier/{i}" for i in range(6)},
                        "Backend barrier did not receive the exact six distinct targets")
                    require(all(not r["done"].done() for r in responses), "Concurrent barrier responded early")
                    barrier_release.set()
                    received = await asyncio.gather(*(r["done"] for r in responses))
                    details = [response_check(response, 200, f"barrier:/barrier/{i}".encode()+b"\0binary") for i, response in enumerate(received)]
                    require(len({r["streamId"] for r in details}) == 6, "H3 stream IDs not distinct")
                    return {"streams": details, "backendBarrierReceiptsBeforeRelease": len(observed),
                        "backendTargetsBeforeRelease": [r["target"] for r in observed], "handshakes": client.handshakes}
                finally:
                    barrier_release.set()
        await test("six-concurrent-h3-streams-with-real-upstream-barrier", concurrent)
        async def cancellation_case():
            async with connected(port, prefix/"ca.pem") as client:
                response = client.begin("/slow")
                await asyncio.wait_for(response["firstData"].wait(), TIMEOUT)
                require(any(r["target"] == "/slow" for r in receipts), "Slow stream not observed by native backend")
                survivor = client.begin("/survive")
                await asyncio.wait_for(survivor_seen.wait(), TIMEOUT)
                require(not survivor["done"].done(), "Unrelated stream was not in flight at cancellation")
                require(not response["done"].done() and not slow_closed.is_set(),
                    "Slow upstream/stream was already closed before cancellation")
                client.cancel(response)
                await asyncio.wait_for(slow_closed.wait(), TIMEOUT)
                require(not survivor["done"].done(), "Cancellation incorrectly completed the unrelated stream")
                survivor_release.set()
                surviving = response_check(await asyncio.wait_for(survivor["done"], TIMEOUT), 200,
                    b"unrelated-stream-survives-cancellation")
                after = response_check(await client.request("/payload.bin"), 200, payload)
                return {"cancelledStream": response["stream"], "receivedBeforeCancel": len(response["body"]),
                    "nativeBackendClosed": True, "unrelatedStreamHeldDuringCancellation": True,
                    "survivingStream": surviving, "afterCancellation": after, "handshakes": client.handshakes}
        await test("cancel-observed-stream-closes-upstream-and-preserves-other-streams", cancellation_case)
        async def certificate_negative(wrong_hostname):
            before = len(CLIENTS)
            try:
                async with connected(port, prefix/("ca.pem" if wrong_hostname else "wrong-ca.pem"),
                                     hostname="wrong.invalid" if wrong_hostname else "localhost"):
                    raise AssertionError("Untrusted certificate was accepted")
            except ConnectionError:
                pass
            require(len(CLIENTS) == before+1, "Negative control created no real QUIC client")
            failure = CLIENTS[-1].terminated
            require(failure and failure["errorCode"] == 0x100+42, f"Not TLS bad_certificate: {failure}")
            reason = failure["reason"]
            require(("hostname 'wrong.invalid' doesn't match" in reason) if wrong_hostname else
                    ("unable to get local issuer certificate" in reason.lower()), f"Not intended certificate verification failure: {reason}")
            require(not CLIENTS[-1].handshakes, "Rejected certificate nevertheless completed handshake")
            return failure
        await test("unrelated-ca-rejected-by-real-quic-tls-verification", lambda: certificate_negative(False))
        await test("wrong-hostname-rejected-by-real-quic-tls-verification", lambda: certificate_negative(True))
        report["receipts"] = receipts
    except asyncio.CancelledError:
        report["interrupted"] = True
        report["error"] = "Interrupted during native HTTP3 fixture"
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        cancellation.cancel()
        await asyncio.gather(cancellation, return_exceptions=True)
        barrier_release.set()
        survivor_release.set()
        for client in CLIENTS:
            for response in client.responses.values():
                if not response["done"].done():
                    response["done"].cancel()
                elif not response["done"].cancelled():
                    response["done"].exception()
            if client._transport and not client._transport.is_closing():
                client.close()
                client._transport.close()
            if client._timer:
                client._timer.cancel()
            if client._transmit_task:
                client._transmit_task.cancel()
        if native and native.returncode is None:
            native.send_signal(signal.SIGQUIT)
            try:
                await asyncio.wait_for(native.wait(), 2)
            except asyncio.TimeoutError:
                native.kill()
                await native.wait()
                cleanup_errors.append("Native SIGQUIT timed out")
        if backend:
            backend.close()
            await backend.wait_closed()
        for writer in tuple(backend_writers):
            writer.close()
        if backend_tasks:
            done, pending = await asyncio.wait(backend_tasks, timeout=2)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            if pending:
                cleanup_errors.append("Backend tasks required cancellation")
        close_deadline = loop.time() + 0.5
        while not all(client.transport_lost for client in CLIENTS) and loop.time() < close_deadline:
            await asyncio.sleep(0.01)
        native_log = ""
        if prefix:
            try:
                native_log = (prefix/"error.log").read_text()
            except FileNotFoundError:
                if native:
                    cleanup_errors.append("Native error log unavailable")
            report["nativeErrorLogTail"] = native_log[-8192:]
            shutil.rmtree(prefix)
        if report["identity"].get("binarySha256"):
            report["identity"]["binaryUnchangedDuringTest"] = digest(binary.read_bytes()) == report["identity"]["binarySha256"]
            report["sourceUnchangedDuringTest"] = source_hashes() == report["identity"]["sourceFilesSha256"]
            report["identity"]["clientUnchangedDuringTest"] = dependency_identity() == dependencies
        else:
            report["sourceUnchangedDuringTest"] = False
        report["unexpectedNativeErrors"] = [line for line in native_log.splitlines() if re.search(r"\[(?:crit|alert|emerg)\]", line)]
        report["cleanup"] = {"nativeStopped": native is None or native.returncode is not None,
            "nativeExit": native.returncode if native else None,
            "fixturesStopped": not backend_writers and not backend_tasks,
            "openSockets": len(backend_writers)+sum(1 for c in CLIENTS if c._transport and not c._transport.is_closing()),
            "temporaryRootRemoved": prefix is None or not prefix.exists(), "errors": cleanup_errors}
        report["cleanup"]["udpTransportsStopped"] = all(client.transport_lost for client in CLIENTS)
        report["cleanup"]["udpClientsCreated"] = len(CLIENTS)
        report["cleanup"]["udpClientsClosed"] = sum(client.transport_lost for client in CLIENTS)
        report["success"] = (len(report["tests"]) == 7 and all(t["status"] == "passed" for t in report["tests"])
            and not report.get("error") and not report["fixtureErrors"] and not report["unexpectedNativeErrors"]
            and report["identity"].get("binaryUnchangedDuringTest") is True and report["sourceUnchangedDuringTest"] is True
            and report["identity"].get("clientUnchangedDuringTest") is True and report["cleanup"]["udpTransportsStopped"]
            and report["cleanup"]["nativeStopped"] and report["cleanup"]["fixturesStopped"]
            and report["cleanup"]["openSockets"] == 0 and report["cleanup"]["temporaryRootRemoved"]
            and not cleanup_errors and native is not None and native.returncode == 0)
        report["finishedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(signum)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(os.environ.get("X10_NGINX_BINARY", ROOT/"x10/.build/objs/nginx")))
    parser.add_argument("--output", type=Path)
    options = parser.parse_args()
    logging.basicConfig(level=logging.CRITICAL)
    report = asyncio.run(run(options.binary))
    serialized = json.dumps(report, indent=2)+"\n"
    if options.output:
        options.output.parent.mkdir(parents=True, exist_ok=True)
        options.output.write_text(serialized)
    sys.stdout.write(serialized)
    return 0 if report["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
