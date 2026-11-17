"""Local fakes for the tests and `egressguard demo`: a throwaway CA and HTTPS servers that record requests.

Everything listens on 127.0.0.1 only. Nothing here is used by `egressguard run` against real traffic.
"""

from __future__ import annotations

import datetime as dt
import json
import socket
import ssl
import threading
from collections.abc import Iterable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import TracebackType
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_fake_pki(directory: Path, hosts: Iterable[str]) -> Path:
    """Write `upstream-ca.pem` (a stand-in for a public CA) and `<host>.pem` (cert + key) per host."""
    directory.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = _name("egressguard fake upstream CA (testing only)")
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = directory / "upstream-ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for host in hosts:
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(host))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(hours=1))
            .not_valid_after(now + dt.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
            )
            .sign(ca_key, hashes.SHA256())
        )
        (directory / f"{host}.pem").write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
            + key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return ca_path


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, name: str, ctx: ssl.SSLContext, owner: FakeUpstream) -> None:
        self.name = name
        self.ctx = ctx
        self.owner = owner
        super().__init__(("127.0.0.1", 0), _Handler)

    def get_request(self) -> tuple[Any, Any]:
        sock, addr = self.socket.accept()
        with self.owner.lock:
            self.owner.connections[self.name] += 1
        return self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass  # aborted handshakes are expected in negative tests


class _Handler(BaseHTTPRequestHandler):
    server: _Server
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        self.request.settimeout(10)
        self.request.do_handshake()
        super().setup()

    def _handle(self) -> None:
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        rec = {
            "server": self.server.name,
            "method": self.command,
            "path": self.path,
            # Canonical names: a client may reach the proxy over HTTP/2, whose header names are lowercase.
            "headers": {"-".join(w.capitalize() for w in k.split("-")): v for k, v in self.headers.items()},
            "body": body.decode("utf-8", "replace"),
        }
        self.server.owner.record(rec)
        out = json.dumps({"ok": True, "server": self.server.name}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = do_PUT = _handle

    def log_message(self, format: str, *args: Any) -> None:
        pass


class FakeUpstream:
    """One HTTPS server per fake host name, each on its own free port of 127.0.0.1."""

    def __init__(self, pki_dir: Path, hosts: Iterable[str], record_file: Path | None = None) -> None:
        self.hosts = list(hosts)
        self.lock = threading.Lock()
        self.requests: list[dict[str, Any]] = []
        self.connections: dict[str, int] = dict.fromkeys(self.hosts, 0)
        self.record_file = record_file
        self._servers: dict[str, _Server] = {}
        for host in self.hosts:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(pki_dir / f"{host}.pem")
            self._servers[host] = _Server(host, ctx, self)
        self._threads: list[threading.Thread] = []

    def record(self, rec: dict[str, Any]) -> None:
        with self.lock:
            self.requests.append(rec)
            if self.record_file is not None:
                with self.record_file.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")

    def port(self, host: str) -> int:
        return int(self._servers[host].server_address[1])

    def resolve_map(self) -> dict[str, tuple[str, int]]:
        return {h: ("127.0.0.1", self.port(h)) for h in self.hosts}

    def requests_to(self, host: str) -> list[dict[str, Any]]:
        with self.lock:
            return [r for r in self.requests if r["server"] == host]

    def start(self) -> FakeUpstream:
        for srv in self._servers.values():
            t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
            t.start()
            self._threads.append(t)
        return self

    def stop(self) -> None:
        for srv in self._servers.values():
            srv.shutdown()
            srv.server_close()
        for t in self._threads:
            t.join(timeout=5)

    def __enter__(self) -> FakeUpstream:
        return self.start()

    def __exit__(
        self, et: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.stop()


def port_is_listening(port: int, host: str = "127.0.0.1") -> bool:
    try:
        socket.create_connection((host, port), 0.3).close()
        return True
    except OSError:
        return False
