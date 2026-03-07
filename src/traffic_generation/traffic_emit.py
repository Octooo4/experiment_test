from __future__ import annotations

import http.client
import re
import socket
import sys
import urllib.parse
from typing import Tuple

from traffic_generation.http_builder import HttpRequestSpec, validate_http_request
from traffic_generation.rule_parse import sanitize_header_value

PRINT_RESPONSE: bool = False


def _parse_server(server: str) -> Tuple[str, int, bool]:
    if "://" in server:
        u = urllib.parse.urlparse(server)
        if not u.hostname:
            raise ValueError("Invalid server URL")
        use_tls = u.scheme.lower() == "https"
        port = u.port or (443 if use_tls else 80)
        return u.hostname, port, use_tls
    if ":" in server and server.count(":") == 1:
        h, p = server.split(":", 1)
        return h, int(p), False
    return server, 80, False


def send_http_request(server: str, req: HttpRequestSpec, timeout: int = 3) -> Tuple[int, bytes]:
    validate_http_request(req)

    host, port, use_tls = _parse_server(server)
    path = req.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    conn: http.client.HTTPConnection
    conn = (
        http.client.HTTPSConnection(host, port, timeout=timeout)
        if use_tls
        else http.client.HTTPConnection(host, port, timeout=timeout)
    )

    safe_headers = {k: sanitize_header_value(v) for k, v in req.headers.items()}
    body_bytes = req.body.encode("utf-8", errors="replace") if req.body else None
    conn.request(method=req.method, url=path, body=body_bytes, headers=safe_headers)
    resp = conn.getresponse()
    data = resp.read()
    status = int(resp.status)
    conn.close()

    if PRINT_RESPONSE:
        try:
            sys.stdout.write(data.decode("utf-8", errors="replace") + "\n")
        except Exception:
            pass
    return status, data


def send_raw_http_bytes(server: str, raw_bytes: bytes, timeout: int = 3) -> Tuple[int, bytes]:
    host, port, use_tls = _parse_server(server)
    if use_tls:
        raise ValueError("send_raw_http_bytes currently supports only plain HTTP")

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(raw_bytes)
        sock.shutdown(socket.SHUT_WR)

        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)

    data = b"".join(chunks)
    m = re.match(rb"HTTP/\d\.\d\s+(\d{3})", data)
    status = int(m.group(1)) if m else 0

    if PRINT_RESPONSE:
        try:
            sys.stdout.write(data.decode("utf-8", errors="replace") + "\n")
        except Exception:
            pass

    return status, data
