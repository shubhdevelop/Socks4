#!/usr/bin/env python3
"""Tailscale-hosted browser UI for exercising SOCKS4/SOCKS4a CONNECT and SOCKS4 BIND."""

from __future__ import annotations

import argparse
import ipaddress
import json
import secrets
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

MAX_PAYLOAD_BYTES = 4096
MAX_REPLY_BYTES = 16 * 1024
SOCKET_TIMEOUT_SECONDS = 8
TUNNEL_IDLE_SECONDS = 120

PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SOCKS4 Relay &amp; BIND Tester</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
    body { max-width: 48rem; margin: 2rem auto; padding: 0 1rem; }
    form { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }
    label { display: grid; gap: .35rem; }
    input, textarea { padding: .5rem; }
    .full { grid-column: 1 / -1; }
    button { padding: .6rem 1rem; font-weight: 600; }
    pre { max-height: 28rem; overflow: auto; padding: 1rem; border: 1px solid; white-space: pre-wrap; }
    #status { min-height: 1.5rem; }
  </style>
</head>
<body>
  <h1>SOCKS4 Relay &amp; BIND Tester</h1>
  <p>Exercise SOCKS4/SOCKS4a CONNECT tunnels, or run a complete SOCKS4 BIND transaction. SOCKS5 is not supported.</p>
  <section id="handshake-stage">
    <h2>1. CONNECT handshake</h2>
    <form id="handshake-form">
      <label>SOCKS version <input name="version" type="number" value="4" min="4" max="4" required></label>
      <label>User ID <input name="userId" value="webapp" maxlength="255" required></label>
      <label>Proxy host <input name="proxyHost" value="127.0.0.1" required></label>
      <label>Proxy port <input name="proxyPort" type="number" value="1080" min="1" max="65535" required></label>
      <label>Destination IP <input name="destinationIp" value="0.0.0.1" required></label>
      <label>Destination domain (optional) <input name="domain" value="example.com" maxlength="253"></label>
      <label>Destination port <input name="port" type="number" value="80" min="1" max="65535" required></label>
      <div class="full"><button>Negotiate connection</button></div>
    </form>
  </section>
  <section id="packet-stage" hidden>
    <h2>2. CONNECT packets</h2>
    <form id="packet-form">
      <label class="full">TCP packet <textarea name="payload" rows="3" required>ping through SOCKS4</textarea></label>
      <div class="full"><button>Send packet</button> <button type="button" id="close-tunnel">Close connection</button></div>
    </form>
  </section>
  <section id="bind-stage">
    <h2>3. BIND test</h2>
    <p>Creates an expected peer, optionally verifies an unexpected peer is rejected, then relays data in both directions. Peer source IPs must belong to the host running this web app.</p>
    <form id="bind-form">
      <label>SOCKS version <input name="version" type="number" value="4" min="4" max="4" required></label>
      <label>User ID <input name="userId" value="webapp" maxlength="255" required></label>
      <label>Proxy host <input name="proxyHost" value="127.0.0.1" required></label>
      <label>Proxy port <input name="proxyPort" type="number" value="1080" min="1" max="65535" required></label>
      <label>Expected peer source IP <input name="expectedPeerIp" value="127.0.0.1" required></label>
      <label>Expected peer source port <input name="expectedPeerPort" type="number" value="0" min="0" max="65535" required></label>
      <label class="full">Unexpected peer source IP (optional) <input name="unexpectedPeerIp" value="127.0.0.2"></label>
      <div class="full"><button>Run BIND test</button></div>
    </form>
  </section>
  <section id="bind-listener-stage">
    <h2>4. Interactive BIND listener</h2>
    <p>Open a listener, then run the shown <code>telnet</code> command from the expected peer machine. Its text appears below.</p>
    <form id="bind-listener-form">
      <label>SOCKS version <input name="version" type="number" value="4" min="4" max="4" required></label>
      <label>User ID <input name="userId" value="webapp" maxlength="255" required></label>
      <label>Proxy host <input name="proxyHost" value="127.0.0.1" required></label>
      <label>Proxy port <input name="proxyPort" type="number" value="1080" min="1" max="65535" required></label>
      <label>Expected telnet peer source IP <input name="expectedPeerIp" value="127.0.0.1" required></label>
      <label>Expected telnet peer source port <input name="expectedPeerPort" type="number" value="0" min="0" max="65535" required></label>
      <div class="full"><button>Open BIND listener</button> <button type="button" id="close-bind-listener">Close BIND listener</button></div>
    </form>
  </section>
  <p id="status" role="status"></p>
  <pre id="response" aria-live="polite">Negotiate a connection or run a BIND test.</pre>
  <script>
    const handshakeForm = document.querySelector('#handshake-form');
    const packetForm = document.querySelector('#packet-form');
    const bindForm = document.querySelector('#bind-form');
    const bindListenerForm = document.querySelector('#bind-listener-form');
    const closeBindListener = document.querySelector('#close-bind-listener');
    const packetStage = document.querySelector('#packet-stage');
    const closeTunnel = document.querySelector('#close-tunnel');
    const destinationIp = handshakeForm.elements.destinationIp;
    const domain = handshakeForm.elements.domain;
    const status = document.querySelector('#status');
    const response = document.querySelector('#response');
    let tunnel;
    let bindListener;
    let bindPollTimer;

    domain.addEventListener('input', () => {
      if (domain.value) destinationIp.value = '0.0.0.1';
    });

    async function request(path, values) {
      const result = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(values),
      });
      return result.json();
    }

    function forgetTunnel(message) {
      tunnel = undefined;
      packetStage.hidden = true;
      status.textContent = message;
    }

    function forgetBindListener(message) {
      bindListener = undefined;
      clearTimeout(bindPollTimer);
      status.textContent = message;
    }

    async function pollBindListener() {
      if (!bindListener) return;
      try {
        const data = await request('/api/bind-poll', { listener: bindListener });
        if (!data.ok) {
          forgetBindListener(`BIND listener failed: ${data.error}`);
          return;
        }
        status.textContent = data.summary;
        if (data.response) {
          response.textContent += `${response.textContent ? '\\n' : ''}${data.response}`;
        }
        if (data.closed) {
          bindListener = undefined;
          clearTimeout(bindPollTimer);
          return;
        }
      } catch (error) {
        forgetBindListener(`BIND listener failed: ${error.message}`);
        return;
      }
      if (bindListener) bindPollTimer = window.setTimeout(pollBindListener, 1000);
    }

    handshakeForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      status.textContent = 'Negotiating SOCKS4 connection…';
      response.textContent = '';
      try {
        const data = await request('/api/handshake', Object.fromEntries(new FormData(handshakeForm)));
        if (!data.ok) {
          forgetTunnel(`Handshake failed: ${data.error}`);
          return;
        }
        tunnel = data.tunnel;
        packetStage.hidden = false;
        status.textContent = data.summary;
        response.textContent = 'Connection established. Send a packet.';
      } catch (error) {
        forgetTunnel(`Handshake failed: ${error.message}`);
      }
    });

    packetForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!tunnel) {
        forgetTunnel('Negotiate a connection first.');
        return;
      }
      status.textContent = 'Sending packet…';
      response.textContent = '';
      try {
        const data = await request('/api/packets', {
          tunnel,
          ...Object.fromEntries(new FormData(packetForm)),
        });
        if (!data.ok) {
          forgetTunnel(`Packet failed: ${data.error}`);
          return;
        }
        status.textContent = data.summary;
        response.textContent = data.response || '';
      } catch (error) {
        status.textContent = `Packet failed: ${error.message}`;
      }
    });

    bindForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      status.textContent = 'Running SOCKS4 BIND test…';
      response.textContent = '';
      try {
        const data = await request('/api/bind-test', Object.fromEntries(new FormData(bindForm)));
        if (!data.ok) {
          status.textContent = `BIND test failed: ${data.error}`;
          return;
        }
        status.textContent = data.summary;
        response.textContent = data.response;
      } catch (error) {
        status.textContent = `BIND test failed: ${error.message}`;
      }
    });

    bindListenerForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (bindListener) {
        await request('/api/bind-close', { listener: bindListener });
        forgetBindListener('');
      }
      status.textContent = 'Opening SOCKS4 BIND listener…';
      response.textContent = '';
      try {
        const data = await request('/api/bind-listen', Object.fromEntries(new FormData(bindListenerForm)));
        if (!data.ok) {
          status.textContent = `BIND listener failed: ${data.error}`;
          return;
        }
        bindListener = data.listener;
        status.textContent = data.summary;
        response.textContent = data.response;
        pollBindListener();
      } catch (error) {
        forgetBindListener(`BIND listener failed: ${error.message}`);
      }
    });

    closeBindListener.addEventListener('click', async () => {
      if (!bindListener) return;
      try {
        await request('/api/bind-close', { listener: bindListener });
      } catch (error) {
        status.textContent = `BIND listener cleanup failed: ${error.message}`;
      }
      forgetBindListener('BIND listener closed.');
    });

    closeTunnel.addEventListener('click', async () => {
      if (tunnel) {
        try {
          await request('/api/close', { tunnel });
        } catch (error) {
          status.textContent = `Connection cleanup failed: ${error.message}`;
        }
      }
      forgetTunnel('Connection closed.');
      response.textContent = 'Negotiate a new connection to send more packets.';
    });
  </script>
</body>
</html>
"""


def port(value: Any, name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be an integer") from error
    if not 1 <= parsed <= 65535:
        raise ValueError(f"{name} must be between 1 and 65535")
    return parsed


def bind_peer_port(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("expected peer source port must be an integer") from error
    if not 0 <= parsed <= 65535:
        raise ValueError("expected peer source port must be between 0 and 65535")
    return parsed


def host(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError(f"{name} must be 1 to 253 characters")
    if "\x00" in value or any(character.isspace() for character in value):
        raise ValueError(f"{name} cannot contain whitespace or NUL")
    return value

def destination_ip(value: Any) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValueError("destination IP must be an IPv4 address") from error


def domain(value: Any) -> str | None:
    if value == "":
        return None
    return host(value, "destination domain")

def socks_version(value: Any) -> int:
    if value in (4, "4"):
        return 4
    raise ValueError("only SOCKS version 4 is supported")


def user_id(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("user ID must be text")
    if "\x00" in value:
        raise ValueError("user ID cannot contain NUL")
    encoded = value.encode("utf-8")
    if not 1 <= len(encoded) <= 255:
        raise ValueError("user ID must be between 1 and 255 UTF-8 bytes")
    return encoded


def recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise OSError("proxy closed the connection during the SOCKS handshake")
        chunks.extend(chunk)
    return bytes(chunks)


def socks4_connect(
    version: int,
    user: bytes,
    proxy_host: str,
    proxy_port: int,
    address: ipaddress.IPv4Address,
    destination_port: int,
    destination_domain: str | None,
) -> socket.socket:
    request = (
        version.to_bytes(1, "big")
        + b"\x01"
        + destination_port.to_bytes(2, "big")
        + address.packed
        + user
        + b"\x00"
    )
    if destination_domain is not None:
        request += destination_domain.encode("idna") + b"\x00"

    connection = socket.create_connection((proxy_host, proxy_port), timeout=SOCKET_TIMEOUT_SECONDS)
    connection.settimeout(SOCKET_TIMEOUT_SECONDS)
    try:
        connection.sendall(request)
        response = recv_exact(connection, 8)
        if response[1] != 0x5A:
            raise OSError(f"SOCKS4 CONNECT rejected with status 0x{response[1]:02x}")
    except Exception:
        connection.close()
        raise
    return connection


def socks4_bind_test(
    version: int,
    user: bytes,
    proxy_host: str,
    proxy_port: int,
    expected_peer_ip: ipaddress.IPv4Address,
    expected_peer_port: int,
    unexpected_peer_ip: ipaddress.IPv4Address | None,
) -> dict[str, str]:
    request = (
        version.to_bytes(1, "big")
        + b"\x02"
        + expected_peer_port.to_bytes(2, "big")
        + expected_peer_ip.packed
        + user
        + b"\x00"
    )
    control = socket.create_connection((proxy_host, proxy_port), timeout=SOCKET_TIMEOUT_SECONDS)
    control.settimeout(SOCKET_TIMEOUT_SECONDS)
    unexpected_peer: socket.socket | None = None
    expected_peer: socket.socket | None = None
    try:
        control.sendall(request)
        first_reply = recv_exact(control, 8)
        if first_reply[1] != 0x5A:
            raise OSError(f"SOCKS4 BIND rejected with status 0x{first_reply[1]:02x}")

        bound_ip = ipaddress.IPv4Address(first_reply[4:8])
        bound_port = int.from_bytes(first_reply[2:4], "big")
        if bound_port == 0:
            raise OSError("SOCKS4 BIND reply contained port 0")

        unexpected_result = "not requested"
        if unexpected_peer_ip is not None:
            if unexpected_peer_ip == expected_peer_ip:
                raise ValueError("unexpected peer source IP must differ from the expected peer source IP")
            unexpected_peer = socket.create_connection(
                (str(bound_ip), bound_port),
                timeout=SOCKET_TIMEOUT_SECONDS,
                source_address=(str(unexpected_peer_ip), 0),
            )
            unexpected_peer.settimeout(1)
            try:
                if unexpected_peer.recv(1) != b"":
                    raise OSError("proxy relayed data to an unexpected peer")
            except TimeoutError as error:
                raise OSError("proxy kept the unexpected peer connection open") from error
            finally:
                unexpected_peer.close()
                unexpected_peer = None
            unexpected_result = "rejected"

        expected_peer = socket.create_connection(
            (str(bound_ip), bound_port),
            timeout=SOCKET_TIMEOUT_SECONDS,
            source_address=(str(expected_peer_ip), expected_peer_port),
        )
        expected_peer.settimeout(SOCKET_TIMEOUT_SECONDS)
        second_reply = recv_exact(control, 8)
        if second_reply[1] != 0x5A:
            raise OSError(f"SOCKS4 BIND peer rejected with status 0x{second_reply[1]:02x}")

        client_payload = b"webapp-client-to-peer"
        peer_payload = b"webapp-peer-to-client"
        control.sendall(client_payload)
        received_by_peer = recv_exact(expected_peer, len(client_payload))
        if received_by_peer != client_payload:
            raise OSError("BIND relay corrupted client-to-peer payload")
        expected_peer.sendall(peer_payload)
        received_by_webapp = recv_exact(control, len(peer_payload))
        if received_by_webapp != peer_payload:
            raise OSError("BIND relay corrupted peer-to-client payload")

        return {
            "summary": "SOCKS4 BIND completed with bidirectional relay.",
            "response": (
                f"First reply: {first_reply.hex()} (listener {bound_ip}:{bound_port})\n"
                f"Unexpected peer: {unexpected_result}\n"
                f"Second reply: {second_reply.hex()}\n"
                f"Webapp → peer received: {received_by_peer.decode('utf-8', errors='replace')!r}\n"
                f"Peer → webapp received: {received_by_webapp.decode('utf-8', errors='replace')!r}"
            ),
        }
    finally:
        if unexpected_peer is not None:
            unexpected_peer.close()
        if expected_peer is not None:
            expected_peer.close()
        control.close()


def socks4_bind_listener(
    version: int,
    user: bytes,
    proxy_host: str,
    proxy_port: int,
    expected_peer_ip: ipaddress.IPv4Address,
    expected_peer_port: int,
) -> tuple[socket.socket, bytes]:
    request = (
        version.to_bytes(1, "big")
        + b"\x02"
        + expected_peer_port.to_bytes(2, "big")
        + expected_peer_ip.packed
        + user
        + b"\x00"
    )
    connection = socket.create_connection((proxy_host, proxy_port), timeout=SOCKET_TIMEOUT_SECONDS)
    connection.settimeout(SOCKET_TIMEOUT_SECONDS)
    try:
        connection.sendall(request)
        first_reply = recv_exact(connection, 8)
        if first_reply[1] != 0x5A:
            raise OSError(f"SOCKS4 BIND rejected with status 0x{first_reply[1]:02x}")
        if int.from_bytes(first_reply[2:4], "big") == 0:
            raise OSError("SOCKS4 BIND reply contained port 0")
        connection.setblocking(False)
        return connection, first_reply
    except Exception:
        connection.close()
        raise


@dataclass
class Tunnel:
    connection: socket.socket
    lock: threading.Lock = field(default_factory=threading.Lock)
    last_used: float = field(default_factory=time.monotonic)


@dataclass
class BindSession:
    connection: socket.socket
    listener_ip: ipaddress.IPv4Address
    listener_port: int
    lock: threading.Lock = field(default_factory=threading.Lock)
    last_used: float = field(default_factory=time.monotonic)
    connected: bool = False
    peer_ip: ipaddress.IPv4Address | None = None
    peer_port: int | None = None
    pending: bytearray = field(default_factory=bytearray)


class TunnelRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tunnels: dict[str, Tunnel] = {}

    def _close_expired_locked(self) -> None:
        deadline = time.monotonic() - TUNNEL_IDLE_SECONDS
        for token, tunnel in list(self._tunnels.items()):
            if tunnel.last_used > deadline:
                continue
            tunnel.lock.acquire()
            try:
                if tunnel.last_used <= deadline and self._tunnels.get(token) is tunnel:
                    del self._tunnels[token]
                    tunnel.connection.close()
            finally:
                tunnel.lock.release()

    def open(self, connection: socket.socket) -> str:
        with self._lock:
            self._close_expired_locked()
            token = secrets.token_urlsafe(32)
            self._tunnels[token] = Tunnel(connection)
            return token

    def acquire(self, token: str) -> Tunnel:
        with self._lock:
            self._close_expired_locked()
            tunnel = self._tunnels.get(token)
            if tunnel is None:
                raise ValueError("connection is unknown or has expired")
            tunnel.lock.acquire()
            tunnel.last_used = time.monotonic()
            return tunnel

    def release(self, tunnel: Tunnel) -> None:
        tunnel.last_used = time.monotonic()
        tunnel.lock.release()

    def close(self, token: str) -> None:
        with self._lock:
            tunnel = self._tunnels.get(token)
            if tunnel is None:
                raise ValueError("connection is unknown or has expired")
            tunnel.lock.acquire()
            try:
                del self._tunnels[token]
                tunnel.connection.close()
            finally:
                tunnel.lock.release()

    def close_all(self) -> None:
        with self._lock:
            for token, tunnel in list(self._tunnels.items()):
                tunnel.lock.acquire()
                try:
                    del self._tunnels[token]
                    tunnel.connection.close()
                finally:
                    tunnel.lock.release()


class BindSessionRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, BindSession] = {}

    def _close_expired_locked(self) -> None:
        deadline = time.monotonic() - TUNNEL_IDLE_SECONDS
        for token, session in list(self._sessions.items()):
            if session.last_used > deadline:
                continue
            session.lock.acquire()
            try:
                if session.last_used <= deadline and self._sessions.get(token) is session:
                    del self._sessions[token]
                    session.connection.close()
            finally:
                session.lock.release()

    def open(self, session: BindSession) -> str:
        with self._lock:
            self._close_expired_locked()
            token = secrets.token_urlsafe(32)
            self._sessions[token] = session
            return token

    def acquire(self, token: str) -> BindSession:
        with self._lock:
            self._close_expired_locked()
            session = self._sessions.get(token)
            if session is None:
                raise ValueError("BIND listener is unknown or has expired")
            session.lock.acquire()
            session.last_used = time.monotonic()
            return session

    @staticmethod
    def release(session: BindSession) -> None:
        session.last_used = time.monotonic()
        session.lock.release()

    def close(self, token: str) -> None:
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                raise ValueError("BIND listener is unknown or has expired")
            session.lock.acquire()
            try:
                del self._sessions[token]
                session.connection.close()
            finally:
                session.lock.release()

    def close_all(self) -> None:
        with self._lock:
            for token, session in list(self._sessions.items()):
                session.lock.acquire()
                try:
                    del self._sessions[token]
                    session.connection.close()
                finally:
                    session.lock.release()


TUNNELS = TunnelRegistry()


BIND_SESSIONS = BindSessionRegistry()


def connection_token(data: dict[str, Any]) -> str:
    token = data.get("tunnel")
    if not isinstance(token, str) or not 1 <= len(token) <= 128:
        raise ValueError("connection token is invalid")
    return token


def packet(data: dict[str, Any]) -> bytes:
    payload = data.get("payload")
    if not isinstance(payload, str):
        raise ValueError("packet must be text")
    message = payload.encode("utf-8")
    if not 1 <= len(message) <= MAX_PAYLOAD_BYTES:
        raise ValueError(f"packet must be between 1 and {MAX_PAYLOAD_BYTES} UTF-8 bytes")
    return message


def negotiate(data: dict[str, Any]) -> dict[str, str]:
    version = socks_version(data.get("version"))
    user = user_id(data.get("userId"))
    proxy_host = host(data.get("proxyHost"), "proxy host")
    proxy_port = port(data.get("proxyPort"), "proxy port")
    address = destination_ip(data.get("destinationIp"))
    destination_domain = domain(data.get("domain"))
    destination_port = port(data.get("port"), "destination port")
    if destination_domain is not None and address != ipaddress.IPv4Address("0.0.0.1"):
        raise ValueError("destination IP must be 0.0.0.1 when a domain is provided")
    connection = socks4_connect(
        version,
        user,
        proxy_host,
        proxy_port,
        address,
        destination_port,
        destination_domain,
    )
    mode = "SOCKS4a" if destination_domain is not None else "SOCKS4"
    return {
        "summary": f"{mode} tunnel established; send packets through it.",
        "tunnel": TUNNELS.open(connection),
    }


def test_bind(data: dict[str, Any]) -> dict[str, str]:
    version = socks_version(data.get("version"))
    user = user_id(data.get("userId"))
    proxy_host = host(data.get("proxyHost"), "proxy host")
    proxy_port = port(data.get("proxyPort"), "proxy port")
    expected_peer_ip = destination_ip(data.get("expectedPeerIp"))
    expected_peer_port = bind_peer_port(data.get("expectedPeerPort"))
    unexpected_peer_value = data.get("unexpectedPeerIp")
    unexpected_peer_ip = (
        None if unexpected_peer_value == "" else destination_ip(unexpected_peer_value)
    )
    return socks4_bind_test(
        version,
        user,
        proxy_host,
        proxy_port,
        expected_peer_ip,
        expected_peer_port,
        unexpected_peer_ip,
    )


def bind_listener_token(data: dict[str, Any]) -> str:
    token = data.get("listener")
    if not isinstance(token, str) or not 1 <= len(token) <= 128:
        raise ValueError("BIND listener token is invalid")
    return token


def open_bind_listener(data: dict[str, Any]) -> dict[str, str]:
    version = socks_version(data.get("version"))
    user = user_id(data.get("userId"))
    proxy_host = host(data.get("proxyHost"), "proxy host")
    proxy_port = port(data.get("proxyPort"), "proxy port")
    expected_peer_ip = destination_ip(data.get("expectedPeerIp"))
    expected_peer_port = bind_peer_port(data.get("expectedPeerPort"))
    connection, first_reply = socks4_bind_listener(
        version,
        user,
        proxy_host,
        proxy_port,
        expected_peer_ip,
        expected_peer_port,
    )
    listener_ip = ipaddress.IPv4Address(first_reply[4:8])
    listener_port = int.from_bytes(first_reply[2:4], "big")
    token = BIND_SESSIONS.open(BindSession(connection, listener_ip, listener_port))
    return {
        "summary": f"BIND listener ready at {listener_ip}:{listener_port}.",
        "listener": token,
        "response": (
            f"First reply: {first_reply.hex()}\n"
            f"From the expected peer machine, run:\n"
            f"telnet {listener_ip} {listener_port}"
        ),
    }


def poll_bind_listener(data: dict[str, Any]) -> dict[str, Any]:
    token = bind_listener_token(data)
    session = BIND_SESSIONS.acquire(token)
    peer_closed = False
    try:
        while True:
            try:
                chunk = session.connection.recv(MAX_REPLY_BYTES)
            except BlockingIOError:
                break
            if not chunk:
                if not session.connected and len(session.pending) < 8:
                    raise OSError("proxy closed the BIND listener before accepting a peer")
                peer_closed = True
                break
            session.pending.extend(chunk)

        if not session.connected and len(session.pending) < 8:
            result: dict[str, Any] = {
                "summary": (
                    f"Waiting for a peer to connect to "
                    f"{session.listener_ip}:{session.listener_port}."
                ),
                "response": "",
                "closed": False,
            }
        else:
            if not session.connected:
                second_reply = bytes(session.pending[:8])
                del session.pending[:8]
                if second_reply[1] != 0x5A:
                    raise OSError(
                        f"SOCKS4 BIND peer rejected with status 0x{second_reply[1]:02x}"
                    )
                session.connected = True
                session.peer_ip = ipaddress.IPv4Address(second_reply[4:8])
                session.peer_port = int.from_bytes(second_reply[2:4], "big")

            payload = bytes(session.pending)
            session.pending.clear()
            if payload:
                suffix = " Peer disconnected." if peer_closed else ""
                result = {
                    "summary": (
                        f"Received {len(payload)} byte(s) from "
                        f"{session.peer_ip}:{session.peer_port}.{suffix}"
                    ),
                    "response": payload.decode("utf-8", errors="replace"),
                    "closed": peer_closed,
                }
            else:
                result = {
                    "summary": (
                        f"Peer {session.peer_ip}:{session.peer_port} "
                        f"{'disconnected.' if peer_closed else 'connected; waiting for data.'}"
                    ),
                    "response": "",
                    "closed": peer_closed,
                }
    except OSError:
        BIND_SESSIONS.release(session)
        BIND_SESSIONS.close(token)
        raise
    else:
        BIND_SESSIONS.release(session)
        if peer_closed:
            BIND_SESSIONS.close(token)
        return result


def close_bind_listener(data: dict[str, Any]) -> dict[str, str]:
    BIND_SESSIONS.close(bind_listener_token(data))
    return {"summary": "BIND listener closed."}


def send_packet(data: dict[str, Any]) -> dict[str, str]:
    token = connection_token(data)
    message = packet(data)
    tunnel = TUNNELS.acquire(token)
    try:
        tunnel.connection.sendall(message)
        response = tunnel.connection.recv(MAX_REPLY_BYTES)
    except OSError:
        TUNNELS.release(tunnel)
        TUNNELS.close(token)
        raise
    TUNNELS.release(tunnel)

    text = response.decode("utf-8", errors="replace")
    summary = (
        f"Received {len(response)} bytes through the SOCKS4 relay"
        if response
        else "Packet sent; destination sent no data"
    )
    return {"summary": summary, "response": text}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = PAGE.encode()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        handlers = {
            "/api/handshake": negotiate,
            "/api/packets": send_packet,
            "/api/bind-test": test_bind,
            "/api/bind-listen": open_bind_listener,
            "/api/bind-poll": poll_bind_listener,
            "/api/bind-close": close_bind_listener,
            "/api/close": self.close_tunnel,
        }
        handler = handlers.get(self.path)
        if handler is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= content_length <= 4096:
                raise ValueError("request body must be between 1 and 4096 bytes")
            data = json.loads(self.rfile.read(content_length))
            if not isinstance(data, dict):
                raise ValueError("request body must be a JSON object")
            result = {"ok": True, **handler(data)}
            status = HTTPStatus.OK
        except (UnicodeError, ValueError) as error:
            result = {"ok": False, "error": str(error), "response": ""}
            status = HTTPStatus.BAD_REQUEST
        except OSError as error:
            result = {"ok": False, "error": str(error), "response": ""}
            status = HTTPStatus.BAD_GATEWAY
        payload = json.dumps(result).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    @staticmethod
    def close_tunnel(data: dict[str, Any]) -> dict[str, str]:
        TUNNELS.close(connection_token(data))
        return {"summary": "Connection closed."}

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.client_address[0]} - {format % args}")


def tailscale_ipv4() -> str:
    try:
        result = subprocess.run(
            ["tailscale", "ip", "-4"],
            check=True,
            capture_output=True,
            text=True,
        )
        addresses = result.stdout.splitlines()
        if len(addresses) != 1:
            raise ValueError
        return str(ipaddress.IPv4Address(addresses[0]))
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        raise RuntimeError("could not determine a Tailscale IPv4 address; pass --host explicitly") from error


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", help="address to listen on (defaults to this machine's Tailscale IPv4 address)")
    parser.add_argument("--port", type=int, default=8000, help="HTTP port (default: 8000)")
    args = parser.parse_args()
    try:
        listen_host = args.host or tailscale_ipv4()
    except RuntimeError as error:
        parser.error(str(error))
    server = ThreadingHTTPServer((listen_host, args.port), Handler)
    print(f"SOCKS4 test UI: http://{listen_host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        TUNNELS.close_all()
        BIND_SESSIONS.close_all()
        server.server_close()


if __name__ == "__main__":
    main()
