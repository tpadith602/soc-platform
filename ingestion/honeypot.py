#!/usr/bin/env python3
"""
SOC Platform — Honeypot Engine

Three low-interaction decoy services running on non-standard ports:

  Port 2222  — fake SSH server
               Presents an SSH banner, records the client's version string
               and any credential bytes sent, then closes the connection.

  Port 8080  — fake HTTP server
               Returns a plausible 200 response, records method, path,
               User-Agent, and full request headers.

  Port 2121  — fake FTP server
               Presents an FTP greeting, captures USER/PASS attempts,
               then responds with 530 Login incorrect.

Design principles
─────────────────
• Low-interaction: we never execute attacker payloads or forward traffic.
  We only read, log, and close.
• Every connection to a honeypot port is suspicious by definition — there
  is no legitimate reason to connect to these ports on this host.
• Alerts are routed through ingestion/database.py::SOCDatabase.add_alert()
  with source_component='honeypot' and detection_method='honeypot', so the
  dashboard can distinguish them from NIDS/ML/SSH-monitor alerts.
• Repeat-offender cooldown: same IP only generates one alert per
  ALERT_COOLDOWN seconds per port, preventing log floods from scanners that
  hammer a port repeatedly.
• Each listener runs in its own daemon thread. The main HoneypotEngine
  thread just waits for the shutdown event.
"""

import logging
import logging.handlers
import socketserver
import socket
import threading
import time
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import LOG_DIR, LOG_MAX_BYTES, LOG_BACKUP_COUNT
from ingestion.database import SOCDatabase

# ------------------------------------------------------------------ #
# Logging                                                              #
# ------------------------------------------------------------------ #

log = logging.getLogger("soc.honeypot")
log.setLevel(logging.INFO)
_fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
_sh  = logging.StreamHandler()
_sh.setFormatter(_fmt)
log.addHandler(_sh)
_fh = logging.handlers.RotatingFileHandler(
    LOG_DIR / 'honeypot.log', maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT
)
_fh.setFormatter(_fmt)
log.addHandler(_fh)

# ------------------------------------------------------------------ #
# Configuration                                                        #
# ------------------------------------------------------------------ #

HONEYPOT_PORTS: Dict[str, int] = {
    'SSH':  2222,
    'HTTP': 8080,
    'FTP':  2121,
}

RECV_TIMEOUT    = 5      # seconds to wait for attacker to send data
ALERT_COOLDOWN  = 60     # FIX: reduced from 300s — 1 minute cooldown per (ip,port)
PRUNE_INTERVAL  = 600    # prune cooldown table every 10 minutes
PRUNE_MAX_AGE   = 3600   # drop cooldown entries older than 1 hour

READ_BYTES      = 4096   # max bytes to read from attacker per connection

# ------------------------------------------------------------------ #
# Cooldown tracker (shared across all honeypot handlers)              #
# ------------------------------------------------------------------ #

class _CooldownTracker:
    """Thread-safe per-(ip, port) alert cooldown."""

    def __init__(self):
        self._table: Dict[Tuple[str, int], float] = {}
        self._lock  = threading.Lock()
        self._last_prune = time.time()

    def should_alert(self, ip: str, port: int) -> bool:
        now = time.time()
        key = (ip, port)
        with self._lock:
            last = self._table.get(key, 0)
            if now - last < ALERT_COOLDOWN:
                return False
            self._table[key] = now
            self._maybe_prune(now)
        return True

    def _maybe_prune(self, now: float) -> None:
        if now - self._last_prune < PRUNE_INTERVAL:
            return
        stale = [k for k, ts in self._table.items() if now - ts > PRUNE_MAX_AGE]
        for k in stale:
            del self._table[k]
        self._last_prune = now


_cooldown = _CooldownTracker()

# ------------------------------------------------------------------ #
# Shared alert writer                                                  #
# ------------------------------------------------------------------ #

_db_lock = threading.Lock()
_db: SOCDatabase = None


def _get_db() -> SOCDatabase:
    global _db
    if _db is None:
        with _db_lock:
            if _db is None:
                _db = SOCDatabase()
    return _db


def _raise_alert(
    src_ip:      str,
    src_port:    int,
    dst_port:    int,
    service:     str,
    description: str,
    payload:     str = '',
    severity:    str = 'HIGH',
) -> None:
    if not _cooldown.should_alert(src_ip, dst_port):
        log.debug(f"Cooldown active for {src_ip}:{dst_port} — skipping alert")
        return

    truncated = (payload[:500] + '…') if len(payload) > 500 else payload
    explanation = f"Honeypot {service} (:{dst_port}) interaction from {src_ip}: {description}"
    if truncated:
        explanation += f" | Payload: {truncated!r}"

    alert = {
        'source_ip':        src_ip,
        'destination_ip':   'honeypot',
        'destination_port': dst_port,
        'protocol':         'TCP',
        'severity':         severity,
        'confidence':       1.0,   # any connection to a honeypot port = certain suspicious intent
        'explanation':      explanation,
        'country':          'Unknown',
        'ip_category':      'Public',
        'status':           'new',
        'attack_type':      f'Honeypot-{service}',
        'source_component': 'honeypot',
        'detection_method': 'honeypot',
        'packet_info':      f'src_port={src_port}',
        'isp':              'Honeypot',
    }
    ok = _get_db().add_alert(alert)
    if ok:
        log.warning(f"🍯 HONEYPOT HIT [{service}:{dst_port}] from {src_ip} — {description}")
    else:
        log.error(f"Failed to write honeypot alert for {src_ip}")

# ------------------------------------------------------------------ #
# Base handler mixin                                                   #
# ------------------------------------------------------------------ #

class _BaseHoneypotHandler(socketserver.BaseRequestHandler):
    service_name = 'UNKNOWN'
    dst_port     = 0

    def _recv(self) -> bytes:
        try:
            self.request.settimeout(RECV_TIMEOUT)
            return self.request.recv(READ_BYTES)
        except (socket.timeout, OSError):
            return b''

    def _send(self, data: bytes) -> None:
        try:
            self.request.sendall(data)
        except OSError:
            pass

    def _close(self) -> None:
        try:
            self.request.close()
        except OSError:
            pass

    def handle(self):
        src_ip   = self.client_address[0]
        src_port = self.client_address[1]
        log.info(f"🍯 [{self.service_name}:{self.dst_port}] connection from {src_ip}:{src_port}")
        try:
            self.interact(src_ip, src_port)
        except Exception as e:
            log.debug(f"[{self.service_name}] handler error for {src_ip}: {e}")
        finally:
            self._close()

    def interact(self, src_ip: str, src_port: int):
        raise NotImplementedError

# ------------------------------------------------------------------ #
# Fake SSH (port 2222)                                                 #
# ------------------------------------------------------------------ #

class _SSHHandler(_BaseHoneypotHandler):
    service_name = 'SSH'
    dst_port     = HONEYPOT_PORTS['SSH']

    # RFC 4253 §4.2 — server sends its identification string first
    SSH_BANNER = b'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n'

    def interact(self, src_ip: str, src_port: int):
        self._send(self.SSH_BANNER)
        data = self._recv()

        if data:
            # First bytes from client are the client's identification string
            # e.g. b'SSH-2.0-OpenSSH_9.0\r\n'
            client_banner = data.split(b'\n')[0].decode('utf-8', errors='replace').strip()
            description   = f"SSH banner exchange — client: {client_banner!r}"

            # Read a second chunk — may contain key-exchange init
            kex_data = self._recv()
            if kex_data:
                description += f" + {len(kex_data)} bytes key-exchange data"
        else:
            description = "SSH port probe (connected, sent no data)"

        # Send a plausible disconnect packet so the client doesn't retry immediately
        # SSH_MSG_DISCONNECT (type 1) with "by application" reason
        try:
            disconnect = bytes([0,0,0,12, 10, 6, 0,0,0,1, 0,0,0,0, 0,0])
            self._send(disconnect)
        except OSError:
            pass

        _raise_alert(src_ip, src_port, self.dst_port, self.service_name, description, severity='HIGH')


# ------------------------------------------------------------------ #
# Fake HTTP (port 8080)                                               #
# ------------------------------------------------------------------ #

class _HTTPHandler(_BaseHoneypotHandler):
    service_name = 'HTTP'
    dst_port     = HONEYPOT_PORTS['HTTP']

    HTTP_RESPONSE = (
        b'HTTP/1.1 200 OK\r\n'
        b'Server: Apache/2.4.54 (Ubuntu)\r\n'
        b'Content-Type: text/html; charset=utf-8\r\n'
        b'Content-Length: 45\r\n'
        b'Connection: close\r\n'
        b'\r\n'
        b'<html><body><h1>Welcome</h1></body></html>\r\n'
    )

    def interact(self, src_ip: str, src_port: int):
        data = self._recv()

        if not data:
            _raise_alert(src_ip, src_port, self.dst_port, self.service_name,
                         "HTTP port probe (no request sent)", severity='MEDIUM')
            return

        raw = data.decode('utf-8', errors='replace')
        lines = raw.split('\r\n')

        # Parse request line
        request_line = lines[0] if lines else ''
        parts = request_line.split(' ')
        method = parts[0] if len(parts) > 0 else 'UNKNOWN'
        path   = parts[1] if len(parts) > 1 else '/'

        # Extract interesting headers
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                k, _, v = line.partition(':')
                headers[k.strip().lower()] = v.strip()

        user_agent = headers.get('user-agent', 'none')
        host       = headers.get('host', 'none')

        description = (
            f"{method} {path} — "
            f"Host: {host!r}, "
            f"User-Agent: {user_agent!r}"
        )

        # Classify severity by what's being scanned
        HIGH_VALUE_PATHS = (
            '/admin', '/wp-admin', '/phpmyadmin', '/.env', '/config',
            '/etc/passwd', '/shell', '/cmd', '/api/v1', '/.git',
            '/manager', '/actuator', '/console', '/login',
        )
        severity = 'CRITICAL' if any(p in path.lower() for p in HIGH_VALUE_PATHS) else 'HIGH'

        self._send(self.HTTP_RESPONSE)
        _raise_alert(src_ip, src_port, self.dst_port, self.service_name,
                     description, payload=raw[:200], severity=severity)


# ------------------------------------------------------------------ #
# Fake FTP (port 2121)                                                 #
# ------------------------------------------------------------------ #

class _FTPHandler(_BaseHoneypotHandler):
    service_name = 'FTP'
    dst_port     = HONEYPOT_PORTS['FTP']

    FTP_BANNER  = b'220 FTP server ready\r\n'
    FTP_USER_OK = b'331 Password required for user\r\n'
    FTP_FAIL    = b'530 Login incorrect.\r\n'
    FTP_BYE     = b'221 Goodbye.\r\n'

    def interact(self, src_ip: str, src_port: int):
        self._send(self.FTP_BANNER)

        username = ''
        password = ''

        # Read USER command
        data = self._recv()
        if not data:
            _raise_alert(src_ip, src_port, self.dst_port, self.service_name,
                         "FTP port probe (banner grab only)", severity='MEDIUM')
            return

        # Split on CRLF — some clients send USER and PASS in one TCP segment
        raw   = data.decode('utf-8', errors='replace')
        lines = [l.strip() for l in raw.replace('\r\n', '\n').replace('\r', '\n').split('\n') if l.strip()]

        for line in lines:
            if line.upper().startswith('USER') and not username:
                username = line[4:].strip()
                self._send(self.FTP_USER_OK)
            elif line.upper().startswith('PASS') and not password:
                password = line[4:].strip()

        # If PASS wasn't in the first segment, wait for a second recv
        if username and not password:
            data2 = self._recv()
            if data2:
                line2 = data2.decode('utf-8', errors='replace').strip()
                if line2.upper().startswith('PASS'):
                    password = line2[4:].strip()

        self._send(self.FTP_FAIL)
        self._send(self.FTP_BYE)

        if username or password:
            description = f"FTP login attempt — user: {username!r}, pass: {password!r}"
            severity    = 'CRITICAL'
        else:
            description = f"FTP probe — raw data: {line!r}"
            severity    = 'HIGH'

        _raise_alert(src_ip, src_port, self.dst_port, self.service_name,
                     description, severity=severity)


# ------------------------------------------------------------------ #
# Server factory                                                       #
# ------------------------------------------------------------------ #

class _ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads      = True

    def handle_error(self, request, client_address):
        # Suppress noisy tracebacks from scanners that close mid-handshake
        pass


def _make_server(handler_class, port: int) -> _ReusableTCPServer:
    server = _ReusableTCPServer(('0.0.0.0', port), handler_class)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return server


# ------------------------------------------------------------------ #
# Main engine                                                          #
# ------------------------------------------------------------------ #

class HoneypotEngine:
    def __init__(self):
        self.running  = True
        self._servers = []
        self._threads = []
        log.info("🍯 Honeypot Engine initialising")

    def _start_listener(self, handler_cls, service_name: str, port: int) -> bool:
        try:
            server = _make_server(handler_cls, port)
            self._servers.append(server)
            t = threading.Thread(
                target=server.serve_forever,
                name=f"Honeypot-{service_name}",
                daemon=True,
            )
            t.start()
            self._threads.append(t)
            log.info(f"✅ Honeypot {service_name} listening on 0.0.0.0:{port}")
            return True
        except OSError as e:
            log.error(
                f"❌ Cannot bind honeypot {service_name} on port {port}: {e}. "
                f"Is port {port} already in use? Try: sudo ss -tlnp | grep {port}"
            )
            return False

    def start(self):
        listeners = [
            (_SSHHandler,  'SSH',  HONEYPOT_PORTS['SSH']),
            (_HTTPHandler, 'HTTP', HONEYPOT_PORTS['HTTP']),
            (_FTPHandler,  'FTP',  HONEYPOT_PORTS['FTP']),
        ]
        started = 0
        for handler_cls, name, port in listeners:
            if self._start_listener(handler_cls, name, port):
                started += 1

        if started == 0:
            log.error("❌ No honeypot listeners started — all ports failed to bind")
            return

        log.info(
            f"🍯 Honeypot Engine running — "
            f"{started}/{len(listeners)} services active. "
            f"Monitoring: SSH:{HONEYPOT_PORTS['SSH']} "
            f"HTTP:{HONEYPOT_PORTS['HTTP']} "
            f"FTP:{HONEYPOT_PORTS['FTP']}"
        )

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        self.running = False
        for server in self._servers:
            try:
                server.shutdown()
            except Exception:
                pass
        log.info("🍯 Honeypot Engine stopped")


# ------------------------------------------------------------------ #
# Entry point                                                          #
# ------------------------------------------------------------------ #

if __name__ == '__main__':
    engine = HoneypotEngine()
    try:
        engine.start()
    except KeyboardInterrupt:
        engine.stop()
