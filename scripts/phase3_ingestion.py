#!/usr/bin/env python3
"""
SSH Brute-Force Detection Engine

FIX: Ubuntu 24.04 uses systemd-journald by default. /var/log/auth.log may
not exist unless rsyslog is installed. This version tries auth.log first,
then falls back to tailing the systemd journal directly via `journalctl -f`
so SSH brute-force detection works on ALL Ubuntu versions regardless of
whether rsyslog is installed.
"""

import re
import time
import os
import subprocess
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Dict, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import LOG_DIR, LOG_MAX_BYTES, LOG_BACKUP_COUNT
from ingestion.database import SOCDatabase

AUTH_LOG_CANDIDATES = [
    Path('/var/log/auth.log'),   # Debian/Ubuntu + rsyslog
    Path('/var/log/secure'),     # RHEL/CentOS
]

FAILED_PASSWORD_RE = re.compile(
    r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+'
)
INVALID_USER_RE = re.compile(
    r'Invalid user (?P<user>\S+) from (?P<ip>[\d.]+) port \d+'
)
# Pattern for journalctl output (includes timestamp prefix)
JOURNAL_FAILED_RE = re.compile(
    r'sshd\[\d+\]: Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+'
)
JOURNAL_INVALID_RE = re.compile(
    r'sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>[\d.]+) port \d+'
)

ATTEMPT_THRESHOLD = 5
WINDOW_SECONDS    = 120
ALERT_COOLDOWN    = 300
PRUNE_MAX_AGE     = 3600
PRUNE_INTERVAL    = 300

logger = logging.getLogger("ssh_monitor")
logger.setLevel(logging.INFO)
_fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
_sh  = logging.StreamHandler()
_sh.setFormatter(_fmt)
logger.addHandler(_sh)

LOG_DIR.mkdir(parents=True, exist_ok=True)
_fh = logging.handlers.RotatingFileHandler(
    LOG_DIR / 'ml_engine.log', maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT
)
_fh.setFormatter(_fmt)
logger.addHandler(_fh)


def _find_auth_log() -> Optional[Path]:
    """Return path to auth log if it exists and is readable, else None."""
    for path in AUTH_LOG_CANDIDATES:
        if path.exists():
            try:
                path.open('r').close()
                return path
            except PermissionError:
                logger.warning(f"{path} exists but is not readable by this user. "
                               "Run: sudo usermod -aG adm soc")
    return None


def _inode(path: Path) -> int:
    try:
        return os.stat(path).st_ino
    except OSError:
        return -1


class MLEngine:
    def __init__(self):
        self.running     = True
        self.db          = SOCDatabase()
        self.attempts:   Dict[str, Dict] = {}
        self.last_alert: Dict[str, float] = {}
        self._last_prune = time.time()
        logger.info("🚀 SSH Brute-Force Engine started")

    # ── Tracker ───────────────────────────────────────────────────────

    def _record_failure(self, ip: str, user: str) -> None:
        now    = time.time()
        bucket = self.attempts.setdefault(
            ip, {'count': 0, 'users': set(), 'window_start': now, 'last_seen': now}
        )
        bucket['last_seen'] = now
        if now - bucket['window_start'] > WINDOW_SECONDS:
            bucket['count']        = 0
            bucket['users']        = set()
            bucket['window_start'] = now
        bucket['count'] += 1
        bucket['users'].add(user)
        if bucket['count'] >= ATTEMPT_THRESHOLD:
            if now - self.last_alert.get(ip, 0) >= ALERT_COOLDOWN:
                self.last_alert[ip] = now
                self._raise_alert(ip, bucket['count'], bucket['users'])

    def _raise_alert(self, ip: str, count: int, users: set) -> None:
        alert = {
            'source_ip':        ip,
            'destination_port': 22,
            'severity':         'HIGH',
            'confidence':       0.95,
            'explanation':      (
                f'SSH brute-force: {count} failed attempts in {WINDOW_SECONDS}s '
                f'from {ip} (users tried: {", ".join(sorted(users)[:5])})'
            ),
            'country':          'Unknown',
            'ip_category':      'Public',
            'status':           'new',
            'attack_type':      'SSH-BruteForce',
            'source_component': 'ssh_monitor',
            'detection_method': 'rule',
            'isp':              'SOC',
        }
        ok = self.db.add_alert(alert)
        if ok:
            logger.info(f"✅ SSH brute-force alert: {ip} ({count} attempts)")
        else:
            logger.error(f"❌ Failed to write alert for {ip}")

    def _prune_trackers(self) -> None:
        now   = time.time()
        stale = [ip for ip, b in self.attempts.items()
                 if now - b['last_seen'] > PRUNE_MAX_AGE]
        for ip in stale:
            self.attempts.pop(ip, None)
        stale_a = [ip for ip, ts in self.last_alert.items()
                   if now - ts > PRUNE_MAX_AGE]
        for ip in stale_a:
            self.last_alert.pop(ip, None)

    def _parse_line(self, line: str) -> None:
        m = (FAILED_PASSWORD_RE.search(line) or
             INVALID_USER_RE.search(line) or
             JOURNAL_FAILED_RE.search(line) or
             JOURNAL_INVALID_RE.search(line))
        if m:
            self._record_failure(m.group('ip'), m.group('user'))
            logger.debug(f"Failed login: {m.group('ip')} user={m.group('user')}")

    # ── Source 1: tail auth.log ───────────────────────────────────────

    def _tail_file(self, path: Path) -> None:
        current_inode = _inode(path)
        f = open(path, 'r', errors='ignore')
        try:
            f.seek(0, 2)   # jump to EOF
            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    if time.time() - self._last_prune > PRUNE_INTERVAL:
                        self._prune_trackers()
                        self._last_prune = time.time()
                    disk_inode = _inode(path)
                    if disk_inode == -1:
                        logger.warning(f"{path} deleted — waiting for recreation")
                        return
                    if disk_inode != current_inode:
                        logger.info(f"Log rotation detected on {path}, reopening")
                        f.close()
                        time.sleep(1)
                        f = open(path, 'r', errors='ignore')
                        current_inode = _inode(path)
                    continue
                try:
                    self._parse_line(line)
                except Exception as e:
                    logger.error(f"Parse error: {e}")
        finally:
            f.close()

    # ── Source 2: journalctl fallback ────────────────────────────────

    def _tail_journal(self) -> None:
        """
        FIX: Ubuntu 24.04 may not have /var/log/auth.log. Fall back to
        streaming sshd entries directly from the systemd journal.
        This requires no special permissions beyond what journalctl
        allows for the current user.
        """
        logger.info("📋 auth.log not found — falling back to systemd journal (journalctl)")
        cmd = [
            'journalctl', '-f',
            '-u', 'ssh',          # sshd service
            '-u', 'sshd',         # alternate unit name
            '--no-pager',
            '--output', 'short',
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            logger.info("✅ Streaming SSH events from systemd journal")
            for line in proc.stdout:
                if not self.running:
                    break
                try:
                    self._parse_line(line)
                except Exception as e:
                    logger.error(f"Journal parse error: {e}")
                if time.time() - self._last_prune > PRUNE_INTERVAL:
                    self._prune_trackers()
                    self._last_prune = time.time()
        except FileNotFoundError:
            logger.error("journalctl not found — SSH brute-force detection unavailable")
            while self.running:
                time.sleep(60)
        except Exception as e:
            logger.error(f"Journal tail error: {e}")
            time.sleep(10)

    # ── Main ──────────────────────────────────────────────────────────

    def run(self) -> None:
        self._last_prune = time.time()
        auth_log = _find_auth_log()

        if auth_log:
            logger.info(f"🔄 Tailing {auth_log} for SSH brute-force attempts...")
            while self.running:
                try:
                    self._tail_file(auth_log)
                except FileNotFoundError:
                    logger.warning(f"{auth_log} missing — retrying in 5s")
                    time.sleep(5)
                except KeyboardInterrupt:
                    self.running = False
                except Exception as e:
                    logger.error(f"Tail error: {e}")
                    time.sleep(10)
        else:
            # Ubuntu 24 without rsyslog — use journal
            while self.running:
                try:
                    self._tail_journal()
                except KeyboardInterrupt:
                    self.running = False
                except Exception as e:
                    logger.error(f"Journal error: {e}")
                    time.sleep(10)


if __name__ == '__main__':
    engine = MLEngine()
    try:
        engine.run()
    except KeyboardInterrupt:
        logger.info("SSH Brute-Force Engine stopped")
