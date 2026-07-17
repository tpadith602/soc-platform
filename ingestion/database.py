"""
SQLite Database Layer - WAL Mode, SSD Optimised
Single shared module used by every component (NIDS, ML engine, honeypot).
"""

import sqlite3
import threading
import time
import uuid
import logging
from datetime import datetime
from config.settings import DB_PATH, DB_PRAGMAS

# GeoIP + VPN + Telegram — imported lazily so missing deps don't break startup
def _enrich(alert: dict) -> dict:
    try:
        from pipeline.geoip import enrich_alert
        alert = enrich_alert(alert)
    except Exception:
        pass
    try:
        from pipeline.vpn_detector import check_vpn
        vpn = check_vpn(alert.get('source_ip', ''))
        alert['vpn_detected'] = 1 if vpn.get('vpn_detected') else 0
        alert['vpn_type']     = vpn.get('vpn_type')
        alert['vpn_source']   = vpn.get('vpn_source')
    except Exception:
        pass
    return alert

# Initialize notifier eagerly at import time so the sender thread is
# already alive when the first add_alert() call happens. Lazy import
# inside _notify() caused the daemon thread to be killed before it
# could flush the queue in short-lived subprocess contexts.
try:
    from pipeline.telegram_notifier import get_notifier as _get_telegram
    _telegram = _get_telegram()
except Exception:
    _telegram = None


def _notify(alert: dict) -> None:
    try:
        if _telegram is not None:
            _telegram.notify(alert)
    except Exception:
        pass

log = logging.getLogger("soc.database")

# FIX #3 (Multi-Threaded Connection Corruption): SQLite connections are NOT
# thread-safe for concurrent state mutation even with check_same_thread=False.
# The previous design shared a single connection object across the NIDS
# consumer threads, ML engine, and Flask routes, leading to cursor-state races
# and potential corruption. Fix: give each thread its own connection via a
# thread-local pool keyed by thread id. Connections are created lazily on
# first use per thread and cached for the lifetime of that thread.
_local = threading.local()


def _get_conn(db_path: str, row_factory=True) -> sqlite3.Connection:
    """Return this thread's dedicated SQLite connection, creating it if needed."""
    conn = getattr(_local, 'conn', None)
    if conn is None:
        conn = sqlite3.connect(db_path, check_same_thread=True, timeout=10)
        if row_factory:
            conn.row_factory = sqlite3.Row
        # FIX #4 (Pragma Insecurity): pragma names and values are an internal
        # closed set defined in settings.py — the real risk is the f-string
        # allowing arbitrary value injection if settings are ever env-driven.
        # Safe fix: whitelist pragma names and cast values explicitly rather
        # than trusting the dict verbatim.
        SAFE_PRAGMAS = {
            'journal_mode', 'synchronous', 'cache_size',
            'temp_store', 'mmap_size', 'busy_timeout',
        }
        for pragma, value in DB_PRAGMAS.items():
            if pragma not in SAFE_PRAGMAS:
                log.warning(f"Skipping unknown pragma '{pragma}'")
                continue
            # Values are always numeric or a known string keyword — cast to
            # str and verify no shell-special chars before executing.
            safe_value = str(value).strip()
            if not all(c.isalnum() or c in ('-', '_') for c in safe_value):
                log.warning(f"Skipping pragma '{pragma}': unsafe value '{safe_value}'")
                continue
            conn.execute(f"PRAGMA {pragma} = {safe_value};")
        _local.conn = conn
    return conn


def _execute_with_retry(db_path: str, sql: str, params=(), retries: int = 5, base_delay: float = 0.05):
    """Execute SQL with exponential-backoff retry on 'database is locked'."""
    for attempt in range(retries):
        conn = _get_conn(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            conn.commit()
            return cursor
        except sqlite3.OperationalError as e:
            if 'locked' in str(e).lower() and attempt < retries - 1:
                time.sleep(base_delay * (2 ** attempt))
                continue
            raise
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise


class SOCDatabase:
    def __init__(self):
        self.db_path = str(DB_PATH)
        self._schema_lock = threading.Lock()
        self._init_schema()

    def _init_schema(self):
        """Create/upgrade schema once. Uses its own connection on the calling thread."""
        with self._schema_lock:
            conn = _get_conn(self.db_path)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    protocol TEXT,
                    severity TEXT,
                    confidence REAL,
                    explanation TEXT,
                    country TEXT,
                    city TEXT,
                    region TEXT,
                    isp TEXT,
                    asn TEXT,
                    is_anonymized INTEGER DEFAULT 0,
                    ip_category TEXT,
                    status TEXT DEFAULT 'new',
                    acknowledged_by TEXT,
                    comments TEXT,
                    packet_info TEXT,
                    attack_type TEXT,
                    source_component TEXT DEFAULT 'unknown',
                    detection_method TEXT DEFAULT 'rule',
                    latitude  REAL DEFAULT 0.0,
                    longitude REAL DEFAULT 0.0
                )
            ''')
            # Upgrade existing databases that predate new columns
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(alerts)")
            existing_cols = {row[1] for row in cursor.fetchall()}
            for col, defn in [
                ('source_component', "TEXT DEFAULT 'unknown'"),
                ('detection_method', "TEXT DEFAULT 'rule'"),
                ('latitude',  'REAL DEFAULT 0.0'),
                ('longitude', 'REAL DEFAULT 0.0'),
                ('vpn_detected', 'INTEGER DEFAULT 0'),
                ('vpn_type',     'TEXT DEFAULT NULL'),
                ('vpn_source',   'TEXT DEFAULT NULL'),
            ]:
                if col not in existing_cols:
                    conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {defn}")
            conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_source_ip  ON alerts(source_ip)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts(severity)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_status     ON alerts(status)')
            conn.commit()

    @staticmethod
    def make_alert_id(prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex[:12]}"

    def add_alert(self, data: dict) -> bool:
        try:
            # Enrich with GeoIP + send Telegram notification
            data = _enrich(dict(data))
            _notify(data)
            alert_id = data.get('alert_id') or self.make_alert_id(
                data.get('source_component', 'SOC')
            )
            _execute_with_retry(self.db_path, '''
                INSERT INTO alerts (
                    alert_id, timestamp, source_ip, destination_ip,
                    destination_port, protocol, severity, confidence,
                    explanation, country, city, region, isp, asn,
                    is_anonymized, ip_category, status, packet_info,
                    attack_type, source_component, detection_method,
                    latitude, longitude,
                    vpn_detected, vpn_type, vpn_source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert_id,
                data.get('timestamp', datetime.now().isoformat()),
                data.get('source_ip'),
                data.get('destination_ip', 'N/A'),
                data.get('destination_port', 0),
                data.get('protocol', 'TCP'),
                data.get('severity', 'MEDIUM'),
                data.get('confidence', 0.85),
                data.get('explanation'),
                data.get('country', 'Unknown'),
                data.get('city', 'N/A'),
                data.get('region', 'N/A'),
                data.get('isp', 'SOC'),
                data.get('asn', 'N/A'),
                data.get('is_anonymized', 0),
                data.get('ip_category', 'Public'),
                data.get('status', 'new'),
                data.get('packet_info', ''),
                data.get('attack_type', 'Unknown'),
                data.get('source_component', 'unknown'),
                data.get('detection_method', 'rule'),
                float(data.get('latitude',  0.0) or 0.0),
                float(data.get('longitude', 0.0) or 0.0),
                int(data.get('vpn_detected', 0) or 0),
                data.get('vpn_type'),
                data.get('vpn_source'),
            ))
            return True
        except Exception as e:
            log.error(f"add_alert failed: {e}")
            return False

    def get_alerts(self, limit: int = 50, status: str = None):
        conn = _get_conn(self.db_path)
        cursor = conn.cursor()
        if status:
            cursor.execute(
                "SELECT * FROM alerts WHERE status = ? ORDER BY timestamp DESC LIMIT ?",
                (status, limit),
            )
        else:
            cursor.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
        return [dict(row) for row in cursor.fetchall()]

    def get_summary(self):
        conn = _get_conn(self.db_path)
        cursor = conn.cursor()
        total = cursor.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        by_severity = cursor.execute(
            "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity"
        ).fetchall()
        by_status = cursor.execute(
            "SELECT status, COUNT(*) as count FROM alerts GROUP BY status"
        ).fetchall()
        by_method = cursor.execute(
            "SELECT detection_method, COUNT(*) as count FROM alerts GROUP BY detection_method"
        ).fetchall()
        return {
            'total': total,
            'by_severity': [dict(r) for r in by_severity],
            'by_status':   [dict(r) for r in by_status],
            'by_method':   [dict(r) for r in by_method],
        }

    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        try:
            _execute_with_retry(
                self.db_path,
                "UPDATE alerts SET status = 'acknowledged', acknowledged_by = ? WHERE alert_id = ?",
                (acknowledged_by, alert_id),
            )
            return True
        except Exception as e:
            log.error(f"acknowledge_alert failed: {e}")
            return False

    def add_comment(self, alert_id: str, comment: str) -> bool:
        try:
            _execute_with_retry(
                self.db_path,
                "UPDATE alerts SET comments = COALESCE(comments || char(10), '') || ? WHERE alert_id = ?",
                (comment, alert_id),
            )
            return True
        except Exception as e:
            log.error(f"add_comment failed: {e}")
            return False

    def update_status(self, alert_id: str, status: str) -> bool:
        try:
            _execute_with_retry(
                self.db_path,
                "UPDATE alerts SET status = ? WHERE alert_id = ?",
                (status, alert_id),
            )
            return True
        except Exception as e:
            log.error(f"update_status failed: {e}")
            return False

    def close(self):
        conn = getattr(_local, 'conn', None)
        if conn:
            conn.close()
            _local.conn = None
