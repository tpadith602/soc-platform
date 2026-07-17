#!/usr/bin/env python3
"""
Real-Time Network Intrusion Detection Engine — Hybrid (Rule + ML)
"""

import logging
import logging.handlers
import queue
import signal
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, Any

try:
    from scapy.all import sniff, Packet, IP, TCP, UDP, ICMP
except ImportError:
    print("[FATAL] Scapy is required: pip install scapy")
    sys.exit(1)

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import LOG_DIR, LOG_MAX_BYTES, LOG_BACKUP_COUNT, MODEL_DIR
from pipeline.ip_utils import is_local_ip
from pipeline.cloud_filter import should_filter_cloud_alert
from pipeline.flow_features import FlowTracker, build_feature_vector
from ingestion.database import SOCDatabase
from ingestion.ml_inference import MLAnomalyDetector


@dataclass(frozen=True)
class NIDSConfig:
    interface: Optional[str] = None
    bpf_filter: str = "ip"
    queue_maxsize: int = 10000
    consumer_threads: int = 2
    queue_put_timeout: float = 0.5
    queue_get_timeout: float = 1.0
    port_scan_threshold: int = 10     # lowered from 15 — 10 distinct ports/60s is reliable signal
    connection_threshold: int = 200   # raised from 80 — Fastly/Google CDN hits 80 conns easily
    window_seconds: int = 60
    alert_cooldown: int = 300
    tracker_prune_interval: int = 120
    tracker_max_age: int = 600
    ml_min_packets: int = 10
    ml_eval_every_n_packets: int = 15


CONFIG = NIDSConfig()


def setup_logging() -> logging.Logger:
    logger = logging.getLogger("nids")
    logger.setLevel(logging.INFO)
    log_file = LOG_DIR / 'nids_engine.log'
    log_file.parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(threadName)-14s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    fh = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT
    )
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger


log = setup_logging()

packet_queue: queue.Queue = queue.Queue(maxsize=CONFIG.queue_maxsize)
shutdown_event = threading.Event()

stats: Dict[str, int] = {
    "captured": 0, "dropped_queue_full": 0, "processed": 0,
    "alerts_generated": 0, "errors": 0,
}
stats_lock = threading.Lock()


def bump_stat(key: str, amount: int = 1) -> None:
    with stats_lock:
        stats[key] += amount


class DetectionEngine:
    def __init__(self):
        self.db = SOCDatabase()
        # FIX #5 (Global Lock Contention): replaced a single coarse _lock
        # with per-tracker RLocks so port-scan checks and connection-flood
        # checks no longer serialise each other. The ML counters keep their
        # own separate lock. Flow tracker has its own internal lock. Only
        # last_alert_tracker, which is read/written by all three check
        # methods, is still under a shared lock — but that access is a
        # single dict read/write, far faster than the aggregation work it
        # was previously serialising.
        self._ps_lock   = threading.Lock()   # port_scan_tracker
        self._cf_lock   = threading.Lock()   # connection_tracker
        self._al_lock   = threading.Lock()   # last_alert_tracker
        self._ml_lock   = threading.Lock()   # ml packet counters

        self.port_scan_tracker:  Dict[str, Dict[str, Any]] = {}
        self.connection_tracker: Dict[str, Dict[str, Any]] = {}
        self.last_alert_tracker: Dict[str, float]          = {}
        self._ml_packet_counters: Dict[str, int]           = {}

        self.window_seconds  = CONFIG.window_seconds
        self.alert_cooldown  = CONFIG.alert_cooldown
        self.flow_tracker    = FlowTracker(window_seconds=CONFIG.window_seconds)
        self.ml_detector     = MLAnomalyDetector(MODEL_DIR)

        if self.ml_detector.available:
            log.info("✅ Hybrid mode: rule-based + ML anomaly detection active")
        else:
            log.warning("⚠️  ML model not found — running rule-based only")
        log.info("✅ Detection Engine initialised (shared across consumers)")

    # ------------------------------------------------------------------ #
    # Cooldown (shared read; short critical section)                       #
    # ------------------------------------------------------------------ #

    def _check_cooldown(self, src_ip: str) -> bool:
        with self._al_lock:
            last = self.last_alert_tracker.get(src_ip, 0)
        return time.time() - last < self.alert_cooldown

    def _set_cooldown(self, src_ip: str) -> None:
        with self._al_lock:
            self.last_alert_tracker[src_ip] = time.time()

    # ------------------------------------------------------------------ #
    # Rule: Port Scan                                                      #
    # ------------------------------------------------------------------ #

    def _check_port_scan(self, src_ip: str, dst_port: int) -> Optional[Dict]:
        now = time.time()
        with self._ps_lock:
            window = self.port_scan_tracker.setdefault(
                src_ip, {'ports': set(), 'timestamp': now}
            )
            if now - window['timestamp'] > self.window_seconds:
                window['ports']     = set()
                window['timestamp'] = now
            window['ports'].add(dst_port)
            port_count = len(window['ports'])

        if port_count >= CONFIG.port_scan_threshold and not self._check_cooldown(src_ip):
            self._set_cooldown(src_ip)
            return {
                'severity':        'MEDIUM',
                'confidence':      0.88,
                'explanation':     f"Port scan: {port_count} distinct ports from {src_ip}",
                'attack_type':     'PortScan',
                'detection_method':'rule',
            }
        return None

    # ------------------------------------------------------------------ #
    # Rule: Connection Flood                                               #
    # ------------------------------------------------------------------ #

    def _check_connection_flood(self, src_ip: str) -> Optional[Dict]:
        now = time.time()
        with self._cf_lock:
            window = self.connection_tracker.setdefault(
                src_ip, {'count': 0, 'timestamp': now}
            )
            if now - window['timestamp'] > self.window_seconds:
                window['count']     = 0
                window['timestamp'] = now
            window['count'] += 1
            count = window['count']

        if count >= CONFIG.connection_threshold and not self._check_cooldown(src_ip):
            self._set_cooldown(src_ip)
            return {
                'severity':        'HIGH',
                'confidence':      0.92,
                'explanation':     f"Connection flood: {count} connections from {src_ip} in {self.window_seconds}s",
                'attack_type':     'DDoS',
                'detection_method':'rule',
            }
        return None

    # ------------------------------------------------------------------ #
    # ML layer                                                             #
    # ------------------------------------------------------------------ #

    def _check_ml_anomaly(self, src_ip: str) -> Optional[Dict]:
        if not self.ml_detector.available:
            return None
        with self._ml_lock:
            count = self._ml_packet_counters.get(src_ip, 0) + 1
            self._ml_packet_counters[src_ip] = count
            should_eval = (
                count >= CONFIG.ml_min_packets
                and count % CONFIG.ml_eval_every_n_packets == 0
            )
        if not should_eval or self._check_cooldown(src_ip):
            return None
        vec = build_feature_vector(src_ip, self.ml_detector.feature_names, self.flow_tracker)
        result = self.ml_detector.predict(vec)
        if result is None:
            return None
        is_anomaly, confidence, label = result
        if not is_anomaly:
            return None
        self._set_cooldown(src_ip)
        return {
            'severity':        'HIGH' if confidence >= 0.85 else 'MEDIUM',
            'confidence':      round(confidence, 4),
            'explanation':     f"ML flagged {src_ip} as '{label}' (conf {confidence:.0%})",
            'attack_type':     f'ML-Anomaly:{label}',
            'detection_method':'ml',
        }

    # ------------------------------------------------------------------ #
    # Prune                                                                #
    # ------------------------------------------------------------------ #

    def prune_trackers(self) -> None:
        now     = time.time()
        max_age = CONFIG.tracker_max_age

        with self._ps_lock:
            stale = [ip for ip, w in self.port_scan_tracker.items()
                     if now - w['timestamp'] > max_age]
            for ip in stale:
                del self.port_scan_tracker[ip]

        with self._cf_lock:
            stale = [ip for ip, w in self.connection_tracker.items()
                     if now - w['timestamp'] > max_age]
            for ip in stale:
                del self.connection_tracker[ip]

        with self._al_lock:
            stale = [ip for ip, ts in self.last_alert_tracker.items()
                     if now - ts > max_age]
            for ip in stale:
                del self.last_alert_tracker[ip]

        self.flow_tracker.prune(max_age)

        with self._ml_lock:
            stale = [ip for ip in self._ml_packet_counters
                     if self.flow_tracker.generic_stats(ip) is None]
            for ip in stale:
                del self._ml_packet_counters[ip]

        log.debug(
            f"Prune: ps={len(self.port_scan_tracker)} "
            f"cf={len(self.connection_tracker)} "
            f"al={len(self.last_alert_tracker)}"
        )

    # ------------------------------------------------------------------ #
    # Alert write                                                          #
    # ------------------------------------------------------------------ #

    def add_alert(self, alert_data: Dict[str, Any]) -> bool:
        data = dict(alert_data)
        data['source_component'] = 'nids'
        data.setdefault('isp', 'NIDS')
        data.setdefault('attack_type', 'Network Anomaly')
        data.setdefault('detection_method', 'rule')
        ok = self.db.add_alert(data)
        if ok:
            bump_stat("alerts_generated")
            log.info(
                f"✅ Alert [{data['detection_method']}]: {data['severity']} "
                f"from {data.get('source_ip')} ({data.get('attack_type')})"
            )
        return ok

    # ------------------------------------------------------------------ #
    # Packet analysis                                                      #
    # ------------------------------------------------------------------ #

    def analyze_packet(self, packet: Packet) -> Optional[Dict]:
        try:
            if not packet.haslayer(IP):
                return None
            ip     = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            if is_local_ip(src_ip):
                return None

            protocol = "OTHER"
            dst_port = 0
            if packet.haslayer(TCP):
                protocol = "TCP"
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol = "UDP"
                dst_port = packet[UDP].dport
            elif packet.haslayer(ICMP):
                protocol = "ICMP"

            # Skip known CDN/cloud IPs before any tracking
            from pipeline.cloud_filter import is_cloud_ip as _is_cloud
            if _is_cloud(src_ip):
                return None

            # Skip CDN/cloud IPs entirely — they flood the connection tracker
            # and generate HIGH DDoS false positives even though cloud_filter
            # only suppresses MEDIUM. Returning None before any tracking means
            # they never accumulate counts.
            if should_filter_cloud_alert(src_ip, 'MEDIUM'):
                return None

            # FIX: skip CDN/cloud IPs from all detection entirely — they were
            # hitting the connection_threshold and generating HIGH DDoS alerts
            # even though cloud_filter only suppresses MEDIUM. Skipping here
            # means they never enter any tracker at all.
            if cloud_filter.is_cloud_ip(src_ip):
                return None

            # FIX #6 (Fragile packet length): getattr with a default of None
            # and a len(bytes(packet)) fallback could trigger raw-decode
            # exceptions on fragmented packets, swallowing the exception
            # silently. Use a two-stage safe fallback with explicit guards.
            try:
                pkt_len = int(ip.len) if ip.len else len(packet)
            except Exception:
                pkt_len = 64   # conservative default; won't crash tracker

            self.flow_tracker.update(src_ip, dst_ip, dst_port, protocol, pkt_len)

            base = {
                'source_ip':       src_ip,
                'destination_ip':  dst_ip,
                'destination_port':dst_port,
                'protocol':        protocol,
                'packet_info':     str(packet.summary()),
            }

            if dst_port > 0:
                r = self._check_port_scan(src_ip, dst_port)
                if r and not should_filter_cloud_alert(src_ip, r['severity']):
                    return {**base, **r}

            if protocol == "TCP":
                r = self._check_connection_flood(src_ip)
                if r and not should_filter_cloud_alert(src_ip, r['severity']):
                    return {**base, **r}

            r = self._check_ml_anomaly(src_ip)
            if r and not should_filter_cloud_alert(src_ip, r['severity']):
                return {**base, **r}

            return None
        except Exception as e:
            log.error(f"analyze_packet error: {e}")
            return None


# ------------------------------------------------------------------ #
# Producer / Consumer / Support threads                               #
# ------------------------------------------------------------------ #

def _on_packet_captured(packet: Packet) -> None:
    bump_stat("captured")
    try:
        packet_queue.put(packet, timeout=CONFIG.queue_put_timeout)
    except queue.Full:
        bump_stat("dropped_queue_full")


def _should_stop(_: Packet) -> bool:
    return shutdown_event.is_set()


def producer_loop() -> None:
    log.info(f"Producer: iface={CONFIG.interface or '<all>'} filter='{CONFIG.bpf_filter}'")
    while not shutdown_event.is_set():
        try:
            sniff(
                iface=CONFIG.interface,
                filter=CONFIG.bpf_filter,
                prn=_on_packet_captured,
                stop_filter=_should_stop,
                store=False,
            )
        except PermissionError:
            log.critical(
                "Permission denied. Run: sudo setcap cap_net_raw,cap_net_admin=eip venv/bin/python3"
            )
            shutdown_event.set()
            return
        except Exception as e:
            bump_stat("errors")
            log.exception(f"Producer error: {e} — retrying in 5s")
            time.sleep(5)
    log.info("Producer exiting")


def consumer_loop(worker_id: int, engine: DetectionEngine) -> None:
    log.info(f"Consumer-{worker_id} starting")
    while not shutdown_event.is_set() or not packet_queue.empty():
        try:
            packet = packet_queue.get(timeout=CONFIG.queue_get_timeout)
        except queue.Empty:
            continue
        try:
            alert = engine.analyze_packet(packet)
            if alert:
                engine.add_alert(alert)
            bump_stat("processed")
        except Exception as e:
            bump_stat("errors")
            log.exception(f"Consumer-{worker_id} error: {e}")
        finally:
            packet_queue.task_done()
    log.info(f"Consumer-{worker_id} exiting")


def stats_reporter() -> None:
    while not shutdown_event.is_set():
        time.sleep(10)
        with stats_lock:
            log.info(
                f"STATS captured={stats['captured']} processed={stats['processed']} "
                f"dropped={stats['dropped_queue_full']} alerts={stats['alerts_generated']} "
                f"errors={stats['errors']} qsize={packet_queue.qsize()}"
            )


def tracker_pruner_loop(engine: DetectionEngine) -> None:
    while not shutdown_event.is_set():
        time.sleep(CONFIG.tracker_prune_interval)
        engine.prune_trackers()


def main():
    signal.signal(signal.SIGINT,  lambda s, f: shutdown_event.set())
    signal.signal(signal.SIGTERM, lambda s, f: shutdown_event.set())

    log.info("=" * 60)
    log.info("🚀 NIDS Engine starting")
    log.info("=" * 60)

    engine = DetectionEngine()

    threads = [
        threading.Thread(target=producer_loop, name="Producer", daemon=True),
        threading.Thread(target=stats_reporter, name="StatsReporter", daemon=True),
        threading.Thread(target=tracker_pruner_loop, args=(engine,), name="Pruner", daemon=True),
    ] + [
        threading.Thread(target=consumer_loop, args=(i+1, engine),
                         name=f"Consumer-{i+1}", daemon=True)
        for i in range(CONFIG.consumer_threads)
    ]

    for t in threads:
        t.start()

    try:
        while not shutdown_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        shutdown_event.set()

    log.info("Shutting down…")
    for t in threads:
        t.join(timeout=5)
    log.info("✅ NIDS Engine stopped")


if __name__ == "__main__":
    main()
