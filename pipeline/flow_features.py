"""
Flow Feature Extractor

Builds a rolling per-source-IP traffic profile from raw packets, and maps
those generic stats onto whatever feature names the trained model expects
(config/settings.py + scripts/train_model.py persist feature names to
model/features.json).

IMPORTANT HONESTY NOTE: CICIDS2017 features (the dataset train_model.py
trains on) are produced by a dedicated flow exporter (CICFlowMeter) with
~70-80 highly specific bidirectional-flow statistics (fwd/bwd inter-arrival
times, flag counts, subflow stats, etc). Reconstructing all of those exactly
from raw scapy packets in real time is a much bigger project than a single
feature-extractor module. What this module does instead is a best-effort
mapping: it computes a handful of generic, well-understood traffic stats
per source IP (packet count, byte volume, duration, packet-size stats,
unique destination ports/IPs, rate) and fuzzy-matches them onto model
feature names by substring. Any feature name it can't confidently map gets
0.0. This means inference quality depends on how much of the original
feature set actually matters vs. is approximated as zero — treat the ML
layer as a second opinion alongside the rule-based engine, not a
drop-in replacement for the exact CICIDS2017 pipeline.
"""

import threading
import time
from typing import Dict, List, Optional


class FlowTracker:
    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self._flows: Dict[str, dict] = {}
        self._lock = threading.Lock()

    def update(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str, packet_len: int) -> None:
        now = time.time()
        with self._lock:
            flow = self._flows.get(src_ip)
            if flow is None or now - flow['start_time'] > self.window_seconds:
                flow = {
                    'start_time': now,
                    'last_seen': now,
                    'packet_count': 0,
                    'byte_count': 0,
                    'dst_ports': set(),
                    'dst_ips': set(),
                    'last_dst_port': dst_port,
                    'min_pkt_len': None,
                    'max_pkt_len': 0,
                    'syn_count': 0,
                    'protocols': set(),
                }
                self._flows[src_ip] = flow

            flow['last_seen'] = now
            flow['packet_count'] += 1
            flow['byte_count'] += packet_len
            flow['dst_ports'].add(dst_port)
            flow['dst_ips'].add(dst_ip)
            flow['last_dst_port'] = dst_port  # FIX: needed for the destination_port model feature
            flow['protocols'].add(protocol)
            flow['min_pkt_len'] = packet_len if flow['min_pkt_len'] is None else min(flow['min_pkt_len'], packet_len)
            flow['max_pkt_len'] = max(flow['max_pkt_len'], packet_len)

    def packet_count(self, src_ip: str) -> int:
        with self._lock:
            flow = self._flows.get(src_ip)
            return flow['packet_count'] if flow else 0

    def generic_stats(self, src_ip: str) -> Optional[dict]:
        with self._lock:
            flow = self._flows.get(src_ip)
            if not flow:
                return None
            duration_sec = max(flow['last_seen'] - flow['start_time'], 0.001)
            count = flow['packet_count']
            total_bytes = flow['byte_count']
            return {
                'packet_count': count,
                'byte_count': total_bytes,
                'duration': duration_sec,
                'duration_microseconds': duration_sec * 1_000_000,  # FIX: training data's 'duration' column is in µs
                'last_dst_port': flow['last_dst_port'],
                'avg_packet_size': total_bytes / count if count else 0.0,
                'min_packet_size': flow['min_pkt_len'] or 0,
                'max_packet_size': flow['max_pkt_len'],
                'unique_dst_ports': len(flow['dst_ports']),
                'unique_dst_ips': len(flow['dst_ips']),
                'packets_per_second': count / duration_sec,
                'bytes_per_second': total_bytes / duration_sec,
            }

    def prune(self, max_age: int) -> None:
        now = time.time()
        with self._lock:
            stale = [ip for ip, f in self._flows.items() if now - f['last_seen'] > max_age]
            for ip in stale:
                del self._flows[ip]


# FIX: exact-name mapping for the curated 5-feature model trained on the
# user's processed_dataset.csv (destination_port, duration, packet_count,
# byte_count, connection_rate). Checked first since it's a precise match
# with correct units, unlike the generic CICIDS substring mapping below
# which was written for the broader 78-column CICFlowMeter-style schema.
_EXACT_FEATURE_MAP = {
    'destination_port': 'last_dst_port',
    'dst_port': 'last_dst_port',
    'duration': 'duration_microseconds',  # matches training data's microsecond unit
    'packet_count': 'packet_count',
    'byte_count': 'byte_count',
    'connection_rate': 'packets_per_second',  # confirmed equivalent: packet_count / (duration_us) * 1e6
}

# FIX: substring-based fuzzy map from CICIDS2017-style feature names to the
# generic stats above. Order matters - first match wins, so more specific
# patterns are listed before generic ones.
_FEATURE_NAME_MAP = [
    ('flow_duration', 'duration'),
    ('duration', 'duration'),
    ('flow_byts', 'bytes_per_second'),
    ('flow_bytes', 'bytes_per_second'),
    ('byts_per_sec', 'bytes_per_second'),
    ('bytes_per_sec', 'bytes_per_second'),
    ('flow_pkts', 'packets_per_second'),
    ('flow_packets', 'packets_per_second'),
    ('pkts_per_sec', 'packets_per_second'),
    ('packets_per_sec', 'packets_per_second'),
    ('tot_fwd_pkts', 'packet_count'),
    ('tot_bwd_pkts', 'packet_count'),
    ('total_fwd_packets', 'packet_count'),
    ('total_backward_packets', 'packet_count'),
    ('tot_pkts', 'packet_count'),
    ('totlen_fwd_pkts', 'byte_count'),
    ('totlen_bwd_pkts', 'byte_count'),
    ('total_length_of', 'byte_count'),
    ('pkt_len_max', 'max_packet_size'),
    ('max_packet_length', 'max_packet_size'),
    ('pkt_len_min', 'min_packet_size'),
    ('min_packet_length', 'min_packet_size'),
    ('pkt_len_mean', 'avg_packet_size'),
    ('packet_length_mean', 'avg_packet_size'),
    ('avg_pkt_size', 'avg_packet_size'),
    ('average_packet_size', 'avg_packet_size'),
    ('dst_port', None),  # left as 0.0 deliberately - we don't want the port itself driving the score
]


def build_feature_vector(src_ip: str, feature_names: List[str], tracker: FlowTracker) -> List[float]:
    stats = tracker.generic_stats(src_ip) or {}
    vector = []
    for name in feature_names:
        norm = name.strip().lower().replace(' ', '_')

        # FIX: exact match against the curated model's known schema first
        if norm in _EXACT_FEATURE_MAP:
            stat_key = _EXACT_FEATURE_MAP[norm]
            vector.append(float(stats.get(stat_key, 0.0)))
            continue

        value = 0.0
        for pattern, stat_key in _FEATURE_NAME_MAP:
            if pattern in norm:
                value = float(stats.get(stat_key, 0.0)) if stat_key else 0.0
                break
        vector.append(value)
    return vector
