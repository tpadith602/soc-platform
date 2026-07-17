"""
VPN / Tor / Proxy Detection

Two free sources, used in order:

1. ipsum Tor/threat list (local file, no API limit)
   https://github.com/stamparm/ipsum
   Daily-updated list of known malicious IPs with a threat score.
   Score ≥ 3 = flagged. Downloaded once at startup, refreshed every 24h.

2. ip-api.com (free REST API, 45 req/min)
   Detects VPN, proxy, and hosting provider IPs.
   Results cached per-IP for 24 hours to stay well under the rate limit.
   Falls back gracefully if the API is unreachable.

Results are cached in memory so the same IP is never double-checked
within a 24-hour window.
"""

import logging
import threading
import time
from functools import lru_cache
from pathlib import Path
from typing import Optional

log = logging.getLogger("soc.vpn_detector")

try:
    import requests
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False
    log.warning("requests not installed — ip-api.com VPN check disabled")

try:
    from config.settings import DATA_DIR
except Exception:
    DATA_DIR = Path(__file__).parent.parent / 'data'

# ── Configuration ────────────────────────────────────────────────────
IPSUM_URL       = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
IPSUM_LOCAL     = DATA_DIR / 'ipsum_tor_list.txt'
IPSUM_MIN_SCORE = 3          # only flag IPs with threat score ≥ this
IPSUM_REFRESH_H = 24         # refresh ipsum list every N hours

IPAPI_URL       = "http://ip-api.com/json/{ip}?fields=status,proxy,hosting,isp,org,query"
IPAPI_TIMEOUT   = 5          # seconds
IPAPI_RATE_MIN  = 45         # max requests per minute (free tier)
IPAPI_MIN_INTERVAL = 60 / IPAPI_RATE_MIN   # ~1.33s between requests

CACHE_TTL_S     = 86400      # cache results for 24 hours

EMPTY_RESULT = {
    'is_vpn':     False,
    'is_tor':     False,
    'is_proxy':   False,
    'is_hosting': False,
    'vpn_detected': False,
    'vpn_type':   None,
    'vpn_source': None,
}


class VPNDetector:
    def __init__(self):
        self._cache: dict  = {}          # ip → {result, expires}
        self._lock         = threading.Lock()
        self._tor_ips: set = set()
        self._tor_lock     = threading.Lock()
        self._last_api_call: float = 0.0
        self._api_lock     = threading.Lock()
        self._ipsum_loaded_at: float = 0.0

        self._load_ipsum()

        # Schedule background ipsum refresh
        t = threading.Thread(target=self._ipsum_refresher, daemon=True,
                             name="IpsumRefresh")
        t.start()
        log.info("✅ VPN Detector initialised (ipsum Tor list + ip-api.com)")

    # ── ipsum list ───────────────────────────────────────────────────

    def _download_ipsum(self) -> bool:
        if not _REQUESTS_OK:
            return False
        try:
            resp = requests.get(IPSUM_URL, timeout=15)
            if resp.status_code == 200:
                DATA_DIR.mkdir(parents=True, exist_ok=True)
                IPSUM_LOCAL.write_text(resp.text, encoding='utf-8')
                log.info(f"ipsum list downloaded → {IPSUM_LOCAL}")
                return True
        except Exception as e:
            log.warning(f"ipsum download failed: {e}")
        return False

    def _parse_ipsum(self) -> set:
        if not IPSUM_LOCAL.exists():
            return set()
        ips = set()
        try:
            for line in IPSUM_LOCAL.read_text(encoding='utf-8', errors='ignore').splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('\t')
                if len(parts) >= 2:
                    try:
                        if int(parts[1]) >= IPSUM_MIN_SCORE:
                            ips.add(parts[0].strip())
                    except ValueError:
                        pass
                elif len(parts) == 1:
                    ips.add(parts[0].strip())
            log.info(f"ipsum: loaded {len(ips)} flagged IPs (score ≥ {IPSUM_MIN_SCORE})")
        except Exception as e:
            log.warning(f"ipsum parse error: {e}")
        return ips

    def _load_ipsum(self):
        if not IPSUM_LOCAL.exists():
            log.info("ipsum list not found locally — downloading...")
            self._download_ipsum()
        ips = self._parse_ipsum()
        with self._tor_lock:
            self._tor_ips = ips
        self._ipsum_loaded_at = time.time()

    def _ipsum_refresher(self):
        while True:
            time.sleep(IPSUM_REFRESH_H * 3600)
            log.info("Refreshing ipsum Tor/threat list...")
            if self._download_ipsum():
                ips = self._parse_ipsum()
                with self._tor_lock:
                    self._tor_ips = ips

    def _is_tor(self, ip: str) -> bool:
        with self._tor_lock:
            return ip in self._tor_ips

    # ── ip-api.com ───────────────────────────────────────────────────

    def _rate_limited_api_call(self, ip: str) -> Optional[dict]:
        if not _REQUESTS_OK:
            return None
        with self._api_lock:
            now  = time.time()
            wait = IPAPI_MIN_INTERVAL - (now - self._last_api_call)
            if wait > 0:
                time.sleep(wait)
            self._last_api_call = time.time()

        try:
            resp = requests.get(
                IPAPI_URL.format(ip=ip),
                timeout=IPAPI_TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    return data
        except Exception as e:
            log.debug(f"ip-api.com call failed for {ip}: {e}")
        return None

    # ── Cache ─────────────────────────────────────────────────────────

    def _cache_get(self, ip: str) -> Optional[dict]:
        with self._lock:
            entry = self._cache.get(ip)
            if entry and time.time() < entry['expires']:
                return entry['result']
            if entry:
                del self._cache[ip]
        return None

    def _cache_set(self, ip: str, result: dict):
        with self._lock:
            self._cache[ip] = {
                'result':  result,
                'expires': time.time() + CACHE_TTL_S,
            }
            # Prune cache if it grows too large
            if len(self._cache) > 5000:
                now = time.time()
                stale = [k for k, v in self._cache.items() if now >= v['expires']]
                for k in stale:
                    del self._cache[k]

    # ── Public API ────────────────────────────────────────────────────

    def check(self, ip: str) -> dict:
        """
        Returns a dict with keys:
          is_vpn, is_tor, is_proxy, is_hosting,
          vpn_detected, vpn_type, vpn_source
        Never raises — always returns EMPTY_RESULT on any failure.
        """
        if not ip or ip in ('unknown', 'N/A', 'honeypot', ''):
            return dict(EMPTY_RESULT)

        # Private/loopback IPs are never VPNs
        try:
            import ipaddress
            obj = ipaddress.ip_address(ip)
            if obj.is_private or obj.is_loopback:
                return dict(EMPTY_RESULT)
        except ValueError:
            return dict(EMPTY_RESULT)

        # Check cache
        cached = self._cache_get(ip)
        if cached is not None:
            return cached

        result = dict(EMPTY_RESULT)

        # ── Source 1: ipsum (local, instant) ──
        if self._is_tor(ip):
            result.update({
                'is_tor':      True,
                'vpn_detected':True,
                'vpn_type':    'Tor',
                'vpn_source':  'ipsum',
            })
            log.info(f"🧅 Tor exit node detected: {ip} (ipsum)")
            self._cache_set(ip, result)
            return result

        # ── Source 2: ip-api.com ──
        api_data = self._rate_limited_api_call(ip)
        if api_data:
            is_proxy   = bool(api_data.get('proxy', False))
            is_hosting = bool(api_data.get('hosting', False))

            if is_proxy or is_hosting:
                vpn_type = 'Proxy/VPN' if is_proxy else 'Hosting/VPN'
                result.update({
                    'is_vpn':      is_proxy,
                    'is_proxy':    is_proxy,
                    'is_hosting':  is_hosting,
                    'vpn_detected':True,
                    'vpn_type':    vpn_type,
                    'vpn_source':  'ip-api.com',
                })
                log.info(
                    f"🔒 VPN/Proxy detected: {ip} "
                    f"type={vpn_type} "
                    f"isp={api_data.get('isp','?')} "
                    f"(ip-api.com)"
                )

        self._cache_set(ip, result)
        return result

    def prune_cache(self):
        now = time.time()
        with self._lock:
            stale = [k for k, v in self._cache.items() if now >= v['expires']]
            for k in stale:
                del self._cache[k]
        log.debug(f"VPN cache pruned — {len(stale)} stale entries removed")


# ── Singleton ────────────────────────────────────────────────────────
_detector: Optional[VPNDetector] = None
_detector_lock = threading.Lock()


def get_vpn_detector() -> VPNDetector:
    global _detector
    if _detector is None:
        with _detector_lock:
            if _detector is None:
                _detector = VPNDetector()
    return _detector


def check_vpn(ip: str) -> dict:
    """Convenience function — check a single IP."""
    try:
        return get_vpn_detector().check(ip)
    except Exception as e:
        log.error(f"VPN check failed for {ip}: {e}")
        return dict(EMPTY_RESULT)
