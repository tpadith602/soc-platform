"""
GeoIP Enrichment
Wraps MaxMind GeoLite2-City.mmdb to add country/city/lat/lon to every alert.
Fails soft — if the .mmdb file is missing, returns empty enrichment so the
rest of the pipeline keeps working unaffected.
"""

import logging
from pathlib import Path
from typing import Optional
from functools import lru_cache

log = logging.getLogger("soc.geoip")

try:
    import geoip2.database
    import geoip2.errors
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False
    log.warning("geoip2 not installed — pip install geoip2")

try:
    from config.settings import DATA_DIR
except Exception:
    DATA_DIR = Path(__file__).parent.parent / 'data'

MMDB_PATH = DATA_DIR / 'GeoLite2-City.mmdb'

_reader = None


def _get_reader():
    global _reader
    if _reader is not None:
        return _reader
    if not _GEOIP2_AVAILABLE:
        return None
    if not MMDB_PATH.exists():
        log.warning(
            f"GeoLite2-City.mmdb not found at {MMDB_PATH}. "
            "Download from https://www.maxmind.com/en/geolite2/signup "
            "and place at data/GeoLite2-City.mmdb"
        )
        return None
    try:
        _reader = geoip2.database.Reader(str(MMDB_PATH))
        log.info(f"✅ GeoIP database loaded from {MMDB_PATH}")
        return _reader
    except Exception as e:
        log.error(f"Failed to load GeoIP database: {e}")
        return None


@lru_cache(maxsize=4096)
def lookup(ip: str) -> dict:
    """
    Returns enrichment dict with keys:
      country, country_code, city, region, latitude, longitude, isp
    All values default to 'Unknown'/0.0 if lookup fails.
    """
    default = {
        'country':      'Unknown',
        'country_code': 'XX',
        'city':         'Unknown',
        'region':       'Unknown',
        'latitude':     0.0,
        'longitude':    0.0,
        'isp':          'Unknown',
    }

    reader = _get_reader()
    if reader is None:
        return default

    try:
        r = reader.city(ip)
        return {
            'country':      r.country.name or 'Unknown',
            'country_code': r.country.iso_code or 'XX',
            'city':         r.city.name or 'Unknown',
            'region':       (r.subdivisions.most_specific.name or 'Unknown'),
            'latitude':     float(r.location.latitude or 0.0),
            'longitude':    float(r.location.longitude or 0.0),
            'isp':          'Unknown',   # City DB doesn't include ISP; use ASN DB if needed
        }
    except Exception:
        return default


def enrich_alert(alert: dict) -> dict:
    """Add GeoIP fields to an alert dict in-place and return it."""
    ip = alert.get('source_ip', '')
    if not ip or ip in ('honeypot', 'N/A', 'Unknown', ''):
        return alert
    geo = lookup(ip)
    alert.update(geo)
    return alert
