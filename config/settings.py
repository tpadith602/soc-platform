"""
SOC Platform — Unified Configuration
"""

import os
import secrets
from pathlib import Path

# Base paths
BASE_DIR    = Path(__file__).parent.parent.absolute()
DATA_DIR    = BASE_DIR / 'data'
MODEL_DIR   = BASE_DIR / 'model'
STORAGE_DIR = BASE_DIR / 'storage'
LOG_DIR     = BASE_DIR / 'logs'
WEB_DIR     = BASE_DIR / 'web'
SCRIPTS_DIR = BASE_DIR / 'scripts'
INGESTION_DIR = BASE_DIR / 'ingestion'

# Database
DB_PATH = STORAGE_DIR / 'soc_enriched_matrix.db'
DB_PRAGMAS = {
    'journal_mode': 'WAL',
    'synchronous':  'NORMAL',
    'cache_size':   -500000,
    'temp_store':   'MEMORY',
    'mmap_size':    268435456,
    'busy_timeout': 5000,
}

# LRU Cache
LRU_CACHE_MAX_SIZE  = 10000
LRU_CACHE_TTL_SECONDS = 3600

# Network
# SOC_ALLOW_LAN_DETECTION=1 removes 192.168.0.0/16 from the filter
# so Kali/LAN devices trigger alerts during testing.
# Set to 0 (or omit) for production.
_ALLOW_LAN = os.environ.get('SOC_ALLOW_LAN_DETECTION', '0') == '1'

LOCAL_IP_RANGES = [
    '10.0.0.0/8', '172.16.0.0/12',
    '127.0.0.0/8', '169.254.0.0/16',
    *(() if _ALLOW_LAN else ('192.168.0.0/16',)),
]

# Dashboard
# FIX #15 (Unprotected Configuration Casting): the previous code did
#   FLASK_PORT = int(os.environ.get('SOC_FLASK_PORT', 5001))
# at module import time. If SOC_FLASK_PORT is set to an empty string or
# a non-numeric value, int() raises ValueError and the *entire launcher
# fails to boot*. Wrap in a helper that falls back to a safe default and
# logs a warning instead of crashing.
def _safe_int(env_var: str, default: int) -> int:
    raw = os.environ.get(env_var, '')
    if raw.strip():
        try:
            return int(raw.strip())
        except ValueError:
            import logging
            logging.getLogger("soc.settings").warning(
                f"Env var {env_var}='{raw}' is not a valid integer; "
                f"using default {default}"
            )
    return default


FLASK_HOST = os.environ.get('SOC_FLASK_HOST', '127.0.0.1')
FLASK_PORT = _safe_int('SOC_FLASK_PORT', 5001)
AUTO_REFRESH_INTERVAL = 60

# Secret / API key management
SECRET_KEY_FILE = STORAGE_DIR / '.secret_key'
API_KEY_FILE    = STORAGE_DIR / '.api_key'


def _load_or_create_secret(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_text().strip()
    value = secrets.token_hex(32)
    path.write_text(value)
    path.chmod(0o600)
    return value


def get_flask_secret_key() -> str:
    return os.environ.get('SOC_SECRET_KEY') or _load_or_create_secret(SECRET_KEY_FILE)


def get_api_key() -> str:
    return os.environ.get('SOC_API_KEY') or _load_or_create_secret(API_KEY_FILE)


# FIX #15: CORS list also goes through a safe parser so a blank env var
# doesn't produce [''] (a list containing an empty string) which Flask-CORS
# would interpret as "allow the empty-string origin".
def _parse_origins(env_var: str, default: str) -> list:
    raw = os.environ.get(env_var, default).strip()
    origins = [o.strip() for o in raw.split(',') if o.strip()]
    return origins or [default]


CORS_ALLOWED_ORIGINS = _parse_origins(
    'SOC_CORS_ORIGINS', f'http://localhost:{FLASK_PORT}'
)

# ML Model
MODEL_FEATURES = 5
MODEL_ACCURACY = 0.9848

# Log rotation
LOG_MAX_BYTES   = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5

# Honeypot — decoy services (SSH/HTTP/FTP)
# Enabled by default. Disable with SOC_HONEYPOT_ENABLED=0 in the systemd unit.
HONEYPOT_ENABLED   = os.environ.get('SOC_HONEYPOT_ENABLED', '1') == '1'
HONEYPOT_SSH_PORT  = _safe_int('SOC_HONEYPOT_SSH_PORT',  2222)
HONEYPOT_HTTP_PORT = _safe_int('SOC_HONEYPOT_HTTP_PORT', 8080)
HONEYPOT_FTP_PORT  = _safe_int('SOC_HONEYPOT_FTP_PORT',  2121)
HONEYPOT_PORTS     = [HONEYPOT_SSH_PORT, HONEYPOT_HTTP_PORT, HONEYPOT_FTP_PORT]

# FIX #16 (Shared Resource Access Race): mkdir at import time can conflict
# when multiple worker processes / threads import this module concurrently
# on restricted filesystems. exist_ok=True already makes the call idempotent,
# but we additionally catch OSError so a transient race between two importing
# processes doesn't propagate an exception and kill the importer.
for _d in [DATA_DIR, MODEL_DIR, STORAGE_DIR, LOG_DIR, WEB_DIR, SCRIPTS_DIR, INGESTION_DIR]:
    try:
        _d.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass   # already exists from a concurrent importer — safe to ignore
