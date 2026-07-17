"""
Telegram Alert Notifier
Sends CRITICAL and HIGH alerts to a Telegram chat instantly.
Fails soft — if token/chat_id are missing or the API call fails,
logs a warning and continues without crashing anything.
"""

import logging
import threading
import time
import os
import json
from typing import Optional
from pathlib import Path
from queue import Queue, Empty

log = logging.getLogger("soc.telegram")

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False
    log.warning("requests not installed — pip install requests")

# ------------------------------------------------------------------ #
# Configuration — set via environment variables in systemd unit or   #
# directly in /opt/soc-platform/config/telegram.json                 #
# ------------------------------------------------------------------ #

CONFIG_FILE = Path(__file__).parent.parent / 'config' / 'telegram.json'

def _load_config() -> dict:
    # 1. Environment variables take priority
    token   = os.environ.get('SOC_TELEGRAM_TOKEN', '').strip()
    chat_id = os.environ.get('SOC_TELEGRAM_CHAT_ID', '').strip()
    if token and chat_id:
        return {'token': token, 'chat_id': chat_id}

    # 2. Config file
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                data = json.load(f)
            if data.get('token') and data.get('chat_id'):
                return data
        except Exception as e:
            log.warning(f"Failed to read {CONFIG_FILE}: {e}")

    return {}


SEVERITY_EMOJI = {
    'CRITICAL': '🚨',
    'HIGH':     '🔴',
    'MEDIUM':   '🟡',
    'LOW':      '🟢',
}

METHOD_EMOJI = {
    'rule':     '📏',
    'ml':       '🤖',
    'honeypot': '🍯',
}


def _escape(text: str) -> str:
    """Escape special characters for Telegram MarkdownV2."""
    # Characters that must be escaped in MarkdownV2
    special = r'\_*[]()~`>#+-=|{}.!'
    return ''.join(f'\\{c}' if c in special else c for c in str(text))


def _format_message(alert: dict) -> str:
    sev     = alert.get('severity', 'UNKNOWN')
    emoji   = SEVERITY_EMOJI.get(sev, '⚠️')
    method  = alert.get('detection_method', 'rule')
    m_emoji = METHOD_EMOJI.get(method, '📡')

    country = alert.get('country', 'Unknown')
    city    = alert.get('city', '')
    loc     = f"{city}, {country}" if city and city not in ('Unknown', 'N/A', '') else country

    # Truncate and escape user-controlled fields that may contain special chars
    explanation = _escape(alert.get('explanation', '')[:200])
    src_ip      = _escape(alert.get('source_ip', 'N/A'))
    attack_type = _escape(alert.get('attack_type', 'Unknown'))
    timestamp   = _escape(alert.get('timestamp', '')[:19])
    loc_esc     = _escape(loc)
    port        = _escape(str(alert.get('destination_port', 'N/A')))
    conf        = f"{float(alert.get('confidence', 0)):.0%}"

    # VPN/Tor badge
    vpn_detected = bool(alert.get('vpn_detected', 0))
    vpn_type     = alert.get('vpn_type') or ''
    vpn_line     = f"🔒 *VPN/Proxy/Tor:* {_escape(vpn_type)}" if vpn_detected else ""

    lines = [
        f"{emoji} *SOC ALERT — {sev}*" + (" 🔒 VPN/TOR" if vpn_detected else ""),
        f"",
        f"🌐 *Source IP:* `{src_ip}`",
        f"📍 *Location:* {loc_esc}",
    ]
    if vpn_line:
        lines.append(vpn_line)
    lines += [
        f"⚔️ *Attack:* {attack_type}",
        f"{m_emoji} *Detected by:* {_escape(method.upper())}",
        f"🎯 *Port:* {port}",
        f"📊 *Confidence:* {conf}",
        f"",
        f"📝 {explanation}",
        f"",
        f"🕐 `{timestamp}`",
    ]
    return '\n'.join(lines)


class TelegramNotifier:
    """
    Async notifier — alerts are queued and sent by a background thread
    so slow Telegram API calls never block the detection pipeline.
    """

    NOTIFY_SEVERITIES = {'CRITICAL', 'HIGH'}
    API_TIMEOUT       = 10   # seconds
    RETRY_DELAY       = 5    # seconds between retries on failure
    MAX_RETRIES       = 3

    def __init__(self):
        self._config  = _load_config()
        self._queue:  Queue = Queue(maxsize=500)
        self._enabled = bool(self._config.get('token') and self._config.get('chat_id'))
        self._thread: Optional[threading.Thread] = None

        if not _REQUESTS_AVAILABLE:
            log.warning("Telegram disabled — requests library not available")
            self._enabled = False
            return

        if not self._enabled:
            log.warning(
                "Telegram disabled — no token/chat_id configured. "
                "Set SOC_TELEGRAM_TOKEN and SOC_TELEGRAM_CHAT_ID env vars, "
                f"or create {CONFIG_FILE} with {{\"token\":\"...\",\"chat_id\":\"...\"}}"
            )
            return

        self._base_url = (
            f"https://api.telegram.org/bot{self._config['token']}/sendMessage"
        )
        self._chat_id  = str(self._config['chat_id'])
        self._thread   = threading.Thread(
            target=self._sender_loop, name="TelegramSender", daemon=True
        )
        self._thread.start()
        log.info(f"✅ Telegram notifier active → chat_id={self._chat_id}")

    def notify(self, alert: dict) -> None:
        """Call this from the detection pipeline. Non-blocking."""
        if not self._enabled:
            return
        sev = alert.get('severity', '')
        if sev not in self.NOTIFY_SEVERITIES:
            return
        try:
            self._queue.put_nowait(alert)
        except Exception:
            log.warning("Telegram queue full — dropping notification")

    def _send(self, alert: dict) -> bool:
        text = _format_message(alert)
        for attempt in range(self.MAX_RETRIES):
            try:
                resp = requests.post(
                    self._base_url,
                    json={
                        'chat_id':    self._chat_id,
                        'text':       text,
                        'parse_mode': 'MarkdownV2',
                    },
                    timeout=self.API_TIMEOUT,
                )
                if resp.status_code == 200:
                    return True
                log.warning(f"Telegram API error {resp.status_code}: {resp.text[:100]}")
            except Exception as e:
                log.warning(f"Telegram send failed (attempt {attempt+1}): {e}")
            if attempt < self.MAX_RETRIES - 1:
                time.sleep(self.RETRY_DELAY)
        return False

    def _sender_loop(self) -> None:
        log.info("Telegram sender thread started")
        while True:
            try:
                alert = self._queue.get(timeout=5)
                ok    = self._send(alert)
                if ok:
                    log.info(
                        f"📨 Telegram sent: {alert.get('severity')} "
                        f"{alert.get('attack_type')} from {alert.get('source_ip')}"
                    )
                self._queue.task_done()
            except Empty:
                continue
            except Exception as e:
                log.error(f"Telegram sender error: {e}")


# Singleton — imported once, shared across all components
_notifier: Optional[TelegramNotifier] = None
_notifier_lock = threading.Lock()


def get_notifier() -> TelegramNotifier:
    global _notifier
    if _notifier is None:
        with _notifier_lock:
            if _notifier is None:
                _notifier = TelegramNotifier()
    return _notifier


def notify(alert: dict) -> None:
    """Module-level convenience function."""
    get_notifier().notify(alert)
