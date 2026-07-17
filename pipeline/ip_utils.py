"""
IP Utilities - Local IP Detection

FIX: The previous version used ip_obj.is_private which is hardcoded in
Python's ipaddress module and ALWAYS returns True for 192.168.x.x, 10.x.x.x,
and 172.16.x.x — regardless of what LOCAL_IP_RANGES contains. This meant
removing 192.168.0.0/16 from the config had zero effect; Kali's LAN IP was
always filtered and never reached the detection engine.

Fix: removed ip_obj.is_private entirely. Now ONLY the configured
LOCAL_IP_RANGES list is used. Set SOC_ALLOW_LAN_DETECTION=1 in the systemd
unit (removes 192.168.0.0/16 from the list) to allow LAN IPs through.
"""

import ipaddress
import os
from config.settings import LOCAL_IP_RANGES

# FIX: build nets fresh at import time — not cached, so env var changes
# take effect after a restart without needing to clear an lru_cache.
def _build_nets():
    nets = []
    for r in LOCAL_IP_RANGES:
        try:
            nets.append(ipaddress.ip_network(r, strict=False))
        except ValueError:
            pass
    return nets

_PRIVATE_NETS = _build_nets()


def is_local_ip(ip_str: str) -> bool:
    """Return True if ip_str should be excluded from detection.
    
    ONLY checks against the configured LOCAL_IP_RANGES list.
    Does NOT use ip_obj.is_private — that property is hardcoded
    in Python and ignores our config entirely.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        # Always skip loopback (127.x.x.x, ::1) — these are genuine localhost
        if ip_obj.is_loopback:
            return True
        # Check only against our configured ranges
        for net in _PRIVATE_NETS:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        return False


def categorize_ip(ip_str: str) -> tuple:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_loopback:
            return ('Loopback', 'Local testing')
        for net in _PRIVATE_NETS:
            if ip_obj in net:
                return ('Private', 'Local network')
        return ('Public', None)
    except ValueError:
        return ('Invalid', 'Not a valid IP')
