"""
Cloud Provider IP Filter

Filters known cloud/CDN provider IPs to suppress false positives.
Also includes Telegram server ranges to prevent the SOC platform from
alerting on its own outbound notification traffic.
"""

import ipaddress
import json
import logging
from pathlib import Path
from typing import Optional, Dict, List

log = logging.getLogger("soc.cloud_filter")

try:
    from config.settings import DATA_DIR
except Exception:
    DATA_DIR = Path(__file__).parent.parent / 'data'

EXTERNAL_RANGES_FILE = DATA_DIR / 'cloud_ranges.json'

CLOUD_PROVIDERS: Dict[str, List[str]] = {
    'Google Cloud': [
        # GCP regional ranges (covers 34.x.x.x alerts seen in dashboard)
        '34.0.0.0/9',    '34.128.0.0/10',
        '35.184.0.0/13', '35.192.0.0/11',
        '35.224.0.0/12', '35.240.0.0/13',
        '104.154.0.0/15','104.196.0.0/14',
        '108.59.80.0/20','130.211.0.0/22',
        '146.148.0.0/17','162.216.148.0/22',
        '162.222.176.0/21','173.255.112.0/20',
        '192.158.28.0/22','199.192.112.0/22',
        '208.68.108.0/22',
    ],
    'Google': [
        # Google LLC (covers 142.250.x, 142.251.x, 216.239.x seen in dashboard)
        '142.250.0.0/15',
        '142.251.0.0/16',
        '216.239.32.0/19',
        '172.217.0.0/16',
        '173.194.0.0/16',
        '74.125.0.0/16',
        '64.233.160.0/19',
        '66.102.0.0/20',
        '66.249.80.0/20',
    ],
    'AWS': [
        '52.94.0.0/16',  '52.119.0.0/16',
        '54.239.0.0/16', '99.77.128.0/17',
        '52.46.0.0/18',  '52.84.0.0/15',
        '54.182.0.0/16', '54.192.0.0/16',
        '54.230.0.0/16', '54.239.128.0/18',
        '204.246.164.0/22',
    ],
    'Azure': [
        '40.74.0.0/15',  '40.120.0.0/16',
        '52.146.0.0/15', '52.232.0.0/13',
        '13.64.0.0/11',  '13.96.0.0/13',
        '20.33.0.0/16',  '20.34.0.0/15',
    ],
    'Cloudflare': [
        # Covers 104.17.x.x seen in dashboard
        '103.21.244.0/22','103.22.200.0/22',
        '103.31.4.0/22',  '104.16.0.0/12',
        '104.24.0.0/13',  '108.162.192.0/18',
        '131.0.72.0/22',  '141.101.64.0/18',
        '162.158.0.0/15', '172.64.0.0/13',
        '173.245.48.0/20','188.114.96.0/20',
        '190.93.240.0/20','197.234.240.0/22',
        '198.41.128.0/17',
    ],
    'Fastly': [
        # Covers 151.101.x.x seen in dashboard
        '151.101.0.0/16',
        '199.27.72.0/21',
        '23.235.32.0/20',
        '43.249.72.0/22',
        '103.244.50.0/24',
        '103.245.222.0/23',
        '103.245.224.0/24',
        '104.156.80.0/20',
        '157.52.64.0/18',
        '167.82.0.0/17',
        '167.82.128.0/20',
        '167.82.160.0/20',
        '167.82.224.0/20',
        '172.111.64.0/18',
        '185.31.16.0/22',
        '199.27.72.0/21',
        '199.232.0.0/16',
    ],
    'DigitalOcean': [
        '159.89.0.0/16',  '159.203.0.0/16',
        '162.243.0.0/16', '165.227.0.0/16',
        '167.99.0.0/16',  '174.138.0.0/16',
        '178.62.0.0/16',  '188.166.0.0/16',
        '206.189.0.0/16',
    ],
    # FIX: Telegram servers — prevents the SOC platform from alerting
    # on its own outbound Telegram notification API calls.
    # Source: https://core.telegram.org/resources/cidr.txt
    'Telegram': [
        '149.154.160.0/20',
        '91.108.4.0/22',
        '91.108.8.0/22',
        '91.108.12.0/22',
        '91.108.16.0/22',
        '91.108.20.0/22',
        '91.108.56.0/22',
        '91.108.56.0/23',
        '95.161.64.0/20',
    ],
}


def _extract_cidrs_from_aws_format(data: dict) -> Optional[Dict[str, List[str]]]:
    if 'prefixes' in data:
        cidrs = [e['ip_prefix'] for e in data['prefixes'] if 'ip_prefix' in e]
        return {'AWS': cidrs}
    if 'values' in data and isinstance(data['values'], list):
        cidrs = []
        for entry in data['values']:
            cidrs.extend(entry.get('properties', {}).get('addressPrefixes', []))
        return {'Azure': cidrs}
    return None


def _load_external_ranges() -> Optional[Dict[str, List[str]]]:
    if not EXTERNAL_RANGES_FILE.exists():
        return None
    try:
        with open(EXTERNAL_RANGES_FILE) as f:
            data = json.load(f)
        if isinstance(data, dict):
            native = _extract_cidrs_from_aws_format(data)
            if native:
                return native
            return data
    except Exception as e:
        log.warning(f"Failed to load {EXTERNAL_RANGES_FILE}: {e}")
    return None


class CloudFilter:
    def __init__(self):
        self.cloud_nets: Dict[str, list] = {}
        self._load_cloud_ranges()

    def _load_cloud_ranges(self) -> None:
        # Merge built-in + external ranges (external adds/overrides providers)
        source = dict(CLOUD_PROVIDERS)
        external = _load_external_ranges()
        if external:
            for provider, ranges in external.items():
                source.setdefault(provider, [])
                source[provider] = list(set(source[provider] + ranges))

        for provider, ranges in source.items():
            self.cloud_nets[provider] = []
            for entry in ranges:
                try:
                    cidr = entry if isinstance(entry, str) else None
                    if cidr is None:
                        continue
                    self.cloud_nets[provider].append(
                        ipaddress.ip_network(cidr, strict=False)
                    )
                except (ValueError, TypeError) as e:
                    log.debug(f"Skipping invalid CIDR '{entry}' for {provider}: {e}")

        total = sum(len(v) for v in self.cloud_nets.values())
        log.info(f"Cloud filter loaded: {total} CIDRs across {len(self.cloud_nets)} providers")

    def is_cloud_ip(self, ip_str: str) -> Optional[str]:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for provider, nets in self.cloud_nets.items():
                for net in nets:
                    if ip_obj in net:
                        return provider
            return None
        except ValueError:
            return None

    def should_filter(self, ip_str: str, severity: str = 'MEDIUM') -> bool:
        # Never suppress CRITICAL/HIGH even from cloud — compromised cloud
        # instances are a real attack vector
        if severity in ('CRITICAL', 'HIGH'):
            return False
        return self.is_cloud_ip(ip_str) is not None


cloud_filter = CloudFilter()


def is_cloud_ip(ip_str: str) -> Optional[str]:
    return cloud_filter.is_cloud_ip(ip_str)


def should_filter_cloud_alert(ip_str: str, severity: str = 'MEDIUM') -> bool:
    return cloud_filter.should_filter(ip_str, severity)
