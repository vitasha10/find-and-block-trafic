import re
import yaml
import time
from typing import List, Dict, Any

class RuleConfig:
    def __init__(self, cfg: Dict[str, Any]):
        self.protected_ips = set(cfg.get("protected_ips", []))
        self.large_packet_threshold = cfg.get("large_packet_threshold", 1500)
        self.port_scan_threshold = cfg.get("port_scan_threshold", 15)
        self.port_scan_window_seconds = cfg.get("port_scan_window_seconds", 10)
        self.rate_limit_pps = cfg.get("rate_limit_pps", 100)
        self.rate_limit_window_seconds = cfg.get("rate_limit_window_seconds", 2)
        self.suspicious_payload_regexes = [re.compile(rx, re.IGNORECASE) for rx in cfg.get("suspicious_payload_regexes", [])]
        self.block_durations_seconds = cfg.get("block_durations_seconds", 600)
        self.auto_block_on_detection = cfg.get("auto_block_on_detection", True)
        self.enable_icmp_unreachable = cfg.get("enable_icmp_unreachable", False)
        self.icmp_unreachable_rate_limit = cfg.get("icmp_unreachable_rate_limit", 10)
        self.http_methods_watch = set(cfg.get("http_methods_watch", ["GET", "POST", "HEAD"]))
        self.suspicious_user_agents = [re.compile(rx, re.IGNORECASE) for rx in cfg.get("suspicious_user_agents", [])]
        self.max_repeated_http_path = cfg.get("max_repeated_http_path", 50)
        self.http_repeated_window_seconds = cfg.get("http_repeated_window_seconds", 30)
        self.refresh_time = time.time()

def load_rules(path: str) -> RuleConfig:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return RuleConfig(data)

def default_config_yaml():
    return """# Конфигурация правил обнаружения
protected_ips:
  - "91.226.80.174"

large_packet_threshold: 1500
port_scan_threshold: 15
port_scan_window_seconds: 10
rate_limit_pps: 100
rate_limit_window_seconds: 2
block_durations_seconds: 600
auto_block_on_detection: true
enable_icmp_unreachable: false
icmp_unreachable_rate_limit: 10

suspicious_payload_regexes:
  - "(?:select.+from|union.+select)"
  - "/etc/passwd"
  - "\\\\x90\\\\x90\\\\x90"
  - "(?:<script>|onerror=|onload=)"

http_methods_watch: ["GET", "POST", "HEAD", "PUT", "DELETE"]
suspicious_user_agents:
  - "sqlmap"
  - "nikto"
  - "nmap"

max_repeated_http_path: 50
http_repeated_window_seconds: 30
"""