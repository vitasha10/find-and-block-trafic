import time
import logging
from collections import defaultdict, deque
from typing import Dict, Any, List, Tuple, Optional

logger = logging.getLogger("detector")

class DetectionEvent:
    def __init__(self, event_type: str, src_ip: str, detail: str, severity: str = "medium", extra: Optional[Dict[str, Any]] = None):
        self.timestamp = time.time()
        self.event_type = event_type
        self.src_ip = src_ip
        self.detail = detail
        self.severity = severity
        self.extra = extra or {}

class TrafficDetector:
    def __init__(self, rule_config, firewall_manager):
        self.cfg = rule_config
        self.fw = firewall_manager
        # state
        self.port_activity = defaultdict(lambda: deque())  # src_ip -> deque of (timestamp, dport)
        self.packet_rates = defaultdict(lambda: deque())  # src_ip -> deque of timestamps
        self.http_paths = defaultdict(lambda: deque())    # (src_ip, path) -> deque timestamps
        self.icmp_sent = defaultdict(lambda: deque())     # ip -> deque times
        self.last_events: List[DetectionEvent] = []
        self.max_events_store = 200

    def update_config(self, cfg):
        logger.info("Обновление конфигурации детектора")
        self.cfg = cfg

    def _add_event(self, evt: DetectionEvent):
        self.last_events.append(evt)
        if len(self.last_events) > self.max_events_store:
            self.last_events.pop(0)
        logger.info(f"Событие: {evt.event_type} {evt.src_ip} {evt.detail}")

    def analyze_packet(self, meta: Dict[str, Any]):
        """
        meta fields:
         src_ip, dst_ip, size, dport, sport, proto, payload (bytes or str), raw_http (dict or None)
        """
        src = meta.get("src_ip")
        if not src:
            return
        now = time.time()

        # 1. Large packet
        size = meta.get("size", 0)
        if size > self.cfg.large_packet_threshold:
            self._trigger("large_packet", src, f"Размер пакета {size} > {self.cfg.large_packet_threshold}", "low")

        # 2. Port scan detection
        dport = meta.get("dport")
        if dport is not None:
            dq = self.port_activity[src]
            dq.append((now, dport))
            # clean
            while dq and now - dq[0][0] > self.cfg.port_scan_window_seconds:
                dq.popleft()
            unique_ports = len({p for _, p in dq})
            if unique_ports >= self.cfg.port_scan_threshold:
                self._trigger("port_scan", src, f"Уникальных портов {unique_ports} за {self.cfg.port_scan_window_seconds}s", "high")

        # 3. Rate limiting
        rate_q = self.packet_rates[src]
        rate_q.append(now)
        while rate_q and now - rate_q[0] > self.cfg.rate_limit_window_seconds:
            rate_q.popleft()
        if len(rate_q) >= self.cfg.rate_limit_pps * self.cfg.rate_limit_window_seconds:
            self._trigger("rate_flood", src, f"Частота пакетов ~{len(rate_q)/self.cfg.rate_limit_window_seconds:.1f} pps", "high")

        # 4. Suspicious payload
        payload = meta.get("payload")
        if isinstance(payload, bytes):
            try:
                payload_str = payload.decode(errors="ignore")
            except:
                payload_str = ""
        else:
            payload_str = payload or ""
        for rx in self.cfg.suspicious_payload_regexes:
            if rx.search(payload_str):
                self._trigger("payload_signature", src, f"Совпадение сигнатуры: {rx.pattern}", "high")
                break

        # 5. HTTP analysis
        http = meta.get("raw_http")
        if http:
            path = http.get("path")
            method = http.get("method")
            agent = http.get("user_agent", "")
            if method in self.cfg.http_methods_watch:
                key = (src, path)
                pq = self.http_paths[key]
                pq.append(now)
                while pq and now - pq[0] > self.cfg.http_repeated_window_seconds:
                    pq.popleft()
                if len(pq) > self.cfg.max_repeated_http_path:
                    self._trigger("http_repeated_path", src,
                                  f"{len(pq)} запросов к {path} за {self.cfg.http_repeated_window_seconds}s", "medium")
            for rx in self.cfg.suspicious_user_agents:
                if rx.search(agent):
                    self._trigger("http_user_agent", src, f"Подозрительный User-Agent '{agent}'", "medium")
                    break

        # 6. Protected IP targeted?
        dst_ip = meta.get("dst_ip")
        if dst_ip in self.cfg.protected_ips:
            # Could weight suspicion; simple example
            pass

    def _trigger(self, event_type: str, src_ip: str, detail: str, severity: str):
        evt = DetectionEvent(event_type, src_ip, detail, severity)
        self._add_event(evt)
        if self.cfg.auto_block_on_detection:
            self.block_ip(src_ip, reason=event_type)

    def block_ip(self, ip: str, reason: str):
        if self.fw.is_blocked(ip):
            return
        self.fw.block_ip(ip, self.cfg.block_durations_seconds)

    def maybe_send_icmp(self, ip: str):
        if not self.cfg.enable_icmp_unreachable:
            return
        dq = self.icmp_sent[ip]
        now = time.time()
        dq.append(now)
        while dq and now - dq[0] > 60:
            dq.popleft()
        if len(dq) < self.cfg.icmp_unreachable_rate_limit:
            self.fw.send_icmp_unreachable(ip)