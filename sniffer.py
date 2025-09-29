import logging
import threading
from scapy.all import sniff, IP, TCP, Raw
from PyQt5.QtCore import QThread, pyqtSignal

logger = logging.getLogger("sniffer")

class SnifferThread(QThread):
    packet_captured = pyqtSignal(dict)
    stats_update = pyqtSignal(dict)

    def __init__(self, detector, iface=None, bpf_filter=None):
        super().__init__()
        self.detector = detector
        self.iface = iface
        self.bpf_filter = bpf_filter
        self._stop_event = threading.Event()
        self.total_packets = 0
        self.total_suspicious = 0

    def stop(self):
        self._stop_event.set()

    def run(self):
        logger.info("Запуск сниффера")
        try:
            sniff(iface=self.iface,
                  prn=self._process_packet,
                  filter=self.bpf_filter,
                  store=False,
                  stop_filter=lambda p: self._stop_event.is_set())
        except PermissionError:
            logger.error("Недостаточно прав для сниффинга. Запустите с sudo/Администратор.")
        except Exception as e:
            logger.error(f"Ошибка сниффера: {e}")
        logger.info("Сниффер остановлен")

    def _process_packet(self, pkt):
        if self._stop_event.is_set():
            return True
        meta = {}
        if IP in pkt:
            ip = pkt[IP]
            meta["src_ip"] = ip.src
            meta["dst_ip"] = ip.dst
            meta["size"] = len(pkt)
            if TCP in pkt:
                tcp = pkt[TCP]
                meta["sport"] = tcp.sport
                meta["dport"] = tcp.dport
                meta["proto"] = "TCP"
                if Raw in pkt:
                    raw = pkt[Raw].load
                    meta["payload"] = raw
                    # naive HTTP parse
                    try:
                        text = raw.decode(errors="ignore")
                        if text.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ")):
                            line = text.split("\r\n")[0]
                            parts = line.split()
                            if len(parts) >= 2:
                                method = parts[0]
                                path = parts[1]
                            else:
                                method = "UNKNOWN"
                                path = "/"
                            ua = ""
                            for l in text.split("\r\n"):
                                if l.lower().startswith("user-agent:"):
                                    ua = l.split(":", 1)[1].strip()
                                    break
                            meta["raw_http"] = {"method": method, "path": path, "user_agent": ua}
                    except:
                        pass
            else:
                meta["proto"] = "IP"
        else:
            return

        self.total_packets += 1
        self.detector.analyze_packet(meta)
        # Determine if suspicious by last event source
        suspicious = False
        if self.detector.last_events and self.detector.last_events[-1].src_ip == meta.get("src_ip"):
            # heuristic: if event was just added (within 0.5s)
            if (self.detector.last_events[-1].timestamp):
                suspicious = True
        if suspicious:
            self.total_suspicious += 1

        self.packet_captured.emit({
            "src": meta.get("src_ip"),
            "dst": meta.get("dst_ip"),
            "proto": meta.get("proto"),
            "sport": meta.get("sport"),
            "dport": meta.get("dport"),
            "size": meta.get("size"),
            "suspicious": suspicious
        })
        if self.total_packets % 20 == 0:
            self.stats_update.emit({
                "total": self.total_packets,
                "suspicious": self.total_suspicious
            })