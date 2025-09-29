import platform
import subprocess
import logging
import time
from scapy.all import IP, ICMP, send

logger = logging.getLogger("firewall")

class FirewallManager:
    def __init__(self):
        self.system = platform.system().lower()
        self.blocked = {}  # ip -> unblock_time (epoch)
        self.applied_rules = set()

    def is_blocked(self, ip: str):
        expiry = self.blocked.get(ip)
        if expiry and expiry > time.time():
            return True
        if expiry and expiry <= time.time():
            # expired
            self.blocked.pop(ip, None)
        return False

    def block_ip(self, ip: str, duration: int):
        if self.is_blocked(ip):
            return
        cmd = None
        if "linux" in self.system:
            cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        elif "windows" in self.system:
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name=BlockSuspicious_{ip}",
                   "dir=in", "action=block", f"remoteip={ip}"]
        elif "darwin" in self.system or "mac" in self.system:
            # Simplified: require manual pf table pre-setup
            cmd = ["pfctl", "-t", "suspicious", "-T", "add", ip]
        else:
            logger.warning(f"Неизвестная ОС, пропуск системной блокировки для {ip}")
        if cmd:
            try:
                subprocess.run(cmd, check=True)
                logger.info(f"IP {ip} заблокирован firewall командой: {' '.join(cmd)}")
                self.applied_rules.add(ip)
            except Exception as e:
                logger.error(f"Не удалось применить firewall правило для {ip}: {e}")
        self.blocked[ip] = time.time() + duration

    def send_icmp_unreachable(self, target_ip: str):
        pkt = IP(dst=target_ip)/ICMP(type=3, code=1)
        try:
            send(pkt, verbose=False)
            logger.info(f"Отправлен ICMP Destination Unreachable к {target_ip}")
        except Exception as e:
            logger.error(f"Ошибка отправки ICMP unreachable: {e}")

    def cleanup_expired(self):
        now = time.time()
        expired = [ip for ip, t in self.blocked.items() if t <= now]
        for ip in expired:
            logger.info(f"Срок блокировки для {ip} истёк")
            self.blocked.pop(ip, None)