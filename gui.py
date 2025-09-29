import os
import time
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout, QTableWidget,
    QTableWidgetItem, QApplication, QGroupBox, QFormLayout, QSpinBox,
    QTextEdit, QCheckBox, QFileDialog, QMessageBox, QLineEdit
)
from PyQt5.QtCore import Qt, QTimer
from rules import load_rules
from detector import TrafficDetector
from firewall import FirewallManager
from sniffer import SnifferThread

class MainWindow(QWidget):
    def __init__(self, config_path: str):
        super().__init__()
        self.setWindowTitle("Сетевой Монитор / IDS")
        self.resize(1300, 800)
        self.config_path = config_path
        self.rule_config = load_rules(config_path)
        self.fw = FirewallManager()
        self.detector = TrafficDetector(self.rule_config, self.fw)
        self.sniffer_thread = None

        self._build_ui()
        self._timer = QTimer()
        self._timer.timeout.connect(self.refresh_events)
        self._timer.start(1000)

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # Controls
        ctl_box = QHBoxLayout()
        self.btn_start = QPushButton("Старт")
        self.btn_stop = QPushButton("Стоп")
        self.btn_reload = QPushButton("Перезагрузить правила")
        self.btn_block_manual = QPushButton("Блокировать IP")
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("IP для блокировки")
        self.btn_start.clicked.connect(self.start_sniffer)
        self.btn_stop.clicked.connect(self.stop_sniffer)
        self.btn_reload.clicked.connect(self.reload_rules)
        self.btn_block_manual.clicked.connect(self.block_manual)
        ctl_box.addWidget(self.btn_start)
        ctl_box.addWidget(self.btn_stop)
        ctl_box.addWidget(self.btn_reload)
        ctl_box.addWidget(self.ip_input)
        ctl_box.addWidget(self.btn_block_manual)
        layout.addLayout(ctl_box)

        # Stats
        self.stats_label = QLabel("Пакетов: 0 | Подозрительных: 0 | Заблокировано: 0")
        layout.addWidget(self.stats_label)

        # Packet table
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Источник", "Назначение", "Протокол", "Sport", "Dport", "Размер", "Флаг"])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

        # Events
        self.events_box = QTextEdit()
        self.events_box.setReadOnly(True)
        layout.addWidget(QLabel("События:"))
        layout.addWidget(self.events_box)

        # Config group (editable thresholds)
        cfg_group = QGroupBox("Параметры")
        form = QFormLayout()
        self.spin_large = QSpinBox(); self.spin_large.setMaximum(100000); self.spin_large.setValue(self.rule_config.large_packet_threshold)
        self.spin_portscan = QSpinBox(); self.spin_portscan.setMaximum(10000); self.spin_portscan.setValue(self.rule_config.port_scan_threshold)
        self.spin_rate_pps = QSpinBox(); self.spin_rate_pps.setMaximum(100000); self.spin_rate_pps.setValue(self.rule_config.rate_limit_pps)
        self.chk_auto_block = QCheckBox(); self.chk_auto_block.setChecked(self.rule_config.auto_block_on_detection)
        self.chk_icmp = QCheckBox(); self.chk_icmp.setChecked(self.rule_config.enable_icmp_unreachable)
        self.btn_apply = QPushButton("Применить")
        self.btn_apply.clicked.connect(self.apply_thresholds)
        form.addRow("Порог большого пакета:", self.spin_large)
        form.addRow("Порог порт-скана (уникальные порты):", self.spin_portscan)
        form.addRow("Макс pps:", self.spin_rate_pps)
        form.addRow("Авто-блокировка:", self.chk_auto_block)
        form.addRow("ICMP unreachable:", self.chk_icmp)
        form.addRow(self.btn_apply)
        cfg_group.setLayout(form)
        layout.addWidget(cfg_group)

        # Load/save config buttons
        cfg_buttons_layout = QHBoxLayout()
        self.btn_save_cfg = QPushButton("Сохранить config.yaml")
        self.btn_open_cfg = QPushButton("Открыть config.yaml в проводнике")
        self.btn_save_cfg.clicked.connect(self.save_current_config)
        self.btn_open_cfg.clicked.connect(self.open_config_file)
        cfg_buttons_layout.addWidget(self.btn_save_cfg)
        cfg_buttons_layout.addWidget(self.btn_open_cfg)
        layout.addLayout(cfg_buttons_layout)

    def start_sniffer(self):
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            QMessageBox.warning(self, "Внимание", "Сниффер уже запущен")
            return
        self.sniffer_thread = SnifferThread(detector=self.detector)
        self.sniffer_thread.packet_captured.connect(self.on_packet)
        self.sniffer_thread.stats_update.connect(self.on_stats)
        self.sniffer_thread.start()

    def stop_sniffer(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()

    def reload_rules(self):
        try:
            new_cfg = load_rules(self.config_path)
            self.detector.update_config(new_cfg)
            self.rule_config = new_cfg
            QMessageBox.information(self, "OK", "Правила перезагружены")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось перезагрузить: {e}")

    def block_manual(self):
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Внимание", "Введите IP")
            return
        self.detector.block_ip(ip, reason="manual")
        QMessageBox.information(self, "OK", f"{ip} заблокирован")

    def apply_thresholds(self):
        self.rule_config.large_packet_threshold = self.spin_large.value()
        self.rule_config.port_scan_threshold = self.spin_portscan.value()
        self.rule_config.rate_limit_pps = self.spin_rate_pps.value()
        self.rule_config.auto_block_on_detection = self.chk_auto_block.isChecked()
        self.rule_config.enable_icmp_unreachable = self.chk_icmp.isChecked()
        self.detector.update_config(self.rule_config)
        QMessageBox.information(self, "OK", "Параметры применены")

    def save_current_config(self):
        # Overwrite config_path with current in-memory thresholds (partial save)
        import yaml
        data = {
            "protected_ips": list(self.rule_config.protected_ips),
            "large_packet_threshold": self.rule_config.large_packet_threshold,
            "port_scan_threshold": self.rule_config.port_scan_threshold,
            "port_scan_window_seconds": self.rule_config.port_scan_window_seconds,
            "rate_limit_pps": self.rule_config.rate_limit_pps,
            "rate_limit_window_seconds": self.rule_config.rate_limit_window_seconds,
            "block_durations_seconds": self.rule_config.block_durations_seconds,
            "auto_block_on_detection": self.rule_config.auto_block_on_detection,
            "enable_icmp_unreachable": self.rule_config.enable_icmp_unreachable,
            "icmp_unreachable_rate_limit": self.rule_config.icmp_unreachable_rate_limit,
            "suspicious_payload_regexes": [r.pattern for r in self.rule_config.suspicious_payload_regexes],
            "http_methods_watch": list(self.rule_config.http_methods_watch),
            "suspicious_user_agents": [r.pattern for r in self.rule_config.suspicious_user_agents],
            "max_repeated_http_path": self.rule_config.max_repeated_http_path,
            "http_repeated_window_seconds": self.rule_config.http_repeated_window_seconds
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
        QMessageBox.information(self, "OK", "config.yaml сохранён")

    def open_config_file(self):
        folder = os.path.abspath(self.config_path)
        folder_dir = os.path.dirname(folder)
        if os.name == "nt":
            os.startfile(folder_dir)
        else:
            import subprocess
            subprocess.Popen(["xdg-open" if os.name == "posix" else "open", folder_dir])

    def on_packet(self, pkt_info):
        row = self.table.rowCount()
        self.table.insertRow(row)
        cells = [
            pkt_info.get("src"),
            pkt_info.get("dst"),
            pkt_info.get("proto"),
            str(pkt_info.get("sport") or ""),
            str(pkt_info.get("dport") or ""),
            str(pkt_info.get("size") or ""),
            "YES" if pkt_info.get("suspicious") else ""
        ]
        for col, val in enumerate(cells):
            item = QTableWidgetItem(val)
            if col == 6 and val == "YES":
                item.setBackground(Qt.red)
            self.table.setItem(row, col, item)
        self.table.scrollToBottom()

    def on_stats(self, stats):
        self.stats_label.setText(
            f"Пакетов: {stats['total']} | Подозрительных(эвент): {stats['suspicious']} | Заблокировано: {len(self.fw.blocked)}"
        )

    def refresh_events(self):
        # Show only last 100 events
        evs = self.detector.last_events[-100:]
        lines = []
        for e in evs:
            ts = time.strftime("%H:%M:%S", time.localtime(e.timestamp))
            lines.append(f"{ts} [{e.severity}] {e.event_type} {e.src_ip} :: {e.detail}")
        self.events_box.setPlainText("\n".join(lines))

def run_app(config_path="config.yaml"):
    app = QApplication([])
    if not os.path.exists(config_path):
        from rules import default_config_yaml
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(default_config_yaml())
    win = MainWindow(config_path)
    win.show()
    return app.exec_()