import queue
import threading
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import (QApplication, QComboBox, QFileDialog, QHBoxLayout, QHeaderView,
                               QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit,
                               QPushButton, QSplitter, QTabWidget, QTableView, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from .filters import FilterError, compile_filter
from .parser import decode, hexdump
from .pcap import Pcap, PcapError, read_pcap, write_pcap
from .streams import FlowTracker


class PacketModel(QAbstractTableModel):
    headings = ["编号", "时间", "源地址", "目的地址", "协议", "长度", "摘要"]

    def __init__(self):
        super().__init__()
        self.rows = []

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headings)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headings[section]

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        packet = self.rows[index.row()]
        if role == Qt.DisplayRole:
            return [packet.number, datetime.fromtimestamp(packet.timestamp).strftime("%H:%M:%S.%f"),
                    packet.source, packet.destination, packet.protocol, len(packet.raw), packet.summary][index.column()]
        if role == Qt.ForegroundRole and index.column() == 4:
            return QColor({"HTTP": "#00796b", "DNS": "#8e24aa", "TCP": "#1565c0", "ICMP": "#c05621",
                           "TLS": "#00796b", "ARP": "#c05621"}.get(packet.protocol, "#374151"))

    def replace(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def append(self, rows):
        if rows:
            self.beginInsertRows(QModelIndex(), len(self.rows), len(self.rows) + len(rows) - 1)
            self.rows.extend(rows)
            self.endInsertRows()


class CaptureWorker(threading.Thread):
    def __init__(self, interface, expression):
        super().__init__(daemon=True)
        self.interface, self.expression = interface, expression
        self.events = queue.Queue(maxsize=4096)
        self.stop_event = threading.Event()
        self.dropped = 0
        self.error = ""

    def run(self):
        handle = None
        try:
            backend = Pcap()
            handle, linktype = backend.open(self.interface, self.expression)
            while not self.stop_event.is_set():
                record = backend.next(handle)
                if record is None:
                    self.stop_event.wait(0.01)
                    continue
                try:
                    self.events.put_nowait((*record, linktype))
                except queue.Full:
                    self.dropped += 1
        except Exception as error:
            self.error = str(error)
        finally:
            if handle:
                backend.lib.pcap_close(handle)


class MainWindow(QMainWindow):
    limit = 20000
    byte_limit = 64 * 1024 * 1024

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Sniffer | 张家乐 202618015029006")
        self.resize(1320, 850)
        self.packets, self.worker, self.linktype = [], None, None
        self.stored_bytes = 0
        self.capacity_reached = False
        self.tracker = FlowTracker()
        self.predicate = compile_filter("")
        self.flow_filter = ""
        self.model = PacketModel()
        self.build_ui()
        self.refresh_interfaces()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.drain)
        self.timer.start(100)

    def build_ui(self):
        root = QWidget()
        layout = QVBoxLayout(root)
        title = QLabel("Network Sniffer · 协议分析")
        title.setStyleSheet("font-size:24px; font-weight:700; color:#0f766e; padding:8px 0;")
        layout.addWidget(title)
        controls = QHBoxLayout()
        self.interfaces = QComboBox()
        self.interfaces.setMinimumWidth(190)
        self.refresh_button = QPushButton("刷新网卡")
        self.refresh_button.clicked.connect(self.refresh_interfaces)
        self.capture_filter = QLineEdit()
        self.capture_filter.setPlaceholderText("捕获过滤 BPF，例如 tcp or udp port 53；开始前设置")
        self.start_button = QPushButton("开始抓包")
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button = QPushButton("停止")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_capture)
        for widget in (self.interfaces, self.refresh_button, self.capture_filter, self.start_button, self.stop_button):
            controls.addWidget(widget)
        layout.addLayout(controls)
        actions = QHBoxLayout()
        self.open_button = QPushButton("打开 PCAP")
        self.open_button.clicked.connect(self.open_dialog)
        self.save_button = QPushButton("保存全部 PCAP")
        self.save_button.clicked.connect(self.save_dialog)
        self.clear_button = QPushButton("清空")
        self.clear_button.clicked.connect(self.clear)
        self.demo_button = QPushButton("加载教学样例")
        self.demo_button.clicked.connect(self.load_demo)
        self.follow_button = QPushButton("追踪选中 TCP 流")
        self.follow_button.clicked.connect(self.follow_selected)
        self.reset_flow_button = QPushButton("取消流筛选")
        self.reset_flow_button.clicked.connect(self.reset_flow)
        for widget in (self.open_button, self.save_button, self.clear_button, self.demo_button,
                       self.follow_button, self.reset_flow_button):
            actions.addWidget(widget)
        actions.addStretch()
        layout.addLayout(actions)
        filtering = QHBoxLayout()
        filtering.addWidget(QLabel("显示过滤"))
        self.display_filter = QLineEdit()
        self.display_filter.setPlaceholderText("例：(tcp or udp) and not port 53 | http | ipv6 | src host 127.0.0.1")
        self.display_filter.returnPressed.connect(self.apply_filter)
        apply_button = QPushButton("应用")
        apply_button.clicked.connect(self.apply_filter)
        filtering.addWidget(self.display_filter)
        filtering.addWidget(apply_button)
        layout.addLayout(filtering)
        self.session_label = QLabel("就绪。实时抓包需 BPF 权限；教学样例不需要权限。")
        self.session_label.setWordWrap(True)
        layout.addWidget(self.session_label)
        split = QSplitter(Qt.Vertical)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        for column, width in enumerate((60, 145, 180, 180, 85, 65, 350)):
            self.table.setColumnWidth(column, width)
        self.table.selectionModel().currentRowChanged.connect(self.selection_changed)
        split.addWidget(self.table)
        tabs = QTabWidget()
        details_split = QSplitter(Qt.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["协议 / 字段", "值"])
        self.tree.setColumnWidth(0, 185)
        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont("Menlo", 11))
        details_split.addWidget(self.tree)
        details_split.addWidget(self.hex_view)
        details_split.setSizes([550, 700])
        tabs.addTab(details_split, "协议详情与原始字节")
        self.flow_view = QPlainTextEdit()
        self.flow_view.setReadOnly(True)
        self.flow_view.setFont(QFont("Menlo", 11))
        tabs.addTab(self.flow_view, "TCP 流（按捕获顺序）")
        self.stats_view = QPlainTextEdit()
        self.stats_view.setReadOnly(True)
        tabs.addTab(self.stats_view, "统计与能力说明")
        self.tabs = tabs
        split.addWidget(tabs)
        split.setSizes([390, 300])
        layout.addWidget(split)
        self.setCentralWidget(root)
        palette = QPalette()
        for role, color in (
            (QPalette.Window, "#f6f8fa"), (QPalette.WindowText, "#1f2937"),
            (QPalette.Base, "#ffffff"), (QPalette.AlternateBase, "#f1f5f9"),
            (QPalette.Text, "#1f2937"), (QPalette.Button, "#e9eef3"),
            (QPalette.ButtonText, "#1f2937"), (QPalette.PlaceholderText, "#596579"),
            (QPalette.Highlight, "#155e75"), (QPalette.HighlightedText, "#ffffff"),
            (QPalette.ToolTipBase, "#ffffff"), (QPalette.ToolTipText, "#1f2937"),
        ):
            palette.setColor(role, QColor(color))
        for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText, QPalette.PlaceholderText):
            palette.setColor(QPalette.Disabled, role, QColor("#64748b"))
        self.setPalette(palette)
        self.setStyleSheet("QWidget {color:#1f2937;} QMainWindow {background:#f6f8fa;} "
                           "QLineEdit,QComboBox {background:#ffffff; color:#1f2937; padding:6px; "
                           "selection-background-color:#155e75; selection-color:#ffffff;} "
                           "QPushButton {background:#e9eef3; color:#1f2937; padding:6px 10px; "
                           "border:1px solid #b8c4d1; border-radius:4px;} "
                           "QPushButton:hover {background:#dce7ef;} "
                           "QPushButton:pressed {background:#cbdce7;} "
                           "QPushButton:disabled,QLineEdit:disabled,QComboBox:disabled "
                           "{background:#edf1f5; color:#64748b;} "
                           "QTableView,QTreeWidget,QPlainTextEdit,QComboBox QAbstractItemView "
                           "{background:#ffffff; color:#1f2937; alternate-background-color:#f1f5f9; "
                           "selection-background-color:#155e75; selection-color:#ffffff;} "
                           "QTableView::item:selected,QTreeWidget::item:selected "
                           "{background:#155e75; color:#ffffff;} "
                           "QHeaderView::section {background:#e6f1f0; color:#1f2937; padding:6px; border:0;} "
                           "QTabBar::tab {background:#e9eef3; color:#334155; padding:7px 12px;} "
                           "QTabBar::tab:selected {background:#ffffff; color:#0f5b55;} "
                           "QToolTip {background:#ffffff; color:#1f2937; border:1px solid #b8c4d1;}")
        self.update_status()

    def refresh_interfaces(self):
        self.interfaces.clear()
        try:
            for name, description in Pcap().devices():
                self.interfaces.addItem(name + (f" — {description}" if description else ""), name)
            loopback = self.interfaces.findData("lo0")
            if loopback >= 0:
                self.interfaces.setCurrentIndex(loopback)
        except Exception as error:
            self.show_error(str(error))

    def show_error(self, message):
        QMessageBox.warning(self, "操作提示", message)

    def set_running(self, running):
        for widget in (self.start_button, self.interfaces, self.capture_filter, self.refresh_button,
                       self.open_button, self.clear_button, self.demo_button, self.save_button):
            widget.setEnabled(not running)
        self.stop_button.setEnabled(running)

    def start_capture(self):
        if self.worker:
            return
        if not self.interfaces.currentData():
            self.show_error("请先选择网卡")
            return
        if self.packets and QMessageBox.question(self, "开始新会话", "开始新抓包将清空当前数据，是否继续？") != QMessageBox.Yes:
            return
        self.clear()
        self.worker = CaptureWorker(self.interfaces.currentData(), self.capture_filter.text())
        self.set_running(True)
        self.session_label.setText(f"实时抓包：{self.interfaces.currentData()}；捕获过滤：{self.capture_filter.text() or '无'}")
        self.worker.start()

    def stop_capture(self):
        if self.worker:
            self.worker.stop_event.set()
            self.stop_button.setEnabled(False)
            self.session_label.setText("正在停止；等待后台释放抓包句柄…")

    def drain(self):
        if not self.worker:
            return
        records = []
        for count in range(1000):
            try:
                records.append(self.worker.events.get_nowait())
            except queue.Empty:
                break
        if records:
            self.ingest(records)
        if self.capacity_reached:
            self.worker.stop_event.set()
        self.update_status()
        if not self.worker.is_alive() and self.worker.events.empty():
            error, dropped = self.worker.error, self.worker.dropped
            self.worker = None
            self.set_running(False)
            self.session_label.setText(f"抓包结束。应用队列丢弃 {dropped} 包；驱动/内核丢包未统计。"
                                       + ("已达到包数或 64 MiB 容量上限。" if self.capacity_reached else ""))
            if error:
                self.show_error(error)

    def ingest(self, records):
        visible = []
        for timestamp, raw, original, linktype in records:
            if len(self.packets) >= self.limit or self.stored_bytes + len(raw) > self.byte_limit:
                self.capacity_reached = True
                break
            if self.linktype is not None and self.linktype != linktype:
                raise PcapError("同一会话不支持混合链路类型")
            self.linktype = linktype
            packet = decode(len(self.packets) + 1, timestamp, raw, original, linktype)
            self.packets.append(packet)
            self.stored_bytes += len(raw)
            self.capacity_reached = len(self.packets) >= self.limit or self.stored_bytes >= self.byte_limit
            self.tracker.add(packet)
            if self.matches(packet):
                visible.append(packet)
        self.model.append(visible)
        if self.flow_filter:
            self.flow_view.setPlainText(self.tracker.describe(self.flow_filter))
        self.update_status()

    def matches(self, packet):
        return self.predicate(packet) and (not self.flow_filter or packet.flow_id == self.flow_filter)

    def apply_filter(self):
        try:
            predicate = compile_filter(self.display_filter.text())
        except (FilterError, RecursionError) as error:
            self.show_error(str(error))
            return
        self.predicate = predicate
        self.refilter()

    def refilter(self):
        self.model.replace([packet for packet in self.packets if self.matches(packet)])
        self.tree.clear()
        self.hex_view.clear()
        self.update_status()

    def clear(self):
        if self.worker:
            return
        self.packets, self.linktype, self.flow_filter = [], None, ""
        self.stored_bytes, self.capacity_reached = 0, False
        self.tracker = FlowTracker()
        self.model.replace([])
        self.tree.clear()
        self.hex_view.clear()
        self.flow_view.clear()
        self.update_status()

    def selection_changed(self, current, previous):
        if not current.isValid() or current.row() >= len(self.model.rows):
            return
        packet = self.model.rows[current.row()]
        self.tree.clear()
        for layer, fields in packet.layers.items():
            parent = QTreeWidgetItem([layer, ""])
            self.tree.addTopLevelItem(parent)
            for name, value in fields.items():
                parent.addChild(QTreeWidgetItem([str(name), str(value)]))
        self.tree.expandAll()
        self.hex_view.setPlainText(hexdump(packet.raw))

    def follow_selected(self):
        index = self.table.currentIndex()
        if not index.isValid():
            self.show_error("请先选择一个 TCP 数据包")
            return
        packet = self.model.rows[index.row()]
        if not packet.flow_id:
            self.show_error("所选数据包不包含 TCP 层")
            return
        self.flow_filter = packet.flow_id
        self.display_filter.clear()
        self.predicate = compile_filter("")
        self.flow_view.setPlainText(self.tracker.describe(self.flow_filter))
        self.refilter()
        self.tabs.setCurrentIndex(1)

    def reset_flow(self):
        self.flow_filter = ""
        self.refilter()

    def open_dialog(self):
        path, selected = QFileDialog.getOpenFileName(self, "打开经典 PCAP", "", "PCAP (*.pcap);;所有文件 (*)")
        if path:
            self.load_file(path)

    def load_file(self, path):
        if self.worker:
            return
        try:
            records = []
            truncated = False
            byte_count = 0
            for record in read_pcap(path):
                if len(records) == self.limit or byte_count + len(record[1]) > self.byte_limit:
                    truncated = True
                    break
                records.append(record)
                byte_count += len(record[1])
            self.clear()
            self.display_filter.clear()
            self.predicate = compile_filter("")
            self.ingest(records)
            self.session_label.setText(f"离线文件：{Path(path).name}" + ("；因包数或 64 MiB 上限，仅加载部分数据" if truncated else ""))
        except (OSError, PcapError) as error:
            self.show_error(str(error))

    def load_demo(self):
        self.load_file(Path(__file__).resolve().parents[1] / "samples" / "teaching.pcap")
        self.session_label.setText("教学样例：人工构造的协议测试数据，用于离线验证；不代表实时抓包。")

    def save_dialog(self):
        if not self.packets:
            self.show_error("没有可保存的数据包")
            return
        path, selected = QFileDialog.getSaveFileName(self, "保存当前会话全部包（含被过滤的包）", "capture.pcap", "PCAP (*.pcap)")
        if path:
            try:
                write_pcap(path, self.packets, self.linktype)
            except OSError as error:
                self.show_error(str(error))

    def update_status(self):
        counts = Counter(packet.protocol for packet in self.packets)
        total = sum(len(packet.raw) for packet in self.packets)
        self.statusBar().showMessage(f"已存 {len(self.packets)} / {self.limit} 包 · 显示 {len(self.model.rows)} 包 · "
                                     f"{total} 字节 · TCP 流 {len(self.tracker.flows)}"
                                     + (f" · 当前 {self.flow_filter}" if self.flow_filter else ""))
        self.stats_view.setPlainText("协议统计（整个会话，按最上层已识别协议互斥计数）\n\n" +
                                    "\n".join(f"{name:10s} {count}" for name, count in sorted(counts.items())) +
                                    "\n\n能力与限制\n"
                                    "• libpcap 直接调用；实时模式为非混杂模式。\n"
                                    "• 支持 Ethernet/VLAN、macOS Loopback、Raw IP。\n"
                                    "• IPv4/IPv6、ARP、TCP/UDP、ICMP/ICMPv6、DNS 首个问题、段内 HTTP/1.x、TLS 记录头特征。\n"
                                    "• 不做 IP 分片重组、TCP 字节流重组、HTTPS 解密或进程关联。\n"
                                    "• 仅支持经典 PCAP；不支持 PCAPNG。上限 20000 包 / 64 MiB 原始字节，队列上限 4096。\n"
                                    "• TCP 流按双向端点归组，并使用 SYN/空闲超时区分部分端点复用。\n"
                                    "• 队列丢弃不等于内核丢包；不提供无丢包保证。")

    def closeEvent(self, event):
        if self.worker:
            self.worker.stop_event.set()
            self.worker.join(timeout=1)
            if self.worker.is_alive():
                event.ignore()
                return
        event.accept()


def run(path=None):
    application = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    if path:
        window.load_file(path)
    return application.exec()
