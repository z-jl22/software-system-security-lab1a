import json
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QPainter
from PySide6.QtWidgets import QApplication

from sniffer.gui import MainWindow


def main():
    root = Path(__file__).resolve().parents[1]
    output = root / "output" / "verification"
    frames = output / "video-frames"
    frames.mkdir(parents=True, exist_ok=True)
    application = QApplication([])
    window = MainWindow()
    window.resize(1440, 940)
    window.show()
    application.processEvents()
    frame_number = 0
    screenshots = []

    def snapshot(name, caption, seconds=5):
        nonlocal frame_number
        application.processEvents()
        image = window.grab().toImage()
        painter = QPainter(image)
        painter.fillRect(0, image.height() - 54, image.width(), 54, QColor("#123c3b"))
        painter.setPen(QColor("white"))
        painter.setFont(QFont("PingFang SC", 17))
        painter.drawText(18, image.height() - 18, caption)
        painter.end()
        image.save(str(output / f"{name}.png"))
        screenshots.append(name)
        for count in range(seconds * 2):
            image.save(str(frames / f"{frame_number:04d}.png"))
            frame_number += 1

    window.load_demo()
    assert len(window.packets) == 15
    assert window.model.rowCount() == 15
    snapshot("01-overview", "离线教学演示 | 人工构造 PCAP：15 包，覆盖 HTTP / DNS / ICMP / IPv6 / ARP / TLS")
    window.table.selectRow(3)
    snapshot("02-http-detail", "点击 HTTP 请求：非 80 端口 8080，通过载荷特征识别 HTTP/1.1")
    window.display_filter.setText("http")
    window.apply_filter()
    assert window.model.rowCount() == 2
    snapshot("03-http-filter", "显示过滤 http：仅显示请求和响应；原始会话仍保留全部数据")
    window.display_filter.setText("(tcp or udp) and not port 53")
    window.apply_filter()
    assert window.model.rowCount() == 9
    snapshot("04-logical-filter", "逻辑过滤：(tcp or udp) and not port 53，排除 DNS 流量")
    window.display_filter.clear()
    window.apply_filter()
    window.table.selectRow(3)
    window.follow_selected()
    assert window.model.rowCount() == 8
    assert "GET /lab" in window.flow_view.toPlainText()
    snapshot("05-tcp-flow", "TCP 流追踪：双向 8 包；按捕获顺序展示，未做 TCP 字节流重组", 7)
    window.reset_flow()
    window.display_filter.setText("dns")
    window.apply_filter()
    window.tabs.setCurrentIndex(0)
    window.table.selectRow(0)
    assert window.model.rowCount() == 2
    snapshot("06-dns", "DNS 解析：查询域名 example.test，展示事务 ID、问题数与响应标志")
    window.display_filter.setText("ipv6")
    window.apply_filter()
    window.table.selectRow(0)
    assert window.model.rowCount() == 1
    snapshot("07-ipv6", "IPv6 + ICMPv6：按网络层过滤，并显示上层 Echo Request")
    window.display_filter.clear()
    window.apply_filter()
    window.tabs.setCurrentWidget(window.stats_view)
    snapshot("08-statistics", "统计与能力说明：真实界面自动操作演示；教学数据不作为实时抓包证据")
    live_path = output / "live-loopback.pcap"
    if live_path.exists():
        window.load_file(live_path)
        window.display_filter.setText("http")
        window.apply_filter()
        assert window.model.rowCount() > 0
        window.tabs.setCurrentIndex(0)
        window.table.selectRow(0)
        snapshot("09-live-http", "真实 macOS lo0 抓包回放：本程序调用 libpcap 捕获的本机 HTTP 请求", 7)
    window.load_file(root / "samples" / "loopback.pcap")
    assert len(window.packets) == 13
    window.clear()
    assert window.model.rowCount() == 0 and not window.tracker.flows
    window.close()
    evidence = {"result": "PASS", "screenshots": screenshots, "video_frames": frame_number,
                "checks": ["PCAP load", "packet selection", "HTTP filter", "boolean filter", "TCP flow",
                           "DNS filter", "IPv6 filter", "loopback load", "clear session"]}
    (output / "gui-result.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(evidence, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
