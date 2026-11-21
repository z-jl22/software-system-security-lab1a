"""Verify process selection and later attribution with synthetic GUI data."""
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PySide6.QtWidgets import QApplication
from sniffer.gui import MainWindow
from sniffer.processes import ConnectionSnapshot, ProcessIdentity, connection_key
from tools.generate_samples import ethernet, tcp


def main():
    application = QApplication([])
    window = MainWindow()
    window.resize(1440, 940)
    window.show()
    target = ProcessIdentity(12345, "synthetic-start", "Demo client")
    other = ProcessIdentity(12346, "synthetic-start", "Other client")
    def owners(port, process):
        return {connection_key("192.0.2.10", port, "192.0.2.20", 8080): {process}}
    window.tracker.observe_processes(ConnectionSnapshot(100, 100.1, owners(51000, target), 1))
    records = []
    for port in (51000, 52000, 53000):
        raw = ethernet(tcp(port, 8080, 1000, 1, 24, b"test"))
        records.append((100.2, raw, len(raw), 1))
    window.ingest(records)
    window.follow_process()
    assert window.model.rowCount() == 1
    window.tracker.observe_processes(ConnectionSnapshot(100.3, 100.4, owners(52000, target), 1))
    window.tracker.observe_processes(ConnectionSnapshot(100.3, 100.4, owners(53000, other), 1))
    window.refresh_processes()
    window.refilter()
    assert window.model.rowCount() == 2
    assert "已关联 TCP 流：2" in window.process_view.toPlainText()
    assert all(target in window.tracker.flows[packet.flow_id].owners for packet in window.model.rows)
    application.processEvents()
    output = Path(__file__).resolve().parents[1] / "output" / "verification"
    output.mkdir(parents=True, exist_ok=True)
    window.grab().save(str(output / "10-process-gui-synthetic.png"))
    window.table.selectRow(0)
    window.follow_selected()
    assert window.process_filter is None and window.model.rowCount() == 1
    window.reset_flow()
    window.follow_process()
    window.reset_process()
    assert window.model.rowCount() == 3
    window.clear()
    assert window.process_filter is None and window.process_selector.currentData() is None
    window.close()
    print("PASS: synthetic GUI process filtering, later attribution, single-flow switch, reset and clear")


if __name__ == "__main__":
    main()
