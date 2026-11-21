"""Verify real macOS packet-to-process attribution using only local held sockets."""
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sniffer.parser import decode
from sniffer.pcap import Pcap, write_pcap
from sniffer.processes import sample_connections
from sniffer.streams import FlowTracker


def main():
    root = Path(__file__).resolve().parents[1]
    output = root / "output" / "verification"
    output.mkdir(parents=True, exist_ok=True)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    backend, tracker, packets = Pcap(), FlowTracker(), []
    handle, linktype = backend.open("lo0", f"tcp port {port}")
    children, connections = [], []
    child_source = ("import socket,sys,time; "
                    "sockets=[socket.create_connection(('127.0.0.1',int(sys.argv[1]))) "
                    "for _ in range(int(sys.argv[2]))]; "
                    "[s.sendall(b'GET /process-test HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n') for s in sockets]; "
                    "print('READY',flush=True); sys.stdin.readline()")
    try:
        for count in (2, 1):
            child = subprocess.Popen([sys.executable, "-c", child_source, str(port), str(count)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            children.append(child)
            for index in range(count):
                connection, address = listener.accept()
                connections.append(connection)
                connection.recv(4096)
                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            assert child.stdout.readline().strip() == "READY"
        snapshot = sample_connections()
        tracker.observe_processes(snapshot)
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            record = backend.next(handle)
            if record:
                timestamp, raw, original = record
                packet = decode(len(packets) + 1, timestamp, raw, original, linktype)
                packets.append(packet)
                tracker.add(packet)
            else:
                time.sleep(0.01)
        processes = tracker.processes()
        target = next(process for process in processes if process.pid == children[0].pid)
        other = next(process for process in processes if process.pid == children[1].pid)
        target_flows, other_flows = tracker.process_flows(target), tracker.process_flows(other)
        assert len(target_flows) == 2, target_flows
        assert len(other_flows) == 1, other_flows
        assert not ({flow.identifier for flow in target_flows} & {flow.identifier for flow in other_flows})
        write_pcap(output / "process-live.pcap", packets, linktype)
        evidence = {"result": "PASS", "source": "real macOS lo0 libpcap capture + lsof/ps snapshots",
                    "packets": len(packets), "target_pid": target.pid, "target_name": target.name,
                    "target_flow_count": len(target_flows), "other_pid": other.pid,
                    "other_flow_count": len(other_flows), "flows_disjoint": True,
                    "description": tracker.describe_process(target)}
        (output / "process-result.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(evidence, ensure_ascii=False, indent=2))
    finally:
        backend.lib.pcap_close(handle)
        for child in children:
            if child.poll() is None:
                child.communicate("\n", timeout=5)
        for connection in connections:
            connection.close()
        listener.close()


if __name__ == "__main__":
    main()
