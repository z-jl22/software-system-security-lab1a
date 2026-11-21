import http.client
import http.server
import json
import shlex
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sniffer.parser import decode
from sniffer.pcap import read_pcap
from tools.local_traffic import Handler


def main():
    root = Path(__file__).resolve().parents[1]
    output = root / "output" / "verification"
    output.mkdir(parents=True, exist_ok=True)
    capture = output / "live-loopback.pcap"
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    command = " ".join(shlex.quote(part) for part in ["/usr/bin/python3", str(root / "main.py"),
                       "--capture", "lo0", "--filter", f"tcp port {port} or icmp or icmp6", "--seconds", "8",
                       "--output", str(capture)])
    script = "on run argv\nreturn do shell script (item 1 of argv) with administrator privileges\nend run"
    process = subprocess.Popen(["/usr/bin/osascript", "-e", script, command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.monotonic() + 120
    try:
        while process.poll() is None and time.monotonic() < deadline:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            connection.request("GET", "/lab-live-verification")
            response = connection.getresponse()
            response.read()
            connection.close()
            subprocess.run(["/sbin/ping", "-c", "1", "127.0.0.1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.3)
        if process.poll() is None:
            process.terminate()
            raise RuntimeError("管理员授权等待超时；请自行运行使用指南中的抓包命令")
        stdout, stderr = process.communicate(timeout=5)
        if process.returncode:
            raise RuntimeError(stderr.decode(errors="replace"))
        print(stdout.decode(errors="replace"))
    finally:
        server.shutdown()
        server.server_close()
    packets = [decode(index, timestamp, raw, original, linktype)
               for index, (timestamp, raw, original, linktype) in enumerate(read_pcap(capture), 1)]
    counts = Counter(packet.protocol for packet in packets)
    if not counts["HTTP"] or not counts["ICMP"]:
        raise RuntimeError(f"实时验证未获得预期 HTTP/ICMP 数据：{counts}")
    evidence = {"source": "real macOS lo0 capture via this project's libpcap wrapper",
                "packets": len(packets), "protocols": dict(counts), "http_port": port,
                "capture": capture.name, "result": "PASS"}
    (output / "live-result.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(evidence, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
