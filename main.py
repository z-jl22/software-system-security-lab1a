import argparse
import json
import time

from sniffer.parser import decode
from sniffer.pcap import Pcap, read_pcap, write_pcap


def main():
    parser = argparse.ArgumentParser(description="Network Sniffer for macOS")
    parser.add_argument("--list", action="store_true", help="列出 libpcap 网卡")
    parser.add_argument("--read", metavar="PCAP", help="在 GUI 中打开经典 PCAP")
    parser.add_argument("--inspect", metavar="PCAP", help="无 GUI 解析 PCAP，输出 JSON")
    parser.add_argument("--capture", metavar="INTERFACE", help="命令行实时抓包，需要 BPF 权限")
    parser.add_argument("--filter", default="", help="BPF 捕获过滤表达式")
    parser.add_argument("--seconds", type=float, default=10, help="命令行抓包时长")
    parser.add_argument("--output", default="capture.pcap", help="命令行抓包输出 PCAP")
    args = parser.parse_args()
    if args.list:
        for name, description in Pcap().devices():
            print(name, description)
        return
    if args.inspect:
        for number, record in enumerate(read_pcap(args.inspect), 1):
            timestamp, raw, original, linktype = record
            packet = decode(number, timestamp, raw, original, linktype)
            print(json.dumps({"number": number, "protocol": packet.protocol, "source": packet.source,
                              "destination": packet.destination, "summary": packet.summary}, ensure_ascii=False))
        return
    if args.capture:
        if not 0 < args.seconds <= 3600:
            parser.error("--seconds 必须在 0–3600 秒范围内")
        backend = Pcap()
        handle, linktype = backend.open(args.capture, args.filter)
        packets = []
        try:
            end = time.monotonic() + args.seconds
            while time.monotonic() < end and len(packets) < 20000:
                record = backend.next(handle)
                if record:
                    timestamp, raw, original = record
                    packet = decode(len(packets) + 1, timestamp, raw, original, linktype)
                    packets.append(packet)
                    print(packet.number, packet.protocol, packet.summary, flush=True)
                else:
                    time.sleep(0.01)
        except KeyboardInterrupt:
            pass
        finally:
            backend.lib.pcap_close(handle)
            write_pcap(args.output, packets, linktype)
        print(f"保存 {len(packets)} 包到 {args.output}")
        return
    from sniffer.gui import run
    raise SystemExit(run(args.read))


if __name__ == "__main__":
    main()
