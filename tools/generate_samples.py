import ipaddress
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sniffer.parser import decode
from sniffer.pcap import write_pcap


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    value = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def ipv4(payload, protocol=6, source="192.0.2.10", destination="192.0.2.20", fragment=0):
    source_raw, destination_raw = ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, fragment, 64, protocol, 0,
                         source_raw, destination_raw)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def tcp(source_port, destination_port, sequence, acknowledgement, flags, payload=b"", reverse=False):
    source, destination = ("192.0.2.20", "192.0.2.10") if reverse else ("192.0.2.10", "192.0.2.20")
    header = struct.pack("!HHIIBBHHH", source_port, destination_port, sequence, acknowledgement, 0x50, flags, 65535, 0, 0)
    pseudo = ipaddress.ip_address(source).packed + ipaddress.ip_address(destination).packed + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    header = header[:16] + struct.pack("!H", checksum(pseudo + header + payload)) + header[18:]
    return ipv4(header + payload, 6, source, destination)


def ethernet(payload, kind=0x0800):
    return bytes.fromhex("020000000002020000000001") + struct.pack("!H", kind) + payload


def sample_frames():
    request = b"GET /lab HTTP/1.1\r\nHost: example.test:8080\r\nConnection: close\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nHello Lantern"
    frames = [ethernet(tcp(51000, 8080, 1000, 0, 2)),
              ethernet(tcp(8080, 51000, 9000, 1001, 18, reverse=True)),
              ethernet(tcp(51000, 8080, 1001, 9001, 16)),
              ethernet(tcp(51000, 8080, 1001, 9001, 24, request)),
              ethernet(tcp(8080, 51000, 9001, 1001 + len(request), 24, response, True)),
              ethernet(tcp(8080, 51000, 9001 + len(response), 1001 + len(request), 17, reverse=True)),
              ethernet(tcp(51000, 8080, 1001 + len(request), 9002 + len(response), 17)),
              ethernet(tcp(8080, 51000, 9002 + len(response), 1002 + len(request), 16, reverse=True))]
    question = b"\x07example\x04test\x00\x00\x01\x00\x01"
    dns_query = struct.pack("!HHHHHH", 0x1234, 0x100, 1, 0, 0, 0) + question
    dns_response = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + question + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x14"
    frames.append(ethernet(ipv4(struct.pack("!HHHH", 53000, 53, len(dns_query) + 8, 0) + dns_query, 17)))
    frames.append(ethernet(ipv4(struct.pack("!HHHH", 53, 53000, len(dns_response) + 8, 0) + dns_response, 17,
                                   "192.0.2.20", "192.0.2.10")))
    for kind, source, destination in ((8, "192.0.2.10", "192.0.2.20"), (0, "192.0.2.20", "192.0.2.10")):
        icmp = struct.pack("!BBHHH", kind, 0, 0, 12, 1) + b"Lantern test"
        icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
        frames.append(ethernet(ipv4(icmp, 1, source, destination)))
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes.fromhex("020000000001c000020a000000000000c0000214")
    frames.append(ethernet(arp, 0x0806))
    source6, destination6 = ipaddress.IPv6Address("2001:db8::10").packed, ipaddress.IPv6Address("2001:db8::20").packed
    icmp6 = struct.pack("!BBHHH", 128, 0, 0, 12, 1) + b"IPv6 test"
    pseudo = source6 + destination6 + struct.pack("!I3xB", len(icmp6), 58)
    icmp6 = icmp6[:2] + struct.pack("!H", checksum(pseudo + icmp6)) + icmp6[4:]
    frames.append(ethernet(struct.pack("!IHBB", 6 << 28, len(icmp6), 58, 64) + source6 + destination6 + icmp6, 0x86DD))
    frames.append(ethernet(tcp(51001, 443, 2000, 0, 24, b"\x16\x03\x03\x00\x04test")))
    return frames


def generate(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    frames = sample_frames()
    packets = [decode(index, 1795233600 + index * 0.05, frame, len(frame), 1) for index, frame in enumerate(frames, 1)]
    write_pcap(directory / "teaching.pcap", packets, 1)
    loopback = []
    for index, frame in enumerate(frames):
        if frame[12:14] == b"\x08\x00":
            raw = struct.pack("<I", 2) + frame[14:]
            loopback.append(decode(index + 1, 1795233600 + index * 0.05, raw, len(raw), 0))
    write_pcap(directory / "loopback.pcap", loopback, 0)
    return packets


if __name__ == "__main__":
    generate(Path(__file__).resolve().parents[1] / "samples")
