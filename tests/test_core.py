import ctypes as ct
import os
import random
import struct
import tempfile
import unittest
from pathlib import Path

from sniffer.filters import FilterError, compile_filter
from sniffer.parser import DecodeError, decode, dns_name
from sniffer.pcap import BpfProgram, Pcap, PcapError, read_pcap, write_pcap
from sniffer.streams import FlowTracker
from tools.generate_samples import ethernet, ipv4, sample_frames, tcp


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.frames = sample_frames()
        self.packets = [decode(index, 100 + index, frame, len(frame), 1) for index, frame in enumerate(self.frames, 1)]

    def test_http_nonstandard_port(self):
        request = self.packets[3]
        self.assertEqual(request.protocol, "HTTP")
        self.assertEqual(request.destination_port, 8080)
        self.assertIn("GET /lab", request.summary)
        self.assertEqual(self.packets[4].protocol, "HTTP")

    def test_port_does_not_imply_http(self):
        raw = ethernet(tcp(50000, 80, 1, 1, 24, b"not HTTP"))
        self.assertEqual(decode(1, 1, raw, len(raw), 1).protocol, "TCP")

    def test_dns_request_response(self):
        self.assertEqual(self.packets[8].layers["DNS"]["查询域名"], "example.test")
        self.assertTrue(self.packets[9].layers["DNS"]["响应"])

    def test_dns_pointer_loop(self):
        with self.assertRaises(DecodeError):
            dns_name(b"\xc0\x00", 0)

    def test_dns_compression(self):
        self.assertEqual(dns_name(b"\x03www\x00\xc0\x00", 5), ("www", 7))

    def test_icmp_arp_ipv6_tls(self):
        self.assertEqual([packet.protocol for packet in self.packets[10:]], ["ICMP", "ICMP", "ARP", "ICMPv6", "TLS"])

    def test_filters_nested_and_precedence(self):
        predicate = compile_filter("(tcp or udp) and not port 53")
        self.assertTrue(predicate(self.packets[3]))
        self.assertFalse(predicate(self.packets[8]))
        self.assertTrue(compile_filter("http or udp and port 53")(self.packets[8]))
        self.assertTrue(compile_filter("tcp and src host 192.0.2.10 and dst port 8080")(self.packets[3]))
        self.assertTrue(compile_filter("ipv4 and http")(self.packets[3]))
        self.assertTrue(compile_filter("ipv6 and icmp6")(self.packets[13]))

    def test_invalid_filters(self):
        for expression in ("http tcp", "tcp and", "(tcp", "port 65536", "host xyz", "tcp)", "__import__('os')"):
            with self.subTest(expression=expression), self.assertRaises(FilterError):
                compile_filter(expression)

    def test_bidirectional_flows(self):
        tracker = FlowTracker()
        for packet in self.packets:
            tracker.add(packet)
        self.assertEqual(len(tracker.flows), 2)
        self.assertEqual(len(tracker.flows["TCP-0001"].packets), 8)
        self.assertEqual(self.packets[0].flow_id, self.packets[1].flow_id)
        self.assertIn("GET /lab", tracker.describe("TCP-0001"))

    def test_flow_syn_retransmission_and_reuse(self):
        tracker = FlowTracker()
        tracker.add(self.packets[0])
        duplicate = decode(2, 102, self.frames[0], len(self.frames[0]), 1)
        tracker.add(duplicate)
        self.assertEqual(len(tracker.flows), 1)
        raw = ethernet(tcp(51000, 8080, 5000, 0, 2))
        tracker.add(decode(3, 103, raw, len(raw), 1))
        self.assertEqual(len(tracker.flows), 2)

    def test_loopback_both_byte_orders(self):
        for endian in ("<", ">"):
            raw = struct.pack(endian + "I", 2) + self.frames[3][14:]
            self.assertEqual(decode(1, 1, raw, len(raw), 0).protocol, "HTTP")

    def test_vlan_and_raw(self):
        raw = self.frames[3][:12] + struct.pack("!HH", 0x8100, 7) + self.frames[3][12:]
        self.assertEqual(decode(1, 1, raw, len(raw), 1).protocol, "HTTP")
        raw = self.frames[3][14:]
        self.assertEqual(decode(1, 1, raw, len(raw), 12).protocol, "HTTP")

    def test_fragment_not_interpreted_as_tcp(self):
        raw = ethernet(ipv4(bytes(40), fragment=0x2000))
        packet = decode(1, 1, raw, len(raw), 1)
        self.assertNotIn("TCP", packet.layers)
        self.assertIn("分片", packet.summary)

    def test_ipv6_extension(self):
        raw = bytearray(self.frames[13])
        length = int.from_bytes(raw[18:20], "big")
        raw[18:20] = struct.pack("!H", length + 8)
        raw[20] = 0
        raw[54:54] = bytes([58, 0, 0, 0, 0, 0, 0, 0])
        self.assertEqual(decode(1, 1, bytes(raw), len(raw), 1).protocol, "ICMPv6")

    def test_truncated_frames_and_fuzz(self):
        for frame in self.frames:
            for length in range(len(frame)):
                packet = decode(1, 1, frame[:length], len(frame), 1)
                self.assertIsInstance(packet.summary, str)
        generator = random.Random(12345)
        for iteration in range(1000):
            raw = bytes(generator.randrange(256) for count in range(generator.randrange(160)))
            decode(1, 1, raw, len(raw), generator.choice([0, 1, 12, 108, 999]))

    def test_pcap_roundtrip(self):
        with tempfile.TemporaryDirectory(dir="tmp") as directory:
            path = Path(directory) / "roundtrip.pcap"
            write_pcap(path, self.packets, 1)
            records = list(read_pcap(path))
            self.assertEqual([record[1] for record in records], self.frames)
            self.assertEqual(records[0][0], self.packets[0].timestamp)

    def test_bad_pcap(self):
        with tempfile.TemporaryDirectory(dir="tmp") as directory:
            path = Path(directory) / "bad.pcap"
            for raw in (b"", b"\x0a\x0d\x0d\x0a" + bytes(20),
                        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + bytes(3)):
                path.write_bytes(raw)
                with self.assertRaises(PcapError):
                    list(read_pcap(path))

    def test_pcap_endian_nanoseconds(self):
        with tempfile.TemporaryDirectory(dir="tmp") as directory:
            path = Path(directory) / "nano.pcap"
            raw = self.frames[0]
            path.write_bytes(struct.pack(">IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1) +
                             struct.pack(">IIII", 123, 500000000, len(raw), len(raw)) + raw)
            self.assertEqual(list(read_pcap(path))[0][0], 123.5)

    def test_real_libpcap_bpf(self):
        backend = Pcap()
        backend.lib.pcap_open_dead.argtypes = [ct.c_int, ct.c_int]
        backend.lib.pcap_open_dead.restype = ct.c_void_p
        backend.lib.pcap_offline_filter.argtypes = [ct.POINTER(BpfProgram), ct.c_void_p, ct.c_void_p]
        backend.lib.pcap_offline_filter.restype = ct.c_uint
        handle = backend.lib.pcap_open_dead(1, 65535)
        self.assertTrue(handle)
        try:
            program = BpfProgram()
            self.assertEqual(backend.lib.pcap_compile(handle, ct.byref(program), b"tcp and port 8080", 1, 0xFFFFFFFF), 0)
            from sniffer.pcap import Header, Timeval
            for frame, expected in ((self.frames[3], True), (self.frames[8], False)):
                header = Header(Timeval(1, 0), len(frame), len(frame))
                buffer = ct.create_string_buffer(frame)
                result = backend.lib.pcap_offline_filter(ct.byref(program), ct.byref(header), buffer)
                self.assertEqual(bool(result), expected)
        finally:
            if program.instructions:
                backend.lib.pcap_freecode(ct.byref(program))
            backend.lib.pcap_close(handle)


if __name__ == "__main__":
    unittest.main()
