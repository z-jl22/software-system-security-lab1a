import unittest

from sniffer.parser import decode
from sniffer.processes import (ConnectionSnapshot, ProcessIdentity, connection_key, endpoint,
                               parse_connections, parse_start_times)
from sniffer.streams import FlowTracker
from tools.generate_samples import ethernet, tcp


class ProcessTests(unittest.TestCase):
    def packet(self, timestamp=100, port=51000, reverse=False, sequence=1000, flags=24):
        raw = ethernet(tcp(8080 if reverse else port, port if reverse else 8080,
                           sequence, 1, flags, b"test", reverse))
        return decode(1, timestamp, raw, len(raw), 1)

    def test_endpoints(self):
        self.assertEqual(endpoint("[::1]:8080"), ("::1", 8080))
        self.assertEqual(endpoint("[::ffff:192.0.2.1]:80"), ("192.0.2.1", 80))
        self.assertEqual(endpoint("[fe80::1%en0]:80"), ("fe80::1", 80))
        for value in ("*:8080", "127.0.0.1:http", "127.0.0.1:65536"):
            with self.assertRaises(ValueError):
                endpoint(value)

    def test_lsof_records_and_multiple_owners(self):
        output = ("p12\ncclient\nf3\nn192.0.2.10:51000->192.0.2.20:8080\nTST=ESTABLISHED\n"
                  "f4\nn*:8080\nTST=LISTEN\np13\ncserver\nf5\n"
                  "n192.0.2.20:8080->192.0.2.10:51000\nTST=ESTABLISHED\n"
                  "p99\ncunknown\nf6\nn192.0.2.10:52000->192.0.2.20:8080\nTST=ESTABLISHED\n")
        owners = parse_connections(output, {12: "start1", 13: "start2"})
        self.assertEqual(len(owners), 1)
        key = connection_key("192.0.2.10", 51000, "192.0.2.20", 8080)
        self.assertEqual({owner.pid for owner in owners[key]}, {12, 13})

    def test_start_times(self):
        self.assertEqual(parse_start_times("  12 Sat Nov 21 10:00:00 2026\ninvalid\n"),
                         {12: "Sat Nov 21 10:00:00 2026"})

    def test_one_process_multiple_bidirectional_flows(self):
        process = ProcessIdentity(12, "start1", "client")
        tracker = FlowTracker()
        packets = [self.packet(100, 51000), self.packet(100.1, 51000, True), self.packet(100.2, 52000)]
        for packet in packets:
            tracker.add(packet)
        owners = {connection_key("192.0.2.10", port, "192.0.2.20", 8080): {process} for port in (51000, 52000)}
        self.assertTrue(tracker.observe_processes(ConnectionSnapshot(100, 100.1, owners, 1)))
        self.assertEqual(len(tracker.process_flows(process)), 2)
        self.assertEqual(sum(len(flow.packets) for flow in tracker.process_flows(process)), 3)
        self.assertIn("已关联 TCP 流：2", tracker.describe_process(process))

    def test_recent_snapshot_associates_new_packets(self):
        process = ProcessIdentity(12, "start1", "client")
        key = connection_key("192.0.2.10", 51000, "192.0.2.20", 8080)
        tracker = FlowTracker()
        tracker.observe_processes(ConnectionSnapshot(100, 100.1, {key: {process}}, 1))
        tracker.add(self.packet(100.2))
        self.assertEqual(tracker.processes(), [process])

    def test_unrelated_endpoints_and_old_pcap_not_attributed(self):
        process = ProcessIdentity(12, "start1", "client")
        key = connection_key("192.0.2.10", 52000, "192.0.2.20", 8080)
        tracker = FlowTracker()
        tracker.add(self.packet(100))
        tracker.add(self.packet(1, 52000))
        tracker.observe_processes(ConnectionSnapshot(100, 100.1, {key: {process}}, 1))
        self.assertEqual(tracker.processes(), [])

    def test_pid_reuse_and_flow_reuse_remain_separate(self):
        old, new = ProcessIdentity(12, "start1", "client"), ProcessIdentity(12, "start2", "client")
        key = connection_key("192.0.2.10", 51000, "192.0.2.20", 8080)
        tracker = FlowTracker()
        tracker.add(self.packet(100, flags=2))
        tracker.observe_processes(ConnectionSnapshot(100, 100.1, {key: {old}}, 1))
        tracker.add(self.packet(110, sequence=5000, flags=2))
        tracker.observe_processes(ConnectionSnapshot(110, 110.1, {key: {new}}, 1))
        self.assertEqual(len(tracker.process_flows(old)), 1)
        self.assertEqual(len(tracker.process_flows(new)), 1)
        self.assertNotEqual(tracker.process_flows(old)[0].identifier, tracker.process_flows(new)[0].identifier)


if __name__ == "__main__":
    unittest.main()
