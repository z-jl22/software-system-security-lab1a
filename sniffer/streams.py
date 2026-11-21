from dataclasses import dataclass, field


@dataclass
class Flow:
    identifier: str
    endpoints: tuple
    packets: list = field(default_factory=list)
    closed: bool = False
    opening_syn: object = None

    @property
    def byte_count(self):
        return sum(len(packet.raw) for packet in self.packets)


class FlowTracker:
    def __init__(self):
        self.flows = {}
        self.active = {}

    def add(self, packet):
        if "TCP" not in packet.layers:
            return
        key = tuple(sorted(((packet.source, packet.source_port), (packet.destination, packet.destination_port))))
        flow = self.active.get(key)
        syn = bool(packet.flags & 2 and not packet.flags & 16)
        signature = (packet.source, packet.source_port, packet.sequence)
        stale = flow and packet.timestamp - flow.packets[-1].timestamp > 120
        new_syn = flow and syn and (flow.closed or flow.opening_syn != signature)
        if flow is None or stale or new_syn:
            identifier = f"TCP-{len(self.flows) + 1:04d}"
            flow = Flow(identifier, key, opening_syn=signature if syn else None)
            self.flows[identifier] = self.active[key] = flow
        packet.flow_id = flow.identifier
        flow.packets.append(packet)
        if packet.flags & 4:
            flow.closed = True
        if packet.flags & 1:
            fin_sources = {(item.source, item.source_port) for item in flow.packets if item.flags & 1}
            flow.closed = len(fin_sources) == 2

    def describe(self, identifier):
        flow = self.flows[identifier]
        first, last = flow.packets[0], flow.packets[-1]
        lines = [f"{identifier}  {flow.endpoints}",
                 f"数据包：{len(flow.packets)}  捕获字节：{flow.byte_count}  持续：{max(0, last.timestamp - first.timestamp):.6f}s",
                 "此视图按捕获顺序展示双向 TCP 段，未进行 TCP 字节流重组。", ""]
        for packet in flow.packets:
            lines.append(f"#{packet.number} +{packet.timestamp - first.timestamp:.6f}s  "
                         f"{packet.source}:{packet.source_port} → {packet.destination}:{packet.destination_port}")
            lines.append(packet.summary)
            if packet.payload:
                lines.append(packet.payload[:4096].decode("utf-8", errors="replace"))
                if len(packet.payload) > 4096:
                    lines.append("[该段预览限制为 4096 字节；完整字节见数据包详情或 PCAP]")
            lines.append("")
        return "\n".join(lines)
