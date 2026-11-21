from dataclasses import dataclass, field
from collections import deque

from .processes import connection_key


@dataclass
class Flow:
    identifier: str
    endpoints: tuple
    packets: list = field(default_factory=list)
    closed: bool = False
    opening_syn: object = None
    owners: set = field(default_factory=set)

    @property
    def byte_count(self):
        return sum(len(packet.raw) for packet in self.packets)


class FlowTracker:
    def __init__(self):
        self.flows = {}
        self.active = {}
        self.snapshots = deque(maxlen=16)

    def observe_processes(self, snapshot):
        self.snapshots.append(snapshot)
        changed = False
        for flow in self.flows.values():
            changed = self.associate(flow, snapshot) or changed
        return changed

    def associate(self, flow, snapshot):
        first, last = flow.packets[0].timestamp, flow.packets[-1].timestamp
        if last < snapshot.started - 0.75 or first > snapshot.finished + 0.75:
            return False
        key = connection_key(*flow.endpoints[0], *flow.endpoints[1])
        candidates = snapshot.owners.get(key, set())
        if not candidates or not any(snapshot.started - 0.75 <= packet.timestamp <= snapshot.finished + 0.75
                                     for packet in flow.packets):
            return False
        previous = len(flow.owners)
        flow.owners.update(candidates)
        return len(flow.owners) != previous

    def processes(self):
        return sorted({owner for flow in self.flows.values() for owner in flow.owners})

    def process_flows(self, process):
        return [flow for flow in self.flows.values() if process in flow.owners]

    def describe_process(self, process):
        flows = self.process_flows(process)
        lines = [process.label, f"已关联 TCP 流：{len(flows)}；包数：{sum(len(flow.packets) for flow in flows)}",
                 "归属来自实时 lsof 连接快照，属于采样关联；不保证覆盖短连接或不可见进程。",
                 "本机回环连接可能同时属于客户端与服务端进程。", ""]
        for flow in flows:
            lines.append(f"{flow.identifier}  {flow.endpoints[0]} ↔ {flow.endpoints[1]}")
            lines.append(f"包数 {len(flow.packets)}；捕获字节 {flow.byte_count}；"
                         f"持续 {max(0, flow.packets[-1].timestamp - flow.packets[0].timestamp):.6f}s")
        return "\n".join(lines)

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
        for snapshot in self.snapshots:
            self.associate(flow, snapshot)

    def describe(self, identifier):
        flow = self.flows[identifier]
        first, last = flow.packets[0], flow.packets[-1]
        lines = [f"{identifier}  {flow.endpoints}",
                 "关联进程：" + ("；".join(owner.label for owner in sorted(flow.owners)) or "未关联"),
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
