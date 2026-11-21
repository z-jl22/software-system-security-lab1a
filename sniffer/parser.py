import ipaddress
import struct
from dataclasses import dataclass, field


class DecodeError(ValueError):
    pass


@dataclass
class Packet:
    number: int
    timestamp: float
    raw: bytes
    original_length: int
    linktype: int
    source: str = ""
    destination: str = ""
    protocol: str = "UNKNOWN"
    summary: str = ""
    source_port: int = 0
    destination_port: int = 0
    layers: dict = field(default_factory=dict)
    payload: bytes = b""
    sequence: int = 0
    flags: int = 0
    flow_id: str = ""


def need(data, offset, size):
    if offset < 0 or offset + size > len(data):
        raise DecodeError("数据被截断或头部长度无效")


def mac(raw):
    return ":".join(f"{value:02x}" for value in raw)


def decode(number, timestamp, raw, original_length, linktype):
    packet = Packet(number, timestamp, raw, original_length, linktype)
    packet.layers["Frame"] = {"编号": number, "时间戳": f"{timestamp:.6f}",
                              "捕获长度": len(raw), "线上长度": original_length, "链路类型": linktype}
    try:
        offset = 0
        if linktype == 1:
            need(raw, 0, 14)
            packet.source, packet.destination = mac(raw[6:12]), mac(raw[:6])
            kind = struct.unpack_from("!H", raw, 12)[0]
            packet.layers["Ethernet"] = {"源 MAC": packet.source, "目的 MAC": packet.destination,
                                          "EtherType": f"0x{kind:04x}"}
            offset = 14
            while kind in (0x8100, 0x88A8):
                need(raw, offset, 4)
                tag, kind = struct.unpack_from("!HH", raw, offset)
                packet.layers[f"VLAN @{offset}"] = {"VLAN ID": tag & 0xFFF}
                offset += 4
        elif linktype in (0, 108):
            need(raw, 0, 5)
            family = int.from_bytes(raw[:4], "big" if linktype == 108 else "little")
            if family not in (2, 10, 24, 28, 30):
                family = int.from_bytes(raw[:4], "big")
            kind = 0x0800 if family == 2 else 0x86DD if family in (10, 24, 28, 30) else 0
            packet.layers["Loopback"] = {"地址族": family}
            offset = 4
        elif linktype in (12, 101, 228, 229):
            need(raw, 0, 1)
            kind = 0x0800 if raw[0] >> 4 == 4 else 0x86DD if raw[0] >> 4 == 6 else 0
        else:
            packet.summary = f"暂不支持链路类型 {linktype}，保留原始字节"
            return packet
        if kind == 0x0806:
            arp(packet, raw[offset:])
        elif kind == 0x0800:
            ipv4(packet, raw[offset:])
        elif kind == 0x86DD:
            ipv6(packet, raw[offset:])
        else:
            packet.summary = f"未解析 EtherType 0x{kind:04x}"
    except (DecodeError, ValueError, struct.error) as error:
        packet.layers["解析提示"] = {"原因": str(error)}
        packet.summary = (packet.summary + " | " if packet.summary else "") + str(error)
    return packet


def arp(packet, data):
    need(data, 0, 8)
    hardware, protocol, hardware_size, protocol_size, operation = struct.unpack_from("!HHBBH", data)
    packet.protocol = "ARP"
    packet.layers["ARP"] = {"操作": operation, "硬件类型": hardware, "协议类型": f"0x{protocol:04x}"}
    need(data, 8, 2 * (hardware_size + protocol_size))
    if hardware == 1 and protocol == 0x0800 and hardware_size == 6 and protocol_size == 4:
        packet.source = str(ipaddress.IPv4Address(data[14:18]))
        packet.destination = str(ipaddress.IPv4Address(data[24:28]))
        packet.layers["ARP"].update({"发送方 MAC": mac(data[8:14]), "发送方 IP": packet.source,
                                     "目标 MAC": mac(data[18:24]), "目标 IP": packet.destination})
    packet.summary = f"{'Request' if operation == 1 else 'Reply' if operation == 2 else operation} {packet.source} → {packet.destination}"


def ipv4(packet, data):
    need(data, 0, 20)
    header_length = (data[0] & 15) * 4
    total = struct.unpack_from("!H", data, 2)[0]
    if data[0] >> 4 != 4 or header_length < 20 or total < header_length:
        raise DecodeError("IPv4 头部无效")
    need(data, 0, header_length)
    packet.source, packet.destination = str(ipaddress.IPv4Address(data[12:16])), str(ipaddress.IPv4Address(data[16:20]))
    fragment = struct.unpack_from("!H", data, 6)[0]
    packet.protocol = "IPv4"
    packet.layers["IPv4"] = {"源 IP": packet.source, "目的 IP": packet.destination,
                              "头部长度": header_length, "总长度": total, "TTL": data[8],
                              "上层协议": data[9], "分片偏移": (fragment & 0x1FFF) * 8,
                              "MF": bool(fragment & 0x2000)}
    if len(data) < total:
        packet.layers["捕获提示"] = {"状态": "IPv4 数据报未完整捕获"}
    if fragment & 0x3FFF:
        packet.summary = "IPv4 分片；未做 IP 重组，跳过传输层解析"
        return
    transport(packet, data[header_length:total], data[9])


def ipv6(packet, data):
    need(data, 0, 40)
    if data[0] >> 4 != 6:
        raise DecodeError("IPv6 版本无效")
    length = struct.unpack_from("!H", data, 4)[0]
    packet.source, packet.destination = str(ipaddress.IPv6Address(data[8:24])), str(ipaddress.IPv6Address(data[24:40]))
    packet.protocol = "IPv6"
    packet.layers["IPv6"] = {"源 IP": packet.source, "目的 IP": packet.destination,
                              "载荷长度": length, "Next Header": data[6], "Hop Limit": data[7]}
    if not length:
        packet.summary = "空 IPv6 载荷或不支持的 jumbogram"
        return
    if len(data) < 40 + length:
        packet.layers["捕获提示"] = {"状态": "IPv6 数据报未完整捕获"}
    data = data[:40 + length]
    next_header, offset = data[6], 40
    while next_header in (0, 43, 44, 51, 60):
        need(data, offset, 2)
        extension = next_header
        if extension == 44:
            need(data, offset, 8)
            value = struct.unpack_from("!H", data, offset + 2)[0]
            packet.layers["IPv6 Fragment"] = {"偏移": (value >> 3) * 8, "M": bool(value & 1)}
            if value & 0xFFF9:
                packet.summary = "IPv6 分片；未做 IP 重组，跳过传输层解析"
                return
            size = 8
        else:
            size = (data[offset + 1] + 2) * 4 if extension == 51 else (data[offset + 1] + 1) * 8
        need(data, offset, size)
        packet.layers[f"IPv6 Extension @{offset}"] = {"类型": extension, "长度": size}
        next_header, offset = data[offset], offset + size
    transport(packet, data[offset:], next_header)


def transport(packet, data, protocol):
    if protocol == 6:
        need(data, 0, 20)
        packet.source_port, packet.destination_port, packet.sequence, acknowledgement = struct.unpack_from("!HHII", data)
        size, packet.flags = (data[12] >> 4) * 4, data[13]
        if size < 20:
            raise DecodeError("TCP 头部长度无效")
        need(data, 0, size)
        packet.protocol = "TCP"
        flags = ",".join(name for mask, name in ((1, "FIN"), (2, "SYN"), (4, "RST"), (8, "PSH"),
                                                (16, "ACK"), (32, "URG"), (64, "ECE"), (128, "CWR")) if packet.flags & mask)
        packet.payload = data[size:]
        packet.layers["TCP"] = {"源端口": packet.source_port, "目的端口": packet.destination_port,
                                 "序列号": packet.sequence, "确认号": acknowledgement, "标志": flags,
                                 "头部长度": size, "窗口": struct.unpack_from("!H", data, 14)[0],
                                 "载荷长度": len(packet.payload)}
        packet.summary = f"{packet.source_port} → {packet.destination_port} [{flags}] Seq={packet.sequence} Len={len(packet.payload)}"
        application(packet)
    elif protocol == 17:
        need(data, 0, 8)
        packet.source_port, packet.destination_port, length, checksum = struct.unpack_from("!HHHH", data)
        if length < 8 or length > len(data):
            raise DecodeError("UDP 长度无效或数据被截断")
        packet.protocol, packet.payload = "UDP", data[8:length]
        packet.layers["UDP"] = {"源端口": packet.source_port, "目的端口": packet.destination_port,
                                 "长度": length, "校验和": f"0x{checksum:04x}"}
        packet.summary = f"{packet.source_port} → {packet.destination_port} Len={length}"
        if 53 in (packet.source_port, packet.destination_port):
            dns(packet)
    elif protocol in (1, 58):
        need(data, 0, 4)
        packet.protocol = "ICMP" if protocol == 1 else "ICMPv6"
        packet.layers[packet.protocol] = {"Type": data[0], "Code": data[1], "校验和": data[2:4].hex()}
        names = {1: {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable", 11: "Time Exceeded"},
                 58: {128: "Echo Request", 129: "Echo Reply", 135: "Neighbor Solicitation", 136: "Neighbor Advertisement"}}
        packet.summary = names[protocol].get(data[0], f"Type={data[0]} Code={data[1]}")
    else:
        packet.summary = f"未解析的上层协议 {protocol}"


def application(packet):
    payload = packet.payload
    first = payload.split(b"\r\n", 1)[0]
    methods = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")
    if first.startswith(b"HTTP/1.") or (first.startswith(methods) and b" HTTP/1." in first):
        packet.protocol = "HTTP"
        packet.summary = first[:300].decode("utf-8", errors="replace")
        headers = payload.split(b"\r\n\r\n", 1)[0][:16384].decode("utf-8", errors="replace")
        packet.layers["HTTP"] = {"起始行": packet.summary, "当前段头部预览": headers,
                                  "说明": "仅解析当前 TCP 段；跨段头部需要流重组"}
    elif len(payload) >= 5 and payload[0] in (20, 21, 22, 23) and payload[1] == 3 and payload[2] <= 4:
        packet.protocol = "TLS"
        packet.layers["TLS"] = {"记录类型": payload[0], "记录层版本": payload[1:3].hex(),
                                 "声明长度": int.from_bytes(payload[3:5], "big"), "说明": "记录头特征识别，不解密正文；记录版本不等于协商版本"}
        packet.summary = f"TLS record type={payload[0]} length={int.from_bytes(payload[3:5], 'big')}"


def dns(packet):
    data = packet.payload
    need(data, 0, 12)
    transaction, flags, questions, answers, authority, additional = struct.unpack_from("!HHHHHH", data)
    packet.protocol = "DNS"
    details = {"事务 ID": f"0x{transaction:04x}", "响应": bool(flags & 0x8000),
               "问题数": questions, "回答数": answers, "RCODE": flags & 15}
    packet.layers["DNS"] = details
    packet.summary = f"{'Response' if flags & 0x8000 else 'Query'} ID=0x{transaction:04x}"
    if questions:
        name, offset = dns_name(data, 12)
        need(data, offset, 4)
        query_type, query_class = struct.unpack_from("!HH", data, offset)
        details.update({"查询域名": name, "QTYPE": query_type, "QCLASS": query_class})
        packet.summary += f" {name} type={query_type}"


def dns_name(data, offset):
    labels, visited, end = [], set(), None
    for step in range(128):
        need(data, offset, 1)
        if offset in visited:
            raise DecodeError("DNS 压缩指针形成循环")
        visited.add(offset)
        size = data[offset]
        if size & 0xC0 == 0xC0:
            need(data, offset, 2)
            if end is None:
                end = offset + 2
            offset = ((size & 63) << 8) | data[offset + 1]
            continue
        if size & 0xC0:
            raise DecodeError("DNS 标签长度无效")
        offset += 1
        if size == 0:
            return ".".join(labels), end if end is not None else offset
        need(data, offset, size)
        labels.append(data[offset:offset + size].decode("ascii", errors="replace"))
        offset += size
        if sum(len(label) + 1 for label in labels) > 255:
            raise DecodeError("DNS 名称过长")
    raise DecodeError("DNS 名称跳转次数过多")


def hexdump(raw):
    lines = []
    for offset in range(0, len(raw), 16):
        chunk = raw[offset:offset + 16]
        printable = "".join(chr(value) if 32 <= value < 127 else "." for value in chunk)
        lines.append(f"{offset:04x}  {chunk.hex(' '):47s}  {printable}")
    return "\n".join(lines)
