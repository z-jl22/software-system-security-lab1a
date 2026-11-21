import ipaddress
import re


class FilterError(ValueError):
    pass


def compile_filter(expression):
    tokens = re.findall(r"\(|\)|[^\s()]+", expression.lower())
    position = 0
    protocols = {"ethernet": "Ethernet", "arp": "ARP", "ip": "IPv4", "ipv4": "IPv4",
                 "ip6": "IPv6", "ipv6": "IPv6", "tcp": "TCP", "udp": "UDP", "icmp": "ICMP",
                 "icmp6": "ICMPv6", "icmpv6": "ICMPv6", "http": "HTTP", "dns": "DNS", "tls": "TLS"}

    def take():
        nonlocal position
        if position >= len(tokens):
            raise FilterError("表达式不完整")
        token = tokens[position]
        position += 1
        return token

    def atom():
        token = take()
        if token == "not":
            child = atom()
            return lambda packet: not child(packet)
        if token == "(":
            child = disjunction()
            if take() != ")":
                raise FilterError("缺少右括号")
            return child
        if token in protocols:
            layer = protocols[token]
            return lambda packet: layer in packet.layers
        direction = None
        if token in ("src", "dst"):
            direction, token = token, take()
        if token == "host":
            try:
                address = str(ipaddress.ip_address(take()))
            except ValueError:
                raise FilterError("host 后需要有效的 IP 地址")
            return lambda packet: address in ([packet.source] if direction == "src" else
                                              [packet.destination] if direction == "dst" else
                                              [packet.source, packet.destination])
        if token == "port":
            try:
                port = int(take())
            except ValueError:
                raise FilterError("port 后需要 0–65535 的整数")
            if not 0 <= port <= 65535:
                raise FilterError("端口范围应为 0–65535")
            return lambda packet: ("TCP" in packet.layers or "UDP" in packet.layers) and port in (
                [packet.source_port] if direction == "src" else [packet.destination_port] if direction == "dst"
                else [packet.source_port, packet.destination_port])
        raise FilterError(f"不支持的条件：{token}；示例：(tcp or udp) and not port 53")

    def conjunction():
        child = atom()
        while position < len(tokens) and tokens[position] == "and":
            take()
            left, right = child, atom()
            child = lambda packet, left=left, right=right: left(packet) and right(packet)
        return child

    def disjunction():
        child = conjunction()
        while position < len(tokens) and tokens[position] == "or":
            take()
            left, right = child, conjunction()
            child = lambda packet, left=left, right=right: left(packet) or right(packet)
        return child

    if not tokens:
        return lambda packet: True
    if len(tokens) > 128:
        raise FilterError("过滤表达式最多 128 个 token")
    result = disjunction()
    if position != len(tokens):
        raise FilterError(f"条件之间需要 and/or，或存在多余括号：{tokens[position]}")
    return result
