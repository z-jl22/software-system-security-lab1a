import ctypes as ct
import ctypes.util
import struct
from pathlib import Path


class PcapError(RuntimeError):
    pass


class Timeval(ct.Structure):
    _fields_ = [("seconds", ct.c_long), ("microseconds", ct.c_long)]


class Header(ct.Structure):
    _fields_ = [("timestamp", Timeval), ("caplen", ct.c_uint32), ("length", ct.c_uint32)]


class Device(ct.Structure):
    pass


Device._fields_ = [("next", ct.POINTER(Device)), ("name", ct.c_char_p),
                   ("description", ct.c_char_p), ("addresses", ct.c_void_p), ("flags", ct.c_uint)]


class BpfProgram(ct.Structure):
    _fields_ = [("length", ct.c_uint), ("instructions", ct.c_void_p)]


class Pcap:
    def __init__(self):
        library = ctypes.util.find_library("pcap")
        if not library:
            raise PcapError("找不到 libpcap；macOS 通常自带 /usr/lib/libpcap.dylib")
        self.lib = ct.CDLL(library)
        signatures = {
            "pcap_findalldevs": ([ct.POINTER(ct.POINTER(Device)), ct.c_char_p], ct.c_int),
            "pcap_freealldevs": ([ct.POINTER(Device)], None),
            "pcap_open_live": ([ct.c_char_p, ct.c_int, ct.c_int, ct.c_int, ct.c_char_p], ct.c_void_p),
            "pcap_setnonblock": ([ct.c_void_p, ct.c_int, ct.c_char_p], ct.c_int),
            "pcap_datalink": ([ct.c_void_p], ct.c_int),
            "pcap_next_ex": ([ct.c_void_p, ct.POINTER(ct.POINTER(Header)), ct.POINTER(ct.POINTER(ct.c_ubyte))], ct.c_int),
            "pcap_geterr": ([ct.c_void_p], ct.c_char_p),
            "pcap_close": ([ct.c_void_p], None),
            "pcap_compile": ([ct.c_void_p, ct.POINTER(BpfProgram), ct.c_char_p, ct.c_int, ct.c_uint32], ct.c_int),
            "pcap_setfilter": ([ct.c_void_p, ct.POINTER(BpfProgram)], ct.c_int),
            "pcap_freecode": ([ct.POINTER(BpfProgram)], None),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.lib, name)
            function.argtypes, function.restype = arguments, result

    def devices(self):
        head = ct.POINTER(Device)()
        error = ct.create_string_buffer(256)
        if self.lib.pcap_findalldevs(ct.byref(head), error) != 0:
            raise PcapError(error.value.decode(errors="replace"))
        devices = []
        try:
            current = head
            while current:
                device = current.contents
                devices.append((device.name.decode(), (device.description or b"").decode(errors="replace")))
                current = device.next
        finally:
            self.lib.pcap_freealldevs(head)
        return devices

    def open(self, interface, expression=""):
        error = ct.create_string_buffer(256)
        handle = self.lib.pcap_open_live(interface.encode(), 65535, 0, 100, error)
        if not handle:
            raise PcapError(error.value.decode(errors="replace") + "\nmacOS 实时抓包需要 BPF 访问权限，见使用指南。")
        try:
            if expression.strip():
                program = BpfProgram()
                if self.lib.pcap_compile(handle, ct.byref(program), expression.encode(), 1, 0xFFFFFFFF) < 0:
                    raise PcapError(self.error(handle))
                try:
                    if self.lib.pcap_setfilter(handle, ct.byref(program)) < 0:
                        raise PcapError(self.error(handle))
                finally:
                    self.lib.pcap_freecode(ct.byref(program))
            if self.lib.pcap_setnonblock(handle, 1, error) < 0:
                raise PcapError(error.value.decode(errors="replace"))
            return handle, self.lib.pcap_datalink(handle)
        except Exception:
            self.lib.pcap_close(handle)
            raise

    def error(self, handle):
        return self.lib.pcap_geterr(handle).decode(errors="replace")

    def next(self, handle):
        header, data = ct.POINTER(Header)(), ct.POINTER(ct.c_ubyte)()
        result = self.lib.pcap_next_ex(handle, ct.byref(header), ct.byref(data))
        if result == 1:
            value = header.contents
            return (value.timestamp.seconds + value.timestamp.microseconds / 1e6,
                    ct.string_at(data, value.caplen), value.length)
        if result < 0:
            raise PcapError(self.error(handle) if result == -1 else "抓包已结束")
        return None


def read_pcap(path):
    with open(path, "rb") as stream:
        header = stream.read(24)
        formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
                   b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
        if len(header) != 24 or header[:4] not in formats:
            raise PcapError("仅支持经典 PCAP；PCAPNG 请先用 Wireshark 另存为 PCAP")
        endian, scale = formats[header[:4]]
        major, minor, zone, accuracy, snaplen, linktype = struct.unpack(endian + "HHiIII", header[4:])
        if (major, minor) != (2, 4) or snaplen == 0:
            raise PcapError("无效的 PCAP 文件头")
        while True:
            record = stream.read(16)
            if not record:
                break
            if len(record) != 16:
                raise PcapError("PCAP 记录头被截断")
            seconds, fraction, captured, original = struct.unpack(endian + "IIII", record)
            if captured > min(snaplen, 16 * 1024 * 1024) or captured > original or fraction >= scale:
                raise PcapError("PCAP 记录长度或时间戳无效")
            raw = stream.read(captured)
            if len(raw) != captured:
                raise PcapError("PCAP 数据被截断")
            yield seconds + fraction / scale, raw, original, linktype


def write_pcap(path, packets, linktype):
    with open(Path(path), "wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for packet in packets:
            seconds = int(packet.timestamp)
            fraction = min(999999, max(0, round((packet.timestamp - seconds) * 1e6)))
            stream.write(struct.pack("<IIII", seconds, fraction, len(packet.raw), packet.original_length))
            stream.write(packet.raw)
