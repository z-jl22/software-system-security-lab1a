import ipaddress
import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class ProcessIdentity:
    pid: int
    started: str
    name: str

    @property
    def label(self):
        return f"{self.name} · PID {self.pid} · 启动 {self.started}"


@dataclass
class ConnectionSnapshot:
    started: float
    finished: float
    owners: dict
    process_count: int
    warning: str = ""


def endpoint(value):
    address, separator, port = value.rpartition(":")
    if not separator or not port.isdigit():
        raise ValueError("连接端点缺少端口")
    address = address.strip("[]").split("%", 1)[0]
    parsed = ipaddress.ip_address(address)
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        parsed = parsed.ipv4_mapped
    number = int(port)
    if not 0 <= number <= 65535:
        raise ValueError("端口无效")
    return str(parsed), number


def connection_key(source, source_port, destination, destination_port):
    return tuple(sorted((endpoint(f"{source}:{source_port}"), endpoint(f"{destination}:{destination_port}"))))


def parse_start_times(output):
    result = {}
    for line in output.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) == 2 and fields[0].isdigit():
            result[int(fields[0])] = fields[1]
    return result


def parse_connections(output, start_times):
    owners = {}
    pid, name, connection, state = None, "", "", ""

    def finish():
        if pid not in start_times or not name or "->" not in connection or state == "LISTEN":
            return
        local, remote = connection.split("->", 1)
        try:
            key = tuple(sorted((endpoint(local), endpoint(remote))))
        except ValueError:
            return
        owners.setdefault(key, set()).add(ProcessIdentity(pid, start_times[pid], name))

    for line in output.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag in ("p", "f"):
            finish()
            connection, state = "", ""
        if tag == "p":
            pid, name = int(value) if value.isdigit() else None, ""
        elif tag == "c":
            name = value
        elif tag == "n":
            connection = value
        elif tag == "T" and value.startswith("ST="):
            state = value[3:]
    finish()
    return owners


def sample_connections():
    if sys.platform != "darwin":
        raise RuntimeError("进程 TCP 关联当前仅支持 macOS 的 lsof/ps")
    started = time.time()
    environment = dict(os.environ, LC_ALL="C")
    before = subprocess.run(["/bin/ps", "-axo", "pid=,lstart="], capture_output=True,
                            text=True, timeout=2, check=True, env=environment)
    listing = subprocess.run(["/usr/sbin/lsof", "-nP", "-iTCP", "-FpcfnT"], capture_output=True,
                             text=True, timeout=2, env=environment)
    if listing.returncode not in (0, 1) or (listing.returncode == 1 and listing.stderr.strip()):
        raise RuntimeError(listing.stderr.strip() or "lsof 查询失败")
    after = subprocess.run(["/bin/ps", "-axo", "pid=,lstart="], capture_output=True,
                           text=True, timeout=2, check=True, env=environment)
    initial, final = parse_start_times(before.stdout), parse_start_times(after.stdout)
    stable = {pid: value for pid, value in initial.items() if final.get(pid) == value}
    owners = parse_connections(listing.stdout, stable)
    return ConnectionSnapshot(started, time.time(), owners,
                              len({owner for values in owners.values() for owner in values}),
                              listing.stderr.strip()[:500])


class ProcessMonitor(threading.Thread):
    def __init__(self, interval=0.5):
        super().__init__(daemon=True)
        self.interval = interval
        self.stop_event = threading.Event()
        self.events = queue.Queue(maxsize=8)
        self.error = ""

    def run(self):
        while not self.stop_event.is_set():
            try:
                snapshot = sample_connections()
                self.error = ""
                try:
                    self.events.put_nowait(snapshot)
                except queue.Full:
                    self.events.get_nowait()
                    self.events.put_nowait(snapshot)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                self.error = str(error)
            self.stop_event.wait(self.interval)
