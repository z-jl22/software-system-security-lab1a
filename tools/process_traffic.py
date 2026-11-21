"""Generate two sustained local TCP flows from this PID for the GUI demo."""
import os
import socket
import time


def main():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    clients, servers = [], []
    try:
        for _ in range(2):
            clients.append(socket.create_connection(listener.getsockname()))
            servers.append(listener.accept()[0])
        print(f"目标 PID：{os.getpid()}；本机端口：{listener.getsockname()[1]}；两条 TCP 连接持续 60 秒。", flush=True)
        print("请在嗅探器中选择 lo0 开始抓包，选择该 PID 后点击“追踪所选进程”。Ctrl+C 可提前结束。", flush=True)
        for index in range(60):
            for client, server in zip(clients, servers):
                client.sendall(f"GET /process/{index} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
                server.recv(4096)
                server.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                client.recv(4096)
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for connection in clients + servers:
            connection.close()
        listener.close()


if __name__ == "__main__":
    main()
