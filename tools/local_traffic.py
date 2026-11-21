import argparse
import http.client
import http.server
import socket
import subprocess
import threading
import time


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"Hello Sniffer: local HTTP experiment\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description="仅绑定本地回环地址的实验流量生成器")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    print(f"本地服务 http://127.0.0.1:{args.port}/lab；仅生成本机 HTTP/ICMP 流量", flush=True)
    try:
        for count in range(5):
            connection = http.client.HTTPConnection("127.0.0.1", args.port)
            connection.request("GET", f"/lab?round={count + 1}")
            response = connection.getresponse()
            print(response.status, response.read().decode().strip(), flush=True)
            connection.close()
            time.sleep(0.4)
        subprocess.run(["/sbin/ping", "-c", "2", "127.0.0.1"], check=False)
        subprocess.run(["/sbin/ping6", "-c", "2", "::1"], check=False)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
