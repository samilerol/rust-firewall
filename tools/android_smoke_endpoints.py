"""Loopback endpoints for the Android emulator's deterministic forwarding test."""
import socketserver
import threading

QUERY = bytes.fromhex("1234010000010000000000000463697479076578616d706c650000010001")
ANSWER = bytes.fromhex("123481800001000100000000") + QUERY[12:] + bytes.fromhex(
    "c00c00010001000000000004c000022a"
)


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        data = self.request.recv(1)
        if data:
            self.request.sendall(data)


class DnsUdp(socketserver.BaseRequestHandler):
    def handle(self):
        payload, sock = self.request
        if payload == QUERY:
            sock.sendto(ANSWER, self.client_address)


class DnsTcp(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        size = self.rfile.read(2)
        if int.from_bytes(size, "big") == len(QUERY) and self.rfile.read(len(QUERY)) == QUERY:
            self.wfile.write(len(ANSWER).to_bytes(2, "big") + ANSWER)


with socketserver.ThreadingTCPServer(("127.0.0.1", 80), Echo) as web, \
     socketserver.ThreadingTCPServer(("127.0.0.1", 8080), Echo) as blocked, \
     socketserver.ThreadingUDPServer(("127.0.0.1", 53), DnsUdp) as dns_udp, \
     socketserver.ThreadingTCPServer(("127.0.0.1", 53), DnsTcp) as dns_tcp:
    for server in (web, blocked, dns_udp):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print("NETSCOPE_ENDPOINTS_READY", flush=True)
    dns_tcp.serve_forever()
