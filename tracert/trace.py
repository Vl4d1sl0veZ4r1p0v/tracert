# coding=utf-8
import re
import socket

from tracert.icmp import ICMPPackage
from tracert.traceresult import TraceResult

WHOIS_SERVER = "whois.iana.org"
WHOIS_EXPR = re.compile(r"([A-Za-z\-]+):\s+([^\#\n]+)")


class Trace:

    def __init__(self, destination):
        self.time_to_live = 1
        self.depth = float("inf")
        self.destination = socket.gethostbyname(destination)
        self.trace_results = []
        self.sender = None
        self.receiver = None

    @classmethod
    def get_server_data(cls, address):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as whois_sock:
            whois_sock.settimeout(1)
            whois_sock.connect((socket.gethostbyname(WHOIS_SERVER), 43))
            whois_sock.send(address.encode() + b'\r\n')
            try:
                data = cls.receive_data(whois_sock)
                return cls.parse_whois_response(data.decode()).get("whois", "")
            except (socket.timeout, ValueError):
                return ""

    def get_data(self, addr):
        whois_addr = self.get_server_data(addr)

        if not whois_addr:
            return {"route": addr}

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as whois_sock:
            whois_sock.settimeout(2)
            whois_sock.connect((whois_addr, 43))
            whois_sock.send(addr.encode(encoding='utf-8') + b'\r\n')
            data = self.receive_data(whois_sock)
            whois_data = self.parse_whois_response(data.decode("utf-8",
                                                               errors="ignore"))
        whois_data['route'] = addr
        return whois_data

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.sender.close()
        self.receiver.close()

    def __enter__(self):
        self.sender = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
            socket.IPPROTO_ICMP
        )
        self.receiver = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_ICMP)
        self.receiver.settimeout(3)
        return self

    def go(self):
        previous_result = None
        while self.time_to_live <= self.depth:
            self.sender.setsockopt(socket.SOL_IP, socket.IP_TTL,
                                   self.time_to_live)
            self.sender.sendto(ICMPPackage(8, 0).compress(), (self.destination, 80))
            try:
                data, addr = self.receiver.recvfrom(1024)
                whois_data = self.get_data(addr[0])
                icmp_response = ICMPPackage.from_bytes(data[20:])
                trace_result = TraceResult.get_from_data(whois_data)

                if previous_result != trace_result:
                    yield trace_result
                previous_result = trace_result
                if icmp_response.code == icmp_response.type == 0:
                    break

            except socket.timeout:
                continue
            finally:
                self.time_to_live += 1

    @staticmethod
    def parse_whois_response(data):
        result = re.findall(WHOIS_EXPR, data)
        return {key: value for key, value in result}

    @staticmethod
    def receive_data(sock: socket.socket):
        data = b""
        while True:
            temp_data = sock.recv(1024)
            if not temp_data:
                break
            data += temp_data
        return data


