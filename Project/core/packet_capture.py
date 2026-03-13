"""
Packet Capture Engine
Captures and parses live network packets using raw sockets.
Falls back to simulated traffic when run without root privileges.
"""

import socket
import struct
import time
import threading
import random
import ipaddress
from datetime import datetime
from collections import deque


class PacketParser:
    """Parses raw bytes into structured packet data."""

    @staticmethod
    def parse_ethernet(raw: bytes) -> dict | None:
        if len(raw) < 14:
            return None
        dest_mac = PacketParser._format_mac(raw[0:6])
        src_mac = PacketParser._format_mac(raw[6:12])
        eth_proto = struct.unpack("!H", raw[12:14])[0]
        return {"dest_mac": dest_mac, "src_mac": src_mac, "proto": eth_proto, "payload": raw[14:]}

    @staticmethod
    def parse_ip(data: bytes) -> dict | None:
        if len(data) < 20:
            return None
        version_ihl = data[0]
        ihl = (version_ihl & 0xF) * 4
        ttl = data[8]
        proto = data[9]
        src = socket.inet_ntoa(data[12:16])
        dst = socket.inet_ntoa(data[16:20])
        return {"src": src, "dst": dst, "proto": proto, "ttl": ttl, "payload": data[ihl:]}

    @staticmethod
    def parse_tcp(data: bytes) -> dict | None:
        if len(data) < 20:
            return None
        src_port, dst_port, seq, ack = struct.unpack("!HHLL", data[0:12])
        offset_flags = struct.unpack("!H", data[12:14])[0]
        flags = offset_flags & 0x1FF
        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "seq": seq,
            "ack": ack,
            "flags": {
                "FIN": bool(flags & 0x001),
                "SYN": bool(flags & 0x002),
                "RST": bool(flags & 0x004),
                "PSH": bool(flags & 0x008),
                "ACK": bool(flags & 0x010),
                "URG": bool(flags & 0x020),
            },
        }

    @staticmethod
    def parse_udp(data: bytes) -> dict | None:
        if len(data) < 8:
            return None
        src_port, dst_port, length = struct.unpack("!HHH", data[0:6])
        return {"src_port": src_port, "dst_port": dst_port, "length": length}

    @staticmethod
    def parse_icmp(data: bytes) -> dict | None:
        if len(data) < 4:
            return None
        icmp_type, code = data[0], data[1]
        return {"type": icmp_type, "code": code}

    @staticmethod
    def _format_mac(raw: bytes) -> str:
        return ":".join(f"{b:02x}" for b in raw)


class PacketCapture:
    """
    Captures packets from a network interface.
    Requires root/admin on Linux. Falls back to simulation mode otherwise.
    """

    PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

    def __init__(self, interface: str = "eth0", max_queue: int = 1000):
        self.interface = interface
        self.running = False
        self.packet_queue: deque = deque(maxlen=max_queue)
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.simulation_mode = False
        self.stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0}

    def start(self):
        self.running = True
        # AF_PACKET is Linux-only; fall back to simulation on Windows/macOS
        if not hasattr(socket, "AF_PACKET"):
            self.simulation_mode = True
            self._thread = threading.Thread(target=self._simulate_traffic, daemon=True)
            self._thread.start()
            return
        try:
            self._thread = threading.Thread(target=self._capture_live, daemon=True)
            self._thread.start()
        except PermissionError:
            self.simulation_mode = True
            self._thread = threading.Thread(target=self._simulate_traffic, daemon=True)
            self._thread.start()

    def stop(self):
        self.running = False

    def get_packets(self, n: int = 50) -> list:
        with self._lock:
            return list(self.packet_queue)[-n:]

    def _capture_live(self):
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.settimeout(1.0)
            while self.running:
                try:
                    raw, _ = sock.recvfrom(65535)
                    pkt = self._process_raw(raw)
                    if pkt:
                        self._enqueue(pkt)
                except socket.timeout:
                    continue
        except PermissionError:
            self.simulation_mode = True
            self._simulate_traffic()

    def _process_raw(self, raw: bytes) -> dict | None:
        eth = PacketParser.parse_ethernet(raw)
        if not eth or eth["proto"] != 0x0800:
            return None
        ip = PacketParser.parse_ip(eth["payload"])
        if not ip:
            return None
        return self._build_packet(ip)

    def _build_packet(self, ip: dict) -> dict:
        proto_num = ip["proto"]
        proto_name = self.PROTO_MAP.get(proto_num, "OTHER")
        pkt = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip["src"],
            "dst_ip": ip["dst"],
            "protocol": proto_name,
            "ttl": ip["ttl"],
            "flags": {},
            "src_port": None,
            "dst_port": None,
            "length": len(ip["payload"]),
        }
        if proto_num == 6:
            tcp = PacketParser.parse_tcp(ip["payload"])
            if tcp:
                pkt["src_port"] = tcp["src_port"]
                pkt["dst_port"] = tcp["dst_port"]
                pkt["flags"] = tcp["flags"]
        elif proto_num == 17:
            udp = PacketParser.parse_udp(ip["payload"])
            if udp:
                pkt["src_port"] = udp["src_port"]
                pkt["dst_port"] = udp["dst_port"]
        elif proto_num == 1:
            icmp = PacketParser.parse_icmp(ip["payload"])
            if icmp:
                pkt["icmp_type"] = icmp["type"]
        return pkt

    def _simulate_traffic(self):
        """Generate realistic simulated traffic for demo/testing purposes."""
        NORMAL_PORTS = [80, 443, 53, 22, 8080, 3306, 5432, 6379]
        SCAN_PORTS = list(range(20, 25)) + list(range(79, 82)) + [443, 8080, 3389]
        INTERNAL = ["192.168.1." + str(i) for i in range(1, 20)]
        EXTERNAL = ["203.0.113." + str(i) for i in range(1, 30)]

        scenarios = [
            ("normal_http",  0.40),
            ("normal_dns",   0.20),
            ("normal_ssh",   0.10),
            ("port_scan",    0.10),
            ("syn_flood",    0.08),
            ("icmp_sweep",   0.07),
            ("udp_flood",    0.05),
        ]

        while self.running:
            roll = random.random()
            cumulative = 0
            scenario = "normal_http"
            for name, prob in scenarios:
                cumulative += prob
                if roll < cumulative:
                    scenario = name
                    break

            pkts = self._gen_scenario(scenario, INTERNAL, EXTERNAL, NORMAL_PORTS, SCAN_PORTS)
            for p in pkts:
                self._enqueue(p)
                time.sleep(random.uniform(0.02, 0.15))

    def _gen_scenario(self, scenario, internal, external, normal_ports, scan_ports):
        src = random.choice(external if "flood" in scenario or "scan" in scenario else internal)
        dst = random.choice(internal)
        now = datetime.now().isoformat()

        if scenario == "normal_http":
            return [{"timestamp": now, "src_ip": src, "dst_ip": dst,
                     "protocol": "TCP", "src_port": random.randint(49152, 65535),
                     "dst_port": random.choice([80, 443]), "ttl": 64,
                     "flags": {"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": True, "URG": False},
                     "length": random.randint(200, 1400)}]

        elif scenario == "normal_dns":
            return [{"timestamp": now, "src_ip": src, "dst_ip": dst,
                     "protocol": "UDP", "src_port": random.randint(49152, 65535),
                     "dst_port": 53, "ttl": 64, "flags": {}, "length": random.randint(60, 120)}]

        elif scenario == "normal_ssh":
            return [{"timestamp": now, "src_ip": src, "dst_ip": dst,
                     "protocol": "TCP", "src_port": random.randint(49152, 65535),
                     "dst_port": 22, "ttl": 64,
                     "flags": {"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": True, "URG": False},
                     "length": random.randint(100, 500)}]

        elif scenario == "port_scan":
            ports = random.sample(scan_ports, min(6, len(scan_ports)))
            return [{"timestamp": datetime.now().isoformat(), "src_ip": src, "dst_ip": dst,
                     "protocol": "TCP", "src_port": random.randint(49152, 65535),
                     "dst_port": p, "ttl": 64,
                     "flags": {"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False},
                     "length": 40} for p in ports]

        elif scenario == "syn_flood":
            return [{"timestamp": datetime.now().isoformat(),
                     "src_ip": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                     "dst_ip": dst, "protocol": "TCP",
                     "src_port": random.randint(1024, 65535), "dst_port": random.choice([80, 443]),
                     "ttl": random.randint(50, 128),
                     "flags": {"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False},
                     "length": 40} for _ in range(8)]

        elif scenario == "icmp_sweep":
            ips = [f"192.168.1.{i}" for i in random.sample(range(1, 50), 5)]
            return [{"timestamp": datetime.now().isoformat(), "src_ip": src, "dst_ip": ip,
                     "protocol": "ICMP", "src_port": None, "dst_port": None,
                     "ttl": 64, "flags": {}, "icmp_type": 8, "length": 64} for ip in ips]

        elif scenario == "udp_flood":
            return [{"timestamp": datetime.now().isoformat(), "src_ip": src, "dst_ip": dst,
                     "protocol": "UDP", "src_port": random.randint(1024, 65535),
                     "dst_port": random.randint(1, 65535), "ttl": 64, "flags": {},
                     "length": random.randint(500, 1400)} for _ in range(5)]

        return []

    def _enqueue(self, pkt: dict):
        proto = pkt.get("protocol", "OTHER").upper()
        with self._lock:
            self.packet_queue.append(pkt)
            self.stats["total"] += 1
            self.stats[proto.lower() if proto in ("TCP", "UDP", "ICMP") else "other"] += 1