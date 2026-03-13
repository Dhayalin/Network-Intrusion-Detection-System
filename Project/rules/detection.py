"""
Rule-Based Detection Engine
Identifies suspicious patterns: port scans, SYN floods, ICMP sweeps, UDP floods, and more.
"""

import time
from collections import defaultdict, deque
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Alert:
    id: str
    timestamp: str
    rule: str
    severity: Severity
    src_ip: str
    dst_ip: str
    description: str
    packet_count: int = 1
    details: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "rule": self.rule,
            "severity": self.severity.value,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "description": self.description,
            "packet_count": self.packet_count,
            "details": self.details,
        }


class RuleEngine:
    """
    Stateful rule engine. Tracks per-IP state over a sliding time window
    and fires alerts when thresholds are breached.
    """

    # --- Thresholds ---
    PORT_SCAN_THRESHOLD = 10        # unique ports from one src in window
    SYN_FLOOD_THRESHOLD = 50        # SYN packets to one dst in window
    ICMP_SWEEP_THRESHOLD = 8        # unique dst IPs via ICMP from one src
    UDP_FLOOD_THRESHOLD = 100       # UDP packets to one dst in window
    BRUTE_FORCE_THRESHOLD = 8       # connection attempts to SSH/RDP
    WINDOW_SECONDS = 10             # sliding window size

    # Ports considered sensitive
    SENSITIVE_PORTS = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                       1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 27017}

    def __init__(self):
        # State trackers: keyed by src_ip or (src_ip, dst_ip)
        self._syn_tracker:   defaultdict[tuple, deque] = defaultdict(deque)  # (src,dst) -> timestamps
        self._port_tracker:  defaultdict[str,  dict]   = defaultdict(lambda: {"ports": set(), "times": deque()})
        self._icmp_tracker:  defaultdict[str,  dict]   = defaultdict(lambda: {"ips": set(),   "times": deque()})
        self._udp_tracker:   defaultdict[tuple, deque] = defaultdict(deque)
        self._brute_tracker: defaultdict[tuple, deque] = defaultdict(deque)

        self.alerts: deque = deque(maxlen=500)
        self._alert_counter = 0
        self._suppression: dict[str, float] = {}   # rule+src -> last alert time

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def analyze(self, packet: dict) -> list[Alert]:
        """Run all rules against a single packet. Returns any new alerts."""
        fired: list[Alert] = []
        now = time.time()

        proto = packet.get("protocol", "")
        src = packet.get("src_ip", "")
        dst = packet.get("dst_ip", "")
        dst_port = packet.get("dst_port")
        flags = packet.get("flags", {})

        if proto == "TCP":
            fired += self._rule_port_scan(src, dst, dst_port, now)
            if flags.get("SYN") and not flags.get("ACK"):
                fired += self._rule_syn_flood(src, dst, now)
            if dst_port in (22, 3389):
                fired += self._rule_brute_force(src, dst, dst_port, now)

        elif proto == "ICMP":
            fired += self._rule_icmp_sweep(src, dst, now)

        elif proto == "UDP":
            fired += self._rule_udp_flood(src, dst, now)

        for alert in fired:
            self.alerts.append(alert)

        return fired

    def get_recent_alerts(self, n: int = 100) -> list[dict]:
        return [a.to_dict() for a in list(self.alerts)[-n:]]

    def get_stats(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for a in self.alerts:
            counts[a.severity.value] += 1
        return {"total": len(self.alerts), "by_severity": counts}

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def _rule_port_scan(self, src, dst, dst_port, now) -> list[Alert]:
        if dst_port is None:
            return []
        state = self._port_tracker[src]
        self._trim(state["times"], now)
        state["times"].append(now)
        state["ports"].add(dst_port)

        # Prune ports older than window (approximate — reset on trigger)
        if len(state["ports"]) >= self.PORT_SCAN_THRESHOLD:
            if self._should_fire(f"PORT_SCAN:{src}", now, cooldown=15):
                alert = self._make_alert(
                    rule="PORT_SCAN", severity=Severity.HIGH,
                    src=src, dst=dst,
                    desc=f"Port scan detected: {len(state['ports'])} unique ports probed",
                    count=len(state["times"]),
                    details={"ports_probed": sorted(state["ports"])[:20]},
                )
                state["ports"].clear()
                return [alert]
        return []

    def _rule_syn_flood(self, src, dst, now) -> list[Alert]:
        key = (src, dst)
        q = self._syn_tracker[key]
        self._trim(q, now)
        q.append(now)
        if len(q) >= self.SYN_FLOOD_THRESHOLD:
            if self._should_fire(f"SYN_FLOOD:{src}:{dst}", now, cooldown=10):
                return [self._make_alert(
                    rule="SYN_FLOOD", severity=Severity.CRITICAL,
                    src=src, dst=dst,
                    desc=f"SYN flood: {len(q)} SYN packets in {self.WINDOW_SECONDS}s",
                    count=len(q),
                    details={"rate_per_sec": round(len(q) / self.WINDOW_SECONDS, 1)},
                )]
        return []

    def _rule_icmp_sweep(self, src, dst, now) -> list[Alert]:
        state = self._icmp_tracker[src]
        self._trim(state["times"], now)
        state["times"].append(now)
        state["ips"].add(dst)
        if len(state["ips"]) >= self.ICMP_SWEEP_THRESHOLD:
            if self._should_fire(f"ICMP_SWEEP:{src}", now, cooldown=15):
                alert = self._make_alert(
                    rule="ICMP_SWEEP", severity=Severity.MEDIUM,
                    src=src, dst=dst,
                    desc=f"ICMP host sweep: {len(state['ips'])} hosts pinged",
                    count=len(state["times"]),
                    details={"hosts_probed": sorted(state["ips"])[:20]},
                )
                state["ips"].clear()
                return [alert]
        return []

    def _rule_udp_flood(self, src, dst, now) -> list[Alert]:
        key = (src, dst)
        q = self._udp_tracker[key]
        self._trim(q, now)
        q.append(now)
        if len(q) >= self.UDP_FLOOD_THRESHOLD:
            if self._should_fire(f"UDP_FLOOD:{src}:{dst}", now, cooldown=10):
                return [self._make_alert(
                    rule="UDP_FLOOD", severity=Severity.HIGH,
                    src=src, dst=dst,
                    desc=f"UDP flood: {len(q)} packets in {self.WINDOW_SECONDS}s",
                    count=len(q),
                    details={"rate_per_sec": round(len(q) / self.WINDOW_SECONDS, 1)},
                )]
        return []

    def _rule_brute_force(self, src, dst, port, now) -> list[Alert]:
        key = (src, dst, port)
        q = self._brute_tracker[key]
        self._trim(q, now)
        q.append(now)
        if len(q) >= self.BRUTE_FORCE_THRESHOLD:
            service = "SSH" if port == 22 else "RDP"
            if self._should_fire(f"BRUTE:{src}:{dst}:{port}", now, cooldown=20):
                return [self._make_alert(
                    rule="BRUTE_FORCE", severity=Severity.HIGH,
                    src=src, dst=dst,
                    desc=f"{service} brute-force attempt: {len(q)} connections in {self.WINDOW_SECONDS}s",
                    count=len(q),
                    details={"service": service, "port": port},
                )]
        return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _trim(self, q: deque, now: float):
        """Remove entries older than WINDOW_SECONDS."""
        cutoff = now - self.WINDOW_SECONDS
        while q and q[0] < cutoff:
            q.popleft()

    def _should_fire(self, key: str, now: float, cooldown: float) -> bool:
        last = self._suppression.get(key, 0)
        if now - last >= cooldown:
            self._suppression[key] = now
            return True
        return False

    def _make_alert(self, *, rule, severity, src, dst, desc, count=1, details=None) -> Alert:
        self._alert_counter += 1
        return Alert(
            id=f"ALT-{self._alert_counter:05d}",
            timestamp=datetime.now().isoformat(),
            rule=rule,
            severity=severity,
            src_ip=src,
            dst_ip=dst,
            description=desc,
            packet_count=count,
            details=details or {},
        )
