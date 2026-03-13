"""
NIDS Manager
Orchestrates packet capture, detection, and alert logging.
"""

import json
import logging
import os
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

from core.packet_capture import PacketCapture
from rules.detection import RuleEngine


LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "nids.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("nids")


class NIDSManager:
    """
    Central controller for the NIDS.
    Starts packet capture, pipes packets through the rule engine,
    and exposes state to the web layer.
    """

    def __init__(self, interface: str = "eth0"):
        self.capture = PacketCapture(interface=interface)
        self.engine = RuleEngine()
        self._running = False
        self._thread: threading.Thread | None = None
        self._recent_packets: deque = deque(maxlen=200)
        self._lock = threading.Lock()
        self._start_time = None

        # Alert log file
        self._alert_log = LOG_DIR / "alerts.jsonl"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        self._running = True
        self._start_time = time.time()
        self.capture.start()
        self._thread = threading.Thread(target=self._process_loop, daemon=True)
        self._thread.start()
        mode = "SIMULATION" if self.capture.simulation_mode else "LIVE"
        logger.info(f"NIDS started in {mode} mode on interface '{self.capture.interface}'")

    def stop(self):
        self._running = False
        self.capture.stop()
        logger.info("NIDS stopped.")

    # ------------------------------------------------------------------
    # Data access (called by Flask routes)
    # ------------------------------------------------------------------

    def get_dashboard_data(self) -> dict:
        with self._lock:
            packets = list(self._recent_packets)

        alert_stats = self.engine.get_stats()
        capture_stats = self.capture.stats.copy()
        uptime = int(time.time() - self._start_time) if self._start_time else 0

        return {
            "uptime_seconds": uptime,
            "simulation_mode": self.capture.simulation_mode,
            "capture_stats": capture_stats,
            "alert_stats": alert_stats,
            "recent_packets": packets[-50:],
            "recent_alerts": self.engine.get_recent_alerts(50),
            "protocol_distribution": self._protocol_distribution(packets),
            "top_talkers": self._top_talkers(packets),
            "traffic_timeline": self._traffic_timeline(packets),
        }

    # ------------------------------------------------------------------
    # Internal processing loop
    # ------------------------------------------------------------------

    def _process_loop(self):
        seen = 0
        while self._running:
            packets = self.capture.get_packets(200)
            new_packets = packets[seen:]
            seen = len(packets)

            for pkt in new_packets:
                with self._lock:
                    self._recent_packets.append(pkt)

                alerts = self.engine.analyze(pkt)
                for alert in alerts:
                    logger.warning(f"[{alert.severity.value}] {alert.rule} | {alert.src_ip} -> {alert.dst_ip} | {alert.description}")
                    self._log_alert(alert)

            time.sleep(0.1)

    def _log_alert(self, alert):
        try:
            with open(self._alert_log, "a") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")
        except Exception as e:
            logger.error(f"Failed to write alert log: {e}")

    # ------------------------------------------------------------------
    # Analytics helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _protocol_distribution(packets: list) -> dict:
        counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        for p in packets:
            proto = p.get("protocol", "OTHER").upper()
            counts[proto if proto in counts else "OTHER"] += 1
        return counts

    @staticmethod
    def _top_talkers(packets: list, n: int = 5) -> list:
        from collections import Counter
        c = Counter(p.get("src_ip") for p in packets if p.get("src_ip"))
        return [{"ip": ip, "count": cnt} for ip, cnt in c.most_common(n)]

    @staticmethod
    def _traffic_timeline(packets: list) -> list:
        """Bucket packets into per-second counts for the last 30s."""
        from collections import Counter
        now = datetime.now()
        buckets: Counter = Counter()
        for p in packets:
            try:
                ts = datetime.fromisoformat(p["timestamp"])
                delta = int((now - ts).total_seconds())
                if 0 <= delta <= 30:
                    buckets[delta] += 1
            except Exception:
                pass
        return [{"seconds_ago": s, "count": buckets.get(s, 0)} for s in range(30, -1, -1)]
