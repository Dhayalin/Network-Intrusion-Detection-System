/* NIDS Dashboard — Live frontend logic */

const POLL_INTERVAL = 2000; // ms
let paused = false;
let timelineChart, protoChart;
let seenAlertIds = new Set();

// ── Chart.js defaults ──────────────────────────────────────────────
Chart.defaults.color = "#4a6070";
Chart.defaults.borderColor = "#1e2d3d";
Chart.defaults.font.family = "'Share Tech Mono', monospace";

// ── Init ───────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  document.getElementById("pauseToggle").addEventListener("change", (e) => {
    paused = e.target.checked;
  });
  fetchAndUpdate();
  setInterval(fetchAndUpdate, POLL_INTERVAL);
});

// ── Fetch ──────────────────────────────────────────────────────────
async function fetchAndUpdate() {
  try {
    const res = await fetch("/api/dashboard");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    updateAll(data);
  } catch (err) {
    console.warn("Poll error:", err);
  }
}

// ── Master update ──────────────────────────────────────────────────
function updateAll(data) {
  updateHeader(data);
  updateSeverityCards(data.alert_stats?.by_severity ?? {});
  updateAlertFeed(data.recent_alerts ?? []);
  if (!paused) {
    updatePacketTable(data.recent_packets ?? []);
  }
  updateTimelineChart(data.traffic_timeline ?? []);
  updateProtoChart(data.protocol_distribution ?? {});
  updateTopTalkers(data.top_talkers ?? []);
}

// ── Header ─────────────────────────────────────────────────────────
function updateHeader(data) {
  document.getElementById("uptime").textContent = formatUptime(data.uptime_seconds ?? 0);
  document.getElementById("totalPackets").textContent = fmtNum(data.capture_stats?.total ?? 0);
  document.getElementById("totalAlerts").textContent = fmtNum(data.alert_stats?.total ?? 0);

  const badge = document.getElementById("statusBadge");
  const text  = document.getElementById("statusText");
  if (data.simulation_mode) {
    badge.className = "status-badge sim";
    text.textContent = "SIMULATION MODE";
  } else {
    badge.className = "status-badge live";
    text.textContent = "LIVE CAPTURE";
  }
}

// ── Severity cards ─────────────────────────────────────────────────
function updateSeverityCards(sev) {
  document.getElementById("sevCritical").textContent = sev.CRITICAL ?? 0;
  document.getElementById("sevHigh").textContent     = sev.HIGH ?? 0;
  document.getElementById("sevMedium").textContent   = sev.MEDIUM ?? 0;
  document.getElementById("sevLow").textContent      = sev.LOW ?? 0;
}

// ── Alert feed ─────────────────────────────────────────────────────
function updateAlertFeed(alerts) {
  const feed  = document.getElementById("alertFeed");
  const badge = document.getElementById("alertBadge");
  badge.textContent = alerts.length;

  const newAlerts = alerts.filter(a => !seenAlertIds.has(a.id)).reverse();
  if (newAlerts.length === 0) return;

  // Remove placeholder
  const empty = feed.querySelector(".empty-state");
  if (empty) empty.remove();

  newAlerts.forEach(a => {
    seenAlertIds.add(a.id);
    const el = document.createElement("div");
    el.className = `alert-item ${a.severity}`;
    const time = formatTime(a.timestamp);
    const flags = Object.entries(a.details ?? {})
      .map(([k, v]) => Array.isArray(v) ? `${k}: [${v.slice(0,5).join(", ")}]` : `${k}: ${v}`)
      .join(" · ");
    el.innerHTML = `
      <div class="alert-rule">[${a.severity}] ${a.rule}</div>
      <div class="alert-desc">${escHtml(a.description)}</div>
      <div class="alert-meta">${time} · ${escHtml(a.src_ip)} → ${escHtml(a.dst_ip)}${flags ? " · " + escHtml(flags) : ""}</div>
    `;
    feed.insertBefore(el, feed.firstChild);
  });

  // Keep feed from growing too large
  while (feed.children.length > 60) feed.removeChild(feed.lastChild);
}

// ── Packet table ───────────────────────────────────────────────────
function updatePacketTable(packets) {
  const tbody = document.getElementById("packetTableBody");
  const rows = [...packets].reverse().slice(0, 80).map(p => {
    const proto = (p.protocol ?? "?").toUpperCase();
    const flagStr = p.flags ? formatFlags(p.flags) : "—";
    return `
      <tr>
        <td>${formatTime(p.timestamp)}</td>
        <td class="proto-${proto.toLowerCase()}">${proto}</td>
        <td>${escHtml(p.src_ip ?? "?")}</td>
        <td>${p.src_port ?? "—"}</td>
        <td>${escHtml(p.dst_ip ?? "?")}</td>
        <td>${p.dst_port ?? "—"}</td>
        <td>${flagStr}</td>
        <td>${p.length ?? "?"}</td>
      </tr>`;
  }).join("");
  tbody.innerHTML = rows || `<tr><td colspan="8" style="text-align:center;color:#4a6070;padding:14px">No packets yet…</td></tr>`;
}

function formatFlags(flags) {
  const abbr = {SYN:"S", ACK:"A", FIN:"F", RST:"R", PSH:"P", URG:"U"};
  return Object.entries(abbr).map(([k, v]) =>
    `<span class="${flags[k] ? "flag-on" : "flag-off"}">${v}</span>`
  ).join("");
}

// ── Charts ─────────────────────────────────────────────────────────
function initCharts() {
  const tlCtx = document.getElementById("timelineChart").getContext("2d");
  timelineChart = new Chart(tlCtx, {
    type: "line",
    data: {
      labels: [],
      datasets: [{
        label: "Packets/s",
        data: [],
        borderColor: "#00d4ff",
        backgroundColor: "rgba(0,212,255,.08)",
        tension: 0.4,
        fill: true,
        pointRadius: 0,
        borderWidth: 1.5,
      }]
    },
    options: {
      animation: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { display: false },
        y: { min: 0, ticks: { stepSize: 5 }, grid: { color: "#1e2d3d" } }
      }
    }
  });

  const pcCtx = document.getElementById("protoChart").getContext("2d");
  protoChart = new Chart(pcCtx, {
    type: "doughnut",
    data: {
      labels: ["TCP", "UDP", "ICMP", "OTHER"],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: ["#00d4ff", "#bb86fc", "#ffd740", "#4a6070"],
        borderColor: "#0d1117",
        borderWidth: 2,
      }]
    },
    options: {
      animation: false,
      plugins: {
        legend: {
          position: "right",
          labels: { boxWidth: 10, padding: 10, font: { size: 11 } }
        }
      },
      cutout: "68%",
    }
  });
}

function updateTimelineChart(timeline) {
  if (!timelineChart) return;
  timelineChart.data.labels = timeline.map(t => `-${t.seconds_ago}s`);
  timelineChart.data.datasets[0].data = timeline.map(t => t.count);
  timelineChart.update("none");
}

function updateProtoChart(dist) {
  if (!protoChart) return;
  protoChart.data.datasets[0].data = [
    dist.TCP ?? 0, dist.UDP ?? 0, dist.ICMP ?? 0, dist.OTHER ?? 0
  ];
  protoChart.update("none");
}

// ── Top talkers ────────────────────────────────────────────────────
function updateTopTalkers(talkers) {
  const tbody = document.querySelector("#talkerTable tbody");
  tbody.innerHTML = talkers.map(t => `
    <tr>
      <td>${escHtml(t.ip)}</td>
      <td>${fmtNum(t.count)}</td>
    </tr>`).join("") || `<tr><td colspan="2" style="color:#4a6070;text-align:center;padding:10px">No data</td></tr>`;
}

// ── Helpers ────────────────────────────────────────────────────────
function formatTime(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return d.toTimeString().slice(0, 8);
  } catch { return "—"; }
}

function formatUptime(secs) {
  const h = Math.floor(secs / 3600).toString().padStart(2, "0");
  const m = Math.floor((secs % 3600) / 60).toString().padStart(2, "0");
  const s = (secs % 60).toString().padStart(2, "0");
  return `${h}:${m}:${s}`;
}

function fmtNum(n) {
  return n >= 1000 ? (n / 1000).toFixed(1) + "k" : String(n);
}

function escHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
