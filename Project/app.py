"""
Flask Web Application
Serves the dashboard and exposes REST API endpoints for the frontend.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, jsonify, render_template
from nids_manager import NIDSManager

app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
nids = NIDSManager(interface="eth0")


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/dashboard")
def api_dashboard():
    return jsonify(nids.get_dashboard_data())


@app.route("/api/alerts")
def api_alerts():
    return jsonify(nids.engine.get_recent_alerts(100))


@app.route("/api/packets")
def api_packets():
    return jsonify(nids.capture.get_packets(100))


@app.route("/api/stats")
def api_stats():
    return jsonify({
        "capture": nids.capture.stats,
        "alerts": nids.engine.get_stats(),
        "simulation_mode": nids.capture.simulation_mode,
    })


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

if __name__ == "__main__":
    nids.start()
    print("\n" + "="*55)
    print("  NIDS Dashboard → http://127.0.0.1:5000")
    if nids.capture.simulation_mode:
        print("  ⚠  Running in SIMULATION mode (no root access)")
    print("="*55 + "\n")
    try:
        app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
    finally:
        nids.stop()