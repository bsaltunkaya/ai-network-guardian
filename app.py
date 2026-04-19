"""
AI Network Guardian - Flask Application
API Gateway & Controller serving the unified web interface
and routing requests to the three analysis modules.
"""

from dotenv import load_dotenv
load_dotenv()

import logging
logging.basicConfig(level=logging.DEBUG, format="%(name)s | %(levelname)s | %(message)s")

from flask import Flask, render_template, jsonify, request
from network.detective import scan_network, test_tcp_connection
from network.security import analyze_url
from network.performance import run_diagnostics
from ai.reasoning import ai_engine
from database import save_scan, get_history, get_trend

app = Flask(__name__)


# ──────────────────────────────────────────────────────────────
#  Web Interface
# ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ──────────────────────────────────────────────────────────────
#  Network Detective API
# ──────────────────────────────────────────────────────────────

@app.route("/api/detective/scan", methods=["POST"])
def detective_scan():
    """Run a network scan and return AI-analyzed results."""
    try:
        scan_data = scan_network()
        if isinstance(scan_data, dict) and "error" in scan_data and "devices" not in scan_data:
            return jsonify({"error": scan_data["error"]}), 500

        diagnoses = ai_engine.analyze_network_scan(scan_data)
        save_scan("detective", scan_data, diagnoses)

        return jsonify({
            "scan": scan_data,
            "diagnoses": diagnoses,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ──────────────────────────────────────────────────────────────
#  Connection Test API
# ──────────────────────────────────────────────────────────────

@app.route("/api/detective/connect", methods=["POST"])
def detective_connect():
    """Test TCP connectivity to a specific IP:port and return layer analysis."""
    data = request.get_json() or {}
    ip   = data.get("ip", "").strip()
    port = data.get("port")
    timeout = min(int(data.get("timeout", 5)), 15)

    if not ip:
        return jsonify({"error": "IP address is required"}), 400
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"error": "Port must be an integer between 1 and 65535"}), 400

    try:
        conn_data = test_tcp_connection(ip, port, timeout=timeout)
        diagnoses = ai_engine.analyze_connection_test(conn_data)
        save_scan("connection", conn_data, diagnoses)
        return jsonify({"connection": conn_data, "diagnoses": diagnoses})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ──────────────────────────────────────────────────────────────
#  Security Hunter API
# ──────────────────────────────────────────────────────────────

@app.route("/api/security/analyze", methods=["POST"])
def security_analyze():
    """Analyze a URL for security risks."""
    data = request.get_json()
    url = data.get("url", "").strip() if data else ""

    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        security_data = analyze_url(url)
        if "error" in security_data:
            return jsonify(security_data), 400

        diagnoses = ai_engine.analyze_url_security(security_data)
        save_scan("security", security_data, diagnoses)

        return jsonify({
            "analysis": security_data,
            "diagnoses": diagnoses,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ──────────────────────────────────────────────────────────────
#  Performance & Lag Monitor API
# ──────────────────────────────────────────────────────────────

@app.route("/api/performance/diagnose", methods=["POST"])
def performance_diagnose():
    """Run performance diagnostics."""
    data = request.get_json() or {}
    host = data.get("host", "8.8.8.8").strip()
    ping_count = min(int(data.get("ping_count", 10)), 20)  # cap at 20

    try:
        perf_data = run_diagnostics(host=host, ping_count=ping_count)
        diagnoses = ai_engine.analyze_performance(perf_data)
        save_scan("performance", perf_data, diagnoses)

        return jsonify({
            "performance": perf_data,
            "diagnoses": diagnoses,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ──────────────────────────────────────────────────────────────
#  History API
# ──────────────────────────────────────────────────────────────

@app.route("/api/history/<module>")
def history(module):
    """Get scan history for a module."""
    if module not in ("detective", "security", "performance", "connection"):
        return jsonify({"error": "Invalid module"}), 400

    limit = min(int(request.args.get("limit", 20)), 50)
    data = get_history(module, limit=limit)
    return jsonify({"history": data})


@app.route("/api/trend/<module>")
def trend(module):
    """Get trend data for a module over the last N hours."""
    if module not in ("detective", "security", "performance", "connection"):
        return jsonify({"error": "Invalid module"}), 400

    hours = min(int(request.args.get("hours", 24)), 168)  # max 1 week
    data = get_trend(module, hours=hours)
    return jsonify({"trend": data})


# ──────────────────────────────────────────────────────────────
#  Status API
# ──────────────────────────────────────────────────────────────

@app.route("/api/status")
def status():
    """Return system status including AI mode."""
    return jsonify({"ai_mode": ai_engine.get_mode()})


# ──────────────────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5001)
