"""
╔══════════════════════════════════════════════════════════════════════╗
║          PERSONAL FIREWALL — Flask Web Dashboard                   ║
║  Real-time monitoring interface served on localhost:5000            ║
║  Version: 1.0.0                                                    ║
╚══════════════════════════════════════════════════════════════════════╝

Provides a premium web dashboard that displays:
  • Live firewall activity log in a styled table
  • Real-time counters for Scanned / Allowed / Blocked packets
  • Loaded rule set overview
  • Auto-refreshing via AJAX polling
"""

import os
import sys
import signal
import threading

from flask import Flask, render_template, jsonify

from firewall_engine import FirewallEngine, RULES_FILE, LOG_FILE, Colors


# ═══════════════════════════════════════════════════════════════════════
# Flask Application Setup
# ═══════════════════════════════════════════════════════════════════════

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
)

# Instantiate the firewall engine (shared across threads)
engine = FirewallEngine(
    rules_path=RULES_FILE,
    log_file=LOG_FILE,
)


# ═══════════════════════════════════════════════════════════════════════
# Routes — Dashboard Pages
# ═══════════════════════════════════════════════════════════════════════

@app.route("/")
def dashboard():
    """Serve the main dashboard HTML page."""
    return render_template("dashboard.html")


# ═══════════════════════════════════════════════════════════════════════
# Routes — API Endpoints (consumed by frontend AJAX)
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/metrics")
def api_metrics():
    """Return current packet metrics as JSON."""
    return jsonify(engine.get_metrics())


@app.route("/api/logs")
def api_logs():
    """Return recent log entries as a JSON array."""
    return jsonify(engine.get_recent_logs(count=200))


@app.route("/api/rules")
def api_rules():
    """Return the loaded firewall rules summary."""
    return jsonify(engine.get_rules_summary())


@app.route("/api/status")
def api_status():
    """Health check / status endpoint."""
    return jsonify(
        status="running" if engine._running else "stopped",
        metrics=engine.get_metrics(),
    )


# ═══════════════════════════════════════════════════════════════════════
# Application Entry Point
# ═══════════════════════════════════════════════════════════════════════

def print_dashboard_banner():
    """Display the startup banner for the web dashboard mode."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
  ╔══════════════════════════════════════════════════════════════╗
  ║                                                              ║
  ║        ██████  ██ ██████  ███████ ██     ██  █████  ██       ║
  ║        ██      ██ ██   ██ ██      ██     ██ ██   ██ ██       ║
  ║        █████   ██ ██████  █████   ██  █  ██ ███████ ██       ║
  ║        ██      ██ ██   ██ ██      ██ ███ ██ ██   ██ ██       ║
  ║        ██      ██ ██   ██ ███████  ███ ███  ██   ██ ███████  ║
  ║                                                              ║
  ║         Personal Firewall Engine  v1.0.0                     ║
  ║         Web Dashboard Mode                                   ║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝
{Colors.RESET}
  {Colors.GREEN}{Colors.BOLD}▶ Dashboard:{Colors.RESET}  http://127.0.0.1:5000
  {Colors.GREEN}{Colors.BOLD}▶ Sniffer:{Colors.RESET}    Running in background thread
  {Colors.DIM}  Press Ctrl+C to stop.{Colors.RESET}
"""
    print(banner)


def shutdown_handler(signum, frame):
    """Handle Ctrl+C for graceful shutdown."""
    print(f"\n{Colors.YELLOW}[INFO] Shutting down firewall engine …{Colors.RESET}")
    engine.stop()
    metrics = engine.get_metrics()
    print(f"""
{Colors.CYAN}{Colors.BOLD}
  ╔══════════════════════════════════════════════════════════════╗
  ║                   FIREWALL SESSION REPORT                    ║
  ╠══════════════════════════════════════════════════════════════╣
  ║   Total Packets Scanned:   {metrics['total']:>10,}                        ║
  ║   Packets ALLOWED:         {Colors.GREEN}{metrics['allowed']:>10,}{Colors.CYAN}                        ║
  ║   Packets BLOCKED:         {Colors.RED}{metrics['blocked']:>10,}{Colors.CYAN}                        ║
  ║   Uptime:                  {metrics['uptime']:>10}                        ║
  ╚══════════════════════════════════════════════════════════════╝
{Colors.RESET}""")
    os._exit(0)


if __name__ == "__main__":
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    print_dashboard_banner()

    # Start the Scapy sniffer in a background daemon thread
    engine.start_background()

    # Run Flask (use_reloader=False to avoid double-starting the sniffer)
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False,
        threaded=True,
    )
