"""
╔══════════════════════════════════════════════════════════════════════╗
║              PERSONAL FIREWALL ENGINE — Core Module                 ║
║  User-space Packet Filtering Firewall using Scapy                  ║
║  Author: Security Engineering Team                                 ║
║  Version: 1.0.0                                                    ║
╚══════════════════════════════════════════════════════════════════════╝

This module provides the core firewall engine that:
  1. Sniffs live IPv4 traffic via Scapy on the host network interface.
  2. Parses IP, TCP, UDP, and ICMP headers to extract metadata.
  3. Evaluates each packet against a JSON-defined rule set.
  4. Logs every decision (ALLOW / BLOCK) to both console and file.
  5. Tracks cumulative metrics for a shutdown summary report.
"""

import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from collections import OrderedDict

# ---------------------------------------------------------------------------
# Scapy import with environment setup
# ---------------------------------------------------------------------------
# Suppress Scapy's default startup banner for clean terminal output
os.environ["SCAPY_USE_LIBPCAP"] = "0"

from scapy.all import sniff, IP, TCP, UDP, ICMP, conf  # noqa: E402

# Suppress noisy Scapy runtime warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# ═══════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════

PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

LOG_FILE = "firewall_activity.log"
RULES_FILE = "firewall_rules.json"

# ANSI color codes for rich terminal output
class Colors:
    HEADER  = "\033[95m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


# ═══════════════════════════════════════════════════════════════════════
# Firewall Rules Loader
# ═══════════════════════════════════════════════════════════════════════

class FirewallRules:
    """
    Loads, validates, and provides fast lookups against the rule set
    defined in firewall_rules.json.
    """

    def __init__(self, rules_path: str = RULES_FILE):
        self.rules_path = rules_path
        self.blocked_source_ips: set = set()
        self.blocked_destination_ports: set = set()
        self.blocked_protocols: set = set()
        self.named_rules: list = []
        self.default_policy: str = "ALLOW"

        self._load_rules()

    def _load_rules(self) -> None:
        """Parse the JSON rule file and populate lookup structures."""
        try:
            with open(self.rules_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            root = data.get("firewall_rules", data)

            self.default_policy = root.get("default_policy", "ALLOW").upper()

            # Build fast-lookup sets from the flat lists
            self.blocked_source_ips = set(root.get("blocked_source_ips", []))
            self.blocked_destination_ports = set(
                int(p) for p in root.get("blocked_destination_ports", [])
            )
            self.blocked_protocols = set(
                p.upper() for p in root.get("blocked_protocols", [])
            )

            # Also ingest the detailed named rules (for dashboard display)
            for rule in root.get("rules", []):
                if rule.get("enabled", True):
                    self.named_rules.append(rule)

        except FileNotFoundError:
            print(
                f"{Colors.RED}[ERROR] Rule file '{self.rules_path}' not found. "
                f"Using empty rule set.{Colors.RESET}"
            )
        except json.JSONDecodeError as exc:
            print(
                f"{Colors.RED}[ERROR] Malformed JSON in '{self.rules_path}': "
                f"{exc}{Colors.RESET}"
            )

    def reload(self) -> None:
        """Hot-reload rules from disk (thread-safe replacement)."""
        self.blocked_source_ips = set()
        self.blocked_destination_ports = set()
        self.blocked_protocols = set()
        self.named_rules = []
        self._load_rules()

    def evaluate(self, src_ip: str, dst_port: int | None, proto_name: str) -> tuple:
        """
        Evaluate a packet against all rules.

        Returns:
            (action: str, matched_rule: str | None)
            action is "BLOCK" or "ALLOW".
            matched_rule is a human-readable description if blocked, else None.
        """
        # Rule 1: Check blocked source IPs
        if src_ip in self.blocked_source_ips:
            return ("BLOCK", f"Source IP {src_ip} is blacklisted")

        # Rule 2: Check blocked destination ports
        if dst_port is not None and dst_port in self.blocked_destination_ports:
            return ("BLOCK", f"Destination port {dst_port} is blocked")

        # Rule 3: Check blocked protocols
        if proto_name.upper() in self.blocked_protocols:
            return ("BLOCK", f"Protocol {proto_name} is blocked")

        return (self.default_policy, None)


# ═══════════════════════════════════════════════════════════════════════
# Firewall Logger
# ═══════════════════════════════════════════════════════════════════════

class FirewallLogger:
    """
    Dual-output logger: writes professionally formatted entries to both
    the console (with ANSI colors) and a persistent log file.
    """

    def __init__(self, log_file: str = LOG_FILE):
        self.log_file = log_file
        self._lock = threading.Lock()

        # Set up Python's logging for the file handler
        self._file_logger = logging.getLogger("firewall_file")
        self._file_logger.setLevel(logging.INFO)
        self._file_logger.propagate = False

        # Remove any existing handlers to prevent duplicates on reload
        self._file_logger.handlers.clear()

        handler = logging.FileHandler(self.log_file, mode="a", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._file_logger.addHandler(handler)

        # Write a session header
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        separator = "=" * 90
        self._file_logger.info(separator)
        self._file_logger.info(f"  FIREWALL SESSION STARTED — {now}")
        self._file_logger.info(separator)

    def log(self, action: str, proto: str, src: str, dst: str,
            rule_reason: str | None = None) -> dict:
        """
        Log a single packet decision.

        Returns the log entry as a dictionary (for the web dashboard).
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        # Construct the canonical log line
        log_line = (
            f"[{timestamp}] [ACTION: {action}] "
            f"PROTO: {proto} | SRC: {src} -> DST: {dst}"
        )
        if rule_reason:
            log_line += f" | REASON: {rule_reason}"

        entry = OrderedDict(
            timestamp=timestamp,
            action=action,
            protocol=proto,
            source=src,
            destination=dst,
            reason=rule_reason or "—",
        )

        with self._lock:
            # File output (plain text)
            self._file_logger.info(log_line)

            # Console output (colored)
            if action == "BLOCK":
                color = Colors.RED
                icon = "✖"
            else:
                color = Colors.GREEN
                icon = "✔"

            console_line = (
                f"  {color}{Colors.BOLD}{icon} [{action}]{Colors.RESET} "
                f"{Colors.CYAN}{proto:<5}{Colors.RESET} "
                f"{Colors.DIM}{src}{Colors.RESET} → "
                f"{Colors.YELLOW}{dst}{Colors.RESET}"
            )
            if rule_reason:
                console_line += f"  {Colors.RED}({rule_reason}){Colors.RESET}"
            print(console_line)

        return entry

    def close_session(self) -> None:
        """Write a session footer to the log file."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        separator = "=" * 90
        self._file_logger.info(separator)
        self._file_logger.info(f"  FIREWALL SESSION ENDED — {now}")
        self._file_logger.info(separator + "\n")


# ═══════════════════════════════════════════════════════════════════════
# Packet Parser
# ═══════════════════════════════════════════════════════════════════════

def parse_packet(packet) -> dict | None:
    """
    Extract structured metadata from a captured Scapy packet.

    Returns None if the packet lacks an IP layer (non-IPv4).
    """
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    proto_num = ip_layer.proto
    proto_name = PROTOCOL_MAP.get(proto_num, f"OTHER({proto_num})")

    src_port = None
    dst_port = None

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        src_port = udp.sport
        dst_port = udp.dport

    return dict(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        proto_num=proto_num,
        proto_name=proto_name,
    )


# ═══════════════════════════════════════════════════════════════════════
# Firewall Engine
# ═══════════════════════════════════════════════════════════════════════

class FirewallEngine:
    """
    Central engine that ties together sniffing, rule evaluation, logging,
    and metrics tracking. Designed to run either standalone or inside
    a Flask application via a background thread.
    """

    def __init__(self, rules_path: str = RULES_FILE, log_file: str = LOG_FILE,
                 iface: str | None = None, max_log_entries: int = 500):
        self.rules = FirewallRules(rules_path)
        self.logger = FirewallLogger(log_file)
        self.iface = iface  # None = Scapy auto-selects default iface

        # Metrics (thread-safe via the GIL for simple int increments)
        self.total_packets: int = 0
        self.allowed_packets: int = 0
        self.blocked_packets: int = 0
        self.start_time: float = time.time()

        # Circular buffer of recent log entries for the web dashboard
        self._max_log_entries = max_log_entries
        self._log_entries: list = []
        self._log_lock = threading.Lock()

        # Control flag
        self._running = False
        self._sniffer_thread: threading.Thread | None = None

    # ----- Metrics helpers -----

    def get_metrics(self) -> dict:
        """Return a snapshot of current firewall metrics."""
        uptime_sec = time.time() - self.start_time
        hours, remainder = divmod(int(uptime_sec), 3600)
        minutes, seconds = divmod(remainder, 60)
        return dict(
            total=self.total_packets,
            allowed=self.allowed_packets,
            blocked=self.blocked_packets,
            uptime=f"{hours:02d}:{minutes:02d}:{seconds:02d}",
            uptime_seconds=int(uptime_sec),
            rate=round(self.total_packets / max(uptime_sec, 1), 1),
        )

    def get_recent_logs(self, count: int = 100) -> list:
        """Return the most recent log entries for the dashboard."""
        with self._log_lock:
            return list(self._log_entries[-count:])

    def get_rules_summary(self) -> dict:
        """Return a summary of loaded rules for dashboard display."""
        return dict(
            blocked_ips=sorted(self.rules.blocked_source_ips),
            blocked_ports=sorted(self.rules.blocked_destination_ports),
            blocked_protocols=sorted(self.rules.blocked_protocols),
            named_rules=self.rules.named_rules,
            default_policy=self.rules.default_policy,
        )

    # ----- Core packet handler -----

    def _handle_packet(self, packet) -> None:
        """Callback for Scapy's sniff(); processes a single packet."""
        parsed = parse_packet(packet)
        if parsed is None:
            return  # Skip non-IPv4

        self.total_packets += 1

        src_ip = parsed["src_ip"]
        dst_ip = parsed["dst_ip"]
        src_port = parsed["src_port"]
        dst_port = parsed["dst_port"]
        proto = parsed["proto_name"]

        # Format address strings
        if src_port is not None:
            src_str = f"{src_ip}:{src_port}"
        else:
            src_str = src_ip

        if dst_port is not None:
            dst_str = f"{dst_ip}:{dst_port}"
        else:
            dst_str = dst_ip

        # Evaluate against rule set
        action, reason = self.rules.evaluate(src_ip, dst_port, proto)

        if action == "BLOCK":
            self.blocked_packets += 1
        else:
            self.allowed_packets += 1

        # Log the decision
        entry = self.logger.log(action, proto, src_str, dst_str, reason)

        # Store for dashboard
        with self._log_lock:
            self._log_entries.append(entry)
            # Trim circular buffer
            if len(self._log_entries) > self._max_log_entries:
                self._log_entries = self._log_entries[-self._max_log_entries:]

    # ----- Sniffer lifecycle -----

    def _sniff_loop(self) -> None:
        """Blocking sniff loop; runs in a background thread when used with Flask."""
        try:
            sniff(
                prn=self._handle_packet,
                filter="ip",
                store=False,
                iface=self.iface,
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            print(
                f"\n{Colors.RED}{Colors.BOLD}"
                f"[FATAL] Insufficient permissions to capture packets.\n"
                f"        Run this script with Administrator / root privileges.\n"
                f"        On Windows:  Right-click → Run as Administrator\n"
                f"        On Linux:    sudo python firewall_engine.py{Colors.RESET}\n"
            )
            self._running = False
        except Exception as exc:
            print(f"\n{Colors.RED}[ERROR] Sniffer error: {exc}{Colors.RESET}")
            self._running = False

    def start_background(self) -> None:
        """Start the sniffer in a daemon background thread (for Flask)."""
        if self._running:
            return
        self._running = True
        self._sniffer_thread = threading.Thread(
            target=self._sniff_loop, daemon=True, name="FirewallSniffer"
        )
        self._sniffer_thread.start()

    def stop(self) -> None:
        """Signal the sniffer to stop gracefully."""
        self._running = False
        self.logger.close_session()

    def run_standalone(self) -> None:
        """
        Run the firewall engine in standalone mode (no Flask).
        Blocks until interrupted with Ctrl+C.
        """
        self._print_banner()
        self._print_rules_summary()
        self._running = True

        print(
            f"\n  {Colors.GREEN}{Colors.BOLD}▶ Firewall is ACTIVE — "
            f"sniffing live traffic …{Colors.RESET}"
        )
        print(
            f"  {Colors.DIM}  Press Ctrl+C to stop and view the summary report."
            f"{Colors.RESET}\n"
        )

        try:
            self._sniff_loop()
        except KeyboardInterrupt:
            pass
        finally:
            self._running = False
            self._print_shutdown_report()
            self.logger.close_session()

    # ----- Terminal UI helpers -----

    def _print_banner(self) -> None:
        """Display the startup banner in the terminal."""
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
  ║         User-Space Packet Filtering Simulator                ║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝
{Colors.RESET}"""
        print(banner)

    def _print_rules_summary(self) -> None:
        """Print a formatted summary of loaded firewall rules."""
        r = self.rules
        print(f"  {Colors.BOLD}┌─── Loaded Rule Set ───────────────────────────────┐{Colors.RESET}")
        print(f"  {Colors.BOLD}│{Colors.RESET} Default Policy: {Colors.GREEN if r.default_policy == 'ALLOW' else Colors.RED}{r.default_policy}{Colors.RESET}")

        if r.blocked_source_ips:
            print(f"  {Colors.BOLD}│{Colors.RESET} Blocked Source IPs:    {Colors.RED}{', '.join(sorted(r.blocked_source_ips))}{Colors.RESET}")
        if r.blocked_destination_ports:
            print(f"  {Colors.BOLD}│{Colors.RESET} Blocked Dest. Ports:   {Colors.RED}{', '.join(str(p) for p in sorted(r.blocked_destination_ports))}{Colors.RESET}")
        if r.blocked_protocols:
            print(f"  {Colors.BOLD}│{Colors.RESET} Blocked Protocols:     {Colors.RED}{', '.join(sorted(r.blocked_protocols))}{Colors.RESET}")

        print(f"  {Colors.BOLD}│{Colors.RESET} Named Rules Loaded:    {Colors.CYAN}{len(r.named_rules)}{Colors.RESET}")
        print(f"  {Colors.BOLD}└───────────────────────────────────────────────────┘{Colors.RESET}")

    def _print_shutdown_report(self) -> None:
        """Print the final metrics summary on graceful shutdown."""
        metrics = self.get_metrics()
        print(f"""
{Colors.CYAN}{Colors.BOLD}
  ╔══════════════════════════════════════════════════════════════╗
  ║                   FIREWALL SESSION REPORT                    ║
  ╠══════════════════════════════════════════════════════════════╣
  ║                                                              ║
  ║   Total Packets Scanned:   {metrics['total']:>10,}                        ║
  ║   Packets ALLOWED:         {Colors.GREEN}{metrics['allowed']:>10,}{Colors.CYAN}                        ║
  ║   Packets BLOCKED:         {Colors.RED}{metrics['blocked']:>10,}{Colors.CYAN}                        ║
  ║                                                              ║
  ║   Uptime:                  {metrics['uptime']:>10}                        ║
  ║   Avg. Packets/sec:        {metrics['rate']:>10}                        ║
  ║                                                              ║
  ║   Log File:  {LOG_FILE:<45}  ║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝
{Colors.RESET}""")


# ═══════════════════════════════════════════════════════════════════════
# Standalone Execution Entry Point
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    engine = FirewallEngine(
        rules_path=RULES_FILE,
        log_file=LOG_FILE,
    )
    engine.run_standalone()
