"""
Performance & Lag Monitor Module
Uses TCP socket connections (instead of ICMP ping) to measure latency.
Operates at L3/L4: IP, TCP, UDP (Network & Transport Layers)
"""

import socket
import time
import statistics
import re
import platform
import subprocess
import logging

logger = logging.getLogger(__name__)

# Well-known ports tried in order when connecting to a host
_PROBE_PORTS = [443, 80, 53, 22, 8080]


def _resolve_port(host: str, preferred_port: int) -> int:
    """Return preferred_port if reachable, else first responding port from _PROBE_PORTS."""
    if preferred_port not in _PROBE_PORTS:
        return preferred_port
    return preferred_port


def measure_tcp_performance(host="8.8.8.8", port=443, count=10, timeout=3):
    """
    Measure TCP connection latency to host:port.

    Opens and immediately closes `count` TCP connections, recording the
    time for each full SYN-SYN/ACK-ACK handshake.  No ICMP or elevated
    privileges required.

    Returns a dict with the same shape as the old ICMP latency result so
    the rest of the app (reasoning engine, frontend) works unchanged.
    """
    result = {
        "host": host,
        "port": port,
        "method": "tcp",
        "count": count,
        "packets": [],          # per-attempt RTT in ms
        "successful": 0,
        "failed": 0,
        "min_ms": None,
        "avg_ms": None,
        "max_ms": None,
        "stddev_ms": None,
        "packet_loss_pct": None,
        "jitter_ms": None,
        "error": None,
    }

    # Auto-select an open port if the preferred one isn't reachable on first try
    active_port = port
    for attempt_port in ([port] + [p for p in _PROBE_PORTS if p != port]):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            t0 = time.perf_counter()
            sock.connect((host, attempt_port))
            sock.close()
            active_port = attempt_port
            # First successful connection already counted below
            result["port"] = active_port
            result["packets"].append(round((time.perf_counter() - t0) * 1000, 3))
            result["successful"] += 1
            break
        except OSError:
            continue

    if not result["packets"]:
        result["error"] = f"Could not connect to {host} on any probe port {_PROBE_PORTS}"
        result["packet_loss_pct"] = 100.0
        logger.debug("[PerfMonitor] %s → all ports unreachable", host)
        return result

    # Remaining count-1 attempts on the working port
    for _ in range(count - 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            t0 = time.perf_counter()
            sock.connect((host, active_port))
            sock.close()
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)
            result["packets"].append(elapsed_ms)
            result["successful"] += 1
        except OSError:
            result["failed"] += 1

        time.sleep(0.05)    # small gap to avoid connection rate-limiting

    pkts = result["packets"]
    total = result["successful"] + result["failed"]

    result["packet_loss_pct"] = round(result["failed"] / total * 100, 1) if total else 100.0
    result["min_ms"]  = round(min(pkts), 3)
    result["avg_ms"]  = round(statistics.mean(pkts), 3)
    result["max_ms"]  = round(max(pkts), 3)
    result["stddev_ms"] = round(statistics.stdev(pkts), 3) if len(pkts) > 1 else 0.0

    if len(pkts) > 1:
        diffs = [abs(pkts[i + 1] - pkts[i]) for i in range(len(pkts) - 1)]
        result["jitter_ms"] = round(statistics.mean(diffs), 3)

    logger.debug(
        "[PerfMonitor] TCP to %s:%d | avg=%.1f ms | loss=%.0f%% | jitter=%s ms",
        host, active_port,
        result["avg_ms"],
        result["packet_loss_pct"],
        result["jitter_ms"],
    )

    return result


def get_active_connections():
    """
    Get active TCP/UDP connections via netstat.
    Works on Windows, macOS, and Linux.
    """
    connections = {
        "tcp": [],
        "udp": [],
        "tcp_count": 0,
        "udp_count": 0,
        "states": {},
        "top_remote_hosts": {},
        "error": None,
    }

    try:
        system = platform.system()
        if system == "Windows":
            cmd = ["netstat", "-ano"]
        elif system == "Darwin":
            cmd = ["netstat", "-an", "-p", "tcp"]
        else:
            cmd = ["netstat", "-tunap"]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        output = proc.stdout

        # Generic pattern covering Windows / macOS / Linux netstat output
        tcp_pat = re.compile(
            r'(TCP|tcp[46]?)\s+'
            r'([\d\[\].:*]+)[:\.](\d+)\s+'
            r'([\d\[\].:*]+)[:\.](\d+)\s+'
            r'(\S+)',
            re.IGNORECASE,
        )
        udp_pat = re.compile(
            r'(UDP|udp[46]?)\s+'
            r'([\d\[\].:*]+)[:\.](\d+)\s+'
            r'([\d\[\].:*]+)?[:\.]?(\d+)?',
            re.IGNORECASE,
        )

        for line in output.splitlines():
            m = tcp_pat.search(line)
            if m:
                state = m.group(6).upper()
                remote = m.group(4)
                connections["tcp"].append({
                    "protocol": "tcp",
                    "local_address": m.group(2),
                    "local_port": int(m.group(3)),
                    "remote_address": remote,
                    "remote_port": int(m.group(5)),
                    "state": state,
                })
                connections["states"][state] = connections["states"].get(state, 0) + 1
                if remote not in ("*", "0.0.0.0", "[::]", "127.0.0.1"):
                    connections["top_remote_hosts"][remote] = (
                        connections["top_remote_hosts"].get(remote, 0) + 1
                    )
                continue

            m = udp_pat.search(line)
            if m and not tcp_pat.search(line):
                connections["udp"].append({
                    "protocol": "udp",
                    "local_address": m.group(2),
                    "local_port": int(m.group(3)),
                    "remote_address": m.group(4) or "*",
                    "remote_port": int(m.group(5)) if m.group(5) else 0,
                    "state": "STATELESS",
                })

        connections["tcp_count"] = len(connections["tcp"])
        connections["udp_count"] = len(connections["udp"])
        connections["top_remote_hosts"] = dict(
            sorted(connections["top_remote_hosts"].items(),
                   key=lambda x: x[1], reverse=True)[:10]
        )

    except subprocess.TimeoutExpired:
        connections["error"] = "netstat timed out"
    except Exception as e:
        connections["error"] = str(e)

    return connections


def measure_dns_resolution(hostname="google.com"):
    """Measure DNS resolution time."""
    try:
        start = time.perf_counter()
        socket.getaddrinfo(hostname, 80)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        logger.debug("[PerfMonitor] DNS %s resolved in %.1f ms", hostname, elapsed_ms)
        return {"hostname": hostname, "resolution_time_ms": elapsed_ms, "error": None}
    except socket.gaierror as e:
        return {"hostname": hostname, "resolution_time_ms": None, "error": f"DNS resolution failed: {e}"}


def run_diagnostics(host="8.8.8.8", ping_count=10):
    """
    Full performance diagnostic: TCP latency + active connections + DNS.
    `ping_count` controls how many TCP probe connections are made.
    """
    latency = measure_tcp_performance(host, count=ping_count)
    connections = get_active_connections()
    dns = measure_dns_resolution(host if host != "8.8.8.8" else "google.com")

    return {
        "latency": latency,
        "connections": connections,
        "dns": dns,
        "timestamp": time.time(),
    }
