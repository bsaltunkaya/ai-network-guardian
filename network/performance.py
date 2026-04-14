"""
Performance & Lag Monitor Module
Measures ping latency and active TCP/UDP sessions to diagnose
performance degradation causes.
Operates at L3/L4: IP, ICMP, TCP, UDP (Network & Transport Layers)
"""

import subprocess
import re
import platform
import time


def measure_latency(host="8.8.8.8", count=10, timeout=5):
    """
    Measure ping latency to a target host.
    Returns min/avg/max/stddev and per-packet data.
    """
    result = {
        "host": host,
        "count": count,
        "packets": [],
        "min_ms": None,
        "avg_ms": None,
        "max_ms": None,
        "stddev_ms": None,
        "packet_loss_pct": None,
        "jitter_ms": None,
        "error": None,
    }

    try:
        flag = "-c" if platform.system() != "Windows" else "-n"
        timeout_flag = "-W" if platform.system() != "Windows" else "-w"
        cmd = ["ping", flag, str(count), timeout_flag, str(timeout), host]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=count * timeout + 10
        )
        output = proc.stdout

        # Parse individual ping times
        time_pattern = re.compile(r'time[=<]([\d.]+)\s*ms')
        for line in output.split('\n'):
            match = time_pattern.search(line)
            if match:
                result["packets"].append(float(match.group(1)))

        # Parse summary statistics (macOS/Linux)
        stats_pattern = re.compile(
            r'([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms'
        )
        stats_match = stats_pattern.search(output)
        if stats_match:
            result["min_ms"] = float(stats_match.group(1))
            result["avg_ms"] = float(stats_match.group(2))
            result["max_ms"] = float(stats_match.group(3))
            result["stddev_ms"] = float(stats_match.group(4))
        elif result["packets"]:
            result["min_ms"] = min(result["packets"])
            result["avg_ms"] = sum(result["packets"]) / len(result["packets"])
            result["max_ms"] = max(result["packets"])

        # Parse packet loss
        loss_pattern = re.compile(r'([\d.]+)%\s*packet loss')
        loss_match = loss_pattern.search(output)
        if loss_match:
            result["packet_loss_pct"] = float(loss_match.group(1))

        # Calculate jitter (average difference between consecutive packets)
        if len(result["packets"]) > 1:
            diffs = [abs(result["packets"][i+1] - result["packets"][i])
                     for i in range(len(result["packets"])-1)]
            result["jitter_ms"] = round(sum(diffs) / len(diffs), 2)

    except subprocess.TimeoutExpired:
        result["error"] = "Ping timed out"
    except FileNotFoundError:
        result["error"] = "Ping command not found"
    except Exception as e:
        result["error"] = str(e)

    return result


def get_active_connections():
    """
    Get active TCP and UDP connections using netstat.
    Returns structured connection data with protocol breakdown.
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
        # Use netstat (works on both macOS and Linux)
        if platform.system() == "Darwin":
            cmd = ["netstat", "-an", "-p", "tcp"]
            cmd_udp = ["netstat", "-an", "-p", "udp"]
        else:
            cmd = ["netstat", "-tuln"]
            cmd_udp = None

        # TCP connections
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

        tcp_pattern = re.compile(
            r'(tcp[46]?)\s+\d+\s+\d+\s+'
            r'([\d.*:]+\.(\d+))\s+'
            r'([\d.*:]+\.(\d+))\s*'
            r'(\S+)?'
        )

        for line in proc.stdout.split('\n'):
            match = tcp_pattern.search(line)
            if match:
                proto = match.group(1)
                local = match.group(2)
                local_port = match.group(3)
                remote = match.group(4)
                remote_port = match.group(5)
                state = match.group(6) or "UNKNOWN"

                conn_entry = {
                    "protocol": proto,
                    "local_address": local,
                    "local_port": int(local_port),
                    "remote_address": remote,
                    "remote_port": int(remote_port),
                    "state": state,
                }
                connections["tcp"].append(conn_entry)

                # Track states
                connections["states"][state] = connections["states"].get(state, 0) + 1

                # Track remote hosts
                remote_host = remote.rsplit('.', 1)[0]
                if remote_host != "*" and remote_host != "0.0.0.0" and remote_host != "127.0.0.1":
                    connections["top_remote_hosts"][remote_host] = \
                        connections["top_remote_hosts"].get(remote_host, 0) + 1

        # UDP connections
        if cmd_udp:
            proc_udp = subprocess.run(cmd_udp, capture_output=True, text=True, timeout=15)
            udp_pattern = re.compile(
                r'(udp[46]?)\s+\d+\s+\d+\s+'
                r'([\d.*:]+\.(\d+))\s+'
                r'([\d.*:]+\.(\d+))?'
            )
            for line in proc_udp.stdout.split('\n'):
                match = udp_pattern.search(line)
                if match:
                    conn_entry = {
                        "protocol": match.group(1),
                        "local_address": match.group(2),
                        "local_port": int(match.group(3)),
                        "remote_address": match.group(4) if match.group(4) else "*.*",
                        "remote_port": int(match.group(5)) if match.group(5) else 0,
                        "state": "STATELESS",
                    }
                    connections["udp"].append(conn_entry)

        connections["tcp_count"] = len(connections["tcp"])
        connections["udp_count"] = len(connections["udp"])

        # Sort top remote hosts
        connections["top_remote_hosts"] = dict(
            sorted(connections["top_remote_hosts"].items(),
                   key=lambda x: x[1], reverse=True)[:10]
        )

    except subprocess.TimeoutExpired:
        connections["error"] = "Netstat timed out"
    except Exception as e:
        connections["error"] = str(e)

    return connections


def measure_dns_resolution(hostname="google.com"):
    """Measure DNS resolution time."""
    import socket
    try:
        start = time.time()
        socket.getaddrinfo(hostname, 80)
        elapsed = (time.time() - start) * 1000  # ms
        return {
            "hostname": hostname,
            "resolution_time_ms": round(elapsed, 2),
            "error": None,
        }
    except socket.gaierror as e:
        return {
            "hostname": hostname,
            "resolution_time_ms": None,
            "error": f"DNS resolution failed: {e}",
        }


def run_diagnostics(host="8.8.8.8", ping_count=10):
    """
    Full performance diagnostic combining latency, connections,
    and DNS resolution tests.
    """
    latency = measure_latency(host, count=ping_count)
    connections = get_active_connections()
    dns = measure_dns_resolution()

    return {
        "latency": latency,
        "connections": connections,
        "dns": dns,
        "timestamp": time.time(),
    }
