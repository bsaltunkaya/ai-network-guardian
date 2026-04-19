"""
Network Detective Module
Identifies active devices on the local network using ARP inspection,
ping sweep, and MAC vendor lookup.
Operates at L1/L2: ARP, MAC (Data Link Layer)
"""

import subprocess
import re
import platform
import socket
import time
import logging

logger = logging.getLogger(__name__)


# Common MAC OUI prefixes -> vendor mapping
MAC_VENDORS = {
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:1A:A1": "Cisco",
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0A:27": "Apple",
    "00:0A:95": "Apple", "00:0D:93": "Apple", "00:10:FA": "Apple",
    "00:11:24": "Apple", "00:14:51": "Apple", "00:16:CB": "Apple",
    "00:17:F2": "Apple", "00:19:E3": "Apple", "00:1B:63": "Apple",
    "00:1C:B3": "Apple", "00:1D:4F": "Apple", "00:1E:52": "Apple",
    "00:1E:C2": "Apple", "00:1F:5B": "Apple", "00:1F:F3": "Apple",
    "00:21:E9": "Apple", "00:22:41": "Apple", "00:23:12": "Apple",
    "00:23:32": "Apple", "00:23:6C": "Apple", "00:23:DF": "Apple",
    "00:24:36": "Apple", "00:25:00": "Apple", "00:25:4B": "Apple",
    "00:25:BC": "Apple", "00:26:08": "Apple", "00:26:4A": "Apple",
    "00:26:B0": "Apple", "00:26:BB": "Apple", "00:C6:10": "Apple",
    "04:0C:CE": "Apple", "04:15:52": "Apple", "04:1E:64": "Apple",
    "04:26:65": "Apple", "04:48:9A": "Apple", "04:4B:ED": "Apple",
    "04:52:F3": "Apple", "04:54:53": "Apple", "04:D3:CF": "Apple",
    "04:DB:56": "Apple", "04:E5:36": "Apple", "04:F1:3E": "Apple",
    "04:F7:E4": "Apple", "08:00:07": "Apple", "08:66:98": "Apple",
    "08:6D:41": "Apple", "08:74:02": "Apple",
    "A4:83:E7": "Apple", "A8:5C:2C": "Apple", "AC:87:A3": "Apple",
    "B8:17:C2": "Apple", "B8:27:EB": "Raspberry Pi",
    "B8:41:A4": "Samsung", "B8:57:D8": "Samsung",
    "00:1A:11": "Google", "3C:5A:B4": "Google", "54:60:09": "Google",
    "00:15:5D": "Microsoft", "00:50:F2": "Microsoft",
    "28:6C:07": "Xiaomi", "64:09:80": "Xiaomi",
    "00:E0:4C": "Realtek", "52:54:00": "Realtek/QEMU",
    "00:1C:7E": "Toshiba",
    "00:26:5A": "D-Link", "00:05:5D": "D-Link",
    "00:14:6C": "Netgear", "00:1B:2F": "Netgear",
    "00:1D:7E": "Linksys", "00:06:25": "Linksys",
    "00:0E:8F": "Sercomm", "00:26:5B": "Hitron",
    "00:1E:58": "D-Link", "00:22:6B": "Cisco-Linksys",
    "00:24:01": "D-Link",
    "F8:1A:67": "TP-Link", "50:C7:BF": "TP-Link",
    "00:23:CD": "TP-Link", "00:27:19": "TP-Link",
    "30:B5:C2": "TP-Link", "54:C8:0F": "TP-Link",
    "00:1F:1F": "Edimax",
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware",
    "08:00:27": "VirtualBox",
    "00:18:0A": "Intel", "00:1B:21": "Intel", "00:1C:C0": "Intel",
    "00:1D:E0": "Intel", "00:1E:64": "Intel", "00:1E:65": "Intel",
    "00:1F:3B": "Intel", "00:1F:3C": "Intel", "00:22:FA": "Intel",
    "00:24:D7": "Intel", "00:27:10": "Intel",
    "00:1A:2B": "Ayecom", "00:18:F3": "ASUSTek",
    "00:1A:92": "ASUSTek", "00:22:15": "ASUSTek",
    "00:23:54": "ASUSTek", "00:24:8C": "ASUSTek",
    "00:25:22": "ASUSTek", "00:26:18": "ASUSTek",
    "2C:56:DC": "Huawei", "00:E0:FC": "Huawei",
    "00:25:9E": "Huawei", "00:46:4B": "Huawei",
    "20:F4:1B": "Huawei", "24:09:95": "Huawei",
    "70:72:3C": "Huawei",
    "00:07:04": "ZyXEL", "00:13:49": "ZyXEL",
    "00:19:CB": "ZyXEL", "00:1F:57": "ZyXEL",
    "00:23:F8": "ZyXEL", "00:26:F3": "ZyXEL",
    "FC:F5:28": "ZyXEL", "B0:B2:DC": "ZyXEL",
    "7C:B0:C2": "Intel", "68:17:29": "Intel",
    "34:02:86": "Intel", "A4:34:D9": "Intel",
    "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:1E:06": "Wibrain",
    "AA:BB:CC": "Private/Unknown",
    "FF:FF:FF": "Broadcast",
}

# Device type heuristics based on vendor
VENDOR_DEVICE_TYPES = {
    "Apple": "Computer/Phone",
    "Samsung": "Phone/Tablet",
    "Google": "Smart Device",
    "Microsoft": "Computer",
    "Xiaomi": "Phone/IoT",
    "Raspberry Pi": "IoT/SBC",
    "Cisco": "Router/Switch",
    "D-Link": "Router/AP",
    "Netgear": "Router/AP",
    "Linksys": "Router/AP",
    "TP-Link": "Router/AP",
    "Edimax": "Router/AP",
    "ZyXEL": "Router/AP",
    "Huawei": "Router/Phone",
    "ASUSTek": "Router/Computer",
    "Intel": "Computer",
    "Realtek": "Computer/Embedded",
    "VMware": "Virtual Machine",
    "VirtualBox": "Virtual Machine",
    "Toshiba": "Computer",
}


def lookup_mac_vendor(mac_address):
    """Look up the vendor from MAC address OUI prefix."""
    mac_upper = mac_address.upper().replace("-", ":")
    prefix = mac_upper[:8]
    return MAC_VENDORS.get(prefix, "Unknown Vendor")


def estimate_device_type(vendor):
    """Estimate device type from vendor name."""
    return VENDOR_DEVICE_TYPES.get(vendor, "Unknown Device")


def get_local_ip_range():
    """Detect the local IP and subnet prefix."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}", local_ip
    except Exception:
        return "192.168.1", "192.168.1.1"


def _should_skip_ip(ip: str, local_ip: str) -> bool:
    """Return True for IPs that should be excluded from results."""
    if ip == local_ip:
        return True
    parts = ip.split('.')
    if len(parts) != 4:
        return True
    last = int(parts[3])
    first = int(parts[0])
    # Broadcast (.255), multicast (224-239), loopback (127)
    if last == 255 or first == 127:
        return True
    if 224 <= first <= 239:
        return True
    return False


def get_arp_table(local_ip: str = ""):
    """
    Parse `arp -a` output on Windows, macOS, and Linux.

    Windows format:
        Interface: 10.65.233.85 --- 0x8
          Internet Address      Physical Address      Type
          10.65.233.144         0a-6c-44-f6-ef-dc     dynamic

    macOS/Linux format:
        ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0
    """
    devices = []
    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, timeout=10,
            # Use cp1252/utf-8 with errors='replace' to survive any encoding
            text=True, encoding="utf-8", errors="replace",
        )
        output = result.stdout
        logger.debug("[ARP] raw output (%d lines):\n%s", len(output.splitlines()), output[:800])

        is_windows = platform.system() == "Windows"

        # Windows:  "  10.65.233.144         0a-6c-44-f6-ef-dc     dynamic"
        win_pattern = re.compile(
            r'^\s*([\d.]+)\s+([\da-fA-F][\da-fA-F-]{16,})\s+(dynamic|static)',
            re.IGNORECASE,
        )
        # macOS/Linux: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0"
        unix_pattern = re.compile(
            r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([\da-fA-F:]+)',
            re.IGNORECASE,
        )

        current_interface = "unknown"
        iface_pattern = re.compile(r'Interface:\s*([\d.]+)', re.IGNORECASE)

        for line in output.splitlines():
            # Track current interface on Windows
            iface_match = iface_pattern.search(line)
            if iface_match:
                current_interface = iface_match.group(1)
                continue

            if is_windows:
                m = win_pattern.match(line)
                if not m:
                    continue
                ip  = m.group(1)
                mac = m.group(2).replace("-", ":").upper()
            else:
                m = unix_pattern.search(line)
                if not m:
                    continue
                ip  = m.group(1)
                mac = m.group(2).upper()
                if mac in ("FF:FF:FF:FF:FF:FF", "(INCOMPLETE)"):
                    continue

            if _should_skip_ip(ip, local_ip):
                logger.debug("[ARP] skipped %s", ip)
                continue

            vendor      = lookup_mac_vendor(mac)
            device_type = estimate_device_type(vendor)

            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = None

            devices.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "device_type": device_type,
                "interface": current_interface,
                "hostname": hostname,
                "is_responsive": None,
            })
            logger.debug("[ARP] found  %s  mac=%s  vendor=%s", ip, mac, vendor)

    except subprocess.TimeoutExpired:
        return {"error": "arp -a timed out", "devices": []}
    except FileNotFoundError:
        return {"error": "arp command not found", "devices": []}
    except Exception as e:
        return {"error": str(e), "devices": []}

    logger.debug("[ARP] total parsed: %d devices", len(devices))
    return devices


def ping_host(ip: str, count: int = 1, timeout: int = 2) -> bool:
    """Ping a host; returns True if reachable."""
    try:
        if platform.system() == "Windows":
            cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), ip]
        else:
            cmd = ["ping", "-c", str(count), "-W", str(timeout), ip]
        r = subprocess.run(cmd, capture_output=True, timeout=timeout + 5)
        return r.returncode == 0
    except Exception:
        return False


def test_tcp_connection(ip: str, port: int, timeout: int = 5) -> dict:
    """
    Attempt a TCP connection to ip:port and return a Layer 1-4 analysis.

    Status values:
        connected   — SYN-ACK received, port is open
        refused     — RST received, port is closed but host is up
        timeout     — No response; likely filtered by firewall
        unreachable — No route to host; L3 routing failure
        error       — Unexpected OS error
    """
    result = {
        "target": {"ip": ip, "port": port, "timeout": timeout},
        "status": None,
        "latency_ms": None,
        "layer_analysis": {
            "L1_physical":  None,
            "L2_datalink":  None,
            "L3_network":   None,
            "L4_transport": None,
        },
        "error": None,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        t0 = time.perf_counter()
        sock.connect((ip, port))
        latency_ms = round((time.perf_counter() - t0) * 1000, 3)
        sock.close()

        result["status"] = "connected"
        result["latency_ms"] = latency_ms
        result["layer_analysis"] = {
            "L1_physical":  "OK — Physical link active (full handshake completed)",
            "L2_datalink":  "OK — MAC/ARP resolved, frames delivered",
            "L3_network":   "OK — IP routing functional, packets delivered",
            "L4_transport": f"OPEN — TCP port {port} accepted the connection ({latency_ms} ms RTT)",
        }

    except ConnectionRefusedError:
        result["status"] = "refused"
        result["layer_analysis"] = {
            "L1_physical":  "OK — Physical link active (RST packet received)",
            "L2_datalink":  "OK — MAC/ARP resolved, host reachable",
            "L3_network":   "OK — IP routing functional, host responded",
            "L4_transport": f"CLOSED — Port {port} sent TCP RST; no service is listening on this port",
        }

    except (socket.timeout, TimeoutError):
        result["status"] = "timeout"
        result["layer_analysis"] = {
            "L1_physical":  "UNKNOWN — Cannot confirm physical link",
            "L2_datalink":  "UNKNOWN — ARP reachability unclear",
            "L3_network":   "SUSPECT — Packets may be dropped by router or firewall",
            "L4_transport": f"FILTERED — Port {port} did not respond within {timeout}s; likely blocked by firewall",
        }

    except OSError as e:
        err_lower = str(e).lower()
        if any(x in err_lower for x in ["unreachable", "no route", "network is unreachable", "10065", "10051"]):
            result["status"] = "unreachable"
            result["layer_analysis"] = {
                "L1_physical":  "UNKNOWN — Physical layer status unconfirmed",
                "L2_datalink":  "FAIL — Cannot resolve MAC address; host may be offline or on different subnet",
                "L3_network":   f"FAIL — No route to {ip}; routing table has no path to this host",
                "L4_transport": "N/A — Transport layer unreachable (L3 failure blocks L4)",
            }
        else:
            result["status"] = "error"
            result["error"] = str(e)
            result["layer_analysis"] = {
                "L1_physical":  "UNKNOWN",
                "L2_datalink":  "UNKNOWN",
                "L3_network":   "UNKNOWN",
                "L4_transport": f"ERROR — {e}",
            }

    logger.debug(
        "[ConnTest] %s:%d => %s  latency=%s ms  error=%s",
        ip, port, result["status"], result["latency_ms"], result["error"],
    )
    return result


def _detect_gateway(subnet: str, devices: list):
    """
    Best-effort gateway detection:
    1. <subnet>.1  (most common home/office gateway)
    2. <subnet>.254 (common on some ISPs)
    3. First device in the ARP table
    """
    for suffix in ("1", "254"):
        candidate = f"{subnet}.{suffix}"
        if any(d["ip"] == candidate for d in devices):
            return candidate
    return devices[0]["ip"] if devices else None


def scan_network():
    """
    Full network scan: reads ARP table, filters noise, pings each host,
    detects gateway, and returns structured device list.
    """
    subnet, local_ip = get_local_ip_range()
    logger.debug("[Scan] local_ip=%s  subnet=%s", local_ip, subnet)

    raw = get_arp_table(local_ip=local_ip)
    if isinstance(raw, dict) and "error" in raw:
        logger.warning("[Scan] ARP error: %s", raw["error"])
        return {
            "devices": [],
            "total_found": 0,
            "responsive": 0,
            "unknown_count": 0,
            "subnet": subnet,
            "local_ip": local_ip,
            "gateway": None,
            "gateway_candidates": [],
            "warning": raw["error"],
        }
    devices = raw
    logger.debug("[Scan] ARP returned %d devices before ping", len(devices))

    # Ping verify each device (cap at 30 to stay fast)
    for device in devices[:30]:
        device["is_responsive"] = ping_host(device["ip"])
        logger.debug("[Scan] ping %s => %s", device["ip"], device["is_responsive"])

    gateway = _detect_gateway(subnet, devices)
    gateway_candidates = [d["ip"] for d in devices if d["ip"].endswith(".1") or d["ip"].endswith(".254")]
    unknown_devices    = [d for d in devices if d["vendor"] == "Unknown Vendor"]

    logger.debug(
        "[Scan] done — total=%d  responsive=%d  unknown=%d  gateway=%s",
        len(devices),
        sum(1 for d in devices if d.get("is_responsive")),
        len(unknown_devices),
        gateway,
    )

    return {
        "devices": devices,
        "total_found": len(devices),
        "responsive": sum(1 for d in devices if d.get("is_responsive")),
        "unknown_count": len(unknown_devices),
        "subnet": subnet,
        "local_ip": local_ip,
        "gateway": gateway,
        "gateway_candidates": gateway_candidates,
    }
