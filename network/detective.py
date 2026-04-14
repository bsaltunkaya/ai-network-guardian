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


def get_arp_table():
    """Parse the system ARP table to find devices on the local network."""
    devices = []
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=10
        )
        # macOS format: hostname (IP) at MAC on interface [ethernet]
        # Linux format: hostname (IP) at MAC [ether] on interface
        pattern = re.compile(
            r'\?\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([\da-fA-F:]+)\s+on\s+(\w+)'
        )
        alt_pattern = re.compile(
            r'(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([\da-fA-F:]+)'
        )

        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            match = pattern.search(line)
            if match:
                ip = match.group(1)
                mac = match.group(2)
                interface = match.group(3)
            else:
                match = alt_pattern.search(line)
                if match:
                    ip = match.group(2)
                    mac = match.group(3)
                    interface = "unknown"
                else:
                    continue

            if mac == "(incomplete)" or mac == "ff:ff:ff:ff:ff:ff":
                continue

            vendor = lookup_mac_vendor(mac)
            device_type = estimate_device_type(vendor)

            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.timeout):
                hostname = None

            devices.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "device_type": device_type,
                "interface": interface,
                "hostname": hostname,
                "is_responsive": None,  # will be filled by ping
            })
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        return {"error": str(e), "devices": []}

    return devices


def ping_host(ip, count=1, timeout=2):
    """Ping a single host and return True if responsive."""
    try:
        flag = "-c" if platform.system() != "Windows" else "-n"
        timeout_flag = "-W" if platform.system() != "Windows" else "-w"
        result = subprocess.run(
            ["ping", flag, str(count), timeout_flag, str(timeout * 1000 if platform.system() == "Windows" else timeout), ip],
            capture_output=True, text=True, timeout=timeout + 3
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, Exception):
        return False


def get_local_ip_range():
    """Detect the local network IP range."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}", local_ip
    except Exception:
        return "192.168.1", "192.168.1.1"


def scan_network():
    """
    Full network scan combining ARP table with ping verification.
    Returns structured device list with vendor and type info.
    """
    raw = get_arp_table()
    if isinstance(raw, dict) and "error" in raw:
        # Return a properly structured response even on error
        subnet, local_ip = get_local_ip_range()
        return {
            "devices": raw.get("devices", []),
            "total_found": 0,
            "responsive": 0,
            "unknown_count": 0,
            "subnet": subnet,
            "local_ip": local_ip,
            "gateway_candidates": [],
            "warning": raw["error"],
        }
    devices = raw

    subnet, local_ip = get_local_ip_range()

    # Ping verify each discovered device (limited to keep it fast)
    for device in devices[:30]:  # cap at 30 to avoid long scans
        device["is_responsive"] = ping_host(device["ip"])

    # Classify devices
    gateway_candidates = [d for d in devices if d["ip"].endswith(".1")]
    unknown_devices = [d for d in devices if d["vendor"] == "Unknown Vendor"]

    return {
        "devices": devices,
        "total_found": len(devices),
        "responsive": sum(1 for d in devices if d.get("is_responsive")),
        "unknown_count": len(unknown_devices),
        "subnet": subnet,
        "local_ip": local_ip,
        "gateway_candidates": [d["ip"] for d in gateway_candidates],
    }
