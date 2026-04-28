"""
AI Reasoning Core & Diagnostic Generator
Uses the Google Gemini API (plain HTTP) to analyze network measurements
and produce explainable, TCP/IP layer-aware diagnostics.
Falls back to a rule-based engine if no API key is configured.
"""

import json
import logging
import os
import re
import urllib.request
import urllib.error
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class Diagnosis:
    """A single diagnostic finding from the AI reasoning engine."""
    title: str
    layer: str          # "Application", "Transport", "Network", "Data Link"
    confidence: float   # 0.0 - 1.0
    severity: str       # "info", "low", "medium", "high", "critical"
    evidence: list
    explanation: str
    recommendation: str

    def to_dict(self):
        return asdict(self)


# ──────────────────────────────────────────────────────────────
#  System prompt for AI analysis
# ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are AI Network Guardian, an expert network diagnostic AI.
You analyze raw network measurements and produce clear, explainable diagnoses
for users with limited technical knowledge.

TCP/IP Layer Reference:
- Application Layer (L7): HTTP, HTTPS, DNS, WHOIS, FTP, SMTP
- Transport Layer (L4): TCP, UDP — connection management, ports, sessions
- Network Layer (L3): IP, ICMP — routing, addressing, ping/latency
- Data Link Layer (L2): Ethernet, ARP, MAC — local network, device identification

For EVERY diagnosis you MUST:
1. Map it to the responsible TCP/IP layer (Application, Transport, Network, or Data Link)
2. Provide a confidence score (0.0–1.0) based on evidence strength
3. List specific supporting evidence from the measurements
4. Write a plain-English explanation mentioning which TCP/IP layer and protocol is involved
5. Give a concrete, actionable recommendation the user can follow
6. Assign a severity: "info", "low", "medium", "high", or "critical"

Respond ONLY with a valid JSON array of diagnosis objects. No markdown fences, no extra text.
Each object must have exactly these keys: title, layer, confidence, severity, evidence, explanation, recommendation.
"evidence" must be an array of strings. All other values are strings except confidence (float).

Always include at least one diagnosis. If everything looks healthy, return a positive "info" severity diagnosis.
Be specific about protocols and layer numbers. Avoid vague statements."""

MODULE_PROMPTS = {
    "detective": """Analyze this LOCAL NETWORK SCAN data. The scan used:
- ARP table inspection (Data Link layer) to discover devices
- ICMP ping sweep (Network layer) to verify responsiveness
- MAC OUI lookup to identify device vendors

Focus on: unknown/unauthorized devices, non-responsive hosts, suspicious patterns,
device count relative to expected home/office network size, and any rogue infrastructure.

Network scan data:
""",
    "security": """Analyze this URL SECURITY ASSESSMENT data. The analysis checked:
- HTTPS/SSL certificate metadata (Application layer)
- WHOIS domain registration data (Application layer)
- Phishing risk indicators based on certificate + domain signals

Focus on: certificate validity and trust chain, domain age and registration patterns,
phishing risk signals, TLS version strength, and overall website trustworthiness.

IMPORTANT RULES you must apply:

WHOIS rules:
- If whois_quality.all_fields_missing is true: set confidence <= 0.50 for all WHOIS-related diagnoses and explicitly mention reduced confidence
- If domain_age_days < 365 (1 year): include a warning about the young domain age
- If whois_quality.registrar_missing is true: flag the domain as suspicious due to missing registrar
- If whois_quality.note is present: include it verbatim in the relevant diagnosis explanation

Institutional domain rules (domains ending in .edu.*, .gov.*, .mil.*, .ac.*):
- These are government-controlled TLDs and should be treated with higher trust
- Wildcard certificates are NORMAL for institutional domains -- do NOT flag them
- Missing WHOIS data is NORMAL for institutional domains (restricted by policy) -- do NOT penalize
- Government CAs like TUBITAK, HARICA, CFCA, SECOM are legitimate national certificate authorities -- treat them as trusted, not "uncommon"

Phishing detection rules:
- High-threat keywords in domain names (phishing, malware, hack, spoof, fraud, scam) are strong risk signals even if the cert is valid and domain is old
- Wildcard cert + free CA (Let's Encrypt) + suspicious keywords = phishing infrastructure pattern
- A suspicious subdomain on an unrelated parent domain (e.g. "login.randomsite.com") is a strong impersonation signal
- Positive indicators (valid cert, old domain) should NEVER fully override active risk signals

Always respect the pre-computed risk_score in phishing_assessment -- your severity should align with it.

IMPORTANT -- Website context diagnosis:
You MUST include ONE extra diagnosis with title "Website Overview" (severity "info", layer "Application") that describes what this website likely IS and DOES based on the domain name, certificate subject/organization, WHOIS registrant, and any other clues in the data. Write it like a human would explain it to a friend, e.g. "This looks like a university website for Gebze Technical University in Turkey" or "This appears to be a phishing test page hosted on a DNS filtering service." Be specific and natural. If you cannot determine the purpose, say so honestly.

Security analysis data:
""",
    "performance": """Analyze this NETWORK PERFORMANCE diagnostic data. The measurements include:
- ICMP ping latency statistics (Network layer) — min/avg/max/jitter/packet loss
- Active TCP/UDP connection states (Transport layer) — counts, states, top remote hosts
- DNS resolution time (Application layer)

Focus on: latency quality for real-time use, packet loss impact, jitter stability,
connection count health, unusual connection states, DNS speed, and overall performance.

Performance diagnostic data:
""",
    "connection": """Analyze this TCP CONNECTION TEST result. The test attempted a direct TCP socket
connection to a specific IP:port and recorded the outcome at each network layer.

Status meanings:
- connected:   L1-L4 all functional; port is open and accepting connections
- refused:     L1-L3 OK; port is CLOSED (TCP RST received) — no service listening
- timeout:     L4 filtered; firewall is silently dropping packets to this port
- unreachable: L3 failure; no route to host, host offline, or wrong subnet

Layer analysis fields:
- L1_physical:  Physical link status (inferred)
- L2_datalink:  MAC/ARP reachability (Data Link layer)
- L3_network:   IP routing result (Network layer)
- L4_transport: TCP port status (Transport layer)

Focus on: what each layer result implies, root cause of failure, whether this is a
firewall/routing/application issue, and concrete steps to resolve it.

Connection test data:
""",
}


# ──────────────────────────────────────────────────────────────
#  Gemini API (plain HTTP, no SDK)
# ──────────────────────────────────────────────────────────────

GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
GEMINI_MODELS = ["gemini-2.5-flash", "gemini-2.5-pro"]


def _call_gemini(module, data):
    """POST to Gemini REST API. Tries Flash first, falls back to Pro on 429."""
    import time as _time
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None

    data_str = json.dumps(data, indent=2, default=str)
    if len(data_str) > 8000:
        data_str = data_str[:8000] + "\n... (truncated)"

    prompt = SYSTEM_PROMPT + "\n\n" + MODULE_PROMPTS.get(module, "") + data_str

    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}]
    }).encode()

    for model in GEMINI_MODELS:
        url = f"{GEMINI_BASE}/{model}:generateContent?key={api_key}"
        try:
            logger.debug("[Gemini] trying %s for module=%s", model, module)
            req = urllib.request.Request(
                url, data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read())

            text = result["candidates"][0]["content"]["parts"][0]["text"].strip()

            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()

            diagnoses = json.loads(text)
            if not isinstance(diagnoses, list):
                return None

            required_keys = {"title", "layer", "confidence", "severity", "evidence", "explanation", "recommendation"}
            valid = []
            for d in diagnoses:
                if isinstance(d, dict) and required_keys.issubset(d.keys()):
                    d["confidence"] = float(d["confidence"])
                    if not isinstance(d["evidence"], list):
                        d["evidence"] = [str(d["evidence"])]
                    valid.append(d)
            logger.debug("[Gemini] %s succeeded for module=%s", model, module)
            return valid if valid else None

        except urllib.error.HTTPError as e:
            if e.code == 429:
                logger.warning("[Gemini] %s rate limited, trying next model...", model)
                continue
            logger.warning("[Gemini] %s failed: %s", model, e)
            return None
        except Exception as e:
            logger.warning("[Gemini] %s failed: %s", model, e)
            return None

    logger.warning("[Gemini] all models rate limited, falling back to rules")
    return None


# ──────────────────────────────────────────────────────────────
#  Rule-based Fallback Engine
# ──────────────────────────────────────────────────────────────

class RuleBasedFallback:
    """Deterministic fallback when Claude API is unavailable."""

    def analyze_network_scan(self, scan_data):
        diagnoses = []
        devices = scan_data.get("devices", [])
        total = scan_data.get("total_found", 0)
        unknown_count = scan_data.get("unknown_count", 0)

        if unknown_count > 0:
            ratio = unknown_count / max(total, 1)
            severity = "high" if ratio > 0.5 else ("medium" if ratio > 0.2 else "low")
            confidence = 0.85 if ratio > 0.5 else (0.70 if ratio > 0.2 else 0.60)
            unknown_ips = [d["ip"] for d in devices if d["vendor"] == "Unknown Vendor"][:5]
            diagnoses.append(Diagnosis(
                title="Unknown Devices Detected on Network",
                layer="Data Link",
                confidence=confidence, severity=severity,
                evidence=[
                    f"{unknown_count} out of {total} devices have unrecognized MAC vendors",
                    f"Sample IPs: {', '.join(unknown_ips)}",
                    "MAC OUI prefix did not match known manufacturer database",
                ],
                explanation=f"Found {unknown_count} device(s) with unidentified MAC vendors at the Data Link layer. This may indicate unauthorized devices or newer hardware not in the vendor database.",
                recommendation="Review unknown devices. Consider enabling MAC filtering or WPA3 on your router.",
            ))

        non_responsive = [d for d in devices if d.get("is_responsive") is False]
        if non_responsive:
            diagnoses.append(Diagnosis(
                title="Non-Responsive Devices in ARP Cache",
                layer="Network", confidence=0.65, severity="low",
                evidence=[
                    f"{len(non_responsive)} in ARP table but not responding to ICMP",
                    f"IPs: {', '.join(d['ip'] for d in non_responsive[:5])}",
                ],
                explanation=f"{len(non_responsive)} device(s) are in the ARP table (Data Link reachable) but don't respond to ICMP ping (Network layer filtered). Likely firewalled or recently disconnected.",
                recommendation="These devices may have ICMP disabled. Investigate if unrecognized.",
            ))

        if total > 15:
            diagnoses.append(Diagnosis(
                title="High Device Count on Local Network",
                layer="Data Link", confidence=0.75, severity="medium",
                evidence=[f"{total} active devices detected", f"Subnet: {scan_data.get('subnet', '?')}.0/24"],
                explanation=f"{total} devices detected, above typical levels. Increases broadcast traffic and attack surface at the Data Link layer.",
                recommendation="Review connected devices. Consider network segmentation with VLANs.",
            ))

        if total > 0 and unknown_count == 0 and not non_responsive:
            diagnoses.append(Diagnosis(
                title="Network Appears Healthy",
                layer="Data Link", confidence=0.80, severity="info",
                evidence=[f"All {total} devices recognized", "All respond to ICMP ping"],
                explanation="No anomalies detected. All devices have known MAC vendors and respond to connectivity checks.",
                recommendation="Continue regular monitoring.",
            ))

        return [d.to_dict() for d in diagnoses]

    def analyze_url_security(self, security_data):
        diagnoses = []
        cert = security_data.get("certificate", {})
        wh = security_data.get("whois", {})
        phishing = security_data.get("phishing_assessment", {})
        url_info = security_data.get("url", {})
        hostname = url_info.get("hostname", "unknown")

        if not url_info.get("is_https"):
            diagnoses.append(Diagnosis(
                title="No HTTPS Encryption", layer="Application",
                confidence=0.95, severity="high",
                evidence=[f"Scheme: {url_info.get('scheme', 'http')}", "Data in cleartext"],
                explanation=f"{hostname} lacks HTTPS. All data is transmitted unencrypted at the Application layer.",
                recommendation="Avoid entering sensitive data. Check for an HTTPS version.",
            ))

        if cert.get("error"):
            diagnoses.append(Diagnosis(
                title="SSL/TLS Certificate Problem", layer="Application",
                confidence=0.90, severity="high",
                evidence=[f"Error: {cert['error']}", f"Host: {hostname}"],
                explanation=f"Certificate verification failed for {hostname}. Server identity cannot be confirmed at the Application layer.",
                recommendation="Do not proceed unless you trust this site completely.",
            ))

        if cert.get("is_expired"):
            diagnoses.append(Diagnosis(
                title="Expired SSL Certificate", layer="Application",
                confidence=0.95, severity="critical",
                evidence=[f"Expired {abs(cert.get('days_until_expiry', 0))} days ago", f"Expiry: {cert.get('not_after', 'N/A')}"],
                explanation=f"The SSL certificate for {hostname} has expired. Identity verification no longer guaranteed.",
                recommendation="Avoid sensitive data entry until the certificate is renewed.",
            ))

        whois_quality = security_data.get("whois_quality", {})
        confidence_modifier = whois_quality.get("confidence_modifier", 1.0)

        risk_score = phishing.get("risk_score", 0)
        risk_level = phishing.get("risk_level", "safe")

        is_institutional = bool(re.search(
            r'\.(edu|gov|mil|ac|k12)(\.[a-z]{2,3})?$', hostname.lower()
        ))

        if whois_quality.get("all_fields_missing") and not is_institutional:
            diagnoses.append(Diagnosis(
                title="WHOIS Data Unavailable — Reduced Confidence",
                layer="Application",
                confidence=0.50,
                severity="medium",
                evidence=["All WHOIS fields returned N/A", "Domain may use a privacy proxy or WHOIS is restricted"],
                explanation=f"No WHOIS data could be retrieved for {hostname}. Domain ownership, registration date, and registrar are all unknown. Confidence in this analysis is reduced to 50%.",
                recommendation="Treat this domain with caution. Verify the site through other means before entering sensitive information.",
            ))

        if whois_quality.get("registrar_missing") and not whois_quality.get("all_fields_missing"):
            diagnoses.append(Diagnosis(
                title="Registrar Information Missing",
                layer="Application",
                confidence=round(0.70 * confidence_modifier, 2),
                severity="low",
                evidence=["Registrar field is empty in WHOIS data"],
                explanation=f"The registrar for {hostname} is not listed in WHOIS records. This may indicate a privacy shield service or incomplete registration data.",
                recommendation="Verify domain ownership through alternative sources.",
            ))

        risk_indicators = [i for i in phishing.get("indicators", []) if i.get("weight", 0) > 0]

        if risk_score >= 30:
            severity = "critical" if risk_score >= 70 else ("high" if risk_score >= 50 else "medium")
            diagnoses.append(Diagnosis(
                title=f"Phishing Risk Detected ({risk_level.title()})", layer="Application",
                confidence=min(0.60 + risk_score * 0.004, 0.95), severity=severity,
                evidence=[f"Risk score: {risk_score}/100"] + [i["signal"] for i in risk_indicators[:5]],
                explanation=f"Multiple signals indicate {hostname} may be malicious. Score: {risk_score}/100 from certificate, domain, and WHOIS analysis at the Application layer.",
                recommendation="Do not enter passwords or personal information. Verify the URL carefully.",
            ))
        elif risk_score >= 10:
            diagnoses.append(Diagnosis(
                title=f"Minor Risk Signals Detected", layer="Application",
                confidence=0.60, severity="low",
                evidence=[f"Risk score: {risk_score}/100"] + [i["signal"] for i in risk_indicators[:3]],
                explanation=f"Some risk signals were found for {hostname} but the overall score is low. Exercise normal caution.",
                recommendation="Probably safe, but verify the URL if anything looks unusual.",
            ))

        if risk_score < 10 and cert.get("valid") and not cert.get("is_expired"):
            diagnoses.append(Diagnosis(
                title="Website Appears Secure", layer="Application",
                confidence=0.85, severity="info",
                evidence=[
                    f"Valid cert from {cert.get('issuer', {}).get('organizationName', 'N/A')}",
                    f"Risk score: {risk_score}/100",
                    f"TLS: {cert.get('protocol_version', 'N/A')}",
                ],
                explanation=f"{hostname} has a valid certificate, zero risk signals, and proper HTTPS at the Application layer.",
                recommendation="Site appears safe. Stay vigilant for unexpected behavior.",
            ))

        return [d.to_dict() for d in diagnoses]

    def analyze_performance(self, perf_data):
        diagnoses = []
        latency = perf_data.get("latency", {})
        connections = perf_data.get("connections", {})
        dns = perf_data.get("dns", {})
        avg_ms = latency.get("avg_ms")
        loss = latency.get("packet_loss_pct")
        jitter = latency.get("jitter_ms")
        host = latency.get("host", "target")
        dns_time = dns.get("resolution_time_ms")

        if avg_ms is not None and avg_ms > 50:
            severity = "high" if avg_ms > 200 else ("medium" if avg_ms > 100 else "low")
            diagnoses.append(Diagnosis(
                title="Elevated Network Latency", layer="Network",
                confidence=0.85, severity=severity,
                evidence=[f"Avg: {avg_ms:.1f} ms to {host}", f"Max: {latency.get('max_ms', 0):.1f} ms"],
                explanation=f"Average RTT of {avg_ms:.1f} ms measured via ICMP at the Network layer. High latency impacts browsing and real-time applications.",
                recommendation="Move closer to Wi-Fi router, use wired connection, or check for bandwidth hogs.",
            ))

        if loss is not None and loss > 0:
            severity = "critical" if loss > 10 else ("high" if loss > 5 else "medium")
            diagnoses.append(Diagnosis(
                title="Packet Loss Detected", layer="Network",
                confidence=0.85, severity=severity,
                evidence=[f"Loss: {loss}%", f"Host: {host}"],
                explanation=f"{loss}% packet loss at the Network layer. Causes TCP retransmissions at Transport layer, degrading performance.",
                recommendation="Check Wi-Fi signal, test with wired connection, contact ISP if persistent.",
            ))

        if jitter is not None and jitter > 30:
            diagnoses.append(Diagnosis(
                title="High Network Jitter", layer="Network",
                confidence=0.75, severity="high" if jitter > 50 else "medium",
                evidence=[f"Jitter: {jitter:.1f} ms", f"Range: {latency.get('min_ms', 0):.1f}–{latency.get('max_ms', 0):.1f} ms"],
                explanation=f"Jitter of {jitter:.1f} ms shows inconsistent packet delivery at the Network layer. Harmful to VoIP and gaming.",
                recommendation="Enable QoS on router, close bandwidth-heavy apps, prefer wired connection.",
            ))

        tcp_count = connections.get("tcp_count", 0)
        if tcp_count > 100:
            diagnoses.append(Diagnosis(
                title="High TCP Connection Count", layer="Transport",
                confidence=0.70, severity="medium" if tcp_count < 200 else "high",
                evidence=[f"TCP: {tcp_count}", f"UDP: {connections.get('udp_count', 0)}"],
                explanation=f"{tcp_count} active TCP connections at the Transport layer. May indicate many open tabs or background services.",
                recommendation="Close unused tabs/apps. Check for unfamiliar remote hosts.",
            ))

        if dns.get("error"):
            diagnoses.append(Diagnosis(
                title="DNS Resolution Failure", layer="Application",
                confidence=0.90, severity="critical",
                evidence=[f"Error: {dns['error']}"],
                explanation="DNS failed at the Application layer. Cannot resolve domain names to IP addresses.",
                recommendation="Check connection. Try public DNS: 8.8.8.8 or 1.1.1.1.",
            ))
        elif dns_time and dns_time > 200:
            diagnoses.append(Diagnosis(
                title="Slow DNS Resolution", layer="Application",
                confidence=0.75, severity="medium" if dns_time > 500 else "low",
                evidence=[f"DNS time: {dns_time:.1f} ms"],
                explanation=f"DNS resolution took {dns_time:.1f} ms at the Application layer. Slow DNS delays every new page load.",
                recommendation="Switch to Cloudflare (1.1.1.1) or Google (8.8.8.8) DNS.",
            ))

        if avg_ms is not None and avg_ms <= 50 and (loss is None or loss == 0) and (jitter is None or jitter <= 30):
            diagnoses.append(Diagnosis(
                title="Network Performance is Healthy", layer="Network",
                confidence=0.85, severity="info",
                evidence=[f"Latency: {avg_ms:.1f} ms", f"Loss: {loss or 0}%", f"DNS: {dns_time:.1f} ms" if dns_time else "DNS: OK"],
                explanation="All metrics within healthy ranges. Network and Transport layers functioning properly.",
                recommendation="No action needed.",
            ))

        return [d.to_dict() for d in diagnoses]

    def analyze_connection_test(self, conn_data):
        diagnoses = []
        target  = conn_data.get("target", {})
        ip      = target.get("ip", "?")
        port    = target.get("port", "?")
        status  = conn_data.get("status", "error")
        latency = conn_data.get("latency_ms")
        layers  = conn_data.get("layer_analysis", {})

        if status == "connected":
            sev = "info" if (latency or 0) < 100 else "low"
            diagnoses.append(Diagnosis(
                title=f"Port {port} Open — Connection Successful",
                layer="Transport", confidence=0.99, severity=sev,
                evidence=[
                    f"TCP handshake completed in {latency} ms",
                    f"L3: {layers.get('L3_network', 'OK')}",
                    f"L4: {layers.get('L4_transport', 'OPEN')}",
                ],
                explanation=f"TCP connection to {ip}:{port} succeeded at the Transport layer. All layers L1–L4 are functional.",
                recommendation="Service is reachable. If unexpected, verify whether this port should be publicly accessible.",
            ))
            if latency and latency > 200:
                diagnoses.append(Diagnosis(
                    title="High Connection Latency",
                    layer="Network", confidence=0.80, severity="medium",
                    evidence=[f"RTT: {latency} ms"],
                    explanation=f"Connection succeeded but RTT of {latency} ms is high. Network layer routing may be suboptimal.",
                    recommendation="Check routing path, consider CDN or closer server.",
                ))

        elif status == "refused":
            diagnoses.append(Diagnosis(
                title=f"Port {port} Closed — Connection Refused",
                layer="Transport", confidence=0.97, severity="medium",
                evidence=[
                    "TCP RST packet received",
                    f"L3: {layers.get('L3_network', 'OK')}",
                    f"L4: {layers.get('L4_transport', 'CLOSED')}",
                ],
                explanation=f"Host {ip} is reachable at L1–L3 but port {port} is CLOSED at the Transport layer. No service is listening on this port.",
                recommendation=f"Verify the service is running on {ip}. Check if the correct port number is being used.",
            ))

        elif status == "timeout":
            diagnoses.append(Diagnosis(
                title=f"Port {port} Filtered — Connection Timed Out",
                layer="Transport", confidence=0.85, severity="high",
                evidence=[
                    "No TCP response received within timeout",
                    f"L3: {layers.get('L3_network', 'SUSPECT')}",
                    f"L4: {layers.get('L4_transport', 'FILTERED')}",
                ],
                explanation=f"TCP SYN packets to {ip}:{port} received no response. A firewall is silently dropping packets at the Network or Transport layer.",
                recommendation=f"Check firewall rules on {ip} and any intermediate routers. Add an inbound rule for port {port} if the service should be accessible.",
            ))

        elif status == "unreachable":
            diagnoses.append(Diagnosis(
                title=f"Host Unreachable — L3 Routing Failure",
                layer="Network", confidence=0.90, severity="high",
                evidence=[
                    f"No route to {ip}",
                    f"L2: {layers.get('L2_datalink', 'FAIL')}",
                    f"L3: {layers.get('L3_network', 'FAIL')}",
                ],
                explanation=f"The host {ip} cannot be reached at the Network layer. The routing table has no path to this address, or the host is offline.",
                recommendation="Verify the IP address is correct. Check if the host is powered on and connected. Confirm you are on the correct network/subnet.",
            ))

        else:
            diagnoses.append(Diagnosis(
                title="Connection Test Error",
                layer="Network", confidence=0.60, severity="medium",
                evidence=[conn_data.get("error", "Unknown error")],
                explanation="An unexpected error occurred during the TCP connection test.",
                recommendation="Verify the IP address format and try again.",
            ))

        return [d.to_dict() for d in diagnoses]


# ──────────────────────────────────────────────────────────────
#  Main Engine (API-first with rule-based fallback)
# ──────────────────────────────────────────────────────────────

_fallback = RuleBasedFallback()


class AIReasoningCore:
    """
    AI reasoning engine that calls Claude API for analysis,
    falling back to deterministic rules if API is unavailable.
    """

    def __init__(self):
        self.api_available = bool(os.environ.get("GEMINI_API_KEY"))

    def _analyze(self, module, data, fallback_method):
        """Try API first, fall back to rules."""
        if self.api_available:
            result = _call_gemini(module, data)
            if result is not None:
                return result
        return fallback_method(data)

    def analyze_network_scan(self, scan_data):
        return self._analyze("detective", scan_data, _fallback.analyze_network_scan)

    def analyze_url_security(self, security_data):
        return self._analyze("security", security_data, _fallback.analyze_url_security)

    def analyze_performance(self, perf_data):
        return self._analyze("performance", perf_data, _fallback.analyze_performance)

    def analyze_connection_test(self, conn_data):
        return self._analyze("connection", conn_data, _fallback.analyze_connection_test)

    def get_mode(self):
        """Return current reasoning mode for UI display."""
        if self.api_available:
            return "gemini-api"
        return "fallback-no-key"


# Singleton instance
ai_engine = AIReasoningCore()
