"""
Security Hunter Module
Evaluates URL security by analyzing HTTPS certificate metadata
and WHOIS information to produce a phishing risk assessment.
Operates at L7: HTTP/HTTPS, DNS, WHOIS (Application Layer)
"""

import ssl
import socket
import re
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


def parse_url(url):
    """Normalize and parse a URL, extracting the hostname."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return {
        "original": url,
        "scheme": parsed.scheme,
        "hostname": hostname,
        "port": port,
        "path": parsed.path,
        "is_https": parsed.scheme == "https",
    }


def check_ssl_certificate(hostname, port=443, timeout=5):
    """Retrieve and analyze SSL/TLS certificate for a hostname."""
    cert_info = {
        "valid": False,
        "error": None,
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "is_expired": False,
        "san_domains": [],
        "serial_number": None,
        "version": None,
        "protocol_version": None,
        "cipher": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher_info = ssock.cipher()
                protocol = ssock.version()

                # Subject
                subject_dict = {}
                for field in cert.get("subject", ()):
                    for key, value in field:
                        subject_dict[key] = value
                cert_info["subject"] = subject_dict

                # Issuer
                issuer_dict = {}
                for field in cert.get("issuer", ()):
                    for key, value in field:
                        issuer_dict[key] = value
                cert_info["issuer"] = issuer_dict

                # Validity dates
                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)

                cert_info["not_before"] = not_before.isoformat()
                cert_info["not_after"] = not_after.isoformat()
                cert_info["days_until_expiry"] = (not_after - now).days
                cert_info["is_expired"] = now > not_after

                # SAN (Subject Alternative Names)
                san_list = cert.get("subjectAltName", ())
                cert_info["san_domains"] = [val for typ, val in san_list if typ == "DNS"]

                cert_info["serial_number"] = cert.get("serialNumber")
                cert_info["version"] = cert.get("version")
                cert_info["protocol_version"] = protocol
                cert_info["cipher"] = cipher_info[0] if cipher_info else None
                cert_info["valid"] = True

    except ssl.SSLCertVerificationError as e:
        cert_info["error"] = f"Certificate verification failed: {e.verify_message}"
        # Try without verification to get cert details anyway
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cert_info["valid"] = False
        except Exception:
            pass

    except ssl.SSLError as e:
        cert_info["error"] = f"SSL error: {str(e)}"
    except socket.timeout:
        cert_info["error"] = "Connection timed out"
    except socket.gaierror:
        cert_info["error"] = f"DNS resolution failed for {hostname}"
    except ConnectionRefusedError:
        cert_info["error"] = f"Connection refused by {hostname}:{port}"
    except Exception as e:
        cert_info["error"] = f"Unexpected error: {str(e)}"

    return cert_info


def check_whois(domain, timeout=10):
    """Retrieve WHOIS information for a domain."""
    whois_info = {
        "available": False,
        "error": None,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "domain_age_days": None,
        "registrant_country": None,
        "name_servers": [],
        "dnssec": None,
    }

    if not WHOIS_AVAILABLE:
        whois_info["error"] = "python-whois package not installed"
        return whois_info

    # Extract root domain (strip subdomains like www)
    parts = domain.split(".")
    if len(parts) > 2:
        # Handle cases like co.uk, com.tr etc.
        root_domain = ".".join(parts[-2:])
    else:
        root_domain = domain

    try:
        w = whois.whois(root_domain)
        whois_info["available"] = True
        whois_info["registrar"] = w.registrar

        # Handle creation date
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if isinstance(creation, str):
                try:
                    creation = datetime.fromisoformat(creation)
                except ValueError:
                    creation = None
            if creation:
                whois_info["creation_date"] = creation.isoformat()
                age = (datetime.now() - creation.replace(tzinfo=None)).days
                whois_info["domain_age_days"] = age

        # Handle expiration date
        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]
        if expiration:
            if isinstance(expiration, str):
                try:
                    expiration = datetime.fromisoformat(expiration)
                except ValueError:
                    expiration = None
            if expiration:
                whois_info["expiration_date"] = expiration.isoformat()

        whois_info["registrant_country"] = getattr(w, "country", None)
        ns = w.name_servers
        if ns:
            whois_info["name_servers"] = list(ns) if isinstance(ns, (list, set)) else [ns]
        whois_info["dnssec"] = getattr(w, "dnssec", None)

    except Exception as e:
        whois_info["error"] = str(e)

    return whois_info


_NA_STRINGS = {"n/a", "none", "unknown", "redacted", "redacted for privacy",
               "not disclosed", "withheld", "data protected", "privacy protected", ""}


def _is_na_value(value):
    """Return True if a WHOIS field value is effectively empty/N/A."""
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() in _NA_STRINGS
    return False


def compute_phishing_indicators(hostname, cert_info, whois_info):
    """Analyze multiple signals to compute phishing risk indicators."""
    indicators = []
    score_breakdown = {}  # for logging

    # ── Rule 1: SSL Invalid → +40 ────────────────────────────────
    ssl_invalid = bool(cert_info.get("error")) or not cert_info.get("valid")
    if ssl_invalid:
        weight = 40
        score_breakdown["ssl_invalid"] = weight
        indicators.append({
            "signal": "SSL certificate invalid or missing",
            "detail": cert_info.get("error") or "Certificate is not valid",
            "weight": weight,
            "category": "certificate"
        })

    if cert_info.get("is_expired"):
        indicators.append({
            "signal": "Expired SSL certificate",
            "detail": f"Expired {abs(cert_info.get('days_until_expiry', 0))} days ago",
            "weight": 0,  # already counted in ssl_invalid
            "category": "certificate"
        })

    if cert_info.get("days_until_expiry") is not None and 0 < cert_info["days_until_expiry"] < 30:
        w = 10
        score_breakdown["cert_expiring_soon"] = w
        indicators.append({
            "signal": "Certificate expiring soon",
            "detail": f"Expires in {cert_info['days_until_expiry']} days",
            "weight": w,
            "category": "certificate"
        })

    issuer = cert_info.get("issuer") or {}
    org = issuer.get("organizationName", "")
    known_cas = ["Let's Encrypt", "DigiCert", "Comodo", "GlobalSign",
                 "Sectigo", "GeoTrust", "Thawte", "VeriSign",
                 "Amazon", "Google Trust Services", "Cloudflare",
                 "Microsoft", "Baltimore", "ISRG"]
    if org and not any(ca.lower() in org.lower() for ca in known_cas):
        w = 15
        score_breakdown["uncommon_ca"] = w
        indicators.append({
            "signal": "Uncommon certificate authority",
            "detail": f"Issuer: {org}",
            "weight": w,
            "category": "certificate"
        })

    # ── Rule 4: DNS resolution fail → +30 ────────────────────────
    dns_failed = "DNS resolution failed" in (cert_info.get("error") or "")
    if dns_failed:
        w = 30
        score_breakdown["dns_resolution_fail"] = w
        indicators.append({
            "signal": "DNS resolution failed",
            "detail": f"Could not resolve hostname: {hostname}",
            "weight": w,
            "category": "dns"
        })

    # ── Rule 2: WHOIS all N/A → +20 ──────────────────────────────
    whois_fields = [
        whois_info.get("registrar"),
        whois_info.get("creation_date"),
        whois_info.get("expiration_date"),
        whois_info.get("registrant_country"),
        whois_info.get("domain_age_days"),
    ]
    whois_all_na = whois_info.get("available") and all(_is_na_value(f) for f in whois_fields)
    if whois_all_na:
        w = 20
        score_breakdown["whois_all_na"] = w
        indicators.append({
            "signal": "All WHOIS data unavailable (N/A)",
            "detail": "Every WHOIS field returned N/A — privacy proxy or restricted registry",
            "weight": w,
            "category": "whois"
        })
    elif not whois_info.get("available") and whois_info.get("error"):
        w = 20
        score_breakdown["whois_lookup_failed"] = w
        indicators.append({
            "signal": "WHOIS lookup failed",
            "detail": whois_info["error"],
            "weight": w,
            "category": "whois"
        })

    # ── Rule 3: Phishing signals → add directly ──────────────────
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
        w = 20
        score_breakdown["ip_as_hostname"] = w
        indicators.append({
            "signal": "IP address used instead of domain name",
            "detail": "Legitimate sites use domain names",
            "weight": w,
            "category": "domain"
        })

    suspicious_keywords = ["login", "secure", "account", "verify", "update",
                           "confirm", "banking", "paypal", "signin", "password"]
    found_keywords = [kw for kw in suspicious_keywords if kw in hostname.lower()]
    if found_keywords and len(hostname.split('.')) > 3:
        w = 20
        score_breakdown["suspicious_keywords"] = w
        indicators.append({
            "signal": "Suspicious keywords in subdomain-heavy URL",
            "detail": f"Keywords: {', '.join(found_keywords)}; depth: {len(hostname.split('.'))}",
            "weight": w,
            "category": "domain"
        })

    if len(hostname.split('.')) > 4:
        w = 10
        score_breakdown["excessive_subdomains"] = w
        indicators.append({
            "signal": "Excessive subdomain depth",
            "detail": f"{len(hostname.split('.'))} subdomain levels",
            "weight": w,
            "category": "domain"
        })

    if re.search(r'[0-9]', hostname.split('.')[0]) and re.search(r'[a-z]', hostname.split('.')[0]):
        if len(hostname.split('.')[0]) > 10:
            w = 10
            score_breakdown["mixed_alphanumeric"] = w
            indicators.append({
                "signal": "Mixed alphanumeric hostname",
                "detail": "May indicate randomly generated domain",
                "weight": w,
                "category": "domain"
            })

    if whois_info.get("available") and not whois_all_na:
        if _is_na_value(whois_info.get("registrar")):
            w = 15
            score_breakdown["registrar_missing"] = w
            indicators.append({
                "signal": "Registrar information missing",
                "detail": "No registrar in WHOIS — privacy shield or suspicious registration",
                "weight": w,
                "category": "whois"
            })

        age = whois_info.get("domain_age_days")
        if age is not None:
            if age < 30:
                w = 25
                score_breakdown["domain_very_new"] = w
                indicators.append({"signal": "Very recently registered domain", "detail": f"{age} days old", "weight": w, "category": "whois"})
            elif age < 180:
                w = 10
                score_breakdown["domain_new_6mo"] = w
                indicators.append({"signal": "Recently registered domain", "detail": f"{age} days old (< 6 months)", "weight": w, "category": "whois"})
            elif age < 365:
                w = 5
                score_breakdown["domain_under_1yr"] = w
                indicators.append({"signal": "Domain younger than 1 year", "detail": f"{age} days old", "weight": w, "category": "whois"})

    # ── Positive indicators ───────────────────────────────────────
    if cert_info.get("valid") and not cert_info.get("is_expired"):
        w = -10
        score_breakdown["valid_ssl"] = w
        indicators.append({"signal": "Valid SSL certificate", "detail": f"Valid until {cert_info.get('not_after', 'N/A')}", "weight": w, "category": "positive"})

    age_days = whois_info.get("domain_age_days")
    if age_days and age_days > 365:
        w = -15
        score_breakdown["established_domain"] = w
        indicators.append({"signal": "Established domain", "detail": f"{age_days // 365} years old", "weight": w, "category": "positive"})

    # ── Final score ───────────────────────────────────────────────
    risk_score = max(0, min(100, sum(score_breakdown.values())))

    logger.debug(
        "[SecurityHunter] %s | score=%d/100 | breakdown=%s",
        hostname, risk_score, score_breakdown
    )

    return indicators, risk_score


def analyze_url(url):
    """
    Full URL security analysis combining SSL cert check,
    WHOIS lookup, and phishing risk assessment.
    """
    parsed = parse_url(url)
    hostname = parsed["hostname"]

    if not hostname:
        return {"error": "Invalid URL: could not extract hostname"}

    cert_info = check_ssl_certificate(hostname, parsed["port"])
    whois_info = check_whois(hostname)
    indicators, risk_score = compute_phishing_indicators(hostname, cert_info, whois_info)

    # Determine risk level
    if risk_score >= 70:
        risk_level = "critical"
    elif risk_score >= 50:
        risk_level = "high"
    elif risk_score >= 30:
        risk_level = "medium"
    elif risk_score >= 10:
        risk_level = "low"
    else:
        risk_level = "safe"

    # Assess WHOIS data quality — detect all-N/A situation
    # Uses _is_na_value to catch literal "N/A", "REDACTED FOR PRIVACY" etc.
    whois_fields = [
        whois_info.get("registrar"),
        whois_info.get("creation_date"),
        whois_info.get("expiration_date"),
        whois_info.get("registrant_country"),
        whois_info.get("domain_age_days"),
    ]
    whois_all_na = whois_info.get("available") and all(_is_na_value(f) for f in whois_fields)
    whois_quality = {
        "all_fields_missing": whois_all_na,
        "registrar_missing": _is_na_value(whois_info.get("registrar")),
        "domain_age_missing": whois_info.get("domain_age_days") is None,
        "confidence_modifier": 0.5 if whois_all_na else 1.0,
        "note": (
            "All WHOIS fields returned N/A — confidence reduced to 50%. "
            "Domain may use a privacy proxy or WHOIS may be restricted."
        ) if whois_all_na else None,
    }

    return {
        "url": parsed,
        "certificate": cert_info,
        "whois": whois_info,
        "whois_quality": whois_quality,
        "phishing_assessment": {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "indicators": indicators,
        }
    }
