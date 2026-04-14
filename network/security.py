"""
Security Hunter Module
Evaluates URL security by analyzing HTTPS certificate metadata
and WHOIS information to produce a phishing risk assessment.
Operates at L7: HTTP/HTTPS, DNS, WHOIS (Application Layer)
"""

import ssl
import socket
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

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


def compute_phishing_indicators(hostname, cert_info, whois_info):
    """Analyze multiple signals to compute phishing risk indicators."""
    indicators = []
    risk_score = 0  # 0-100

    # --- Certificate-based indicators ---
    if cert_info.get("error"):
        indicators.append({
            "signal": "SSL certificate error",
            "detail": cert_info["error"],
            "weight": 25,
            "category": "certificate"
        })
        risk_score += 25

    if cert_info.get("is_expired"):
        indicators.append({
            "signal": "Expired SSL certificate",
            "detail": f"Certificate expired. Days past expiry: {abs(cert_info.get('days_until_expiry', 0))}",
            "weight": 30,
            "category": "certificate"
        })
        risk_score += 30

    if cert_info.get("days_until_expiry") is not None:
        if 0 < cert_info["days_until_expiry"] < 30:
            indicators.append({
                "signal": "Certificate expiring soon",
                "detail": f"Expires in {cert_info['days_until_expiry']} days",
                "weight": 10,
                "category": "certificate"
            })
            risk_score += 10

    issuer = cert_info.get("issuer", {})
    if issuer:
        org = issuer.get("organizationName", "")
        known_cas = ["Let's Encrypt", "DigiCert", "Comodo", "GlobalSign",
                     "Sectigo", "GeoTrust", "Thawte", "VeriSign",
                     "Amazon", "Google Trust Services", "Cloudflare",
                     "Microsoft", "Baltimore", "ISRG"]
        is_known_ca = any(ca.lower() in org.lower() for ca in known_cas)
        if not is_known_ca and org:
            indicators.append({
                "signal": "Uncommon certificate authority",
                "detail": f"Issuer: {org}",
                "weight": 15,
                "category": "certificate"
            })
            risk_score += 15

    # --- Domain-based indicators ---
    # Check for IP address as hostname
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
        indicators.append({
            "signal": "IP address used instead of domain name",
            "detail": "Legitimate sites typically use domain names",
            "weight": 20,
            "category": "domain"
        })
        risk_score += 20

    # Check for suspicious domain patterns
    suspicious_keywords = ["login", "secure", "account", "verify", "update",
                          "confirm", "banking", "paypal", "signin", "password"]
    hostname_lower = hostname.lower()
    found_keywords = [kw for kw in suspicious_keywords if kw in hostname_lower]
    if found_keywords and len(hostname.split('.')) > 3:
        indicators.append({
            "signal": "Suspicious keywords in subdomain-heavy URL",
            "detail": f"Keywords found: {', '.join(found_keywords)}; subdomain depth: {len(hostname.split('.'))}",
            "weight": 20,
            "category": "domain"
        })
        risk_score += 20

    # Excessive subdomain depth
    if len(hostname.split('.')) > 4:
        indicators.append({
            "signal": "Excessive subdomain depth",
            "detail": f"Domain has {len(hostname.split('.'))} levels, which is unusual",
            "weight": 10,
            "category": "domain"
        })
        risk_score += 10

    # Homograph / typosquatting patterns
    if re.search(r'[0-9]', hostname.split('.')[0]) and re.search(r'[a-z]', hostname.split('.')[0]):
        if len(hostname.split('.')[0]) > 10:
            indicators.append({
                "signal": "Mixed alphanumeric hostname",
                "detail": "Long hostnames mixing letters and numbers may indicate randomly generated domains",
                "weight": 10,
                "category": "domain"
            })
            risk_score += 10

    # --- WHOIS-based indicators ---
    if whois_info.get("available"):
        age = whois_info.get("domain_age_days")
        if age is not None:
            if age < 30:
                indicators.append({
                    "signal": "Very recently registered domain",
                    "detail": f"Domain is only {age} days old",
                    "weight": 25,
                    "category": "whois"
                })
                risk_score += 25
            elif age < 180:
                indicators.append({
                    "signal": "Recently registered domain",
                    "detail": f"Domain is {age} days old (< 6 months)",
                    "weight": 10,
                    "category": "whois"
                })
                risk_score += 10
    elif whois_info.get("error"):
        indicators.append({
            "signal": "WHOIS lookup failed",
            "detail": whois_info["error"],
            "weight": 5,
            "category": "whois"
        })
        risk_score += 5

    # --- Positive indicators (reduce risk) ---
    if cert_info.get("valid") and not cert_info.get("is_expired"):
        indicators.append({
            "signal": "Valid SSL certificate",
            "detail": f"Certificate valid until {cert_info.get('not_after', 'N/A')}",
            "weight": -10,
            "category": "positive"
        })
        risk_score -= 10

    if whois_info.get("domain_age_days") and whois_info["domain_age_days"] > 365:
        indicators.append({
            "signal": "Established domain",
            "detail": f"Domain is {whois_info['domain_age_days'] // 365} years old",
            "weight": -15,
            "category": "positive"
        })
        risk_score -= 15

    risk_score = max(0, min(100, risk_score))

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

    return {
        "url": parsed,
        "certificate": cert_info,
        "whois": whois_info,
        "phishing_assessment": {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "indicators": indicators,
        }
    }
