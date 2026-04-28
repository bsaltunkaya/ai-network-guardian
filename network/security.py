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
    """Analyze multiple signals to compute phishing risk indicators.

    Scoring philosophy: risk signals are never fully cancelled by positive
    indicators.  Positive indicators can reduce the score by at most 50% of
    the negative (risk) total, so a site with ANY risk signal can never reach
    score 0.  Multiple weak signals amplify each other.
    """
    indicators = []
    risk_points = {}    # positive values = risk
    bonus_points = {}   # negative values = trust

    # helper to record a risk signal
    def _risk(key, weight, signal, detail, category):
        risk_points[key] = weight
        indicators.append({"signal": signal, "detail": detail,
                           "weight": weight, "category": category})

    def _bonus(key, weight, signal, detail):
        bonus_points[key] = weight
        indicators.append({"signal": signal, "detail": detail,
                           "weight": weight, "category": "positive"})

    # ── 1. Certificate problems ───────────────────────────────────
    ssl_invalid = bool(cert_info.get("error")) or not cert_info.get("valid")
    if ssl_invalid:
        _risk("ssl_invalid", 40,
              "SSL certificate invalid or missing",
              cert_info.get("error") or "Certificate is not valid",
              "certificate")

    if cert_info.get("is_expired"):
        _risk("cert_expired", 15,
              "Expired SSL certificate",
              f"Expired {abs(cert_info.get('days_until_expiry', 0))} days ago",
              "certificate")

    if cert_info.get("days_until_expiry") is not None and 0 < cert_info["days_until_expiry"] < 30:
        _risk("cert_expiring_soon", 10,
              "Certificate expiring soon",
              f"Expires in {cert_info['days_until_expiry']} days",
              "certificate")

    # ── 2. TLS version analysis ───────────────────────────────────
    tls_ver = (cert_info.get("protocol_version") or "").upper()
    if tls_ver and tls_ver != "TLSV1.3":
        w = 5 if "1.2" in tls_ver else 15
        _risk("old_tls", w,
              f"Outdated TLS version ({cert_info.get('protocol_version')})",
              "Modern sites use TLS 1.3; older versions have known weaknesses",
              "certificate")

    # ── Institutional TLD detection (.edu.*, .gov.*, .mil.*) ──────
    _institutional_tld = re.search(
        r'\.(edu|gov|mil|ac|k12)(\.[a-z]{2,3})?$', hostname.lower()
    )
    is_institutional = bool(_institutional_tld)

    # ── 3. Wildcard certificate detection ─────────────────────────
    san_domains = cert_info.get("san_domains") or []
    subject_cn = (cert_info.get("subject") or {}).get("commonName", "")
    is_wildcard = subject_cn.startswith("*.") or any(d.startswith("*.") for d in san_domains)
    if is_wildcard and not is_institutional:
        num_sans = len(san_domains)
        if num_sans <= 5:
            _risk("wildcard_cert", 10,
                  "Wildcard certificate detected",
                  f"Cert covers {subject_cn} -- one cert can serve unlimited subdomains",
                  "certificate")

    # ── 4. Free / DV-only CA detection ────────────────────────────
    issuer = cert_info.get("issuer") or {}
    org = issuer.get("organizationName", "")
    free_cas = ["Let's Encrypt", "ISRG", "ZeroSSL", "Buypass"]
    premium_cas = ["DigiCert", "Comodo", "GlobalSign", "Sectigo",
                   "GeoTrust", "Thawte", "VeriSign", "Amazon",
                   "Google Trust Services", "Cloudflare", "Microsoft",
                   "Baltimore", "Entrust"]
    gov_cas = ["TUBITAK", "Kamu Sertifikasyon", "HARICA", "CFCA",
               "SECOM", "CNNIC", "ACCV", "AC Camerfirma",
               "Government", "Federal PKI"]
    is_free_ca = any(ca.lower() in org.lower() for ca in free_cas) if org else False
    is_gov_ca = any(ca.lower() in org.lower() for ca in gov_cas) if org else False
    is_known_ca = is_free_ca or is_gov_ca or (any(ca.lower() in org.lower() for ca in premium_cas) if org else False)

    if is_free_ca:
        _risk("free_ca", 5,
              "Free/DV-only certificate authority",
              f"Issuer: {org} -- no organization validation performed",
              "certificate")
    elif org and not is_known_ca:
        _risk("uncommon_ca", 15,
              "Uncommon certificate authority",
              f"Issuer: {org}",
              "certificate")

    # ── 5. DNS resolution failure ─────────────────────────────────
    if "DNS resolution failed" in (cert_info.get("error") or ""):
        _risk("dns_fail", 30,
              "DNS resolution failed",
              f"Could not resolve hostname: {hostname}",
              "dns")

    # ── 6. WHOIS signals ─────────────────────────────────────────
    whois_fields = [
        whois_info.get("registrar"),
        whois_info.get("creation_date"),
        whois_info.get("expiration_date"),
        whois_info.get("registrant_country"),
        whois_info.get("domain_age_days"),
    ]
    whois_all_na = whois_info.get("available") and all(_is_na_value(f) for f in whois_fields)

    if whois_all_na and not is_institutional:
        _risk("whois_all_na", 20,
              "All WHOIS data unavailable (N/A)",
              "Every WHOIS field returned N/A -- privacy proxy or restricted registry",
              "whois")
    elif not whois_info.get("available") and whois_info.get("error") and not is_institutional:
        _risk("whois_failed", 20,
              "WHOIS lookup failed", whois_info["error"], "whois")

    if whois_info.get("available") and not whois_all_na:
        if _is_na_value(whois_info.get("registrar")):
            _risk("registrar_missing", 15,
                  "Registrar information missing",
                  "No registrar in WHOIS -- privacy shield or suspicious registration",
                  "whois")

        age = whois_info.get("domain_age_days")
        if age is not None:
            if age < 30:
                _risk("domain_very_new", 25,
                      "Very recently registered domain",
                      f"{age} days old", "whois")
            elif age < 180:
                _risk("domain_new_6mo", 10,
                      "Recently registered domain",
                      f"{age} days old (< 6 months)", "whois")
            elif age < 365:
                _risk("domain_under_1yr", 5,
                      "Domain younger than 1 year",
                      f"{age} days old", "whois")

    # ── 7. Domain / hostname signals ──────────────────────────────
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
        _risk("ip_hostname", 20,
              "IP address used instead of domain name",
              "Legitimate sites use domain names", "domain")

    # Suspicious keywords -- split into high-threat and moderate
    high_threat_kw = ["phishing", "malware", "hack", "spoof", "fraud",
                      "scam", "exploit", "trojan", "ransomware"]
    moderate_kw = ["login", "secure", "account", "verify", "update",
                   "confirm", "banking", "paypal", "signin", "password",
                   "wallet", "crypto", "authenticate"]
    found_high = [kw for kw in high_threat_kw if kw in hostname.lower()]
    found_mod = [kw for kw in moderate_kw if kw in hostname.lower()]

    if found_high:
        _risk("high_threat_keywords", 45,
              "High-threat keywords in domain name",
              f"Keywords: {', '.join(found_high)}",
              "domain")
    if found_mod:
        deep = len(hostname.split('.')) > 3
        w = 30 if deep else 20
        _risk("suspicious_keywords", w,
              "Suspicious keywords in domain name",
              f"Keywords: {', '.join(found_mod)}; depth: {len(hostname.split('.'))}",
              "domain")

    # Subdomain impersonation: suspicious subdomain on unrelated parent
    parts = hostname.lower().split('.')
    if len(parts) >= 3:
        subdomain = parts[0]
        parent = '.'.join(parts[-2:])
        all_threat_kw = high_threat_kw + moderate_kw
        sub_has_keyword = any(kw in subdomain for kw in all_threat_kw)
        parent_has_keyword = any(kw in parent for kw in all_threat_kw)
        if sub_has_keyword and not parent_has_keyword:
            _risk("subdomain_impersonation", 15,
                  "Suspicious subdomain on unrelated parent domain",
                  f"Subdomain '{subdomain}' contains threat keywords but parent '{parent}' does not",
                  "domain")

    if len(parts) > 4:
        _risk("excessive_subdomains", 10,
              "Excessive subdomain depth",
              f"{len(parts)} subdomain levels", "domain")

    if re.search(r'[0-9]', parts[0]) and re.search(r'[a-z]', parts[0]) and len(parts[0]) > 10:
        _risk("mixed_alphanum", 10,
              "Mixed alphanumeric hostname",
              "May indicate randomly generated domain", "domain")

    # ── 8. Government impersonation ──────────────────────────────
    gov_terms = ["gov", "government", "federal", "irs", "ssa", "medicare"]
    has_gov_term = any(t in hostname.lower() for t in gov_terms)
    is_real_gov = hostname.lower().endswith(".gov") or re.search(r'\.gov\.[a-z]{2,3}$', hostname.lower())
    if has_gov_term and not is_real_gov and not is_institutional:
        _risk("gov_impersonation", 35,
              "Government impersonation detected",
              f"Domain contains '{next(t for t in gov_terms if t in hostname.lower())}' but is not a .gov site",
              "domain")

    # ── 9. Scam bait keywords ─────────────────────────────────────
    bait_kw = ["free", "iphone", "tablet", "prize", "winner", "gift",
               "giveaway", "reward", "bonus", "cashapp", "venmo"]
    found_bait = [kw for kw in bait_kw if kw in hostname.lower()]
    if found_bait:
        w = 30 if len(found_bait) >= 2 else 20
        _risk("scam_bait", w,
              "Scam bait keywords in domain name",
              f"Keywords: {', '.join(found_bait)}",
              "domain")

    # ── 10. Multi-domain SAN analysis ─────────────────────────────
    # One cert covering many unrelated domains = scam network
    if san_domains:
        unique_roots = set()
        for san in san_domains:
            san_clean = san.lstrip("*.")
            san_parts = san_clean.split(".")
            if len(san_parts) >= 2:
                unique_roots.add(".".join(san_parts[-2:]))
        if len(unique_roots) >= 3:
            _risk("multi_domain_cert", 25,
                  "Certificate covers multiple unrelated domains",
                  f"{len(unique_roots)} different domains on one cert: {', '.join(sorted(unique_roots)[:5])}",
                  "certificate")

    # ── 11. Compound signal amplification ─────────────────────────
    has_risk_keywords = any(k in risk_points for k in
        ["high_threat_keywords", "suspicious_keywords", "scam_bait", "gov_impersonation"])
    if is_wildcard and is_free_ca and has_risk_keywords:
        _risk("phishing_infra", 15,
              "Phishing infrastructure pattern detected",
              "Wildcard cert + free CA + suspicious domain -- classic phishing setup",
              "compound")

    # ── 9. Positive indicators ────────────────────────────────────
    if cert_info.get("valid") and not cert_info.get("is_expired"):
        _bonus("valid_ssl", -10,
               "Valid SSL certificate",
               f"Valid until {cert_info.get('not_after', 'N/A')}")

    age_days = whois_info.get("domain_age_days")
    if age_days and age_days > 365:
        _bonus("established_domain", -15,
               "Established domain",
               f"{age_days // 365} years old")

    if org and any(ca.lower() in org.lower() for ca in premium_cas):
        _bonus("premium_ca", -5,
               "Premium certificate authority",
               f"Issuer: {org}")

    if is_gov_ca:
        _bonus("gov_ca", -10,
               "Government/institutional certificate authority",
               f"Issuer: {org}")

    if is_institutional:
        _bonus("institutional_tld", -15,
               "Institutional domain (edu/gov/mil)",
               f"Domain: {hostname}")

    # ── 10. Final score ───────────────────────────────────────────
    # Positive indicators can reduce risk by at most 50%
    raw_risk = sum(risk_points.values())
    raw_bonus = abs(sum(bonus_points.values()))
    capped_bonus = min(raw_bonus, raw_risk * 0.5)
    risk_score = max(0, min(100, round(raw_risk - capped_bonus)))

    score_breakdown = {**risk_points, **bonus_points, "_capped_bonus": -capped_bonus}

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
