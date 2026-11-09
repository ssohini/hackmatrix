import socket
import ssl
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509.oid import NameOID

WEAK_SIG_ALGS = {"md5WithRSAEncryption", "sha1WithRSAEncryption", "md2WithRSAEncryption", "sha1WithDSA", "ecdsa-with-SHA1"}

def _name_to_str(name):
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)

def analyze(hostname: str, port: int = 443):
    signals = []
    score = 100
    details = {"hostname": hostname, "port": port, "has_cert": False, "issuer": "", "subject": "", "not_before": "", "not_after": "", "serial": "", "fingerprint": "", "key_type": "", "key_size": 0, "sig_alg": "", "san": [], "chain_verified": False, "issues": []}
    issues = details["issues"]

    # First, check HTTPS reachability and TLS
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    cert_pem = None
    chain_verified = False
    try:
        with socket.create_connection((hostname, port), timeout=12) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                chain_verified = True
                cert_bin = ssock.getpeercert(binary_form=True)
                cert_pem = ssl.DER_cert_to_PEM_cert(cert_bin)
                # try chain
                try:
                    chain = ssock.getpeercert_chain() if hasattr(ssock, "getpeercert_chain") else None
                    if chain:
                        details["chain_length"] = len(chain)
                except Exception:
                    pass
                tls_version = ssock.version()
                cipher = ssock.cipher()
                details["tls_version"] = tls_version
                details["cipher"] = cipher[0] if cipher else None
                if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    score -= 25
                    issues.append(f"Weak TLS version {tls_version}")
                    signals.append({"name": "TLS version", "detail": tls_version, "state": "bad", "category": "Certificate", "impact": -25})
                else:
                    signals.append({"name": "TLS version", "detail": tls_version, "state": "good", "category": "Certificate", "impact": 0})
    except ssl.SSLCertVerificationError as e:
        issues.append(f"Certificate verification failed: {e}")
        signals.append({"name": "Chain verification", "detail": str(e)[:120], "state": "bad", "category": "Certificate", "impact": -40})
        score -= 40
        # still try to fetch cert without verification
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=12) as sock:
                with ctx2.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert_bin)
        except Exception:
            pass
    except Exception as e:
        issues.append(f"Connection failed: {e}")
        signals.append({"name": "TLS connection", "detail": str(e)[:120], "state": "bad", "category": "Certificate", "impact": -30})
        score -= 30
        # fallback unverified fetch
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=12) as sock:
                with ctx2.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert_bin)
        except Exception:
            pass

    details["chain_verified"] = chain_verified
    if chain_verified:
        signals.append({"name": "Chain verification", "detail": "Certificate chain verified", "state": "good", "category": "Certificate", "impact": 0})
    else:
        if not any(s["name"] == "Chain verification" for s in signals):
            signals.append({"name": "Chain verification", "detail": "Not verified", "state": "bad", "category": "Certificate", "impact": -20})
            score -= 20

    if not cert_pem:
        score = max(0, score - 20)
        issues.append("No certificate retrieved")
        return {"score": max(0, score), "signals": signals, "details": details}

    # Parse cert
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception as e:
        issues.append(f"Parse error: {e}")
        return {"score": max(0, score - 20), "signals": signals, "details": details}

    details["has_cert"] = True
    details["subject"] = _name_to_str(cert.subject)
    details["issuer"] = _name_to_str(cert.issuer)
    details["not_before"] = cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.isoformat()
    details["not_after"] = cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.isoformat()
    details["serial"] = format(cert.serial_number, "x")
    details["fingerprint"] = cert.fingerprint(hashes.SHA256()).hex()

    # SAN
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        details["san"] = san_ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        details["san"] = []

    # Hostname match
    hostname_match = False
    try:
        # check SAN
        for dns in details["san"]:
            if dns == hostname or (dns.startswith("*.") and hostname.endswith(dns[1:])):
                hostname_match = True
                break
        if not hostname_match and not details["san"]:
            # fall back to CN
            try:
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                if cn == hostname or (cn.startswith("*.") and hostname.endswith(cn[1:])):
                    hostname_match = True
            except Exception:
                pass
    except Exception:
        pass
    if not hostname_match:
        score -= 25
        issues.append("Hostname mismatch")
        signals.append({"name": "Hostname match", "detail": "Certificate does not match hostname", "state": "bad", "category": "Certificate", "impact": -25})
    else:
        signals.append({"name": "Hostname match", "detail": "Certificate matches hostname", "state": "good", "category": "Certificate", "impact": 0})

    # Validity dates
    now = datetime.now(timezone.utc)
    nb = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    na = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
    if now < nb:
        score -= 30
        issues.append("Certificate not yet valid")
        signals.append({"name": "Validity", "detail": "Not yet valid", "state": "bad", "category": "Certificate", "impact": -30})
    elif now > na:
        score -= 40
        issues.append("Certificate expired")
        signals.append({"name": "Validity", "detail": "Expired", "state": "bad", "category": "Certificate", "impact": -40})
    else:
        days_left = (na - now).days
        if days_left < 14:
            score -= 10
            issues.append(f"Expires soon ({days_left} days)")
            signals.append({"name": "Expiry", "detail": f"{days_left} days remaining", "state": "warn", "category": "Certificate", "impact": -10})
        else:
            signals.append({"name": "Validity", "detail": f"Valid, {days_left} days remaining", "state": "good", "category": "Certificate", "impact": 0})

    # Key type/size
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        details["key_type"] = "RSA"
        details["key_size"] = pub.key_size
        if pub.key_size < 2048:
            score -= 25
            issues.append(f"Weak RSA key size {pub.key_size}")
            signals.append({"name": "Key strength", "detail": f"RSA {pub.key_size} bits (weak)", "state": "bad", "category": "Certificate", "impact": -25})
        else:
            signals.append({"name": "Key strength", "detail": f"RSA {pub.key_size} bits", "state": "good", "category": "Certificate", "impact": 0})
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        details["key_type"] = "EC"
        details["key_size"] = pub.key_size
        if pub.key_size < 256:
            score -= 20
            issues.append(f"Weak EC key size {pub.key_size}")
            signals.append({"name": "Key strength", "detail": f"EC {pub.key_size} bits (weak)", "state": "bad", "category": "Certificate", "impact": -20})
        else:
            signals.append({"name": "Key strength", "detail": f"EC {pub.key_size} bits", "state": "good", "category": "Certificate", "impact": 0})
    elif isinstance(pub, dsa.DSAPublicKey):
        details["key_type"] = "DSA"
        details["key_size"] = pub.key_size
        score -= 20
        issues.append("DSA key (deprecated)")
        signals.append({"name": "Key strength", "detail": f"DSA {pub.key_size} bits (deprecated)", "state": "bad", "category": "Certificate", "impact": -20})
    else:
        details["key_type"] = type(pub).__name__
        signals.append({"name": "Key strength", "detail": details["key_type"], "state": "info", "category": "Certificate", "impact": 0})

    # Signature algorithm
    try:
        sig_alg = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, "_name") else str(cert.signature_algorithm_oid)
    except Exception:
        sig_alg = str(cert.signature_hash_algorithm)
    details["sig_alg"] = sig_alg
    if any(w in sig_alg.lower() for w in ["md5", "sha1", "md2"]):
        score -= 25
        issues.append(f"Weak signature algorithm {sig_alg}")
        signals.append({"name": "Signature algorithm", "detail": f"{sig_alg} (weak)", "state": "bad", "category": "Certificate", "impact": -25})
    else:
        signals.append({"name": "Signature algorithm", "detail": sig_alg, "state": "good", "category": "Certificate", "impact": 0})

    # Self-signed
    if cert.issuer == cert.subject:
        score -= 15
        issues.append("Self-signed certificate")
        signals.append({"name": "Self-signed", "detail": "Issuer equals subject", "state": "warn", "category": "Certificate", "impact": -15})

    # CA basic constraints
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if bc.value.ca:
            # leaf should not be CA
            score -= 10
            issues.append("Leaf certificate has CA:TRUE")
            signals.append({"name": "Basic constraints", "detail": "CA:TRUE on leaf", "state": "warn", "category": "Certificate", "impact": -10})
    except Exception:
        pass

    # eMudhra-style: check issuer for weak CA key? heuristic: if issuer contains eMudhra and key size small
    issuer_str = details["issuer"].lower()
    if "emudhra" in issuer_str:
        # flag for monitoring
        signals.append({"name": "CA monitoring", "detail": "eMudhra-issued cert — heightened CA key-generation scrutiny", "state": "warn", "category": "Certificate", "impact": 0})
        issues.append("eMudhra CA: verify key-generation hygiene (incident reference)")

    # Key usage
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        details["key_usage"] = str(ku.value)
    except Exception:
        details["key_usage"] = None

    # CT: check for SCT extension (1.3.6.1.4.1.11129.2.4.2)
    try:
        sct_oid = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
        cert.extensions.get_extension_for_oid(sct_oid)
        details["ct_sct"] = True
        signals.append({"name": "Certificate Transparency", "detail": "SCT present", "state": "good", "category": "Certificate", "impact": 0})
    except Exception:
        details["ct_sct"] = False
        score -= 5
        issues.append("No embedded SCT (CT not enforced)")
        signals.append({"name": "Certificate Transparency", "detail": "No embedded SCT", "state": "warn", "category": "Certificate", "impact": -5})

    score = max(0, min(100, score))
    details["issues"] = issues
    return {"score": score, "signals": signals, "details": details}
