"""First real detection engine you write yourself (not a wrapper around a tool).

Checks security headers, cookie attributes, and basic HTTP/TLS observations.
Context-dependent observations are classified as potential findings.
"""

REQUIRED_HEADERS = {
    "Content-Security-Policy": (
        "Medium", "CWE-693", "A05 - Security Misconfiguration",
        "Implement a Content-Security-Policy header to mitigate XSS and data injection attacks."),
    "Strict-Transport-Security": (
        "Medium", "CWE-319", "A02 - Cryptographic Failures",
        "Add Strict-Transport-Security header with a minimum max-age of 31536000."),
    "X-Content-Type-Options": (
        "Low", "CWE-693", "A05 - Security Misconfiguration",
        "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing."),
    "X-Frame-Options": (
        "Low", "CWE-1021", "A05 - Security Misconfiguration",
        "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking."),
}

# Headers that may leak sensitive info
INFO_LEAK_HEADERS = {
    "X-Powered-By": "Server technology disclosure",
    "X-AspNet-Version": "ASP.NET version disclosure",
    "X-AspNetMvc-Version": "ASP.NET MVC version disclosure",
    "Server": None,  # only flag if it contains version info
}


def check_security_headers(headers: dict) -> list:
    present = {k.lower(): v for k, v in headers.items()}
    findings = []
    for header, (severity, cwe, owasp, remediation) in REQUIRED_HEADERS.items():
        if header.lower() not in present:
            findings.append({
                "title": f"Missing {header} header", "severity": severity,
                "cwe": cwe, "owasp": owasp, "cve": None, "endpoint": None,
                "tool": "Custom Security Header Analyzer", "confidence": "High",
                "status": "Confirmed", "remediation": remediation,
                "description": f"The response does not set the {header} header.",
            })

    # Information leakage through headers
    for header, note in INFO_LEAK_HEADERS.items():
        val = present.get(header.lower())
        if val:
            # For Server header, only flag if it contains version-like info
            if header == "Server" and not any(c.isdigit() for c in val):
                continue
            findings.append({
                "title": f"Information disclosure via {header} header",
                "severity": "Informational", "cwe": "CWE-200",
                "owasp": "A05 - Security Misconfiguration", "cve": None,
                "endpoint": None, "tool": "Custom Security Header Analyzer",
                "confidence": "Medium",
                "status": "Potential",
                "remediation": f"Remove or suppress the {header} response header.",
                "description": f"The {header} header discloses: {val}. "
                               f"{note or 'This may aid attackers in fingerprinting the application.'}",
                "evidence": f"{header}: {val}",
            })
    return findings


def check_cookies(response) -> list:
    findings = []
    for cookie in response.cookies:
        if not cookie.secure:
            findings.append({
                "title": "Cookie missing Secure attribute", "severity": "Medium",
                "cwe": "CWE-614", "owasp": "A07 - Identification and Authentication Failures",
                "cve": None, "endpoint": response.url, "tool": "Custom Cookie Analyzer",
                "confidence": "High", "status": "Confirmed",
                "remediation": f"Set the Secure attribute on cookie '{cookie.name}'.",
                "description": f"Cookie '{cookie.name}' lacks the Secure attribute.",
            })
        if not cookie.has_nonstandard_attr("HttpOnly"):
            findings.append({
                "title": "Cookie missing HttpOnly attribute", "severity": "Low",
                "cwe": "CWE-1004", "owasp": "A07 - Identification and Authentication Failures",
                "cve": None, "endpoint": response.url, "tool": "Custom Cookie Analyzer",
                "confidence": "High", "status": "Confirmed",
                "remediation": f"Set the HttpOnly attribute on cookie '{cookie.name}'.",
                "description": f"Cookie '{cookie.name}' lacks the HttpOnly attribute.",
            })
        # SameSite check
        samesite = cookie.get_nonstandard_attr("SameSite")
        if not samesite:
            findings.append({
                "title": "Cookie missing SameSite attribute", "severity": "Low",
                "cwe": "CWE-1275", "owasp": "A07 - Identification and Authentication Failures",
                "cve": None, "endpoint": response.url, "tool": "Custom Cookie Analyzer",
                "confidence": "Medium", "status": "Potential",
                "remediation": f"Set SameSite=Strict or SameSite=Lax on cookie '{cookie.name}'.",
                "description": f"Cookie '{cookie.name}' does not set the SameSite attribute. "
                               "This may increase susceptibility to CSRF attacks depending on context.",
            })
    return findings
