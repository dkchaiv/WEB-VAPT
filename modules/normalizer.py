"""
Every scanner speaks a different format. This module converts each tool's raw
output into ONE common Finding schema so the rest of the pipeline (dedup, risk,
report) never needs to know which tool produced a finding.
"""
import hashlib

FINDING_TEMPLATE = {
    "id": "", "title": "", "severity": "Informational", "confidence": "Medium",
    "endpoint": "", "method": "", "parameter": "", "description": "", "impact": "",
    "remediation": "", "evidence": "", "tool": "", "references": "",
    "owasp": "", "cwe": "", "cve": "", "cvss": None,
    "status": "Needs Manual Validation",
}

SEVERITY_NORMALIZE = {
    "info": "Informational", "informational": "Informational",
    "low": "Low", "medium": "Medium", "high": "High", "critical": "Critical",
}


def _make_id(tool: str, title: str, endpoint: str) -> str:
    """Deterministic finding ID from tool + title + endpoint."""
    raw = f"{tool}:{title}:{endpoint}".lower()
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _normalize_severity(raw: str) -> str:
    return SEVERITY_NORMALIZE.get(raw.lower().strip(), raw.capitalize()) if raw else "Informational"


def normalize_custom_finding(raw: dict) -> dict:
    f = FINDING_TEMPLATE.copy()
    f.update(raw)
    f["severity"] = _normalize_severity(f["severity"])
    f["id"] = _make_id(f["tool"], f["title"], f.get("endpoint", ""))
    return f


def normalize_nuclei_finding(raw: dict) -> dict:
    info = raw.get("info", {})
    classification = info.get("classification", {})
    refs = info.get("reference", [])
    f = FINDING_TEMPLATE.copy()
    f.update({
        "title": info.get("name", "Unnamed Nuclei Finding"),
        "severity": _normalize_severity(info.get("severity", "info")),
        "confidence": "Medium",
        "endpoint": raw.get("matched-at", raw.get("host", "")),
        "description": info.get("description", ""),
        "remediation": info.get("remediation", ""),
        "evidence": raw.get("extracted-results", raw.get("matcher-name", "")),
        "tool": "Nuclei",
        "references": ", ".join(refs) if isinstance(refs, list) else str(refs or ""),
        "cve": ", ".join(classification.get("cve-id", []) or []),
        "cwe": ", ".join(classification.get("cwe-id", []) or []),
        "cvss": classification.get("cvss-score"),
        "status": "Potential",
    })
    f["id"] = _make_id("Nuclei", f["title"], f["endpoint"])
    return f


def normalize_zap_finding(alert: dict) -> dict:
    """Normalize a single ZAP alert dict into the common finding schema."""
    f = FINDING_TEMPLATE.copy()
    risk_map = {"0": "Informational", "1": "Low", "2": "Medium", "3": "High"}
    confidence_map = {"0": "False Positive", "1": "Low", "2": "Medium", "3": "High", "4": "Confirmed"}
    f.update({
        "title": alert.get("name", alert.get("alert", "Unnamed ZAP Finding")),
        "severity": risk_map.get(str(alert.get("riskcode", "0")), "Informational"),
        "confidence": confidence_map.get(str(alert.get("confidence", "2")), "Medium"),
        "endpoint": alert.get("url", ""),
        "method": alert.get("method", ""),
        "parameter": alert.get("param", ""),
        "description": alert.get("description", ""),
        "impact": alert.get("otherinfo", ""),
        "remediation": alert.get("solution", ""),
        "evidence": alert.get("evidence", ""),
        "tool": "ZAP",
        "references": alert.get("reference", ""),
        "cwe": f"CWE-{alert['cweid']}" if alert.get("cweid") and str(alert.get("cweid")) != "-1" else "",
        "owasp": "",
        "cve": "",
        "cvss": None,
        "status": "Potential",
    })
    # ZAP plugin ID as reference
    if alert.get("pluginid"):
        f["references"] = f"ZAP Plugin {alert['pluginid']}. {f['references']}"
    f["id"] = _make_id("ZAP", f["title"], f["endpoint"])
    return f


def normalize_nmap_finding(host: str, port_info: dict) -> dict:
    """Create an informational finding from a discovered Nmap port/service."""
    port = port_info.get("port", "")
    service = port_info.get("service", "unknown")
    version = port_info.get("version", "")
    f = FINDING_TEMPLATE.copy()
    title = f"Open port {port}/{port_info.get('protocol', 'tcp')} — {service}"
    if version:
        title += f" ({version})"
    f.update({
        "title": title,
        "severity": "Informational",
        "confidence": "High",
        "endpoint": f"{host}:{port}",
        "description": f"Port {port} is open running {service} {version}".strip(),
        "evidence": port_info.get("raw_line", ""),
        "tool": "Nmap",
        "status": "Confirmed",
    })
    f["id"] = _make_id("Nmap", f["title"], f["endpoint"])
    return f
