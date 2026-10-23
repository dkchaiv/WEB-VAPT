"""Severity ranking. Extend later with CVSS + confidence + business context."""

SEVERITY_ORDER = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def highest_severity(current: str, new: str) -> str:
    return new if SEVERITY_ORDER.get(new, 0) > SEVERITY_ORDER.get(current, 0) else current


def count_by_severity(findings: list) -> dict:
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "Informational")
        if sev in counts:
            counts[sev] += 1
    return counts
