"""Merges the same finding reported by multiple tools into one entry.

Dedup key = normalized_title + CWE + endpoint + parameter.
When merging, keeps the highest severity and accumulates sources/evidence.
"""
from modules.risk import SEVERITY_ORDER


def _normalize_title(title: str) -> str:
    return title.lower().replace("-", " ").replace("_", " ").strip()


def _finding_key(finding: dict) -> str:
    """Composite key: title + CWE + endpoint + parameter."""
    parts = [
        _normalize_title(finding.get("title", "")),
        (finding.get("cwe") or "").lower(),
        (finding.get("endpoint") or "").lower(),
        (finding.get("parameter") or "").lower(),
    ]
    return "|".join(parts)


def deduplicate(findings: list) -> list:
    merged: dict[str, dict] = {}
    for finding in findings:
        key = _finding_key(finding)
        if key not in merged:
            finding["sources"] = [finding.get("tool", "Unknown")]
            merged[key] = finding
        else:
            existing = merged[key]
            tool = finding.get("tool", "Unknown")
            if tool not in existing.setdefault("sources", []):
                existing["sources"].append(tool)
            # Keep highest severity
            new_sev = finding.get("severity", "Informational")
            old_sev = existing.get("severity", "Informational")
            if SEVERITY_ORDER.get(new_sev, 0) > SEVERITY_ORDER.get(old_sev, 0):
                existing["severity"] = new_sev
            # Accumulate evidence
            new_ev = finding.get("evidence", "")
            if new_ev and new_ev not in existing.get("evidence", ""):
                existing["evidence"] = f"{existing.get('evidence', '')}; {new_ev}".strip("; ")
    return list(merged.values())
