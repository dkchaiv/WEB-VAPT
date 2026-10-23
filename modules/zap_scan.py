"""OWASP ZAP integration via its REST API. No external ZAP Python library needed."""
import json
import os
import time
import requests
import config as cfg


def _zap_api(path: str, params: dict | None = None) -> dict:
    """Call a ZAP API endpoint and return the JSON response."""
    params = params or {}
    if cfg.ZAP_API_KEY:
        params["apikey"] = cfg.ZAP_API_KEY
    url = f"{cfg.ZAP_BASE_URL}{path}"
    resp = requests.get(url, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def check_zap_available() -> bool:
    """Return True if ZAP daemon is reachable."""
    try:
        _zap_api("/JSON/core/view/version/")
        return True
    except Exception:
        return False


def _wait_for_scan(view_path: str, scan_id: str, timeout: int, label: str):
    """Poll a ZAP scan/spider status until 100% or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status = _zap_api(view_path, {"scanId": scan_id})
            progress = int(status.get("status", status.get("scanProgress", "0")))
        except Exception:
            progress = 0
        if progress >= 100:
            return
        print(f"    [{label}] progress: {progress}%")
        time.sleep(5)
    print(f"    [{label}] timed out after {timeout}s")


def run_spider(target: str) -> str | None:
    """Start ZAP spider and wait for completion. Returns scan ID or None."""
    try:
        resp = _zap_api("/JSON/spider/action/scan/", {"url": target, "maxChildren": "10"})
        scan_id = resp.get("scan", resp.get("scanId", "0"))
        _wait_for_scan("/JSON/spider/view/status/", str(scan_id), cfg.ZAP_SPIDER_TIMEOUT, "Spider")
        return str(scan_id)
    except Exception as e:
        print(f"    [Spider] error: {e}")
        return None


def run_passive_scan_wait():
    """Wait until the passive scan queue is empty."""
    deadline = time.time() + cfg.ZAP_SCAN_TIMEOUT
    while time.time() < deadline:
        try:
            resp = _zap_api("/JSON/pscan/view/recordsToScan/")
            remaining = int(resp.get("recordsToScan", "0"))
        except Exception:
            remaining = 0
        if remaining == 0:
            return
        print(f"    [Passive] records remaining: {remaining}")
        time.sleep(3)
    print("    [Passive] timed out waiting for passive scan")


def run_active_scan(target: str) -> str | None:
    """Start ZAP active scan. Returns scan ID or None."""
    try:
        resp = _zap_api("/JSON/ascan/action/scan/", {"url": target})
        scan_id = resp.get("scan", resp.get("scanId", "0"))
        _wait_for_scan("/JSON/ascan/view/status/", str(scan_id), cfg.ZAP_SCAN_TIMEOUT, "Active")
        return str(scan_id)
    except Exception as e:
        print(f"    [Active scan] error: {e}")
        return None


def get_alerts(target: str) -> list[dict]:
    """Retrieve all ZAP alerts for the target as structured dicts."""
    try:
        resp = _zap_api("/JSON/alert/view/alerts/", {"baseurl": target, "count": "500"})
        return resp.get("alerts", [])
    except Exception as e:
        print(f"    [ZAP] failed to retrieve alerts: {e}")
        return []


def run_zap(target: str, active: bool = False) -> dict:
    """Full ZAP workflow: spider → passive → (optional) active → retrieve alerts.

    Returns {"alerts": [...], "raw_saved": path, "error": ...}
    """
    result: dict = {"alerts": [], "raw_saved": None, "error": None}

    if not check_zap_available():
        result["error"] = f"ZAP not reachable at {cfg.ZAP_BASE_URL}"
        return result

    print("  [ZAP] Spidering target...")
    run_spider(target)

    print("  [ZAP] Waiting for passive scan...")
    run_passive_scan_wait()

    if active:
        print("  [ZAP] Running active scan (explicitly enabled)...")
        run_active_scan(target)

    alerts = get_alerts(target)
    result["alerts"] = alerts

    # Save raw alerts
    os.makedirs(cfg.RAW_DIR, exist_ok=True)
    raw_path = os.path.join(cfg.RAW_DIR, "zap_raw.json")
    with open(raw_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)
    result["raw_saved"] = raw_path

    return result
