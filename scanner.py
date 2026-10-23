"""
Orchestrator: ties every module together.
Pipeline: validate → confirm → recon → nmap → ZAP → nuclei → custom checks
         → normalize → dedupe → risk → save JSON → generate PDF.

Each tool is independently configurable and failures are isolated.
"""
import argparse
import json
import os
import sys
import time
from datetime import date
from urllib.parse import urlparse

import config as cfg
from modules.target import validate_target
from modules.recon import run_recon
from modules.custom_checks import check_security_headers, check_cookies
from modules.nmap_scan import run_nmap
from modules.nuclei_scan import run_nuclei
from modules.zap_scan import run_zap
from modules.normalizer import (
    normalize_custom_finding, normalize_nuclei_finding,
    normalize_zap_finding, normalize_nmap_finding,
)
from modules.deduplicator import deduplicate
from modules.risk import count_by_severity
from report_generator import generate_report


def _elapsed(start: float) -> str:
    return f"{time.time() - start:.1f}s"


def main():
    parser = argparse.ArgumentParser(
        description="WebVAPT — Automated Web Application Security Assessment Framework")
    parser.add_argument("--target", required=True, help="Authorized HTTP/HTTPS target URL")
    parser.add_argument("--skip-nmap", action="store_true", help="Skip Nmap scan")
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip Nuclei scan")
    parser.add_argument("--skip-zap", action="store_true", help="Skip ZAP scan")
    parser.add_argument("--zap-active", action="store_true",
                        help="Enable ZAP active scan (disabled by default)")
    parser.add_argument("--confirm", action="store_true",
                        help="Confirm authorized testing (required for active scans)")
    args = parser.parse_args()

    start_all = time.time()
    tools_used = ["HTTP Recon", "Custom Checks"]

    # ── Target validation ───────────────────────────────────────────
    try:
        target = validate_target(args.target)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    # Check allowlist if configured
    if cfg.TARGET_ALLOWLIST:
        host = urlparse(target).netloc
        if not any(host.endswith(allowed) for allowed in cfg.TARGET_ALLOWLIST):
            print(f"[!] Target {host} not in allowlist: {cfg.TARGET_ALLOWLIST}")
            sys.exit(1)

    # Require confirmation for active scanning
    if args.zap_active and not args.confirm:
        print("[!] Active scanning requires --confirm to acknowledge authorized testing.")
        sys.exit(1)

    print(f"[+] Target: {target}")
    print(f"[+] Assessment started at {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Create output directories
    for d in [cfg.RAW_DIR, cfg.NORMALIZED_DIR, cfg.REPORTS_DIR, cfg.EVIDENCE_DIR]:
        os.makedirs(d, exist_ok=True)

    raw_findings: list[dict] = []
    recon_data: dict = {}
    errors: list[str] = []

    # ── HTTP Reconnaissance ─────────────────────────────────────────
    print("\n[+] Running HTTP reconnaissance...")
    t0 = time.time()
    recon_data = run_recon(target)
    if recon_data.get("error"):
        errors.append(f"Recon: {recon_data['error']}")
        print(f"    [!] Recon error: {recon_data['error']}")
    else:
        print(f"    Status: {recon_data['status_code']} | Server: {recon_data.get('server', 'N/A')} "
              f"| Title: {recon_data.get('title', 'N/A')} [{_elapsed(t0)}]")
        if recon_data.get("redirect_url"):
            # Ensure we don't scan unrelated hosts
            orig_host = urlparse(target).netloc
            redir_host = urlparse(recon_data["redirect_url"]).netloc
            if redir_host != orig_host:
                print(f"    [!] Redirect to different host ({redir_host}) — staying on original target")

    # ── Custom security checks ──────────────────────────────────────
    print("\n[+] Running custom security checks...")
    t0 = time.time()
    if recon_data.get("headers"):
        raw_findings += [normalize_custom_finding(f) for f in check_security_headers(recon_data["headers"])]
    if recon_data.get("response_obj") is not None:
        raw_findings += [normalize_custom_finding(f) for f in check_cookies(recon_data["response_obj"])]
    print(f"    Found {len(raw_findings)} issue(s) [{_elapsed(t0)}]")

    # ── Nmap ────────────────────────────────────────────────────────
    if not args.skip_nmap:
        print("\n[+] Running Nmap...")
        t0 = time.time()
        tools_used.append("Nmap")
        host = urlparse(target).hostname
        nmap_result = run_nmap(host)
        if nmap_result.get("error"):
            errors.append(f"Nmap: {nmap_result['error']}")
            print(f"    [!] {nmap_result['error']}")
        else:
            ports = nmap_result.get("ports", [])
            print(f"    Returncode: {nmap_result['returncode']} | "
                  f"Open ports: {len(ports)} [{_elapsed(t0)}]")
            for p in ports:
                raw_findings.append(normalize_nmap_finding(host, p))
    else:
        print("\n[~] Nmap skipped")

    # ── ZAP ─────────────────────────────────────────────────────────
    if not args.skip_zap:
        print("\n[+] Running ZAP scan...")
        t0 = time.time()
        tools_used.append("OWASP ZAP")
        zap_result = run_zap(target, active=args.zap_active)
        if zap_result.get("error"):
            errors.append(f"ZAP: {zap_result['error']}")
            print(f"    [!] {zap_result['error']}")
        else:
            alerts = zap_result.get("alerts", [])
            print(f"    Alerts: {len(alerts)} [{_elapsed(t0)}]")
            for alert in alerts:
                raw_findings.append(normalize_zap_finding(alert))
    else:
        print("\n[~] ZAP skipped")

    # ── Nuclei ──────────────────────────────────────────────────────
    if not args.skip_nuclei:
        print("\n[+] Running Nuclei...")
        t0 = time.time()
        tools_used.append("Nuclei")
        nuclei_raw = run_nuclei(target)
        print(f"    Findings: {len(nuclei_raw)} [{_elapsed(t0)}]")
        raw_findings += [normalize_nuclei_finding(f) for f in nuclei_raw]
    else:
        print("\n[~] Nuclei skipped")

    # ── Deduplication ───────────────────────────────────────────────
    print(f"\n[+] Normalizing & deduplicating {len(raw_findings)} finding(s)...")
    findings = deduplicate(raw_findings)
    print(f"    After dedup: {len(findings)} unique finding(s)")

    # ── Severity breakdown ──────────────────────────────────────────
    counts = count_by_severity(findings)
    print(f"[+] Severity breakdown: {counts}")

    # ── Save normalized JSON ────────────────────────────────────────
    today = date.today().isoformat()
    json_path = os.path.join(cfg.NORMALIZED_DIR, f"findings_{today}.json")
    # Remove response_obj (not serializable) from any finding
    serializable = []
    for f in findings:
        clean = {k: v for k, v in f.items() if k != "response_obj"}
        serializable.append(clean)
    with open(json_path, "w", encoding="utf-8") as fp:
        json.dump(serializable, fp, indent=4, default=str)
    print(f"[+] JSON saved: {json_path}")

    # Also keep a copy in old location for backward compatibility
    old_json = os.path.join(cfg.RESULTS_DIR, f"results_{today}.json")
    with open(old_json, "w", encoding="utf-8") as fp:
        json.dump(serializable, fp, indent=4, default=str)

    # ── Generate PDF report ─────────────────────────────────────────
    pdf_path = os.path.join(cfg.REPORTS_DIR, f"VAPT_Report_{today}.pdf")
    try:
        generate_report(target, findings, pdf_path, recon=recon_data, tools_used=tools_used)
        print(f"[+] PDF report saved: {pdf_path}")
    except Exception as e:
        errors.append(f"PDF generation: {e}")
        print(f"[!] PDF generation failed: {e}")

    # ── Summary ─────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"[+] Assessment completed in {_elapsed(start_all)}")
    print(f"    Total findings: {len(findings)}")
    print(f"    JSON: {json_path}")
    print(f"    PDF:  {pdf_path}")
    if errors:
        print(f"    Errors ({len(errors)}):")
        for e in errors:
            print(f"      - {e}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
