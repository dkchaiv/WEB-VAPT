"""Wraps nmap via subprocess. Never use shell=True with user input (command injection).
Parses text output into port/service dicts and saves raw output to results/raw/.
"""
import json
import os
import re
import subprocess
import config as cfg


def _parse_nmap_ports(stdout: str) -> list[dict]:
    """Extract open-port lines from nmap text output."""
    ports = []
    for line in stdout.splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+(\S+)\s+(.*)", line)
        if m:
            ports.append({
                "port": m.group(1), "protocol": m.group(2),
                "state": m.group(3), "service": m.group(4).split()[0] if m.group(4) else "unknown",
                "version": " ".join(m.group(4).split()[1:]) if m.group(4) else "",
                "raw_line": line.strip(),
            })
    return ports


def run_nmap(host: str) -> dict:
    """Run nmap -sV and return structured result with parsed ports."""
    command = ["nmap", "-sV", host]  # list form = no shell interpretation
    result = {"stdout": "", "stderr": "", "returncode": -1, "ports": [], "error": None}
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=cfg.NMAP_TIMEOUT)
        result["stdout"] = proc.stdout
        result["stderr"] = proc.stderr
        result["returncode"] = proc.returncode
        result["ports"] = _parse_nmap_ports(proc.stdout)
    except FileNotFoundError:
        result["error"] = "nmap is not installed"
        result["stderr"] = "nmap not installed"
    except subprocess.TimeoutExpired:
        result["error"] = f"nmap timed out after {cfg.NMAP_TIMEOUT}s"
        result["stderr"] = "nmap timed out"

    # Save raw output
    os.makedirs(cfg.RAW_DIR, exist_ok=True)
    raw_path = os.path.join(cfg.RAW_DIR, "nmap_raw.json")
    with open(raw_path, "w", encoding="utf-8") as f:
        json.dump({"stdout": result["stdout"], "stderr": result["stderr"],
                    "returncode": result["returncode"]}, f, indent=2)
    result["raw_saved"] = raw_path
    return result
