"""Runs Nuclei and parses its JSONL output into raw dicts (normalized later).
Saves raw output under results/raw/.
"""
import json
import os
import subprocess
import config as cfg


def run_nuclei(target: str) -> list:
    command = ["nuclei", "-target", target, "-jsonl", "-silent"] + cfg.NUCLEI_EXTRA_ARGS
    findings: list[dict] = []
    error = None
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=cfg.NUCLEI_TIMEOUT)
        for line in process.stdout.splitlines():
            if not line.strip():
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if process.returncode != 0 and process.stderr:
            error = process.stderr[:500]
    except FileNotFoundError:
        error = "nuclei is not installed"
        print("    [Nuclei] not installed — skipping")
    except subprocess.TimeoutExpired:
        error = f"nuclei timed out after {cfg.NUCLEI_TIMEOUT}s"
        print(f"    [Nuclei] {error}")

    # Save raw output
    os.makedirs(cfg.RAW_DIR, exist_ok=True)
    raw_path = os.path.join(cfg.RAW_DIR, "nuclei_raw.json")
    with open(raw_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    if error:
        print(f"    [Nuclei] error: {error}")
    return findings
