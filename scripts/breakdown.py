#!/usr/bin/env python3
"""
Vulnerability Breakdown Script for SAST Benchmark on PyGoat
Thesis: Analisis Komparatif Efektivitas Alat SAST Tunggal dan Kombinasi Multi-Tools
        terhadap Akurasi Penilaian Keamanan Perangkat Lunak Python

Focus:
1. Ringkasan Deteksi Berdasarkan Tingkat Keparahan (Severity)
2. Ringkasan Deteksi Berdasarkan Jenis Kerentanan (CWE)
3. Matriks Rincian 19 Celah Ground Truth & Status Deteksi Alat
"""

import csv
import json
import os
import re
import sys
from typing import Dict, List, Set

# Enable UTF-8 output on Windows terminal
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GROUND_TRUTH_FILE = os.path.join(PROJECT_ROOT, "ground_truth.json")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "sast-results")
BREAKDOWN_CSV = os.path.join(PROJECT_ROOT, "sast_vulnerability_breakdown.csv")

ALL_TOOLS = [
    "bandit",
    "semgrep",
    "bearer",
    "codeql"
]

TOOL_DISPLAY_NAMES = {
    "bandit": "Bandit",
    "semgrep": "Semgrep",
    "bearer": "Bearer-CLI",
    "codeql": "CodeQL"
}


def load_ground_truth(filepath: str) -> List[Dict]:
    """Load ground truth vulnerabilities list."""
    if not os.path.exists(filepath):
        print(f"[!] Error: Ground truth file '{filepath}' not found!")
        sys.exit(1)
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_path(path: str) -> str:
    """Normalize file path to use forward slashes and relative to project root."""
    path = path.replace("\\", "/")
    path = re.sub(r"^.*?pygoat-master/", "", path)
    path = re.sub(r"^(\./)+", "", path)
    return path.strip("/")


class SASTParser:
    """Parsers for each of the 4 SAST tools outputs."""

    @staticmethod
    def _safe_load_json(filepath: str):
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            return None
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                return json.load(f)
        except Exception as e:
            print(f"    [!] Warning: Could not parse JSON from {filepath}: {e}")
            return None

    @staticmethod
    def parse_bandit(filepath: str) -> List[Dict]:
        findings = []
        data = SASTParser._safe_load_json(filepath)
        if not data:
            return findings
        for item in data.get("results", []):
            findings.append({
                "tool": "bandit",
                "file": normalize_path(item.get("filename", "")),
                "line": int(item.get("line_number") or 0),
                "rule_id": item.get("test_id", "")
            })
        return findings

    @staticmethod
    def parse_semgrep(filepath: str) -> List[Dict]:
        findings = []
        data = SASTParser._safe_load_json(filepath)
        if not data:
            return findings
        for item in data.get("results", []):
            start = item.get("start") or {}
            findings.append({
                "tool": "semgrep",
                "file": normalize_path(item.get("path", "")),
                "line": int(start.get("line") or 0),
                "rule_id": item.get("check_id", "")
            })
        return findings

    @staticmethod
    def parse_sarif(filepath: str, tool_name: str) -> List[Dict]:
        findings = []
        data = SASTParser._safe_load_json(filepath)
        if not data:
            return findings
        for run in data.get("runs", []):
            for res in run.get("results", []):
                rule_id = res.get("ruleId", "")
                for loc in res.get("locations", []):
                    ploc = loc.get("physicalLocation") or {}
                    uri = (ploc.get("artifactLocation") or {}).get("uri", "")
                    region = ploc.get("region") or {}
                    start_line = region.get("startLine") or 0
                    findings.append({
                        "tool": tool_name,
                        "file": normalize_path(uri),
                        "line": int(start_line),
                        "rule_id": rule_id
                    })
        return findings

    @staticmethod
    def parse_bearer(filepath: str) -> List[Dict]:
        findings = []
        data = SASTParser._safe_load_json(filepath)
        if not data:
            return findings
        for finding in data.get("findings", []):
            findings.append({
                "tool": "bearer",
                "file": normalize_path(finding.get("filename", "")),
                "line": int(finding.get("line_number") or 0),
                "rule_id": finding.get("cwe_ids", [""])[0] if finding.get("cwe_ids") else finding.get("id", "")
            })
        return findings


def load_tool_findings(tool: str) -> List[Dict]:
    base = os.path.join(RESULTS_DIR, tool)
    if tool == "bandit":
        if os.path.exists(f"{base}.json"):
            return SASTParser.parse_bandit(f"{base}.json")
        if os.path.exists(os.path.join(PROJECT_ROOT, "bandit-results.json")):
            return SASTParser.parse_bandit(os.path.join(PROJECT_ROOT, "bandit-results.json"))
    elif tool == "semgrep":
        if os.path.exists(f"{base}.json"):
            return SASTParser.parse_semgrep(f"{base}.json")
        if os.path.exists(os.path.join(PROJECT_ROOT, "semgrep-results.json")):
            return SASTParser.parse_sarif(os.path.join(PROJECT_ROOT, "semgrep-results.json"), "semgrep")
    elif tool == "bearer":
        if os.path.exists(f"{base}.sarif"):
            return SASTParser.parse_sarif(f"{base}.sarif", "bearer")
        if os.path.exists(f"{base}.json"):
            return SASTParser.parse_bearer(f"{base}.json")
    elif tool == "codeql":
        if os.path.exists(f"{base}.sarif"):
            return SASTParser.parse_sarif(f"{base}.sarif", "codeql")
        if os.path.exists(os.path.join(PROJECT_ROOT, "codeql-results.sarif")):
            return SASTParser.parse_sarif(os.path.join(PROJECT_ROOT, "codeql-results.sarif"), "codeql")
    return []


def is_matching(finding: Dict, gt: Dict, line_tolerance: int = 5) -> bool:
    f_file = normalize_path(finding.get("file", ""))
    gt_file = normalize_path(gt.get("file", ""))

    if not f_file or not gt_file:
        return False

    if f_file != gt_file and not f_file.endswith(gt_file) and not gt_file.endswith(f_file):
        return False

    try:
        f_line = int(finding.get("line") or 0)
    except (ValueError, TypeError):
        f_line = 0

    if f_line <= 0:
        return True

    gt_line = int(gt.get("line") or 0)
    min_line = max(1, gt_line - line_tolerance)
    max_line = gt_line + line_tolerance

    return min_line <= f_line <= max_line


def main():
    print("=" * 80)
    print("SAST VULNERABILITY BREAKDOWN EVALUATOR (PyGoat)")
    print("Severity, CWE Category & Ground Truth Detection Matrix")
    print("=" * 80)

    gt_data = load_ground_truth(GROUND_TRUTH_FILE)
    print(f"[*] Loaded Ground Truth: {len(gt_data)} vulnerabilities")

    os.makedirs(RESULTS_DIR, exist_ok=True)

    # 1. Match findings for each tool
    tool_detected_gt: Dict[str, Set[str]] = {}
    for tool in ALL_TOOLS:
        f_list = load_tool_findings(tool)
        detected_set = set()
        for f in f_list:
            for gt in gt_data:
                if is_matching(f, gt):
                    detected_set.add(gt["id"])
        tool_detected_gt[tool] = detected_set
        print(f"    - {TOOL_DISPLAY_NAMES[tool].ljust(12)}: {len(detected_set)}/{len(gt_data)} detected")

    # 2. Group by Severity
    severity_order = ["Critical", "High", "Medium", "Low"]
    severity_counts: Dict[str, Dict] = {s: {"total": 0, "bandit": 0, "semgrep": 0, "bearer": 0, "codeql": 0, "all": 0} for s in severity_order}

    for item in gt_data:
        sev = item.get("severity", "Medium")
        if sev not in severity_counts:
            severity_counts[sev] = {"total": 0, "bandit": 0, "semgrep": 0, "bearer": 0, "codeql": 0, "all": 0}
        severity_counts[sev]["total"] += 1
        item_id = item["id"]

        is_any_detected = False
        for tool in ALL_TOOLS:
            if item_id in tool_detected_gt.get(tool, set()):
                severity_counts[sev][tool] += 1
                is_any_detected = True
        if is_any_detected:
            severity_counts[sev]["all"] += 1

    # 3. Group by Vulnerability Type
    type_counts: Dict[str, Dict] = {}
    for item in gt_data:
        v_type = item.get("type", "Unknown")
        cwe = item.get("cwe", "")
        key = f"{v_type} ({cwe})" if cwe else v_type
        if key not in type_counts:
            type_counts[key] = {"total": 0, "severity": item.get("severity", "Medium"), "bandit": 0, "semgrep": 0, "bearer": 0, "codeql": 0, "all": 0}
        type_counts[key]["total"] += 1
        item_id = item["id"]

        is_any_detected = False
        for tool in ALL_TOOLS:
            if item_id in tool_detected_gt.get(tool, set()):
                type_counts[key][tool] += 1
                is_any_detected = True
        if is_any_detected:
            type_counts[key]["all"] += 1

    # 4. Detailed rows per vulnerability
    breakdown_rows = []
    for item in gt_data:
        b_det = "YES" if item["id"] in tool_detected_gt["bandit"] else "NO"
        s_det = "YES" if item["id"] in tool_detected_gt["semgrep"] else "NO"
        br_det = "YES" if item["id"] in tool_detected_gt["bearer"] else "NO"
        c_det = "YES" if item["id"] in tool_detected_gt["codeql"] else "NO"
        any_det = "YES" if (b_det == "YES" or s_det == "YES" or br_det == "YES" or c_det == "YES") else "NO"

        breakdown_rows.append({
            "id": item["id"],
            "type": item["type"],
            "severity": item.get("severity", "Medium"),
            "cwe": item["cwe"],
            "file": item["file"],
            "line": item["line"],
            "Bandit": b_det,
            "Semgrep": s_det,
            "Bearer_CLI": br_det,
            "CodeQL": c_det,
            "Status_Deteksi": "TERDETEKSI" if any_det == "YES" else "LOLOS (FN)",
            "description": item["description"]
        })

    # Export to CSV
    with open(BREAKDOWN_CSV, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = [
            "id", "type", "severity", "cwe", "file", "line",
            "Bandit", "Semgrep", "Bearer_CLI", "CodeQL", "Status_Deteksi", "description"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(breakdown_rows)

    print(f"\n[+] Vulnerability Breakdown exported to: {BREAKDOWN_CSV}")

    # 5. Build Markdown Summary (Only the 3 Breakdown Tables)
    summary_md = "## 🔍 Laporan Rincian Celah Keamanan (PyGoat - Severity & CWE Breakdown)\n\n"
    summary_md += f"**Total Kerentanan Ground Truth:** {len(gt_data)} celah\n\n"

    # Tabel 1: Severity
    summary_md += "### 1. Ringkasan Deteksi Berdasarkan Tingkat Keparahan (Severity)\n\n"
    summary_md += "| Tingkat Keparahan | Total Celah | Bandit | Semgrep | Bearer-CLI | CodeQL | Terdeteksi Gabungan | Persentase Terdeteksi |\n"
    summary_md += "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n"
    for sev in severity_order:
        data = severity_counts.get(sev, {"total": 0, "bandit": 0, "semgrep": 0, "bearer": 0, "codeql": 0, "all": 0})
        if data["total"] > 0:
            pct = (data["all"] / data["total"]) * 100
            summary_md += f"| {sev} | {data['total']} | {data['bandit']} | {data['semgrep']} | {data['bearer']} | {data['codeql']} | {data['all']} | {pct:.1f}% |\n"

    # Tabel 2: CWE Types
    summary_md += "\n### 2. Ringkasan Deteksi Berdasarkan Jenis Kerentanan (CWE)\n\n"
    summary_md += "| Jenis Kerentanan | Severity | Total Celah | Bandit | Semgrep | Bearer-CLI | CodeQL | Terdeteksi Gabungan |\n"
    summary_md += "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n"
    for k_type, data in type_counts.items():
        summary_md += f"| {k_type} | {data['severity']} | {data['total']} | {data['bandit']} | {data['semgrep']} | {data['bearer']} | {data['codeql']} | {data['all']} / {data['total']} |\n"

    # Tabel 3: Full Ground Truth Matrix
    summary_md += "\n### 3. Rincian 19 Celah Ground Truth & Status Deteksi Alat\n\n"
    summary_md += "| ID | File : Baris | Jenis Kerentanan | Severity | Bandit | Semgrep | Bearer-CLI | CodeQL | Status |\n"
    summary_md += "| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |\n"
    for r in breakdown_rows:
        b_icon = "✔" if r["Bandit"] == "YES" else "✖"
        s_icon = "✔" if r["Semgrep"] == "YES" else "✖"
        br_icon = "✔" if r["Bearer_CLI"] == "YES" else "✖"
        c_icon = "✔" if r["CodeQL"] == "YES" else "✖"
        status_text = "Terdeteksi" if r["Status_Deteksi"] == "TERDETEKSI" else "Lolos (FN)"
        summary_md += f"| {r['id']} | {r['file']}:{r['line']} | {r['type']} | {r['severity']} | {b_icon} | {s_icon} | {br_icon} | {c_icon} | {status_text} |\n"

    print("\n" + summary_md)

    # Output to GitHub Step Summary
    if "GITHUB_STEP_SUMMARY" in os.environ:
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(summary_md)


if __name__ == "__main__":
    main()

