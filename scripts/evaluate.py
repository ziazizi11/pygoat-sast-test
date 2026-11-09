#!/usr/bin/env python3
"""
Evaluation Script for SAST Benchmark Experiment on PyGoat
Thesis: Analisis Komparatif Efektivitas Alat SAST Tunggal dan Kombinasi Multi-Tools
        terhadap Akurasi Penilaian Keamanan Perangkat Lunak Python

Calculates:
1. Confusion Matrix (TP, FP, FN, Precision, Recall, F1-Score) for 15 Scenarios (A, B, C, D)
2. Breakdown by Severity (Critical, High, Medium, Low)
3. Breakdown by Vulnerability Type (SQLi, Command Injection, Hardcoded Secrets, etc.)
4. Full Ground Truth Detection Matrix (19 items with tool-by-tool detection status)
"""

import csv
import json
import os
import re
import sys
from itertools import combinations
from typing import Dict, List, Set, Tuple

# Enable UTF-8 output on Windows terminal
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GROUND_TRUTH_FILE = os.path.join(PROJECT_ROOT, "ground_truth.json")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "sast-results")
OUTPUT_CSV = os.path.join(PROJECT_ROOT, "sast_evaluation_summary.csv")
BREAKDOWN_CSV = os.path.join(PROJECT_ROOT, "sast_vulnerability_breakdown.csv")

ALL_TOOLS = [
    "bandit",
    "semgrep",
    "bearer",
    "codeql"
]

# Display names avoiding GitHub secret masking on 'Bearer +'
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
        """Parse Bandit JSON report."""
        findings = []
        data = SASTParser._safe_load_json(filepath)
        if not data:
            return findings
        for item in data.get("results", []):
            findings.append({
                "tool": "bandit",
                "file": normalize_path(item.get("filename", "")),
                "line": int(item.get("line_number") or 0),
                "rule_id": item.get("test_id", ""),
                "message": item.get("issue_text", "")
            })
        return findings

    @staticmethod
    def parse_semgrep(filepath: str) -> List[Dict]:
        """Parse Semgrep JSON report."""
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
                "rule_id": item.get("check_id", ""),
                "message": item.get("extra", {}).get("message", "")
            })
        return findings

    @staticmethod
    def parse_sarif(filepath: str, tool_name: str) -> List[Dict]:
        """Generic SARIF parser for CodeQL, Snyk, DevSkim, etc."""
        findings = []
        data = SASTParser._safe_load_json(filepath)
        if not data:
            return findings
        for run in data.get("runs", []):
            for res in run.get("results", []):
                rule_id = res.get("ruleId", "")
                message = (res.get("message") or {}).get("text", "")
                for loc in res.get("locations", []):
                    ploc = loc.get("physicalLocation") or {}
                    uri = (ploc.get("artifactLocation") or {}).get("uri", "")
                    region = ploc.get("region") or {}
                    start_line = region.get("startLine") or 0
                    findings.append({
                        "tool": tool_name,
                        "file": normalize_path(uri),
                        "line": int(start_line),
                        "rule_id": rule_id,
                        "message": message
                    })
        return findings

    @staticmethod
    def parse_bearer(filepath: str) -> List[Dict]:
        """Parse Bearer JSON report."""
        findings = []
        data = SASTParser._safe_load_json(filepath)
        if not data:
            return findings
        for finding in data.get("findings", []):
            findings.append({
                "tool": "bearer",
                "file": normalize_path(finding.get("filename", "")),
                "line": int(finding.get("line_number") or 0),
                "rule_id": finding.get("cwe_ids", [""])[0] if finding.get("cwe_ids") else finding.get("id", ""),
                "message": finding.get("title", "")
            })
        return findings


def load_tool_findings(tool: str) -> List[Dict]:
    """Dispatch to specific parser according to available report file."""
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
    """Check if a SAST finding matches a Ground Truth entry."""
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


def evaluate_findings(findings: List[Dict], ground_truth: List[Dict]) -> Tuple[int, int, int, float, float, float, Set[str]]:
    """Compute TP, FP, FN, Precision, Recall, F1-Score and set of detected GT IDs."""
    detected_gt_ids: Set[str] = set()
    tp_findings_indices: Set[int] = set()

    for i, finding in enumerate(findings):
        for gt in ground_truth:
            if is_matching(finding, gt):
                detected_gt_ids.add(gt["id"])
                tp_findings_indices.add(i)

    tp = len(detected_gt_ids)
    fn = len(ground_truth) - tp
    fp = len(findings) - len(tp_findings_indices)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return tp, fp, fn, precision, recall, f1, detected_gt_ids


def main():
    print("=" * 80)
    print("SAST BENCHMARK EVALUATOR (PyGoat) - 15 SCENARIOS COMBINATORIAL ANALYSIS")
    print("Thesis Research Evaluation Pipeline (Bandit, Semgrep, Bearer-CLI, CodeQL)")
    print("=" * 80)

    gt_data = load_ground_truth(GROUND_TRUTH_FILE)
    print(f"[*] Loaded Ground Truth: {len(gt_data)} vulnerabilities")

    os.makedirs(RESULTS_DIR, exist_ok=True)

    # 1. Collect findings for individual tools
    tools_findings: Dict[str, List[Dict]] = {}
    tool_detected_gt: Dict[str, Set[str]] = {}

    print("\n[*] Loading scan outputs from:", RESULTS_DIR)
    for tool in ALL_TOOLS:
        f_list = load_tool_findings(tool)
        tools_findings[tool] = f_list
        _, _, _, _, _, _, detected_ids = evaluate_findings(f_list, gt_data)
        tool_detected_gt[tool] = detected_ids
        status = f"{len(f_list)} raw findings, {len(detected_ids)}/{len(gt_data)} TP detected" if f_list else "0 findings"
        print(f"    - {TOOL_DISPLAY_NAMES[tool].ljust(12)}: {status}")

    # 2. Compute 15 Scenarios
    records = []
    scenario_counter = 1
    scenario_letters = {1: "Skenario A", 2: "Skenario B", 3: "Skenario C", 4: "Skenario D"}

    for k in range(1, len(ALL_TOOLS) + 1):
        letter = scenario_letters[k]
        for combo in combinations(ALL_TOOLS, k):
            tool_display = " + ".join(TOOL_DISPLAY_NAMES[t] for t in combo)
            if k == len(ALL_TOOLS):
                scenario_name = f"{letter} - {tool_display} (Semua Tools)"
            else:
                scenario_name = f"{letter} - {tool_display}"

            # Combine findings (Union strategy)
            combined_findings = []
            for t in combo:
                combined_findings.extend(tools_findings[t])

            tp, fp, fn, prec, rec, f1, _ = evaluate_findings(combined_findings, gt_data)
            records.append({
                "scenario_id": f"SCN-{scenario_counter:03d}",
                "scenario_name": scenario_name,
                "k_tools": k,
                "tool_combination": "+".join(combo),
                "total_findings": len(combined_findings),
                "TP": tp,
                "FP": fp,
                "FN": fn,
                "Precision (%)": f"{prec * 100:.2f}%",
                "Recall (%)": f"{rec * 100:.2f}%",
                "F1_Score (%)": f"{f1 * 100:.2f}%",
                "_prec_num": prec,
                "_rec_num": rec,
                "_f1_num": f1
            })
            scenario_counter += 1

    # Export Scenarios Summary CSV
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = [
            "scenario_id",
            "scenario_name",
            "k_tools",
            "total_findings",
            "TP",
            "FP",
            "FN",
            "Precision (%)",
            "Recall (%)",
            "F1_Score (%)"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)

    # 3. Breakdown by Severity (Critical, High, Medium, Low)
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

    # 4. Breakdown by Vulnerability Type
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

    # Export Breakdown Details CSV
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

    with open(BREAKDOWN_CSV, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = [
            "id", "type", "severity", "cwe", "file", "line",
            "Bandit", "Semgrep", "Bearer_CLI", "CodeQL", "Status_Deteksi", "description"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(breakdown_rows)

    # -------------------------------------------------------------
    # BUILD MARKDOWN SUMMARY (Without asterisks in table cells)
    # -------------------------------------------------------------
    summary_md = "## 📊 Laporan Lengkap Evaluasi SAST (PyGoat - 4 Tools)\n\n"
    summary_md += f"**Total Kerentanan Ground Truth:** {len(gt_data)} celah\n\n"

    # Tabel 1: Evaluasi 15 Skenario
    summary_md += "### 1. Evaluasi Kinerja 15 Skenario (A, B, C, D)\n\n"
    summary_md += "| Skenario Pengujian | TP | FP | FN | Precision (%) | Recall (%) | F1-Score (%) |\n"
    summary_md += "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |\n"
    for r in records:
        # NO asterisks in cells
        summary_md += f"| {r['scenario_name']} | {r['TP']} | {r['FP']} | {r['FN']} | {r['Precision (%)']} | {r['Recall (%)']} | {r['F1_Score (%)']} |\n"

    # Tabel 2: Breakdown Kategori Severity
    summary_md += "\n### 2. Ringkasan Deteksi Berdasarkan Tingkat Keparahan (Severity)\n\n"
    summary_md += "| Tingkat Keparahan | Total Celah | Bandit | Semgrep | Bearer-CLI | CodeQL | Terdeteksi Gabungan | Persentase Terdeteksi |\n"
    summary_md += "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n"
    for sev in severity_order:
        data = severity_counts.get(sev, {"total": 0, "bandit": 0, "semgrep": 0, "bearer": 0, "codeql": 0, "all": 0})
        if data["total"] > 0:
            pct = (data["all"] / data["total"]) * 100
            summary_md += f"| {sev} | {data['total']} | {data['bandit']} | {data['semgrep']} | {data['bearer']} | {data['codeql']} | {data['all']} | {pct:.1f}% |\n"

    # Tabel 3: Breakdown Jenis Kerentanan
    summary_md += "\n### 3. Ringkasan Deteksi Berdasarkan Jenis Kerentanan (CWE)\n\n"
    summary_md += "| Jenis Kerentanan | Severity | Total Celah | Bandit | Semgrep | Bearer-CLI | CodeQL | Terdeteksi Gabungan |\n"
    summary_md += "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n"
    for k_type, data in type_counts.items():
        summary_md += f"| {k_type} | {data['severity']} | {data['total']} | {data['bandit']} | {data['semgrep']} | {data['bearer']} | {data['codeql']} | {data['all']} / {data['total']} |\n"

    # Tabel 4: Rincian 19 Celah Ground Truth
    summary_md += "\n### 4. Rincian 19 Celah Ground Truth & Status Deteksi Alat\n\n"
    summary_md += "| ID | File : Baris | Jenis Kerentanan | Severity | Bandit | Semgrep | Bearer-CLI | CodeQL | Status |\n"
    summary_md += "| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |\n"
    for r in breakdown_rows:
        b_icon = "✔" if r["Bandit"] == "YES" else "✖"
        s_icon = "✔" if r["Semgrep"] == "YES" else "✖"
        br_icon = "✔" if r["Bearer_CLI"] == "YES" else "✖"
        c_icon = "✔" if r["CodeQL"] == "YES" else "✖"
        status_text = "Terdeteksi" if r["Status_Deteksi"] == "TERDETEKSI" else "Lolos (FN)"
        summary_md += f"| {r['id']} | {r['file']}:{r['line']} | {r['type']} | {r['severity']} | {b_icon} | {s_icon} | {br_icon} | {c_icon} | {status_text} |\n"

    # Print to console
    print(summary_md)

    # Output to GitHub Step Summary if in GitHub Actions
    if "GITHUB_STEP_SUMMARY" in os.environ:
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(summary_md)

    print(f"\n[+] Full 15 Scenarios exported to: {OUTPUT_CSV}")
    print(f"[+] Detailed Vulnerability Breakdown exported to: {BREAKDOWN_CSV}")


if __name__ == "__main__":
    main()
