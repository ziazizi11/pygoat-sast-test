#!/usr/bin/env python3
"""
Evaluation Script for SAST Benchmark Experiment on PyGoat
Thesis: Analisis Komparatif Efektivitas Alat SAST Tunggal dan Kombinasi Multi-Tools
        terhadap Akurasi Penilaian Keamanan Perangkat Lunak Python

Calculates TP, FP, FN, Precision (%), Recall (%), and F1-Score (%) for:
- 4 Single Tools (C(4, 1) = 4 scenarios)
- Multi-Tool Combinations (C(4, 2) to C(4, 4) = 11 scenarios)
Total Scenarios: 15 combinations (Power Set without empty set)
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

ALL_TOOLS = [
    "bandit",
    "semgrep",
    "bearer",
    "codeql"
]


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
    # Remove leading ./ or workspace prefixes if any
    path = re.sub(r"^.*?pygoat-master/", "", path)
    path = re.sub(r"^(\./)+", "", path)
    return path.strip("/")


class SASTParser:
    """Parsers for each of the 8 SAST tools outputs."""

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
                message = res.get("message", {}).get("text", "")
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
    def parse_dlint(filepath: str) -> List[Dict]:
        """Parse Flake8/Dlint text output (e.g. app/file.py:10:1: DU100 message)."""
        findings = []
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            return findings
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    match = re.match(r"^(.*?):(\d+):(\d+):\s+(DU\d+)\s+(.*)$", line.strip())
                    if match:
                        file, lineno, _, rule_id, msg = match.groups()
                        findings.append({
                            "tool": "dlint",
                            "file": normalize_path(file),
                            "line": int(lineno),
                            "rule_id": rule_id,
                            "message": msg
                        })
        except Exception as e:
            print(f"    [!] Warning: Could not parse text from {filepath}: {e}")
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

    @staticmethod
    def parse_pysa(filepath: str) -> List[Dict]:
        """Parse Pysa JSON report."""
        findings = []
        data = SASTParser._safe_load_json(filepath)
        if not data:
            return findings
        items = data if isinstance(data, list) else data.get("errors", [])
        for item in items:
            findings.append({
                "tool": "pysa",
                "file": normalize_path(item.get("path", "")),
                "line": int(item.get("line") or 0),
                "rule_id": str(item.get("code", "")),
                "message": item.get("description", "")
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
    elif tool == "dlint":
        if os.path.exists(f"{base}.txt"):
            return SASTParser.parse_dlint(f"{base}.txt")
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
    elif tool == "snyk":
        if os.path.exists(f"{base}.sarif"):
            return SASTParser.parse_sarif(f"{base}.sarif", "snyk")
        if os.path.exists(f"{base}.json"):
            return SASTParser.parse_sarif(f"{base}.json", "snyk")
    elif tool == "devskim":
        if os.path.exists(f"{base}.sarif"):
            return SASTParser.parse_sarif(f"{base}.sarif", "devskim")
        if os.path.exists(f"{base}.json"):
            return SASTParser.parse_sarif(f"{base}.json", "devskim")
    elif tool == "pysa":
        if os.path.exists(f"{base}.json"):
            return SASTParser.parse_pysa(f"{base}.json")
    return []


def is_matching(finding: Dict, gt: Dict, line_tolerance: int = 5) -> bool:
    """
    Check if a SAST finding matches a Ground Truth entry.
    Matches if target files are equal (or endswith relative path) and line is within tolerance.
    """
    f_file = normalize_path(finding.get("file", ""))
    gt_file = normalize_path(gt.get("file", ""))

    if not f_file or not gt_file:
        return False

    # Check file match: exact match or suffix match
    if f_file != gt_file and not f_file.endswith(gt_file) and not gt_file.endswith(f_file):
        return False

    try:
        f_line = int(finding.get("line") or 0)
    except (ValueError, TypeError):
        f_line = 0

    if f_line <= 0:
        # File-level warning
        return True

    gt_line = int(gt.get("line") or 0)
    min_line = max(1, gt_line - line_tolerance)
    max_line = gt_line + line_tolerance

    return min_line <= f_line <= max_line


def evaluate_findings(findings: List[Dict], ground_truth: List[Dict]) -> Tuple[int, int, int, float, float, float]:
    """
    Compute TP, FP, FN, Precision, Recall, and F1-Score for a set of findings.
    """
    detected_gt_ids: Set[str] = set()
    tp_findings_indices: Set[int] = set()

    for i, finding in enumerate(findings):
        matched = False
        for gt in ground_truth:
            if is_matching(finding, gt):
                detected_gt_ids.add(gt["id"])
                tp_findings_indices.add(i)
                matched = True

    tp = len(detected_gt_ids)
    fn = len(ground_truth) - tp
    fp = len(findings) - len(tp_findings_indices)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return tp, fp, fn, precision, recall, f1


def main():
    print("=" * 75)
    print("SAST BENCHMARK EVALUATOR (PyGoat) - 15 SCENARIOS COMBINATORIAL ANALYSIS")
    print("Thesis Research Evaluation Pipeline (4 Tools: Bandit, Semgrep, Bearer, CodeQL)")
    print("=" * 75)

    gt_data = load_ground_truth(GROUND_TRUTH_FILE)
    print(f"[*] Loaded Ground Truth: {len(gt_data)} vulnerabilities")
    for item in gt_data:
        print(f"    - [{item['id']}] {item['type']} ({item['file']}:{item['line']})")

    os.makedirs(RESULTS_DIR, exist_ok=True)

    # 1. Collect findings for all 4 individual tools
    tools_findings: Dict[str, List[Dict]] = {}
    print("\n[*] Loading scan outputs from:", RESULTS_DIR)
    for tool in ALL_TOOLS:
        f_list = load_tool_findings(tool)
        tools_findings[tool] = f_list
        status = f"{len(f_list)} findings" if f_list else "Not found / 0 findings"
        print(f"    - {tool.ljust(10)}: {status}")

    # 2. Compute 15 Scenarios
    records = []
    scenario_counter = 1

    print(f"\n[*] Generating and evaluating 15 Combinations (k=1..4)...")

    for k in range(1, len(ALL_TOOLS) + 1):
        for combo in combinations(ALL_TOOLS, k):
            combo_name = "+".join(combo)
            # Combine findings (Union strategy)
            combined_findings = []
            for t in combo:
                combined_findings.extend(tools_findings[t])

            tp, fp, fn, prec, rec, f1 = evaluate_findings(combined_findings, gt_data)
            records.append({
                "scenario_id": f"SCN-{scenario_counter:03d}",
                "k_tools": k,
                "tool_combination": combo_name,
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

    # 3. Export to CSV
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = [
            "scenario_id",
            "k_tools",
            "tool_combination",
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

    print(f"[+] Successfully evaluated {len(records)} scenarios!")
    print(f"[+] Full results exported to: {OUTPUT_CSV}")

    # 4. Display Single Tool Performance
    summary_md = f"### 📊 Ringkasan Evaluasi Kinerja SAST (4 Tools - PyGoat)\n"
    summary_md += f"**Total Ground Truth Vulnerabilities:** {len(gt_data)}\n\n"
    summary_md += "| Tool / Skenario | TP | FP | FN | Precision (%) | Recall (%) | F1-Score (%) |\n"
    summary_md += "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |\n"

    print("\n" + "=" * 75)
    print("RESULTS: SINGLE TOOLS EVALUATION (k=1)")
    print("=" * 75)
    print(f"{'Tool':<12} | {'TP':<4} | {'FP':<4} | {'FN':<4} | {'Precision':<11} | {'Recall':<10} | {'F1-Score':<10}")
    print("-" * 75)
    for r in records[:4]:
        print(f"{r['tool_combination']:<12} | {r['TP']:<4} | {r['FP']:<4} | {r['FN']:<4} | {r['Precision (%)']:<11} | {r['Recall (%)']:<10} | {r['F1_Score (%)']:<10}")
        summary_md += f"| **{r['tool_combination']}** | {r['TP']} | {r['FP']} | {r['FN']} | {r['Precision (%)']} | {r['Recall (%)']} | **{r['F1_Score (%)']}** |\n"

    # 5. Display Top 5 Highest F1-Score Combinations
    records_sorted = sorted(records, key=lambda x: (x["_f1_num"], x["_rec_num"], -x["FP"]), reverse=True)
    print("\n" + "=" * 75)
    print("RESULTS: TOP 5 HIGHEST F1-SCORE COMBINATIONS")
    print("=" * 75)
    print(f"{'Rank':<5} | {'k':<3} | {'Combination':<35} | {'Prec':<8} | {'Rec':<8} | {'F1':<8}")
    print("-" * 75)
    for rank, r in enumerate(records_sorted[:5], 1):
        print(f"#{rank:<4} | {r['k_tools']:<3} | {r['tool_combination'][:35]:<35} | {r['Precision (%)']:<8} | {r['Recall (%)']:<8} | {r['F1_Score (%)']:<8}")

    # Output to GITHUB_STEP_SUMMARY if available
    if "GITHUB_STEP_SUMMARY" in os.environ:
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(summary_md)


if __name__ == "__main__":
    main()
