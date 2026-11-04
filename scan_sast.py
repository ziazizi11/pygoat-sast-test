import json
import os
import sys

# Dukungan output UTF-8 untuk terminal Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

def load_ground_truth(file_path):
    if not os.path.exists(file_path):
        return set()
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return set((os.path.basename(item['file']), int(item['line'])) for item in data)

def parse_sarif(file_path):
    """Parser generik untuk format SARIF (Semgrep, CodeQL, SonarQube SARIF)"""
    findings = set()
    if not os.path.exists(file_path):
        return findings
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for run in data.get('runs', []):
                for result in run.get('results', []):
                    for loc in result.get('locations', []):
                        phys = loc.get('physicalLocation', {})
                        uri = phys.get('artifactLocation', {}).get('uri', '')
                        line = phys.get('region', {}).get('startLine')
                        if uri and line:
                            findings.add((os.path.basename(uri), int(line)))
    except Exception as e:
        print(f"Error parsing SARIF {file_path}: {e}")
    return findings

def parse_bandit(file_path):
    findings = set()
    if not os.path.exists(file_path):
        return findings
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for result in data.get('results', []):
                file_name = result.get('filename', '')
                line = result.get('line_number')
                if file_name and line:
                    findings.add((os.path.basename(file_name), int(line)))
    except Exception as e:
        print(f"Error parsing Bandit: {e}")
    return findings

def parse_sonarqube_json(file_path):
    findings = set()
    if not os.path.exists(file_path):
        return findings
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if 'issues' in data:
                for issue in data.get('issues', []):
                    component = issue.get('component', '').split(':')[-1]
                    line = issue.get('line')
                    if component and line:
                        findings.add((os.path.basename(component), int(line)))
            elif 'runs' in data:
                return parse_sarif(file_path)
    except Exception as e:
        print(f"Error parsing SonarQube JSON: {e}")
    return findings

def evaluate_scenario(name, detected_set, gt_set):
    tp = len(detected_set.intersection(gt_set))
    fp = len(detected_set - gt_set)
    fn = len(gt_set - detected_set)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        'name': name,
        'tp': tp,
        'fp': fp,
        'fn': fn,
        'precision': round(precision * 100, 2),
        'recall': round(recall * 100, 2),
        'f1': round(f1 * 100, 2)
    }

def main():
    gt_set = load_ground_truth('ground_truth.json')

    # Parsing hasil 4 tools
    semgrep_set = parse_sarif('semgrep-results.json')
    bandit_set = parse_bandit('bandit-results.json')
    codeql_set = parse_sarif('codeql-results.sarif')
    sonar_set = parse_sonarqube_json('sonarqube-results.json')

    results = []

    # ==========================================
    # SKENARIO A: INDIVIDUAL TOOLS (4 SKENARIO)
    # ==========================================
    results.append(evaluate_scenario("Skenario A - Semgrep", semgrep_set, gt_set))
    results.append(evaluate_scenario("Skenario A - Bandit", bandit_set, gt_set))
    results.append(evaluate_scenario("Skenario A - CodeQL", codeql_set, gt_set))
    results.append(evaluate_scenario("Skenario A - SonarQube", sonar_set, gt_set))

    # =======================================================
    # SKENARIO B: KOMBINASI 2 TOOLS - C(4,2) = 6 SKENARIO
    # =======================================================
    results.append(evaluate_scenario("Skenario B - Semgrep + Bandit", semgrep_set.union(bandit_set), gt_set))
    results.append(evaluate_scenario("Skenario B - Semgrep + CodeQL", semgrep_set.union(codeql_set), gt_set))
    results.append(evaluate_scenario("Skenario B - Semgrep + SonarQube", semgrep_set.union(sonar_set), gt_set))
    results.append(evaluate_scenario("Skenario B - Bandit + CodeQL", bandit_set.union(codeql_set), gt_set))
    results.append(evaluate_scenario("Skenario B - Bandit + SonarQube", bandit_set.union(sonar_set), gt_set))
    results.append(evaluate_scenario("Skenario B - CodeQL + SonarQube", codeql_set.union(sonar_set), gt_set))

    # =======================================================
    # SKENARIO C: KOMBINASI 3 TOOLS - C(4,3) = 4 SKENARIO
    # =======================================================
    results.append(evaluate_scenario("Skenario C - Semgrep + Bandit + CodeQL", semgrep_set.union(bandit_set).union(codeql_set), gt_set))
    results.append(evaluate_scenario("Skenario C - Semgrep + Bandit + SonarQube", semgrep_set.union(bandit_set).union(sonar_set), gt_set))
    results.append(evaluate_scenario("Skenario C - Semgrep + CodeQL + SonarQube", semgrep_set.union(codeql_set).union(sonar_set), gt_set))
    results.append(evaluate_scenario("Skenario C - Bandit + CodeQL + SonarQube", bandit_set.union(codeql_set).union(sonar_set), gt_set))

    # =======================================================
    # SKENARIO D: KOMBINASI 4 TOOLS - C(4,4) = 1 SKENARIO
    # =======================================================
    all_four = semgrep_set.union(bandit_set).union(codeql_set).union(sonar_set)
    results.append(evaluate_scenario("Skenario D - Semgrep + Bandit + CodeQL + SonarQube (Semua Tools)", all_four, gt_set))

    # Output Markdown ke GitHub Step Summary & Terminal
    summary_md = f"### 📊 Ringkasan Evaluasi Kinerja SAST (4 Tools)\n"
    summary_md += f"**Total Ground Truth Vulnerabilities:** {len(gt_set)}\n\n"
    summary_md += "| Skenario Pengujian | TP | FP | FN | Precision (%) | Recall (%) | F1-Score (%) |\n"
    summary_md += "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |\n"

    for r in results:
        summary_md += f"| **{r['name']}** | {r['tp']} | {r['fp']} | {r['fn']} | {r['precision']}% | {r['recall']}% | **{r['f1']}%** |\n"

    print(summary_md)

    if 'GITHUB_STEP_SUMMARY' in os.environ:
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as f:
            f.write(summary_md)

if __name__ == '__main__':
    main()