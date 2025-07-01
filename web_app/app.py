from flask import Flask, request, send_file, render_template, jsonify
import os, time, json, requests, tempfile, zipfile
from datetime import datetime

app = Flask(__name__)

SONAR_PROJECT_KEY = "aprajita-bhowal_shopizer"

def get_github_token():
    return (request.json.get("github_token") if request.json else None) or os.getenv("GITHUB_PAT")

def get_sonar_token():
    return (request.json.get("sonar_token") if request.json else None) or os.getenv("SONAR_TOKEN")

def get_semgrep_token():
    return (request.json.get("semgrep_token") if request.json else None) or os.getenv("SEMGREP_TOKEN")

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/trigger-codeql', methods=['POST'])
def trigger_codeql():
    repo_url = request.json.get("repo_url")
    owner, repo = "aprajita-bhowal", "shopizer"
    branch = "3.2.7"
    workflow_file = "codeql-analysis.yml"

    dispatch_url = f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_file}/dispatches"
    headers = {
        "Authorization": f"Bearer {get_github_token()}",
        "Accept": "application/vnd.github+json"
    }
    response = requests.post(dispatch_url, headers=headers, json={"ref": branch})
    if response.status_code != 204:
        return jsonify({"error": "Failed to trigger workflow", "detail": response.text}), 500

    time.sleep(10)
    run_id = None
    for _ in range(30):
        runs_url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs"
        runs_response = requests.get(runs_url, headers=headers).json()
        for run in runs_response.get("workflow_runs", []):
            if run["name"].lower().startswith("codeql") and run["head_branch"] == branch:
                run_id = run["id"]
                status = run["status"]
                conclusion = run["conclusion"]
                if status == "completed":
                    if conclusion != "success":
                        return jsonify({"error": f"Run failed: {conclusion}"}), 500
                    break
        if run_id:
            break
        time.sleep(15)

    if not run_id:
        return jsonify({"error": "Timed out waiting for workflow run"}), 504

    artifacts_url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts"
    artifacts_response = requests.get(artifacts_url, headers=headers).json()
    artifact = next((a for a in artifacts_response.get("artifacts", []) if "codeql-report" in a["name"]), None)
    if not artifact:
        return jsonify({"error": "SARIF artifact not found"}), 404

    download_url = artifact["archive_download_url"]
    zip_resp = requests.get(download_url, headers=headers)
    zip_path = tempfile.NamedTemporaryFile(delete=False, suffix=".zip").name
    with open(zip_path, "wb") as f:
        f.write(zip_resp.content)

    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        extract_dir = tempfile.mkdtemp()
        zip_ref.extractall(extract_dir)
        sarif_file = os.path.join(extract_dir, zip_ref.namelist()[0])

    with open(sarif_file) as f:
        report_json = json.load(f)

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    with open(tmp_file.name, 'w') as f:
        json.dump(report_json, f, indent=2)

    return send_file(tmp_file.name, as_attachment=True, download_name="codeql-report.json", mimetype="application/json")

@app.route('/trigger-sonar', methods=['POST'])
def trigger_sonar():
    API_URL = f"https://sonarcloud.io/api/issues/search?componentKeys={SONAR_PROJECT_KEY}&types=VULNERABILITY"
    auth = (get_sonar_token(), "")
    headers = {"Accept": "application/json"}
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "SonarCloud", "informationUri": "https://sonarcloud.io", "rules": []}},
            "results": []
        }]
    }

    all_issues = []
    page = 1
    while True:
        r = requests.get(f"{API_URL}&p={page}&ps=100", headers=headers, auth=auth)
        if r.status_code != 200:
            return jsonify({"error": "Failed to fetch issues", "detail": r.text}), 500
        data = r.json()
        all_issues.extend(data["issues"])
        if data["paging"]["total"] <= page * 100:
            break
        page += 1

    rules_map = {}
    for issue in all_issues:
        rule_id = issue["rule"]
        severity = issue["severity"]
        message = issue["message"]
        file_path = issue.get("component", "").split(":")[-1]
        line = issue.get("line", 1)

        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": rule_id},
                "helpUri": f"https://rules.sonarsource.com/java/RSPEC-{rule_id.split(':')[-1]}" 
            }

        sarif["runs"][0]["results"].append({
            "ruleId": rule_id,
            "level": severity.lower(),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {"startLine": line}
                }
            }]
        })

    sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules_map.values())

    tmp_path = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    with open(tmp_path.name, 'w') as f:
        json.dump(sarif, f, indent=2)

    return send_file(tmp_path.name, as_attachment=True, download_name="sonarqube-report.json", mimetype="application/json")


@app.route('/trigger-semgrep', methods=['POST'])
def trigger_semgrep():
    repo_url = request.json.get("repo_url")
    headers = {
        "Authorization": f"Bearer {get_semgrep_token()}",
        "Accept": "application/json"
    }

    scans_resp = requests.get(
        "https://semgrep.dev/api/v1/scans",
        headers=headers,
        params={"repo": repo_url, "limit": 1}
    )
    if scans_resp.status_code != 200:
        return jsonify({"error": "Failed to fetch scans", "detail": scans_resp.text}), 500
    scans = scans_resp.json().get("scans", [])
    if not scans:
        return jsonify({"error": "No scans found"}), 404
    scan_id = scans[0]["id"]

    findings_resp = requests.get(
        f"https://semgrep.dev/api/v1/scans/{scan_id}/sarif",
        headers=headers
    )
    if findings_resp.status_code != 200:
        return jsonify({"error": "Failed to fetch findings", "detail": findings_resp.text}), 500

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    with open(tmp_file.name, 'wb') as f:
        f.write(findings_resp.content)

    return send_file(tmp_file.name, as_attachment=True, download_name="semgrep-report.json", mimetype="application/json")


@app.route('/trigger-dependabot', methods=['POST'])
def trigger_dependabot():
    repo_url = request.json.get("repo_url")
    owner, repo = "aprajita-bhowal", "shopizer"

    headers = {
        "Authorization": f"Bearer {get_github_token()}",
        "Accept": "application/vnd.github+json"
    }

    alerts = []
    page = 1
    while True:
        resp = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/dependabot/alerts",
            headers=headers,
            params={"per_page": 100, "page": page}
        )
        if resp.status_code != 200:
            return jsonify({"error": "Failed to fetch dependabot alerts", "detail": resp.text}), 500
        data = resp.json()
        if not data:
            break
        alerts.extend(data)
        page += 1

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    with open(tmp_file.name, 'w') as f:
        json.dump(alerts, f, indent=2)

    return send_file(tmp_file.name, as_attachment=True, download_name="dependabot-report.json", mimetype="application/json")

if __name__ == '__main__':
    app.run(debug=True)
