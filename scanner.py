import os
import sys
import re
from git import Repo
import requests

# Define high-risk patterns with regex and severity levels
SECRET_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "regex": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": "CRITICAL"
    },
    {
        "name": "GitHub Personal Access Token",
        "regex": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
        "severity": "CRITICAL"
    },
    {
        "name": "Stripe Live Key",
        "regex": re.compile(r"rk_live_[0-9a-zA-Z]{24}"),
        "severity": "CRITICAL"
    },
    {
        "name": "Generic API Key / Secret",
        "regex": re.compile(r"(?i)(api_key|secret_key|password|auth_token)\s*=\s*['\"'][0-9a-zA-Z-_]{16,64}['\"']"),
        "severity": "WARNING"
    },
    {
        "name": "Private RSA Key",
        "regex": re.compile(r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "severity": "CRITICAL"
    }
]

def get_diff():
    repo = Repo(".")
    # Get the diff of the current working branch against main/master
    diff = repo.git.diff("origin/main")
    return diff

def scan_diff(diff_text):
    findings = []
    for line in diff_text.splitlines():
        # Only check added or modified lines in the diff
        if line.startswith("+") and not line.startswith("+++"):
            for pattern in SECRET_PATTERNS:
                if pattern["regex"].search(line):
                    findings.append({
                        "type": pattern["name"],
                        "severity": pattern["severity"],
                        "matched_line": line.strip()
                    })
    return findings

def generate_report(findings):
    if not findings:
        return "### 🛡️ GitVigil Security Audit\n\n✅ **No security threats or secret leaks detected in this diff.**"

    report = "### 🚨 GitVigil Security Audit - Leaks Detected!\n\n"
    report += "GitVigil scanned your pull request diff and flagged the following potential security risks:\n\n"
    report += "| Severity | Secret Type | Evidence / Context |\n"
    report += "| :--- | :--- | :--- |\n"
    
    for f in findings:
        badge = "🔴 **CRITICAL**" if f["severity"] == "CRITICAL" else "🟡 **WARNING**"
        safe_line = f["matched_line"][:20] + "..." if len(f["matched_line"]) > 20 else f["matched_line"]
        report += f"| {badge} | {f['type']} | `{safe_line}` |\n"
        
    report += "\n> *Action Required:* Please revoke these secrets immediately, remove them from your commit history, and use environment variables instead."
    return report

def post_comment(report_body):
    token = os.environ.get("GITHUB_TOKEN")
    repo_name = os.environ.get("REPO_NAME")
    pr_number = os.environ.get("PR_NUMBER")

    if not token or not repo_name or not pr_number:
        print("GitHub environment variables missing. Writing report locally.")
        with open("gitvigil_report.md", "w") as f:
            f.write(report_body)
        return

    url = f"https://api.github.com/repos/{repo_name}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }
    response = requests.post(url, json={"body": report_body}, headers=headers)
    
    if response.status_code == 201:
        print("Successfully posted security audit comment to PR.")
    else:
        print(f"Failed to post comment: {response.text}")

    with open("gitvigil_report.md", "w") as f:
        f.write(report_body)

if __name__ == "__main__":
    print("Running GitVigil Multi-Pattern Security Scanner...")
    diff = get_diff()
    findings = scan_diff(diff)
    report = generate_report(findings)
    post_comment(report)