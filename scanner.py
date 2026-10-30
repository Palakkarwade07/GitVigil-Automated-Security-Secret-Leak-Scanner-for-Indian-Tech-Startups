import os
import sys
<<<<<<< HEAD
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
=======
import requests
from git import Repo

BHARATCODE_API_URL = "https://bharatcode.ai/api/model/v1/chat/completions"
API_KEY = os.getenv("BHARATCODE_API_KEY")

def get_git_diff():
    """Extracts the latest git diff from the local repository or CI environment."""
    try:
        repo = Repo(os.getcwd())
        # If running in GitHub Actions, get the pull request diff range if available
        if os.getenv("GITHUB_ACTIONS"):
            diff = repo.git.diff('HEAD^', 'HEAD')
        else:
            diff = repo.git.diff('--cached')
            if not diff:
                diff = repo.git.diff('HEAD~1')
        return diff
    except Exception as e:
        print(f"Warning/Error reading git diff via GitPython: {e}")
        # Fallback: read environment diff or staged changes if any
        return os.getenv("CUSTOM_DIFF", "")

def analyze_code_diff(code_diff):
    """Sends code diff to BharatCode API for deep vulnerability & secret leak analysis."""
    if not API_KEY:
        print("Error: BHARATCODE_API_KEY environment variable is missing.")
        sys.exit(1)

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "qwen-3.8-27b",
        "messages": [
            {
                "role": "system", 
                "content": (
                    "You are GitVigil, an elite AI security sentinel built for the BharatCode Build League. "
                    "Analyze the provided git diff for hardcoded API keys, exposed database credentials, "
                    "JWT secrets, unsafe code patterns, and OWASP Top 10 vulnerabilities. "
                    "Provide a structured, aggressive, and professional Markdown security audit report containing: "
                    "1. Threat Level (CRITICAL / HIGH / MEDIUM / LOW) "
                    "2. Vulnerable Code Snippet "
                    "3. Risk Explanation "
                    "4. Exact Code Fix / Remediation."
                )
            },
            {
                "role": "user", 
                "content": f"Perform a strict security audit on this code diff:\n\n{code_diff}"
            }
        ],
        "temperature": 0.1
    }
    
    try:
        response = requests.post(BHARATCODE_API_URL, json=payload, headers=headers)
        if response.status_code == 200:
            result = response.json()
            return result.get("choices", [{}])[0].get("message", {}).get("content", "No analysis returned.")
        else:
            return f"❌ BharatCode API Error: {response.status_code} - {response.text}"
    except Exception as e:
        return f"❌ Request Failed: {e}"

if __name__ == "__main__":
    print("🔒 GitVigil: Scanning code diff for security vulnerabilities using BharatCode API...")
    diff_data = get_git_diff()
    
    if diff_data and len(diff_data.strip()) > 0:
        report = analyze_code_diff(diff_data)
        print("\n" + "="*50)
        print("🛡️ GITVIGIL SECURITY AUDIT REPORT")
        print("="*50)
        print(report)
        print("="*50)
        
        # Save report to a file so GitHub Actions can post it as a comment
        with open("gitvigil_report.md", "w", encoding="utf-8") as f:
            f.write("### 🛡️ GitVigil Automated Security Audit\n\n")
            f.write(report)
    else:
        print("ℹ️ No code changes detected to scan.")
        with open("gitvigil_report.md", "w", encoding="utf-8") as f:
            f.write("### 🛡️ GitVigil Security Audit\n\nNo code changes or security threats detected in this diff.")
>>>>>>> 5d70ea548f915aebd94bccce53eda58e6015bce7
