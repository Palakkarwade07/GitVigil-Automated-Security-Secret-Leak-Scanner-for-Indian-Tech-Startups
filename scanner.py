import os
import sys
import requests
from git import Repo

BHARATCODE_API_URL = "https://bharatcode.ai/api/model/v1/chat/completions"
API_KEY = os.getenv("BHARATCODE_API_KEY")

def get_git_diff():
    """Extracts the full PR diff using merge-base or falls back safely."""
    try:
        repo = Repo(os.getcwd())
        
        if os.getenv("GITHUB_ACTIONS"):
            base_ref = os.getenv("GITHUB_BASE_REF")
            if base_ref:
                try:
                    # Fetch base ref to ensure git has it for comparison
                    repo.git.fetch("origin", base_ref)
                    merge_base = repo.git.merge_base(f"origin/{base_ref}", "HEAD").strip()
                    print(f"🔍 Computed merge-base between origin/{base_ref} and HEAD: {merge_base}")
                    return repo.git.diff(merge_base, 'HEAD')
                except Exception as e:
                    print(f"⚠️ Merge-base calculation failed ({e}), falling back to HEAD^..HEAD")
            
            # Fallback for GITHUB_ACTIONS if base_ref is missing
            return repo.git.diff('HEAD^', 'HEAD')
        else:
            # Local run fallback
            diff = repo.git.diff('--cached')
            if not diff:
                diff = repo.git.diff('HEAD~1')
            return diff
            
    except Exception as e:
        print(f"❌ Error reading git diff via GitPython: {e}")
        return os.getenv("CUSTOM_DIFF", "")

def analyze_code_diff(code_diff):
    """Sends code diff to BharatCode API for deep vulnerability & secret leak analysis."""
    if not API_KEY:
        print("❌ Error: BHARATCODE_API_KEY environment variable is missing.")
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
        response = requests.post(BHARATCODE_API_URL, json=payload, headers=headers, timeout=30)
        if response.status_code == 200:
            result = response.json()
            return result.get("choices", [{}])[0].get("message", {}).get("content", "No analysis returned.")
        else:
            error_msg = f"❌ BharatCode API Error: Status {response.status_code}\n{response.text}"
            print(error_msg)
            return error_msg
    except Exception as e:
        error_msg = f"❌ Request Failed: {e}"
        print(error_msg)
        return error_msg

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
        
        # Check if the report indicates an API failure
        if report.startswith("❌"):
            with open("gitvigil_report.md", "w", encoding="utf-8") as f:
                f.write("### ❌ GitVigil Security Audit Failed\n\n")
                f.write(report)
            sys.exit(1)  # Fail CI run explicitly on error
            
        # Save successful report for GitHub Actions
        with open("gitvigil_report.md", "w", encoding="utf-8") as f:
            f.write("### 🛡️ GitVigil Automated Security Audit\n\n")
            f.write(report)
    else:
        print("ℹ️ No code changes detected to scan.")
        with open("gitvigil_report.md", "w", encoding="utf-8") as f:
            f.write("### 🛡️ GitVigil Security Audit\n\nNo code changes or security threats detected in this diff.")