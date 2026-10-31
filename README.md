# 🛡️ GitVigil

An enterprise-grade, automated security scanning and secret-leak prevention tool built specifically for modern engineering teams and CI/CD pipelines.


## 🚀 Overview

Accidental credential exposure remains one of the leading vectors for cloud security breaches. **GitVigil** integrates directly into your GitHub pull request workflows to scan codebases in real-time, detect high-risk secrets (such as AWS keys, GitHub tokens, and private keys), categorize them by severity, and post actionable audit reports directly onto the PR discussion timeline.


## 🛠️ Key Features

*   **Multi-Pattern Regex Engine:** Instantly detects high-risk credentials including AWS Access Keys, GitHub Personal Access Tokens, Stripe Live Keys, RSA Private Keys, and generic API secrets.
*   **Severity Categorization:** Automatically assigns **CRITICAL** or **WARNING** badges based on the severity of the exposed secret.
*   **Automated PR Commenting:** Interacts with the GitHub REST API via GitHub Actions to post clean, formatted markdown security audit reports directly on pull requests.
*   **Zero-Config CI/CD Integration:** Runs seamlessly inside standard GitHub Actions workflows on every push or pull request.


## ⚙️ Architecture & Tech Stack

*   **Core Engine:** Python (`scanner.py`) with optimized regular expressions for pattern matching and workspace file traversal.
*   **Automation & CI/CD:** GitHub Actions workflow triggered on pull requests.
*   **API Communication:** Python `requests` library for secure authentication and automated comment posting via the GitHub REST API.


## 🚀 Quick Setup & Usage

1. **Add the Workflow:** Place the workflow configuration file inside `.github/workflows/security-scan.yml`.
2. **Deploy the Scanner:** Ensure `scanner.py` is located in your root repository directory.
3. **Trigger via Pull Request:** Open a pull request or push code changes to trigger the automated security scan and view the audit report posted directly by GitVigil.


## 💡 Built For Security & Scale

GitVigil bridges the gap between development speed and robust security compliance, ensuring that sensitive keys never make it to your production branches.