import os
import requests

GITHUB_API_URL = "https://api.github.com"

def check_dependabot(repo_name, token):
    url = f"{GITHUB_API_URL}/repos/{repo_name}/vulnerability-alerts"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.dorian-preview+json",
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 204:
        print("✅ Dependabot is enabled.")
    else:
        raise Exception("❌ Dependabot is not enabled or misconfigured.")

def check_codeql(repo_name, token):
    url = f"{GITHUB_API_URL}/repos/{repo_name}/code-scanning/alerts"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200 and response.json():
        print("✅ CodeQL analysis is running and alerts are available.")
    else:
        raise Exception("❌ CodeQL is not configured or no alerts are available.")

if __name__ == "__main__":
    repo_name = os.getenv("REPO_NAME")
    token = os.getenv("GITHUB_TOKEN")
    
    if not repo_name or not token:
        raise Exception("Environment variables REPO_NAME or GITHUB_TOKEN are missing.")

    print(f"Checking security configurations for repository: {repo_name}")
    
    # Check Dependabot
    check_dependabot(repo_name, token)
    
    # Check CodeQL
    check_codeql(repo_name, token)

    print("✅ All security configurations are correctly enabled.")
