# Security assessment script by SecureLayer © 2024. All rights reserved.

# new checks added : Docker, Terraform, K8s, AWS, Git GPG signing, Token Rotation  

import os
import re
import subprocess
import json
import requests
from colorama import Fore, init 

init(autoreset=True)

__security_firm_watermark__ = "This script is owned by SecureLayer © 2024."

def watermark_log():
    log_message = "Security assessment script © 2024 by SecureLayer"
    subprocess.run(["logger", log_message], check=True)

print(Fore.CYAN + "This script is designed for macOS hosts only\n")

def get_history_file():
    home_dir = os.path.expanduser("~")
    zsh_history = os.path.join(home_dir, ".zsh_history")
    bash_history = os.path.join(home_dir, ".bash_history")

    if os.path.exists(zsh_history):
        return zsh_history
    elif os.path.exists(bash_history):
        return bash_history
    else:
        print(Fore.RED + "⚠️ No shell history file found.")
        return None

history_file = get_history_file()
if history_file:
    print(Fore.CYAN + f"Using history file: {history_file}\n")
else:
    exit()

print(Fore.CYAN + "Supported package manager: Homebrew\n")

def run_command(command_list):
    try:
        result = subprocess.check_output(command_list, text=True, stderr=subprocess.DEVNULL, timeout=10).strip()
        return result if result else None
    except subprocess.CalledProcessError:
        return None
    except subprocess.TimeoutExpired:
        print(Fore.RED + "⚠️ Command timed out.")
        return None

def pii_patterns():
    return {
        "Emails": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "SSNs": r"\b\d{3}-\d{2}-\d{4}\b",
        "Credit Cards": r"\b(?:\d[ -]*?){13,16}\b",
        "IP Addresses": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "API Keys/Tokens": r"(?i)(api|token|key|secret)[\s:]*[a-zA-Z0-9]{8,}"
    }

def check_pii_in_history():
    print(Fore.YELLOW + "🔍 Checking for PII in history file...")
    try:
        with open(history_file, 'r', errors='replace') as file:
            content = file.read(50000)  # Limit reading to avoid memory overuse.
    except FileNotFoundError:
        print(Fore.RED + "⚠️ History file not found.")
        return None

    findings = {}
    for pii_type, pattern in pii_patterns().items():
        matches = re.findall(pattern, content)
        if matches:
            findings[pii_type] = matches

    if findings:
        print(Fore.RED + f"⚠️ PII found in {history_file}: {findings}")
        return False
    print(Fore.GREEN + f"✅ No PII found in {history_file}.")
    return True

def check_npm_libraries(max_retries=3):
    print(Fore.YELLOW + "🔍 Checking NPM libraries...")
    for attempt in range(max_retries):
        output = run_command(["npm", "audit", "--json"])
        if output:
            try:
                audit_data = json.loads(output)
                total_vulnerabilities = audit_data.get("metadata", {}).get("vulnerabilities", {}).get("total", 0)
                if total_vulnerabilities > 0:
                    print(Fore.RED + "⚠️ Vulnerabilities found in NPM packages.")
                    return False
                print(Fore.GREEN + "✅ All NPM packages are up-to-date.")
                return True
            except json.JSONDecodeError:
                print(Fore.YELLOW + "⚠️ Could not decode NPM audit output.")
                return None
        else:
            print(Fore.YELLOW + f"⚠️ NPM audit failed (Attempt {attempt + 1}/{max_retries}). Trying to clean cache.")
            run_command(["npm", "cache", "clean", "--force"])

    print(Fore.RED + "⚠️ NPM audit failed after maximum retries.")
    return None

def check_ssh_keys():
    print(Fore.YELLOW + "🔍 Checking SSH keys...")
    home_keys = run_command(["find", os.path.expanduser("~"), "-path", "$HOME/.ssh", "-prune", "-o", "-name", "*.pub", "-print"]) 
    ssh_keys = run_command(["find", os.path.expanduser("~/.ssh"), "-name", "*.pub"])

    weak_algo = {"ssh-rsa", "ssh-dss"}
    is_secure = True

    if home_keys:
        print(Fore.RED + f"⚠️ SSH key found outside .ssh directory: {home_keys}")
        is_secure = False

    if ssh_keys:
        for key in ssh_keys.splitlines():
            with open(key, 'r') as f:
                key_data = f.read()
                if any(algo in key_data for algo in weak_algo):
                    print(Fore.RED + f"⚠️ Weak SSH algorithm found: {key}")
                    is_secure = False
                else:
                    print(Fore.GREEN + f"✅ Secure SSH key found: {key}")

    return is_secure

def check_homebrew_updates():
    print(Fore.YELLOW + "🔍 Checking Homebrew packages...")
    output = run_command(["brew", "outdated"])
    if output:
        print(Fore.RED + "⚠️ Outdated brew packages found.")
        return False
    print(Fore.GREEN + "✅ All brew packages are up-to-date.")
    return True

def check_vscode_updates():
    print(Fore.YELLOW + "🔍 Checking VSCode and extensions...")
    vscode_version_output = run_command(["code", "-v"])
    if vscode_version_output:
        local_version = vscode_version_output.splitlines()[0].strip().lstrip('v')
        try:
            latest_version = requests.get("https://api.github.com/repos/microsoft/vscode/releases/latest", timeout=5).json()["tag_name"].lstrip('v')
            if local_version != latest_version:
                print(Fore.RED + f"⚠️ Outdated VSCode version. Local: {local_version}, Latest: {latest_version}")
                return False
            else:
                print(Fore.GREEN + f"✅ VSCode is up-to-date. Version: {local_version}")
        except requests.RequestException:
            print(Fore.YELLOW + "⚠️ Could not fetch latest VSCode version.")
            return None
    else:
        print(Fore.RED + "⚠️ VSCode not found or failed to execute.")
        return None

    # Extension update check
    extensions = run_command(["code", "--list-extensions", "--show-versions"])
    if extensions:
        outdated_extensions = run_command(["code", "--list-extensions", "--outdated"])
        if outdated_extensions:
            print(Fore.RED + "⚠️ Outdated VSCode extensions found.")
            return False
        else:
            print(Fore.GREEN + "✅ All VSCode extensions are up-to-date.")
            return True
    return True

def check_python_versions():
    print(Fore.YELLOW + "🔍 Checking Python and pip versions...")
    python_version = run_command(["python3", "--version"])
    pip_version = run_command(["pip3", "--version"])

    if python_version and pip_version:
        print(Fore.GREEN + f"✅ Python version: {python_version}")
        print(Fore.GREEN + f"✅ Pip version: {pip_version}")
        return True
    else:
        print(Fore.RED + "⚠️ Python or Pip not found.")
        return False

def check_docker_socket():
    print(Fore.YELLOW + "🔍 Checking Docker socket permissions...")
    output = run_command(["ls", "-l", "/var/run/docker.sock"])
    if output and "docker" in output and "rw" in output:
        print(Fore.GREEN + "✅ Docker socket appears restricted.")
        return True
    print(Fore.RED + "⚠️ Docker socket may be world-accessible.")
    return False

def check_tfstate_secrets():
    print(Fore.YELLOW + "🔍 Checking Terraform state files for secrets...")
    tfstate_paths = []
    for root, dirs, files in os.walk(os.path.expanduser("~")):
        for file in files:
            if file.endswith(".tfstate"):
                tfstate_paths.append(os.path.join(root, file))

    secrets_found = False
    for path in tfstate_paths:
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
                if re.search(r'(AKIA|AIza|-----BEGIN PRIVATE KEY-----)', content):
                    print(Fore.RED + f"⚠️ Possible secret found in {path}")
                    secrets_found = True
        except Exception:
            continue
    return not secrets_found

def check_kubeconfig():
    print(Fore.YELLOW + "🔍 Checking Kubernetes config security...")
    kubeconfig_path = os.path.expanduser("~/.kube/config")
    if not os.path.exists(kubeconfig_path):
        print(Fore.YELLOW + "⚠️ Kubeconfig not found.")
        return None

    with open(kubeconfig_path, 'r', errors="ignore") as file:
        content = file.read()
        if "insecure-skip-tls-verify: true" in content:
            print(Fore.RED + "⚠️ Insecure Kubernetes cluster configuration.")
            return False
    print(Fore.GREEN + "✅ Kubeconfig appears secure.")
    return True

def check_aws_credentials():
    print(Fore.YELLOW + "🔍 Checking for exposed AWS credentials...")
    creds_file = os.path.expanduser("~/.aws/credentials")
    if os.path.exists(creds_file):
        with open(creds_file, 'r', errors="ignore") as f:
            content = f.read()
            if "aws_access_key_id" in content:
                print(Fore.RED + "⚠️ AWS credentials file detected.")
                return False
    print(Fore.GREEN + "✅ No exposed AWS credentials file.")
    return True

def check_git_gpg_signing():
    print(Fore.YELLOW + "🔍 Checking Git GPG signing...")
    signing = run_command(["git", "config", "--global", "commit.gpgsign"])
    if signing != "true":
        print(Fore.RED + "⚠️ GPG commit signing not enforced.")
        return False
    print(Fore.GREEN + "✅ GPG commit signing is enabled.")
    return True

def check_python_vulnerabilities():
    print(Fore.YELLOW + "🔍 Checking for Python package vulnerabilities...")
    try:
        output = run_command(["pip-audit", "-f", "json"])
        if output:
            data = json.loads(output)
            if data:
                print(Fore.RED + "⚠️ Vulnerable Python packages found.")
                return False
    except Exception:
        print(Fore.YELLOW + "⚠️ pip-audit not available or failed.")
        return None
    print(Fore.GREEN + "✅ No known Python package vulnerabilities.")
    return True

def check_github_token_rotation():
    print(Fore.YELLOW + "🔍 Checking GitHub token rotation...")
    token_path = os.path.expanduser("~/.github_tokens")
    if not os.path.exists(token_path):
        print(Fore.GREEN + "✅ No GitHub token file detected.")
        return True

    try:
        with open(token_path, 'r') as f:
            token = f.read().strip()
            headers = {"Authorization": f"Bearer {token}"}
            r = requests.get("https://api.github.com/user", headers=headers, timeout=5)
            if r.status_code == 401:
                print(Fore.RED + "⚠️ GitHub token is expired or invalid.")
                return False
            elif r.status_code == 200:
                print(Fore.GREEN + "✅ GitHub token is valid.")
                return True
            else:
                print(Fore.YELLOW + f"⚠️ Unexpected GitHub API status: {r.status_code}")
                return None
    except Exception as e:
        print(Fore.RED + f"⚠️ Error checking GitHub token: {e}")
        return None

def check_container_scan():
    print(Fore.YELLOW + "🔍 Running container image vulnerability scan...")
    images_output = run_command(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"])
    if not images_output:
        print(Fore.YELLOW + "⚠️ No local Docker images found.")
        return True

    images = images_output.splitlines()
    vulnerable_images = []

    for image in images[:3]:  # Limit scan to top 3 images for performance
        scan_output = run_command(["docker", "scout", "cves", image])
        if scan_output and "CRITICAL" in scan_output.upper():
            print(Fore.RED + f"⚠️ Critical CVEs found in image: {image}")
            vulnerable_images.append(image)

    if vulnerable_images:
        return False

    print(Fore.GREEN + "✅ No critical CVEs found in scanned Docker images.")
    return True

def evaluate_security():
    results = {
        "PII Check": check_pii_in_history(),
        "NPM Libraries": check_npm_libraries(),
        "SSH Keys": check_ssh_keys(),
        "Homebrew Packages": check_homebrew_updates(),
        "VSCode": check_vscode_updates(),
        "Python and pip versions": check_python_versions(),
        "Docker Socket": check_docker_socket(),
        "Terraform Secrets": check_tfstate_secrets(),
        "Kubeconfig": check_kubeconfig(),
        "AWS Credentials": check_aws_credentials(),
        "Git GPG Signing": check_git_gpg_signing(),
        "Python Vulnerabilities": check_python_vulnerabilities(),
        "GitHub Token Rotation": check_github_token_rotation(),
        "Container Image Scan": check_container_scan(),
    }

    score = sum(1 for result in results.values() if result is True)
    total_checks = len([r for r in results.values() if r is not None])
    grade = (score / total_checks) * 100 if total_checks > 0 else 0

    recommendation = (
        "Excellent security posture." if grade == 100 else
        "Good, but address detected issues." if grade >= 80 else
        "Moderate risk. Take action soon." if grade >= 50 else
        "High risk. Immediate action required."
    )

    print(Fore.CYAN + "\nSecurity Assessment Report:\n")
    for check, result in results.items():
        color = Fore.GREEN if result else Fore.RED
        status = "Secured" if result else "Not Secured"
        print(color + f"{check}: {status}")

    print(f"\nSecurity Grade: {grade}%")
    print(f"Recommendation: {recommendation}")
    print(Fore.MAGENTA + "\nSecurity assessment delivered with ❤️ by SecureLayer.\n")

if __name__ == "__main__":
    watermark_log()
    evaluate_security()
