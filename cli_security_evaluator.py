# Security assessment script by SecureLayer © 2024. All rights reserved.

# add python verification 
# correct npm loop

import os
import re
import subprocess
import json
import requests
from colorama import Fore, init 

init(autoreset=True)

__security_firm_watermark__ = "This script is owned by SecureLayer © 2024."

def watermark_log():
    log_message = "Security assessment script © 2024 by SLayer"
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
    vscode_version = run_command(["code", "-v"])
    if vscode_version:
        try:
            latest_version = requests.get("https://api.github.com/repos/microsoft/vscode/releases/latest", timeout=5).json()["tag_name"]
            if vscode_version.split()[0] != latest_version:
                print(Fore.RED + f"⚠️ Outdated VSCode version found: {vscode_version}")
                return False
        except requests.RequestException:
            print(Fore.YELLOW + "⚠️ Could not fetch latest VSCode version.")

    extension_updates = run_command(["grep", '"updated":false', os.path.expanduser("~/.vscode/extensions/extensions.json")])
    if extension_updates:
        print(Fore.GREEN + "✅ VSCode and extensions are up-to-date.")
        return True
    return False

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

def evaluate_security():
    results = {
        "PII Check": check_pii_in_history(),
        "NPM Libraries": check_npm_libraries(),
        "SSH Keys": check_ssh_keys(),
        "Homebrew Packages": check_homebrew_updates(),
        "VSCode": check_vscode_updates(),
        "Python and pip versions": check_python_versions(),
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
