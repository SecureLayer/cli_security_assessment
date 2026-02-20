# Security assessment script by SecureLayer © 2024. All rights reserved.

# Improved version with parallel execution, macOS-specific checks and better accuracy.
# AI Help: ChatGPT 4 to start & reviewed/improved by Claude Opus 4.6
        
        
import os
import re
import sys
import stat
import subprocess
import json
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library is required. Install with: pip3 install requests")
    sys.exit(1)

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    # Fallback: no color output
    class _NoColor:
        def __getattr__(self, _):
            return ""
    Fore = _NoColor()
    Style = _NoColor()

__security_firm_watermark__ = "This script has been created and improved by SecureLayer since 2024."

# ---------------------------------------------------------------------------
# Globals & Configuration
# ---------------------------------------------------------------------------

HOME_DIR = os.path.expanduser("~")

# Directories to skip during recursive filesystem scans
SKIP_DIRS = {
    "node_modules", ".git", ".cache", "__pycache__", "venv", ".venv",
    "Library", ".Trash", ".npm", ".nvm", ".pyenv", ".local",
    "Applications", "Pictures", "Music", "Movies", "Downloads",
}

# Luhn algorithm for credit card validation
def _luhn_check(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def run_command(command_list, timeout=30) -> Optional[str]:
    """Run a shell command and return stdout, or None on failure."""
    try:
        result = subprocess.check_output(
            command_list, text=True, stderr=subprocess.DEVNULL, timeout=timeout
        ).strip()
        return result if result else None
    except FileNotFoundError:
        return None
    except subprocess.CalledProcessError:
        return None
    except subprocess.TimeoutExpired:
        return None


def command_exists(cmd: str) -> bool:
    """Check if a command is available on PATH."""
    return run_command(["which", cmd]) is not None


def walk_home_filtered(extensions: set[str], max_depth: int = 6):
    """Walk the home directory, skipping heavy/irrelevant directories.
    Yields full file paths matching the given extensions."""
    for root, dirs, files in os.walk(HOME_DIR):
        # Calculate depth relative to HOME_DIR
        depth = root.replace(HOME_DIR, "").count(os.sep)
        if depth >= max_depth:
            dirs.clear()
            continue

        # Prune skipped directories (modifying dirs in-place)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]

        for f in files:
            if any(f.endswith(ext) for ext in extensions):
                yield os.path.join(root, f)


def watermark_log():
    log_message = "Security assessment script © 2024 by SecureLayer"
    try:
        subprocess.run(["logger", log_message], check=True, timeout=5,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# PII patterns & checker
# ---------------------------------------------------------------------------

def pii_patterns():
    return {
        "Emails": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "SSNs": r"\b\d{3}-\d{2}-\d{4}\b",
        "Credit Cards": r"\b(?:\d[ -]*?){13,16}\b",
        "IP Addresses": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "API Keys/Tokens": r"(?i)(?:api|token|key|secret)[\s:=]+['\"]?[a-zA-Z0-9_\-]{16,}['\"]?",
    }


def check_pii_in_history(history_file: str) -> Optional[bool]:
    """Check shell history for PII leaks."""
    print(Fore.YELLOW + "🔍 Checking for PII in history file...")
    if not history_file or not os.path.exists(history_file):
        print(Fore.YELLOW + "⚠️ History file not found — skipping.")
        return None

    try:
        with open(history_file, "r", errors="replace") as f:
            content = f.read(100_000)
    except OSError:
        print(Fore.RED + "⚠️ Could not read history file.")
        return None

    findings = {}
    for pii_type, pattern in pii_patterns().items():
        matches = re.findall(pattern, content)
        if pii_type == "Credit Cards":
            # Validate with Luhn to eliminate false positives
            matches = [m for m in matches if _luhn_check(m)]
        if pii_type == "IP Addresses":
            # Filter out common non-sensitive IPs
            benign = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}
            matches = [m for m in matches if m not in benign]
        if matches:
            findings[pii_type] = len(matches)

    if findings:
        print(Fore.RED + f"⚠️ PII found in {history_file}: {findings}")
        return False
    print(Fore.GREEN + f"✅ No PII found in {history_file}.")
    return True


# ---------------------------------------------------------------------------
# NPM
# ---------------------------------------------------------------------------

def check_npm_libraries() -> Optional[bool]:
    """Check for NPM audit vulnerabilities (only if npm + package.json exist)."""
    print(Fore.YELLOW + "🔍 Checking NPM libraries...")

    if not command_exists("npm"):
        print(Fore.YELLOW + "⚠️ npm not installed — skipping.")
        return None

    # npm audit only makes sense with a package.json in the cwd
    if not os.path.exists("package.json") and not os.path.exists("package-lock.json"):
        print(Fore.YELLOW + "⚠️ No package.json/lock in cwd — skipping NPM audit.")
        return None

    for attempt in range(2):
        output = run_command(["npm", "audit", "--json"])
        if output:
            try:
                audit_data = json.loads(output)
                vulns = audit_data.get("metadata", {}).get("vulnerabilities", {})
                high_critical = vulns.get("high", 0) + vulns.get("critical", 0)
                total = vulns.get("total", 0)
                if high_critical > 0:
                    print(Fore.RED + f"⚠️ {high_critical} high/critical vulnerabilities in NPM packages.")
                    return False
                if total > 0:
                    print(Fore.YELLOW + f"⚠️ {total} low/moderate NPM vulnerabilities (non-blocking).")
                    return True  # Only high/critical fail the check
                print(Fore.GREEN + "✅ No NPM vulnerabilities found.")
                return True
            except json.JSONDecodeError:
                print(Fore.YELLOW + "⚠️ Could not decode NPM audit output.")
                return None
        if attempt == 0:
            run_command(["npm", "cache", "clean", "--force"])

    print(Fore.RED + "⚠️ NPM audit failed after retries.")
    return None


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

def check_ssh_keys() -> Optional[bool]:
    """Check SSH key algorithms and whether keys exist outside ~/.ssh."""
    print(Fore.YELLOW + "🔍 Checking SSH keys...")
    ssh_dir = os.path.join(HOME_DIR, ".ssh")
    weak_algos = {"ssh-rsa", "ssh-dss"}
    is_secure = True

    # Check for .pub keys outside ~/.ssh
    for pubkey in walk_home_filtered({".pub"}, max_depth=4):
        if not pubkey.startswith(ssh_dir):
            print(Fore.RED + f"⚠️ SSH key found outside .ssh: {pubkey}")
            is_secure = False

    # Check algorithms of keys inside ~/.ssh
    if os.path.isdir(ssh_dir):
        for entry in os.listdir(ssh_dir):
            if entry.endswith(".pub"):
                path = os.path.join(ssh_dir, entry)
                try:
                    with open(path, "r") as f:
                        data = f.read()
                    if any(algo in data for algo in weak_algos):
                        print(Fore.RED + f"⚠️ Weak SSH algorithm: {path}")
                        is_secure = False
                    else:
                        print(Fore.GREEN + f"✅ Secure SSH key: {path}")
                except OSError:
                    continue
    else:
        print(Fore.YELLOW + "⚠️ No .ssh directory found.")
        return None

    return is_secure


# ---------------------------------------------------------------------------
# Homebrew
# ---------------------------------------------------------------------------

def check_homebrew_updates() -> Optional[bool]:
    print(Fore.YELLOW + "🔍 Checking Homebrew packages...")
    if not command_exists("brew"):
        print(Fore.YELLOW + "⚠️ Homebrew not installed — skipping.")
        return None
    output = run_command(["brew", "outdated", "--quiet"])
    if output:
        count = len(output.splitlines())
        print(Fore.RED + f"⚠️ {count} outdated Homebrew packages.")
        return False
    print(Fore.GREEN + "✅ All Homebrew packages are up-to-date.")
    return True


# ---------------------------------------------------------------------------
# VSCode
# ---------------------------------------------------------------------------

def _parse_version(v: str):
    """Parse a version string into a tuple of ints for comparison."""
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else (0,)


def check_vscode_updates() -> Optional[bool]:
    print(Fore.YELLOW + "🔍 Checking VSCode...")

    if not command_exists("code"):
        print(Fore.YELLOW + "⚠️ VSCode CLI ('code') not found — skipping.")
        return None

    version_output = run_command(["code", "-v"])
    if not version_output:
        print(Fore.RED + "⚠️ Could not determine VSCode version.")
        return False

    local_version = version_output.splitlines()[0].strip().lstrip("v")

    try:
        r = requests.get(
            "https://api.github.com/repos/microsoft/vscode/releases/latest",
            timeout=15,
        )
        r.raise_for_status()
        latest_version = r.json().get("tag_name", "").lstrip("v")
    except requests.RequestException:
        print(Fore.YELLOW + "⚠️ Could not fetch latest VSCode version — assuming OK.")
        latest_version = local_version

    local_tuple = _parse_version(local_version)
    latest_tuple = _parse_version(latest_version)

    if local_tuple < latest_tuple:
        print(Fore.RED + f"⚠️ Outdated VSCode. Local: {local_version}, Latest: {latest_version}")
        return False

    print(Fore.GREEN + f"✅ VSCode is up-to-date ({local_version}).")
    return True


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

def check_python_versions() -> Optional[bool]:
    print(Fore.YELLOW + "🔍 Checking Python and pip...")
    py = run_command(["python3", "--version"])
    pip = run_command(["pip3", "--version"])

    if py and pip:
        print(Fore.GREEN + f"✅ {py}")
        print(Fore.GREEN + f"✅ {pip}")
        return True
    elif py:
        print(Fore.GREEN + f"✅ {py}")
        print(Fore.YELLOW + "⚠️ pip3 not found.")
        return True  # Python itself is fine
    else:
        print(Fore.RED + "⚠️ Python3 not found.")
        return False


def check_python_vulnerabilities() -> Optional[bool]:
    print(Fore.YELLOW + "🔍 Checking Python package vulnerabilities...")
    if not command_exists("pip-audit"):
        print(Fore.YELLOW + "⚠️ pip-audit not installed — skipping. Install with: pip3 install pip-audit")
        return None
    output = run_command(["pip-audit", "-f", "json"], timeout=60)
    if output:
        try:
            data = json.loads(output)
            if isinstance(data, list) and len(data) > 0:
                print(Fore.RED + f"⚠️ {len(data)} vulnerable Python packages found.")
                return False
        except json.JSONDecodeError:
            print(Fore.YELLOW + "⚠️ Could not parse pip-audit output.")
            return None
    print(Fore.GREEN + "✅ No known Python package vulnerabilities.")
    return True


# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------

def check_docker_socket() -> Optional[bool]:
    print(Fore.YELLOW + "🔍 Checking Docker socket permissions...")
    sock_path = "/var/run/docker.sock"
    if not os.path.exists(sock_path):
        print(Fore.YELLOW + "⚠️ Docker socket not found — Docker may not be installed.")
        return None

    try:
        st = os.stat(sock_path)
        # Check if socket is world-readable or world-writable
        world_access = st.st_mode & (stat.S_IROTH | stat.S_IWOTH)
        if world_access:
            print(Fore.RED + "⚠️ Docker socket is world-accessible!")
            return False
        print(Fore.GREEN + "✅ Docker socket permissions are restricted.")
        return True
    except OSError as e:
        print(Fore.YELLOW + f"⚠️ Could not stat Docker socket: {e}")
        return None


# ---------------------------------------------------------------------------
# Terraform
# ---------------------------------------------------------------------------

def check_tfstate_secrets() -> Optional[bool]:
    print(Fore.YELLOW + "🔍 Checking Terraform state files for secrets...")
    secret_patterns = re.compile(
        r"(AKIA[0-9A-Z]{16}"               # AWS Access Key
        r"|AIza[0-9A-Za-z\-_]{35}"          # Google API Key
        r"|-----BEGIN (RSA |EC )?PRIVATE KEY-----"  # Private keys
        r"|ghp_[0-9A-Za-z]{36}"             # GitHub PAT
        r"|sk-[0-9A-Za-z]{20,})"            # OpenAI / Stripe style keys
    )
    found_files = list(walk_home_filtered({".tfstate"}, max_depth=6))
    if not found_files:
        print(Fore.YELLOW + "⚠️ No .tfstate files found — skipping.")
        return None

    secrets_found = False
    for path in found_files:
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read(500_000)  # Cap reading
            if secret_patterns.search(content):
                print(Fore.RED + f"⚠️ Possible secret in: {path}")
                secrets_found = True
        except OSError:
            continue

    if not secrets_found:
        print(Fore.GREEN + "✅ No secrets detected in Terraform state files.")
    return not secrets_found


# ---------------------------------------------------------------------------
# Kubernetes
# ---------------------------------------------------------------------------

def check_kubeconfig() -> Optional[bool]:
    print(Fore.YELLOW + "🔍 Checking Kubernetes config security...")
    kube_path = os.path.join(HOME_DIR, ".kube", "config")
    if not os.path.exists(kube_path):
        print(Fore.YELLOW + "⚠️ Kubeconfig not found — skipping.")
        return None

    try:
        st = os.stat(kube_path)
        world_readable = st.st_mode & stat.S_IROTH
        if world_readable:
            print(Fore.RED + "⚠️ Kubeconfig is world-readable!")
            return False
    except OSError:
        pass

    try:
        with open(kube_path, "r", errors="ignore") as f:
            content = f.read()
        if "insecure-skip-tls-verify: true" in content:
            print(Fore.RED + "⚠️ Insecure Kubernetes cluster (TLS verification disabled).")
            return False
    except OSError:
        print(Fore.YELLOW + "⚠️ Could not read kubeconfig.")
        return None

    print(Fore.GREEN + "✅ Kubeconfig appears secure.")
    return True


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------

def check_aws_credentials() -> Optional[bool]:
    print(Fore.YELLOW + "🔍 Checking AWS credentials file...")
    creds_file = os.path.join(HOME_DIR, ".aws", "credentials")
    if not os.path.exists(creds_file):
        print(Fore.GREEN + "✅ No AWS credentials file found.")
        return True

    # Check file permissions
    try:
        st = os.stat(creds_file)
        world_readable = st.st_mode & (stat.S_IROTH | stat.S_IWOTH)
        if world_readable:
            print(Fore.RED + "⚠️ AWS credentials file is world-readable/writable!")
            return False
    except OSError:
        pass

    # Check for long-lived access keys (vs SSO / role-based)
    try:
        with open(creds_file, "r", errors="ignore") as f:
            content = f.read()
        if re.search(r"aws_access_key_id\s*=\s*AKIA", content):
            print(Fore.RED + "⚠️ Long-lived AWS access key detected. Consider using SSO or IAM roles.")
            return False
        print(Fore.GREEN + "✅ AWS credentials file exists but uses short-lived/role-based credentials.")
        return True
    except OSError:
        print(Fore.YELLOW + "⚠️ Could not read AWS credentials file.")
        return None


# ---------------------------------------------------------------------------
# Git
# ---------------------------------------------------------------------------

def check_git_security() -> Optional[bool]:
    """Check Git GPG signing and credential helper configuration."""
    print(Fore.YELLOW + "🔍 Checking Git security configuration...")
    if not command_exists("git"):
        print(Fore.YELLOW + "⚠️ Git not installed — skipping.")
        return None

    is_secure = True

    # GPG signing
    signing = run_command(["git", "config", "--global", "commit.gpgsign"])
    if signing != "true":
        print(Fore.RED + "⚠️ GPG commit signing not enforced.")
        is_secure = False
    else:
        print(Fore.GREEN + "✅ GPG commit signing is enabled.")

    # Credential helper (plaintext store is insecure)
    cred_helper = run_command(["git", "config", "--global", "credential.helper"])
    if cred_helper and "store" in cred_helper:
        print(Fore.RED + "⚠️ Git credential helper uses plaintext 'store'. Use 'osxkeychain' instead.")
        is_secure = False
    elif cred_helper:
        print(Fore.GREEN + f"✅ Git credential helper: {cred_helper}")

    return is_secure


# ---------------------------------------------------------------------------
# GitHub Token
# ---------------------------------------------------------------------------

def check_github_token_rotation() -> Optional[bool]:
    print(Fore.YELLOW + "🔍 Checking GitHub token...")
    token_path = os.path.join(HOME_DIR, ".github_tokens")
    if not os.path.exists(token_path):
        print(Fore.GREEN + "✅ No GitHub token file detected.")
        return True

    try:
        with open(token_path, "r") as f:
            token = f.read().strip()
        if not token:
            print(Fore.YELLOW + "⚠️ GitHub token file is empty.")
            return None
        headers = {"Authorization": f"Bearer {token}"}
        r = requests.get("https://api.github.com/user", headers=headers, timeout=15)
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


# ---------------------------------------------------------------------------
# macOS-Specific Checks
# ---------------------------------------------------------------------------

def check_filevault() -> Optional[bool]:
    """Check if FileVault disk encryption is enabled."""
    print(Fore.YELLOW + "🔍 Checking FileVault encryption...")
    output = run_command(["fdesetup", "status"])
    if output and "On" in output:
        print(Fore.GREEN + "✅ FileVault is enabled.")
        return True
    elif output and "Off" in output:
        print(Fore.RED + "⚠️ FileVault is disabled — disk is not encrypted!")
        return False
    print(Fore.YELLOW + "⚠️ Could not determine FileVault status.")
    return None


def check_gatekeeper() -> Optional[bool]:
    """Check if macOS Gatekeeper is enabled."""
    print(Fore.YELLOW + "🔍 Checking Gatekeeper status...")
    output = run_command(["spctl", "--status"])
    if output and "enabled" in output.lower():
        print(Fore.GREEN + "✅ Gatekeeper is enabled.")
        return True
    elif output:
        print(Fore.RED + "⚠️ Gatekeeper is disabled!")
        return False
    print(Fore.YELLOW + "⚠️ Could not determine Gatekeeper status.")
    return None


def check_sip() -> Optional[bool]:
    """Check System Integrity Protection status."""
    print(Fore.YELLOW + "🔍 Checking System Integrity Protection (SIP)...")
    output = run_command(["csrutil", "status"])
    if output and "enabled" in output.lower():
        print(Fore.GREEN + "✅ SIP is enabled.")
        return True
    elif output:
        print(Fore.RED + "⚠️ SIP is disabled — system integrity at risk!")
        return False
    print(Fore.YELLOW + "⚠️ Could not determine SIP status.")
    return None


def check_firewall() -> Optional[bool]:
    """Check macOS Application Firewall status."""
    print(Fore.YELLOW + "🔍 Checking macOS firewall...")
    fw_path = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    if not os.path.exists(fw_path):
        print(Fore.YELLOW + "⚠️ Firewall binary not found.")
        return None
    output = run_command([fw_path, "--getglobalstate"])
    if output and "enabled" in output.lower():
        print(Fore.GREEN + "✅ macOS Firewall is enabled.")
        return True
    elif output:
        print(Fore.RED + "⚠️ macOS Firewall is disabled!")
        return False
    print(Fore.YELLOW + "⚠️ Could not determine firewall status.")
    return None


# ---------------------------------------------------------------------------
# Main evaluation engine
# ---------------------------------------------------------------------------

CHECK_REGISTRY = {
    # Category: (function, args)
    "PII in Shell History":     None,   # needs history_file arg, handled below
    "NPM Vulnerabilities":      check_npm_libraries,
    "SSH Keys":                  check_ssh_keys,
    "Homebrew Packages":        check_homebrew_updates,
    "VSCode":                   check_vscode_updates,
    "Python & pip":             check_python_versions,
    "Python Vulnerabilities":   check_python_vulnerabilities,
    "Docker Socket":            check_docker_socket,
    "Terraform Secrets":        check_tfstate_secrets,
    "Kubernetes Config":        check_kubeconfig,
    "AWS Credentials":          check_aws_credentials,
    "Git Security":             check_git_security,
    "GitHub Token":             check_github_token_rotation,
    "FileVault Encryption":     check_filevault,
    "Gatekeeper":               check_gatekeeper,
    "System Integrity (SIP)":   check_sip,
    "macOS Firewall":           check_firewall,
}


def get_history_file() -> Optional[str]:
    for name in (".zsh_history", ".bash_history"):
        path = os.path.join(HOME_DIR, name)
        if os.path.exists(path):
            return path
    return None


def evaluate_security(output_json: bool = False):
    history_file = get_history_file()
    if history_file:
        print(Fore.CYAN + f"Using history file: {history_file}\n")
    else:
        print(Fore.YELLOW + "⚠️ No shell history file found — PII check will be skipped.\n")

    print(Fore.CYAN + "This script is designed for macOS hosts only")
    print(Fore.CYAN + "Supported package manager: Homebrew\n")
    print(Fore.CYAN + "Running security checks in parallel...\n")

    results: dict[str, Optional[bool]] = {}
    start_time = time.time()

    # Build task map
    tasks = {}
    for name, func in CHECK_REGISTRY.items():
        if name == "PII in Shell History":
            tasks[name] = lambda: check_pii_in_history(history_file)
        else:
            tasks[name] = func

    # Execute all checks in parallel (max 6 threads to avoid I/O contention)
    with ThreadPoolExecutor(max_workers=6) as executor:
        future_to_name = {
            executor.submit(fn): name for name, fn in tasks.items()
        }
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                results[name] = future.result()
            except Exception as e:
                print(Fore.RED + f"⚠️ {name} raised an exception: {e}")
                results[name] = None

    elapsed = time.time() - start_time

    # --- Scoring ---
    applicable = {k: v for k, v in results.items() if v is not None}
    passed = sum(1 for v in applicable.values() if v is True)
    total = len(applicable)
    grade = (passed / total) * 100 if total > 0 else 0

    if grade == 100:
        recommendation = "Excellent security posture."
    elif grade >= 80:
        recommendation = "Good, but address the detected issues."
    elif grade >= 50:
        recommendation = "Moderate risk. Take action soon."
    else:
        recommendation = "High risk. Immediate action required."

    # --- Report ---
    if output_json:
        report = {
            "checks": {k: v for k, v in sorted(results.items())},
            "summary": {
                "total_applicable": total,
                "passed": passed,
                "failed": total - passed,
                "skipped": len(results) - total,
                "grade_percent": round(grade, 1),
                "recommendation": recommendation,
            },
            "elapsed_seconds": round(elapsed, 2),
        }
        print(json.dumps(report, indent=2))
    else:
        print(Fore.CYAN + "\n" + "=" * 50)
        print(Fore.CYAN + " Security Assessment Report")
        print(Fore.CYAN + "=" * 50 + "\n")

        for check in sorted(results.keys()):
            result = results[check]
            if result is True:
                print(Fore.GREEN + f"  ✅ {check}: Secured")
            elif result is False:
                print(Fore.RED + f"  ❌ {check}: Not Secured")
            else:
                print(Fore.YELLOW + f"  ⏭️  {check}: Skipped / N/A")

        print()
        print(Fore.CYAN + f"  Checks run:    {total} applicable / {len(results)} total")
        print(Fore.CYAN + f"  Passed:        {passed}")
        print(Fore.CYAN + f"  Failed:        {total - passed}")
        print(Fore.CYAN + f"  Skipped:       {len(results) - total}")
        print()

        color = Fore.GREEN if grade >= 80 else (Fore.YELLOW if grade >= 50 else Fore.RED)
        print(color + f"  Security Grade:    {grade:.0f}%")
        print(color + f"  Recommendation:    {recommendation}")
        print(Fore.CYAN + f"\n  Completed in {elapsed:.1f}s")
        print(Fore.MAGENTA + "\n  Security assessment delivered with ❤️ by SecureLayer.\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="macOS Developer Workstation Security Assessment"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format (for CI/CD integration)",
    )
    args = parser.parse_args()

    watermark_log()
    evaluate_security(output_json=args.json)


if __name__ == "__main__":
    main()