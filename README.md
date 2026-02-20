# Security CLI Assessment Script 🛡️🛡️🛡️

## A Python security‑assessment script that scans mutliples items (shell history, Homebrew, SSH keys, VSCode extensions...) to detect vulnerabilities, outdated software and leaks. 

![Python](https://img.shields.io/badge/Python-3.13+-blue?logo=python)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-red)
![License](https://img.shields.io/badge/license-MIT-green)


### **Overview**
This Python-based security assessment tool helps maintain your system's integrity by performing basic/essential security checks. It evaluates critical aspects of your setup and ensures your machine is free from potential vulnerabilities, outdated software and sensitive data leaks.

Designed specifically for **macOS users**, this script works seamlessly with your shell history, Homebrew packages, SSH keys, VSCode extensions and NPM libraries to keep your work and data secure.

---

### **Features**
- **🔍 PII Scanning**: Detects sensitive information like emails, SSNs, credit cards, and API tokens in shell history.
- **📦 NPM Audit**: Ensures your NPM packages are up-to-date and free from vulnerabilities.
- **🔑 SSH Key Inspection**: Identifies any insecure SSH keys or keys stored in unexpected locations.
- **🍺 Homebrew Package Check**: Verifies if your Homebrew-installed software is up-to-date.
- **🖥️ VSCode Extension Checker**: Confirms your VSCode and extensions are up-to-date.
- **🐳 Docker Socket**: Verifies the security of your Docker socket to detect potential privilege escalations.
- **🛠️ Terraform Secrets**: Scans Terraform state files (*.tfstate) for embedded secrets or credentials.
- **☸️ Kubeconfig**: Checks Kubernetes configuration files for exposed or insecure credentials.
- **☁️ AWS Credentials**: Detects AWS credentials in environment variables or configuration files to avoid accidental exposure.
- **🔏 Git GPG Signing**: Ensures Git commit signing with GPG keys is enforced for commit authenticity.
- **🐍 Python Vulnerabilities**: Scans installed Python packages for known security vulnerabilities.
- **🐍 Python and Pip Versions**: Checks installed Python and Pip versions.
- **🔐 GitHub Token Rotation**: Alerts if GitHub personal access tokens have not been rotated within a secure timeframe.
---

### **Getting Started**

#### **Pre-Requisites**
- Python 3.1.x  
- macOS (Required)  
- Install necessary dependencies:  
  ```bash
  pip install colorama requests
  ```

#### **Usage**
1. Clone this repository.
 ```bash
 git clone https://github.com/SecureLayer/cli_security_assessment.git
 ```
2. Open a terminal and navigate to the script's directory.
 ```bash
  cd cli_security_assessment
 ```
3. Run the script with the following command:  
   ```bash
   python cli_security_evaluator.py
   ```
3 bis. Use poetry to run the script with the following command:  
   ```bash
   poetry run python cli_security_evaluator.py   
   ```
---

### **Script Walkthrough**
1. **Shell History Check**  
   Detects any **PII (Personally Identifiable Information)** in your shell history files (zsh/bash).

2. **NPM Package Security Audit**  
   Uses `npm audit` to ensure your JavaScript dependencies are vulnerability-free.

3. **SSH Key Validation**  
   Looks for **weak algorithms** (e.g., `ssh-rsa`, `ssh-dss`) and SSH keys in the home directory to maintain security hygiene.

4. **Homebrew Software Check**  
   Verifies all installed packages are up-to-date with `brew outdated`.

5. **VSCode Version & Extensions Check**  
   Compares your local VSCode version with the latest release on GitHub and ensures your extensions are updated.

---

### **Example Output**

```
🔍 Checking for PII in history file...
✅ No PII found in ~/.zsh_history.

🔍 Checking NPM libraries...
✅ All NPM packages are up-to-date.

🔍 Checking SSH keys...
✅ Secure SSH key found: ~/.ssh/id_ed25519.pub


Security Assessment Report:

PII Check: Secured
NPM Libraries: Secured
SSH Keys: Secured


Security Grade: 100%
Recommendation: Excellent security posture.

Results delivered with ❤️ by SecureLayer © 2024.
```
   
---

### **Disclaimer**
This tool is provided "as-is" and is intended to **assist** users with security assessments. It is not a substitute for professional security services or audits.

---

### **Contributions & Support**
We welcome contributions! Feel free to submit pull requests or report issues. 
Do not hesitate to contact us at: 
📧 **github@securelayer.co**


### **Final Note**
Keeping your system secure is a continuous journey. This script provides a solid foundation, but always remain vigilant and apply the latest security practices!

💙 **Security is a priority, not an option!** Stay safe with SecureLayer.