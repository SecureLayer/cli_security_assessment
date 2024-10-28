# **README.md: Security Assessment Script**

---

## 🛡️ Security Assessment Script  
*Delivered with ❤️ by SecureLayer © 2024*

### **Overview**
This Python-based security assessment tool helps maintain your system's integrity by performing essential security checks. It evaluates critical aspects of your setup and ensures your machine is free from potential vulnerabilities, outdated software, and sensitive data leaks.

Designed specifically for **macOS users**, this script works seamlessly with your shell history, Homebrew packages, SSH keys, VSCode extensions, and NPM libraries to keep you secure.

---

### **Features**
- **🔍 PII Scanning**: Detects sensitive information like emails, SSNs, credit cards, and API tokens in shell history.
- **📦 NPM Audit**: Ensures your NPM packages are up-to-date and free from vulnerabilities.
- **🔑 SSH Key Inspection**: Identifies any insecure SSH keys or keys stored in unexpected locations.
- **🍺 Homebrew Package Check**: Verifies if your Homebrew-installed software is up-to-date.
- **🖥️ VSCode Extension Checker**: Confirms your VSCode and extensions are up-to-date.

---

### **Getting Started**

#### **Prerequisites**
- Python 3.x  
- macOS (Required)  
- Install necessary dependencies:  
  ```bash
  pip install colorama requests
  ```

#### **Usage**
1. Clone the repository or download the script.
2. Open a terminal and navigate to the script's directory.
3. Run the script with the following command:  
   ```bash
   python cli_security_evaluator.py
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
✅ Secure SSH key found: ~/.ssh/id_rsa.pub

🔍 Checking Homebrew packages...
✅ All brew packages are up-to-date.

🔍 Checking VSCode and extensions...
✅ VSCode and extensions are up-to-date.

Security Assessment Report:

PII Check: Secured
NPM Libraries: Secured
SSH Keys: Secured
Homebrew Packages: Secured
VSCode: Secured

Security Grade: 100%
Recommendation: Excellent security posture.

Results delivered with ❤️ by SecureLayer.
```
   
---

### **Disclaimer**
This tool is provided "as-is" and is intended to assist with **security assessments**. It is not a substitute for professional security services or audits.

---

### **Contributions & Support**
We welcome contributions! Feel free to submit pull requests or report issues. For support, contact us at:  
📧 **github@securelayer.co**

---

### **License**
© 2024 SecureLayer. All rights reserved.  
Unauthorized reuse, modification, or redistribution of this script may result in penalties.

---

### **Final Note**
Keeping your system secure is a continuous journey. This script provides a solid foundation, but always remain vigilant and apply the latest security practices!

---

💙 **Security is a priority, not an option!** Stay safe with SecureLayer.