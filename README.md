<div align="center">

# 🛡️ Viper-Audit Enterprise
### Professional Network Inventory & Security Auditing Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey)]()
[![Status](https://img.shields.io/badge/Status-Active-success)]()

</div>

---

**Viper-Audit Enterprise** is a strictly non-exploitative network reconnaissance tool designed for **System Administrators**, **Blue Teams**, and **Compliance Auditors**. It performs asset discovery and inventory management using passive and low-impact techniques.

[attachment_0](attachment)

##  Compliance & Safety Notice

** WHAT THIS TOOL IS NOT:**

| Category | Status | Description |
| :--- | :--- | :--- |
| **Malware** | ❌ | Contains no payloads, viruses, or persistence mechanisms. |
| **Exploit Framework** | ❌ | Does not exploit vulnerabilities (CVEs) or deliver shellcode. |
| **Brute-Force** | ❌ | Does not perform credential stuffing or password guessing. |
| **Illegal Scanner** | ❌ | Designed for **defensive analysis** and authorized inventory. |

> **Disclaimer:** This tool is for **Authorized Testing Only**. The authors are not responsible for unauthorized use.

---

## Features

* **TCP SYN Scanning (Stealth/Root):** Uses raw sockets to perform "Half-Open" scans. This identifies open ports without completing the TCP handshake, minimizing application logs.
* **TCP Connect Scanning (User/Connect):** A non-privileged mode for standard auditing without root access.
* **Passive OS Fingerprinting:** Analyzes the `TTL` (Time To Live) of incoming packets to estimate the target Operating System (Windows/Linux/Cisco) without active probing.
* **Safety Controls:** Built-in rate limiting (`--delay`), thread capping (Max 50), and target validation to prevent Denial of Service (DoS) on legacy systems.
* **Audit Reports:** Automatically generates structured **JSON** reports for compliance logging.

##  Installation

```bash
# 1. Clone the repository
git clone [https://github.com/syed-sameer-ul-hassan/viper-audit.git](https://github.com/syed-sameer-ul-hassan/viper-audit.git)

# 2. Navigate to directory
cd viper-audit

# 3. Install dependencies (Required for SYN scanning)
pip install -r requirements.txt
