![DVWA](https://github.com/user-attachments/assets/79311e79-744a-4036-b341-000746384ff0)
# 🛡️ DVWA Brute-Force Attack Detection Using SIEM  

## 📖 About The Project  

## 🛡️ Objective  

To demonstrate how a SIEM solution acts as a proactive Layer 2 security control — particularly effective in scenarios where primary security mechanisms like a honeypot might be bypassed, disabled, or unavailable. Even in the absence of decoy systems, a SIEM ensures continuous real-time threat detection through centralized log management, correlation, and alerting.  

## 🎯 Key Capabilities  

🔍 Detecting brute-force attacks on the DVWA application  

🚫 Monitoring unauthorized login attempts and suspicious access patterns  

📈 Tracking attacker behaviors and generating live alerts for security teams  

📡 Ensuring operational visibility even when honeypot defenses fail or are bypassed  

This setup highlights the importance of defense-in-depth — where even if an attacker evades the first layer of decoys (like honeypots), a vigilant SIEM system actively monitors, logs, and responds to security incidents in real-time.
## 🖥️ Technology Stack  

This project utilizes **three VMware Workstation virtual machines** configured for attack simulation, monitoring, and detection:

### 🐉 Kali Linux (Attacker System)  

Kali Linux is employed as the attacker machine, executing brute-force attacks against the DVWA web application hosted on the victim system.

### 🐧 Ubuntu (SIEM Server System)  

Ubuntu acts as the **server system** where the **Wazuh monitoring platform** is deployed.  
Wazuh is an open-source, enterprise-ready security monitoring tool designed to collect, analyze, and correlate logs from connected client systems.  
It provides real-time alerts, visual dashboards, and powerful threat detection capabilities.

**Key Role:** Acts as the central monitoring server in this environment.

### 🖥️ Windows (Victim System)  

A Windows virtual machine serves as the **victim system**, hosting the DVWA (Damn Vulnerable Web Application) platform.  
This machine is targeted by the Kali Linux attacker for brute-force login attempts.

**Key Role:** Victim endpoint being monitored by the SIEM server for malicious activities.

## 🧪 Project Workflow

This section outlines the deployment and setup used to simulate brute-force attacks against the DVWA environment and monitor them using a SIEM solution.

### 🖥️ Victim Machine: Windows 10
![Screenshot (1)](https://github.com/user-attachments/assets/841cf526-168e-488a-a7d2-21fec9d95526)

- The **Damn Vulnerable Web Application (DVWA)** is hosted on a **Windows 10** machine.
- The environment is set up using a local web server stack (e.g., XAMPP or WAMP).
- This machine acts as the **target** in the simulated attack scenario.

### 🌐 DVWA Setup Details

- **Platform**: Windows 10  
- **Application**: Damn Vulnerable Web Application  
- **Private IP Address**: `192.168.2.129`  
- **Access URL**: [http://192.168.2.129/dvwa/]

DVWA is intentionally vulnerable and serves as the entry point for brute-force login attempts in this simulation. The attacker sends repeated POST requests to the login endpoint to trigger SIEM detection mechanisms.

### 🖥️ Attacker Machine: (Kali Linux)
### 📌 Step 1: Discovery of Victim
In this phase, the attacker performs a network discovery operation to identify active hosts within the network range 192.168.12.0/16. Using an ARP request/response capture tool, we detect devices that respond to ARP traffic, revealing their IP addresses, MAC addresses, and vendor information.

### 📸 ScreenShot
![net](https://github.com/user-attachments/assets/40ae610a-f395-40f0-a76c-defb8f2ecc34)

Details of Captured Devices:

### IP Address 
192.168.2.1,
192.168.2.2,
192.168.2.100,	
192.168.2.129 (Victim Machine - Windows 10),
192.168.2.254

### ➡️ Note:
Among the discovered devices, our Victim Machine is a Windows 10 system with IP address 192.168.2.129. This machine will be the target for further attack simulation and SIEM detection in the subsequent steps.

### 📌 Step 2: Nmap Scanning on Victim
In this phase, we target our previously identified Victim Machine — a Windows 10 system with IP address 192.168.2.129 — using Nmap to discover open ports and services running on it.

### 🔍 Nmap Command Used:
nmap 192.168.2.129 -Pn -sCV

### 📸 Screenshot:
![NMAP](https://github.com/user-attachments/assets/1f8ec5ea-945a-4cec-b739-22f7fa3793d1)

### 📝 Scan Summary:
The scan revealed the following open ports on the victim machine:

### 🔓Open Ports
80 (HTTP),
443 (HTTPS),
3306 (MySQL).

### ➡️ Key Insight:
From this scan, we identified that Port 80 (HTTP) and Port 443 (HTTPS) are open — indicating a web service is hosted on this victim system.
Additionally, Port 3306 (MySQL) is open, but for this attack scenario, we will focus on exploiting the web application via ports 80 and 443.
🖥️ Victim OS: Detected based on service headers — Windows 10

### 📸 ScreenShot
![dvwal](https://github.com/user-attachments/assets/1ec522ac-63ef-46e1-b275-f5b5f39e784a)
### ➡️ Observed Behavior:
When accessing http://192.168.2.129 (the victim's IP address) through a web browser, it presented the login page for Damn Vulnerable Web Application (DVWA) — confirming that a vulnerable web application is actively hosted on the target system.

### 🔐 Brute-Force Attack on DVWA Login Page (HTTP)
### ➡️ Tool Used:
Hydra v9.5

### ➡️ Attack Description:
Performed a brute-force attack on the DVWA login page hosted at http://192.168.2.129/DVWA/login.php using Hydra and a password wordlist (rockyou.txt).

### ➡️ Hydra Command Executed:
hydra -l admin -P rockyou.txt 192.168.2.129 http-post-form "/DVWA/login.php:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect."
### 📸 Attack Screenshot:
![succl](https://github.com/user-attachments/assets/599a3340-0107-475e-b914-b5bfd66e071b)
➡️ Findings:
Hydra identified 16 possible valid passwords for the admin user account during the brute-force attempt.

### ✅ Successfully Logged In
***Username: admin***,
***Password: password***

### 🖥️ Monitoring Server: (Ubuntu)
This machine runs Ubuntu OS and is configured as a Wazuh Security Monitoring Server.
### 📸 ScreenShot
![Wazuh](https://github.com/user-attachments/assets/abe33b81-cbf6-49da-b3d0-fb3b86249b9f)

### 📌 About Wazuh:
Wazuh is an open-source Security Information and Event Management (SIEM) solution designed to monitor endpoints, servers, and network infrastructure for suspicious activity, system events, and security breaches. It collects and analyzes logs from multiple sources, detects anomalies, and generates real-time alerts for potential security threats.

### 📊 Current Setup:
***Operating System***: Ubuntu,
***Service Running***: Wazuh Manager & Dashboard,
***Monitored Agents***: Windows 10 endpoint (192.168.2.129).

### 🕵️ Tracking the Attacker:
In this scenario, while the attacker operates from a Kali Linux machine and performs a brute-force attack against the DVWA web application, the attacker remains unaware that the Ubuntu Monitoring Server is actively tracking their activity.

### 📊 Wazuh Dashboard: Event Monitoring View

This screenshot showcases the **Wazuh Threat Hunting Dashboard**, specifically monitoring the **Windows10 agent (ID: 001)** — which is the target machine in this simulation.

---

### 📸 Screenshot:

![logs](https://github.com/user-attachments/assets/96b2eae3-8eef-4737-9cbb-ee5a7f73f000)

---

### 📌 What We See:

- A list of **495 security event hits** within the specified date range.
- Event types include:
  - **Windows Logon Success**
  - **Software Protection Service logs**
  - Detected vulnerabilities like:
    - **CVE-2022-30168**
    - **CVE-2023-28303**
  - These vulnerabilities affect Windows applications such as **Photos** and **Snip & Sketch**.

---

### 📅 Detailed Date & Time Stamps:

Each log entry is recorded with:
- 📅 **Exact date**
- 🕒 **Precise timestamp**
- 📜 **Related rule description**
- ⚠️ **Severity level (rule.level)**
- 🆔 **Unique rule ID**

---

### 📌 Why It’s Important:

Using this log view, a **SOC (Security Operations Center) engineer** can:

- 🕵️‍♂️ Track exactly **how many attempts an attacker made**.
- 📅 Identify the **exact date and time** of each attack attempt or event.
- ⚠️ Prioritize and respond to critical events based on **severity level (rule.level)**.
- 📖 Perform **forensic investigation** and trace attacker behavior in a **timeline format**.

---

**In this case:**

👉 The brute-force attempts and event logs captured from the **attacker’s activity** are fully visible to the monitoring engineer — while the attacker stays unaware that their actions are being logged and analyzed in real-time.

**This is the power of Wazuh integrated into a proactive SOC setup.** 🔒✅

### 📊 Final Detection Attempt — Log Analysis Summary
### 📸 Screenshot:
![logdetails](https://github.com/user-attachments/assets/12d423c9-5b4f-4053-b7eb-36ab4357cf69)

In this final detection attempt:

- 🔍 The **SOC engineer** closely monitors the Wazuh Threat Hunting dashboard.
- 📄 Observes a **Windows Logon Success event** associated with a suspicious actor.
- 🖥️ Target system: **Windows10 agent (ID: 001)**
- 🕒 **Exact date and time** are recorded, ensuring traceable evidence.
- 📑 Event includes:
  - **Event type**: Windows Logon Success  
  - **Rule ID**: 🆔 60106  
  - **Severity Level**: ⚠️ 3  

---

### 📌 Security Operations Center (SOC) Action:

- 🚨 **Immediate Priority Response** initiated:
  - 🚫 Block the attacker's account or IP address.
  - 🔍 Investigate the method of access and any privilege escalation.
  - 🛡️ Isolate the affected machine to contain potential spread.
  - 📝 Document the incident with timestamps and logs for post-incident review.

---

### ✅ Proactive Detection & Response Benefit:

✔️ This detection showcases how **real-time log monitoring with Wazuh** empowers SOC teams to:
- 📈 Quickly identify unauthorized access attempts.
- 🧑‍💻 Take faster incident response decisions.
- 🔐 Strengthen the organization’s overall security posture.

👉 This is a **core advantage** of integrating Wazuh into modern SOC environments:  
**efficient detection, rapid analysis, and immediate, evidence-based response.**



