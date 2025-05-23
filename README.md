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
### 🐉 Kali Linux (Attacker System)
Kali Linux operates as the attacker system in this simulated cybersecurity environment, responsible for reconnaissance and active attack phases against the victim system.

### 🔍 Step 1️⃣ : Network Discovery
The initial phase of the attack involves identifying all active hosts within the network. This is accomplished using the powerful netdiscover utility, which passively detects devices by capturing ARP requests and replies.

![net](https://github.com/user-attachments/assets/f5b9051a-2b3c-46ec-b384-29fa333e252b)

### 📌 Command Executed:

bash
Copy
Edit
netdiscover -r 192.168.12.0/16
📸 Result Preview:
The output displays a list of connected hosts along with their respective IP addresses, MAC addresses, and vendor information.

### 🖥️ IP Address	🔒 MAC Address	🏷️ Vendor
192.168.2.1	00:50:56:00:00:08	VMware, Inc.
192.168.2.2	00:56:6d:11:dd:11	VMware, Inc.
192.168.2.100	00:0c:29:00:19:12	VMware, Inc.
192.168.2.156	00:0c:29:cf:f9:ee	VMware, Inc.
192.168.2.254	00:50:56:f0:02:40	VMware, Inc.

### 🎯 Objective:
Identify the victim machine’s IP address from the discovered hosts to target in subsequent attack phases (such as brute-force login attempts on the DVWA web application).

### Key Role:
Actively performs reconnaissance, discovering live hosts within the network to enumerate targets for further exploitation.

