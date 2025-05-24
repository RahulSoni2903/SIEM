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
80
443
3306

### ➡️ Key Insight:
From this scan, we identified that Port 80 (HTTP) and Port 443 (HTTPS) are open — indicating a web service is hosted on this victim system.
Additionally, Port 3306 (MySQL) is open, but for this attack scenario, we will focus on exploiting the web application via ports 80 and 443.

### 🖥️ Victim OS: Detected based on service headers — Windows 10

