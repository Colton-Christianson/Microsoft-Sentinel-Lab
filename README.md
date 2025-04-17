# Security Information and Event Management (SIEM) Project Summary

## 🎯 Objective  
Design and implement a Security Information and Event Management (SIEM) solution to gain hands-on experience with cybersecurity tools and further develop skills for a career in IT and cybersecurity.

## 🔍 Scope  
Deployed a small, cloud-based network environment using Microsoft Azure. A Linux virtual machine with an exposed RDP port served as a honeypot to attract malicious actors. Microsoft Sentinel was used as the SIEM tool to collect and analyze security events from the environment.

## 🛠️ Tools & Technologies  
- **Cloud Platform:** [Microsoft Azure](https://portal.azure.com)  
- **SIEM Solution:** Microsoft Sentinel  
- **Log Sources:** Windows Security Events via Azure Monitor Agent (AMA)  
- **Threat Detection & Monitoring:**  
  - Custom KQL (Kusto Query Language) queries  
  - Real-time alerting for suspicious activity  

---

## 📋 Planning & Requirements

### ✅ Prerequisites
- Azure Resource Group  
- Deployed Windows Virtual Machine (VM)  
- Appropriate IAM permissions for Sentinel and Log Analytics  

### 🧭 Implementation Steps

#### 1. Create Log Analytics Workspace
- Navigate to Azure Portal → Log Analytics Workspaces → Create & Configure  

#### 2. Enable Microsoft Sentinel
- Search for **Microsoft Sentinel** in Azure Portal  
- Create a new Sentinel instance  
- Link it to the Log Analytics Workspace  

#### 3. Install Azure Monitor Agent (AMA)
- Go to the VM → Extensions + Applications → Install Azure Monitor Agent  
- Create a **Data Collection Rule (DCR)**  
- Add **Windows Security Events** as a data source  
- Assign data to the Log Analytics Workspace  

#### 4. Create Custom KQL Detection Rules

**Successful RDP Login Detection**
SecurityEvent
| where Activity contains "success" and Account !contains "system"

**Unsuccessful RDP Login Detection**
SecurityEvent
| where EventID == 4625
| where AccountType == "User"
| project TimeGenerated, Computer, Account, LogonType, Status, IpAddress
| order by TimeGenerated desc

**Brute Force Detection**
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 5
| order by FailedAttempts desc

#### 5. Results & Outcome
- Successfully deployed Microsoft Sentinel and integrated it with a honeypot VM.
- Created and validated functional custom detection rules using KQL.
- Received accurate alerts for:
  - Successful sign-ins (via personal RDP login activity).
  - Failed sign-in attempt on March 28th at 17:35:19 from an IP address in India (111.118.179.0/24)
  
![A wild hacker appears!!!](https://github.com/user-attachments/assets/64e5e998-bbbb-41bf-ba44-67bfc3f23fc7)
![65% sus](https://github.com/user-attachments/assets/d83dc38c-4c3d-4f45-98e6-627439c0d459)

  - Verified IP details via IPQualityScore.
  - Confirmed that custom detection rules worked correctly and provided real-time alerts of suspicious behavior.
