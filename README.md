# Threat Hunt Report: Masquerading via Renamed System Binary (T1036.003)


## Platforms and Tools Used
- **Microsoft Azure** (Virtual Machine)
- **Microsoft Defender for Endpoint** (EDR telemetry)
- **Kusto Query Language (KQL)** 
- **PowerShell** 

---

## Scenario Overview

This hunt focused on detecting adversary behavior where a legitimate system binary (`cmd.exe`) was renamed to `explorer.exe` and executed from an unusual location (`C:\Users\Public`). This is a form of masquerading, used to evade detection by disguising malicious activity as benign.


---

## 🎯 Objective

Identify the use of a **renamed system utility** (`cmd.exe` renamed to `explorer.exe`) to execute commands from a **non-standard path**, which may indicate **defense evasion**.

---

## 🔬 Investigation Steps

### 🎭 1. Masqueraded Binary Executed from Public Directory

On June 3, 2025 at 5:32 PM, user `labuser` on the device `vm-test-zedd` executed a renamed system binary from a non-standard location. The binary `cmd.exe` was copied and renamed as `explorer.exe`, then used to run a command via PowerShell.

The renamed binary was located in the `C:\Users\Public\` directory and launched with arguments indicative of command-line activity.

**Command Executed:**

```Start-Process "C:\Users\Public\explorer.exe" -ArgumentList "/c whoami"```

This behavior suggests an attempt to blend malicious command execution under the guise of a trusted Windows binary, aligning with the MITRE ATT&CK technique T1036.003 (Masquerading: Rename System Utilities).

**KQL Query:**
```kql
DeviceProcessEvents
| where FileName == "explorer.exe"
| where FolderPath !startswith "C:\\Windows"
| where ProcessCommandLine has_any ("cmd", "whoami", "/c", "/k")
| project Timestamp, DeviceName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, AccountName
| sort by Timestamp desc
```
![1-main](https://github.com/user-attachments/assets/6759a760-65be-4426-9cdb-c3ad35b0d5d7)

---

## 🕒 Timeline of Events

| Timestamp              | Event Description                                                                 |
|------------------------|-----------------------------------------------------------------------------------|
| June 3, 2025 - 5:30 PM | User `labuser` copies `cmd.exe` to `C:\Users\Public\explorer.exe`                 |
| June 3, 2025 - 5:32 PM | `explorer.exe` is executed with arguments `/c whoami` via `powershell.exe`       |
| June 3, 2025 - 5:32 PM | Microsoft Defender for Endpoint logs the event under `DeviceProcessEvents`       |

---

## 📌 Summary of Findings

- A legitimate Windows binary (`cmd.exe`) was **renamed to `explorer.exe`** and executed from a **non-standard directory** (`C:\Users\Public`).
- The renamed binary was launched using PowerShell and passed command-line arguments (`/c whoami`) that are **atypical for `explorer.exe`**.
- This behavior is consistent with **masquerading (MITRE ATT&CK T1036.003)** and may be used by adversaries to **evade detection**, **bypass allowlists**, or **blend into normal activity**.
- The action was successfully detected via KQL using Microsoft Defender for Endpoint, indicating telemetry is working as expected.

---

## 🛡️ Containment

- **Terminate any unauthorized or suspicious process** executing from user-writable directories (e.g., `C:\Users\Public`):
```
Get-Process explorer |
Where-Object { $_.Path -and $_.Path -notlike "C:\Windows\*" } |
Stop-Process -Force
```

- **Remove the renamed binary** and validate its source hash and path:
```
$fakeExplorer = "C:\Users\Public\explorer.exe"
if (Test-Path $fakeExplorer) {
    Remove-Item $fakeExplorer -Force
}
```

---

## 🔧 Remediation

To prevent similar techniques in production environments:

1. **Prevent future executions via NTFS Permissions**  
   Block execution in C:\Users\Public by denying Execute permission for .exe files:
```
$path = "C:\Users\Public"
icacls $path /deny Everyone:(RX)
```

2. **Enable ASR rules**  
   Specifically:
   - `Block executable content from email and webmail`
   - `Use advanced protection against ransomware`

3. **Educate users**  
   Raise awareness of masquerading techniques across the blue team and threat hunting staff.

4. **Use AppLocker or Windows Defender Application Control (WDAC)**  
    Prevent execution from user-writable directories altogether.
