# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Dylan-H54/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop on Aug. 13, 2026 at 9:06:12 A.M. These events began on Aug. 13, 2026 at 8:56:03 A.M.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "my-vm-dh"    
| where FileName contains "tor"    
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1077" height="553" alt="image" src="https://github.com/user-attachments/assets/2a1f5938-087a-469f-9e8c-1fa29f511e32" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.19.exe". Based on the logs returned, at 2026-08-11 8:56:03, an employee on the "my-vm-dh" device ran the file `tor-browser-windows-x86_64-portable-15.0.19.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "my-vm-dh"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.19.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1439" height="389" alt="image" src="https://github.com/user-attachments/assets/191799e8-6a10-4364-8215-a7e026bfc5e9" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at 2026-08-13 8:57:11. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "my-vm-dh"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1427" height="642" alt="image" src="https://github.com/user-attachments/assets/c6fc85d9-c7d4-4fea-b6da-e0cefe25f1df" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At 2026-08-13 08:59:20, an employee on the "my-vm-dh" device successfully established a connection to the remote IP address `213.144.142.24` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\jen1589\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "my-vm-dh"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1602" height="580" alt="image" src="https://github.com/user-attachments/assets/27a847f1-4b96-458c-90e1-e32adca0e70d" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `Aug. 13, 2026 at 8:56:03 A.M.`
- **Event:** The user "jen1589" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.19.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\jen1589\Downloads\tor-browser-windows-x86_64-portable-15.0.19.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-08-11 8:56:03 AM`
- **Event:** The user "jen1589" executed the file `tor-browser-windows-x86_64-portable-15.0.19.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.19.exe /S`
- **File Path:** `C:\Users\jen1589\Downloads\tor-browser-windows-x86_64-portable-15.0.19.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-08-13 8:57:11AM`
- **Event:** User "jen1589" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\jen1589\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-08-13 08:59:20AM`
- **Event:** A network connection to IP `213.144.142.24` on port `9001` by user "jen1589" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\jen1589\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `Aug 13, 2026 8:59:23 AM` - Connected to `192.42.116.116` on port `443`.
  - `Aug 13, 2026 8:50:50 AM` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.


---

## Summary

The user "jen1589" on the "my-vm-dh" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes.

---

## Response Taken

TOR usage was confirmed on the endpoint `my-vm-dh` by the user `jen1589`. The device was isolated, and the user's direct manager was notified.

---
