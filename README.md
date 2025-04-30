<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/SEMAJJAMES128/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

I performed an advanced hunting query focused on the device "sjsentinel", filtering the DeviceFileEvents table for files with names containing "tor" or "firefox", executed by the user account "thelab." The search was further refined to events occurring after 2025-04-27T16:48:38Z, with results sorted by file size. Key details such as file name, SHA256 hash, action type, and folder path were extracted to support the investigation and inform potential incident creation. There was also a creation of a file called “tor-shopping-list.txt” at 2025-04-27T17:04:09.4108282Z.

**Query used to locate events:**

```kql
let VMName = "sjsentinel";
DeviceFileEvents
| where DeviceName == "sjsentinel"
| where FileName has_any ("tor" , "firefox")
| where InitiatingProcessAccountName == "thelab"
| where Timestamp >= datetime(2025-04-27T16:48:38.7199014Z)
| order by FileSize desc
| project FileName, InitiatingProcessAccountName, Timestamp, SHA256, DeviceName, ActionType, FolderPath, Account = InitiatingProcessAccountName

```
<![image](https://github.com/user-attachments/assets/5d60715d-f648-4b1d-9191-d11e7cff097f)">

---

### 2. Searched the `DeviceProcessEvents` Table

Queried the DeviceProcessEvents table for any ProcessCommandLine entries containing the string "tor-browser-windows-x86_64-portable-14.5.exe". Results show that on April 27, 2025, at 12:51 PM, the user account "thelab" executed this file from the Downloads directory using the silent install flag /S. The ActionType was ProcessCreated, confirming the file was run. The executable’s SHA256 hash is 3a678091f74517da5d9accd391107ec3732a5707770a61e22c20c5c17e37d19a. This behavior likely reflects an attempt to install or launch the Tor Browser discreetly, potentially indicating unauthorized software use or an effort to evade network visibility.

**Query used to locate event:**

```kql

let VMName = "sjsentinel";
DeviceProcessEvents
| where DeviceName == "sjsentinel"
| where ProcessCommandLine has "tor-browser-windows-x86_64-portable-14.5.exe  /S"
| project Timestamp, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName

```
<![image](https://github.com/user-attachments/assets/ecc0db73-4ab9-4b0d-ad6a-9d8512b8179e)>

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “thelab” actually opened the tor browser. There was evidence that they did open it at 2025-04-27T16:51:41.4899266Z
There were several other instances of firefox.exe (tor) as well as tor.exe spawned afterwards

**Query used to locate events:**

```kql
let VMName = "sjsentinel";
DeviceProcessEvents
| where DeviceName == "sjsentinel"
| where FileName has_any ("tor.exe", "start-tor-browser.exe", "tor-browser.exe", "tor-browser-win64.exe", "tor-browser-win32.exe", "tor-browser-windows-x86_64-portable-14.5.exe", "Tor Browser Setup.exe", "firefox.exe", "PluggableTransportPlugin.exe")
| order by Timestamp desc
| project FileName, DeviceName, AccountName, FolderPath, ProcessCommandLine, ActionType, Timestamp, SHA256

```
<![image](https://github.com/user-attachments/assets/40102780-44de-4483-b310-d09cbe03c2a5)>

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
