![image](https://github.com/user-attachments/assets/c8ff4936-5fc7-4ca9-8917-59d110269b7e)


# Threat Hunt Report: Unauthorized Remote Execution via PsExec
- [Scenario Creation](https://github.com/SEMAJJAMES128/threat-hunting-scenario-tor/blob/main/Hunt2.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- PSExec (Sysinternals Suite)

##  Scenario

Security noticed an unusual command-line pattern on a lab system suggesting remote code execution activity. Suspicion grew after audit logs revealed system-level process spawns without standard user interaction. Management requested a threat hunt to determine whether tools like PsExec were being used to establish unauthorized remote shells, spawn PowerShell sessions, or create untracked files.
The goal of this hunt is to validate the presence of lateral movement techniques using PsExec, confirm chained execution activity, and assess visibility into file creation from remote shells.


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
![image](https://github.com/user-attachments/assets/5d60715d-f648-4b1d-9191-d11e7cff097f)"

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
![image](https://github.com/user-attachments/assets/ecc0db73-4ab9-4b0d-ad6a-9d8512b8179e)

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
![image](https://github.com/user-attachments/assets/40102780-44de-4483-b310-d09cbe03c2a5)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Queried the DeviceNetworkEvents table for evidence of Tor Browser activity by filtering for known Tor-related ports at the timestamp 2025-04-27T16:52:28.498756Z. Findings show that on April 27, 2025, at 12:52:28 PM, the user account "thelab" on device "sjsentinel" successfully established a network connection (ConnectionSuccess) from the process tor.exe, located at C:\Users\thelab\Desktop\Tor Browser\Browser\TorBrowser\Tor\, to the external IP address 5.135.83.4 over port 9001. As port 9001 is commonly used for Tor Onion Routing relays, this strongly suggests the system initiated outbound communication over the Tor 
anonymity network.

**Query used to locate events:**

```kql
let VMName = "sjsentinel";
DeviceNetworkEvents
| where DeviceName == "sjsentinel"
| project Timestamp, InitiatingProcessAccountName, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFolderPath,InitiatingProcessFileName
| order by Timestamp desc 
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessAccountName != "system"
| where RemotePort in (9001, 9050, 9150, 9051, 9040, 9030)

```
![image](https://github.com/user-attachments/assets/2c0525de-1df5-48c5-a24b-29ab3dfabaf6)

---

## Chronological Event Timeline 

Step 1: 

12:48:38 PM – Download Activity
The user "thelab" renamed or moved the file tor-browser-windows-x86_64-portable-14.5.exe into the Downloads folder.
 📁 Path: C:\Users\thelab\Downloads\
 🔐 ActionType: FileRenamed
 🔍 Hash: 3a678091f74517da...



Step 2: 

12:51:41 PM – Silent Execution of TOR Installer
The same executable was silently run using the /S flag (silent install), indicating intentional, discreet installation.
 ⚙️ ActionType: ProcessCreated
 🧑‍💻 User: thelab
 📁 Path: C:\Users\thelab\Downloads\...



Step 3: 

12:51:42 PM – TOR Files Deployed to Desktop
Tor-related files including firefox.exe and firefox.VisualElementsManifest.xml were created in the Desktop Tor Browser folder.
 📁 Path: C:\Users\thelab\Desktop\Tor Browser\Browser\...
 📄 ActionType: FileCreated
 🔍 Firefox SHA256: 3613fc46eab116864...



Step 4: 

12:52:28 PM – Outbound Connection to Tor Relay Node
The process tor.exe established an outbound connection to 5.135.83.4 over port 9001, a known Tor relay port.
 🌐 ActionType: ConnectionSuccess
 ⚙️ Process Path: C:\Users\thelab\Desktop\Tor Browser\Browser\TorBrowser\Tor\



Step 5: 

12:52:48 PM – Firefox Proxy Connection via TOR
The Tor Browser's firefox.exe initiated a local connection to 127.0.0.1 over port 9150, indicating active Tor traffic tunneling.
 🧑‍💻 User: thelab
 ⚙️ Initiating Process: firefox.exe
 🌐 ActionType: ConnectionSuccess



Step 6: 

5:04:09 PM – Suspicious File Creation
A file named tor-shopping-list.txt was created shortly after Tor usage. This may indicate use of the browser for non-work-related or potentially inappropriate purposes.
 📄 File Type: .txt
 📍 Path and details should be further examined in context.


---

## Summary

The user "thelab" deliberately downloaded and executed the Tor Browser using a silent installer flag. Tor-related files were deployed on the desktop, and soon after, confirmed outbound Tor network traffic was observed. The device connected to a known Tor relay IP on port 9001, followed by proxy activity over 9150, both strongly confirming active Tor session usage. Additionally, the creation of a file named tor-shopping-list.txt suggests potential misuse of the browser for storing or organizing activity that may have occurred through the Tor network.

---

## Response Taken

TOR usage was confirmed on endpoint sjsentinel by the user thelab. The device was isolated and the user's direct manager was notified.

---
