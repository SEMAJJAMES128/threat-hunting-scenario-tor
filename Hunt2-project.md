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


### High-Level PsExec-Related IoC Discovery Plan

- **Check `DeviceProcessEvents`** for execution of `PsExec.exe` and `psexesvc.exe`.
- **Trace process lineage from `psexesvc.exe` → `cmd.exe` → `powershell.exe`.**
- **Use `DeviceFileEvents` to determine whether files were created via the PsExec-launched session.**

---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table for PsExec Execution

Queried for known PsExec binaries (`PsExec.exe`, `psexesvc.exe`) to confirm execution. These are strong indicators of lateral movement or post-exploitation.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "sjpay2"
| where FileName in~ ("PsExec.exe", "psexesvc.exe")
| project FileName, ProcessCommandLine, DeviceName, DeviceId

```
![image](https://github.com/user-attachments/assets/4af48c04-ee01-44a4-a4e0-0664e6728aac)"

---

### 2. Investigated What Was Spawned by PsExec

Queried for any child processes launched by psexesvc.exe. cmd.exe was confirmed as the next link in the process chain, indicating interactive shell access via PsExec.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "sjpay2"
| where InitiatingProcessFileName == "psexesvc.exe"
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName


```
![image](https://github.com/user-attachments/assets/b58fe641-1f9f-4397-831e-fe3e3432aceb)


---

### 3. Traced Follow-up Execution from CMD to PowerShell

Confirmed that powershell.exe was launched via the cmd.exe session initiated by PsExec, continuing the attacker’s activity chain.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "sjpay2"
| where InitiatingProcessFileName == "cmd.exe"
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName

```
![image](https://github.com/user-attachments/assets/75f97e74-4282-4231-aeaf-b0edfcd49bd9)


---

### 4. Searched for File Creation Activity in Public Folder

Queried DeviceFileEvents to determine if PowerShell dropped any files in the C:\Users\Public\ directory. A .txt file was manually confirmed on disk, but not logged in Defender, exposing a telemetry gap.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "sjpay2"
| where FolderPath has "Public"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine;

```
![image](https://github.com/user-attachments/assets/8f42dc90-a656-46fc-8535-cf9af8b8b429)


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
