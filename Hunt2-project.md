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

🟩 Step 1: PsExec Download and Execution

PsExec.exe was executed on host sjpay2 to simulate lateral movement using the command:

PsExec.exe \\localhost cmd.exe

Microsoft Defender for Endpoint logged the execution of PsExec.exe and its service psexesvc.exe.

🟩 Step 2: PsExec Service Spawned Remote Shell

psexesvc.exe launched a new instance of cmd.exe on the same device (sjpay2).
This shell ran with elevated privileges, simulating post-exploitation access.

🟩 Step 3: CMD Launched PowerShell

Within the remote shell session, cmd.exe launched powershell.exe, continuing the chain of execution.
PowerShell was used to run attacker-simulated commands.

🟨 Step 4: Attempted File Drop via PowerShell

Inside the PowerShell session, the following command was executed:

Set-Content -Path "C:\Users\Public\psexec_logged.txt" -Value "test"

The file was confirmed to exist on disk in C:\Users\Public, indicating successful file creation from the attacker’s perspective.

🟥 Step 5: File Creation Not Logged by Defender

Querying DeviceFileEvents for the expected .txt file yielded no results.
This highlights a potential telemetry gap where non-malicious file creations through remote shells may go unlogged unless flagged or audited explicitly.



---

## Summary

The user "thelab" deliberately downloaded and executed the Tor Browser using a silent installer flag. Tor-related files were deployed on the desktop, and soon after, confirmed outbound Tor network traffic was observed. The device connected to a known Tor relay IP on port 9001, followed by proxy activity over 9150, both strongly confirming active Tor session usage. Additionally, the creation of a file named tor-shopping-list.txt suggests potential misuse of the browser for storing or organizing activity that may have occurred through the Tor network.

---

## Response Taken

TOR usage was confirmed on endpoint sjsentinel by the user thelab. The device was isolated and the user's direct manager was notified.

---
