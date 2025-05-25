# Threat Event (Simulated Lateral Movement via PsExec)
**Process-Based Lateral Movement and File Drop Simulation Using PsExec**

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. Downloaded and executed `PsExec.exe` from the Sysinternals suite.

2. Ran the following command to simulate lateral movement:  
   `PsExec.exe \\localhost cmd.exe`

3. From the PsExec-launched `cmd.exe` shell, launched `powershell.exe`.

4. Inside the PowerShell session, executed a file creation command:  
   `Set-Content -Path "C:\Users\Public\psexec_logged.txt" -Value "test"`

5. The file was successfully written to disk, but Defender for Endpoint did **not log** the file creation.

---

## Tables Used to Detect IoCs:

| Parameter | Description |
|----------|-------------|
| **Name** | `DeviceProcessEvents` |
| **Info** | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose** | Used to detect the execution of `PsExec.exe`, the deployment of `psexesvc.exe`, and subsequent process activity such as `cmd.exe` and `powershell.exe` launched via PsExec. |

<br/>

| Parameter | Description |
|----------|-------------|
| **Name** | `DeviceFileEvents` |
| **Info** | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| **Purpose** | Used to detect any files created as a result of remote shell activity. In this case, a `.txt` file was created via PowerShell but was not logged — highlighting a visibility gap in benign file creation events. |

---

## Related Queries:

```kql
// Step 1: Detect Execution of PsExec and Its Service Component
DeviceProcessEvents
| where DeviceName == "sjpay2"
| where FileName in~ ("PsExec.exe", "psexesvc.exe")
| project Timestamp, FileName, ProcessCommandLine, DeviceName, AccountName

// Step 2: Identify the Initial Process Spawned by PsExec
DeviceProcessEvents
| where DeviceName == "sjpay2"
| where InitiatingProcessFileName == "psexesvc.exe"
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName

// Step 3: Investigate Follow-on Processes Launched from cmd.exe
DeviceProcessEvents
| where DeviceName == "sjpay2"
| where InitiatingProcessFileName == "cmd.exe"
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName

// Step 4: Search for File Creation Attempt by PowerShell
DeviceFileEvents
| where DeviceName == "sjpay2"
| where FileName == "psexec_logged.txt"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine

// Step 5: View All File Events Within Public Directory for Context
DeviceFileEvents
| where DeviceName == "sjpay2"
| where FolderPath has "Public"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine

## Created By:
- **Author Name**: Semaj Jones
- **Author Contact**: www.linkedin.com/in/semajjames128
- **Date**: May 25, 2025


## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `May  25, 2025`  | `Semaj Jones`   
