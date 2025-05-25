# Threat Event (Unauthorized Remote Execution via PsExec)
**PsExec Usage for Lateral Movement and Post-Exploitation Simulation**

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. Downloaded and extracted PsExec from Sysinternals suite.
2. Launched PsExec with `\\localhost cmd.exe` to simulate remote shell access.
3. From the remote shell, attempted to run PowerShell and create files in `C:\Users\Public\`.
4. Created a file called `psexec_logged.txt` (file appeared on disk, but was not logged).
5. Validated all command execution using Microsoft Defender for Endpoint (MDE) telemetry.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**            | DeviceProcessEvents                                                         |
| **Info**            | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose**         | Used to detect PsExec execution, command shell creation, and PowerShell activity.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**            | DeviceFileEvents                                                            |
| **Info**            | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| **Purpose**         | Intended to detect file creation attempts made from the remote shell session. (Note: file creation was not logged.)|

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



---

## Created By:
- **Author Name**: Semaj Jones
- **Author Contact**: www.linkedin.com/in/semajjames128
- **Date**: May 25, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `May  25, 2025`  | `Semaj Jones`   
