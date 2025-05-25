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
// Step 1: PsExec Execution
DeviceProcessEvents
| where DeviceName == "sjpay2"
| where FileName in~ ("PsExec.exe", "psexesvc.exe")
| project Timestamp, FileName, ProcessCommandLine, DeviceName, AccountName

// Step 2: Cmd.exe launched via PsExec
DeviceProcessEvents
| where DeviceName == "sjpay2"
| where InitiatingProcessFileName == "psexesvc.exe"
| where FileName == "cmd.exe"
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName

// Step 3: Powershell launched via cmd.exe
DeviceProcessEvents
| where DeviceName == "sjpay2"
| where InitiatingProcessFileName == "cmd.exe"
| where FileName == "powershell.exe"
| project Timestamp, FileName, ProcessCommandLine, AccountName

// Step 4: Attempted file creation by PowerShell
DeviceFileEvents
| where DeviceName == "sjpay2"
| where FileName == "psexec_logged.txt"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine

// Step 5: Broad FileActivity filter by folder for confirmation
DeviceFileEvents
| where DeviceName == "sjpay2"
| where FolderPath has "Public"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName


---

## Created By:
- **Author Name**: Josh Madakor
- **Author Contact**: https://www.linkedin.com/in/joshmadakor/
- **Date**: August 31, 2024

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
| 1.0         | Initial draft                  | `September  6, 2024`  | `Josh Madakor`   
