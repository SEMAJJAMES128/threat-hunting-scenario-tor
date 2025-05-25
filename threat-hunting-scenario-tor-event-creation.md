# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download the TOR browser installer: https://www.torproject.org/download/
2. Install it silently: ```tor-browser-windows-x86_64-portable-14.0.1.exe /S```
3. Opens the TOR browser from the folder on the desktop
4. Connect to TOR and browse a few sites. For example:
   - **WARNING: The links to onion sites change a lot and these have changed. However if you connect to Tor and browse around normal sites a bit, the necessary logs should still be created:**
   - Current Dread Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion```
   - Dark Markets Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/d/DarkNetMarkets```
   - Current Elysium Market: ```elysiumutkwscnmdohj23gkcyp3ebrf4iio3sngc5tvcgyfp4nqqmwad.top/login```

6. Create a folder on your desktop called ```tor-shopping-list.txt``` and put a few fake (illicit) items in there
7. Delete the file.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries:
```kql
// Installer name == tor-browser-windows-x86_64-portable-(version).exe
// Detect the installer being downloaded
let VMName = "sjsentinel";
DeviceFileEvents
| where DeviceName == "sjsentinel"
| where FileName has_any ("tor" , "firefox")
| where InitiatingProcessAccountName == "thelab"
| where Timestamp >= datetime(2025-04-27T16:48:38.7199014Z)
| order by FileSize desc
| project FileName, InitiatingProcessAccountName, Timestamp, SHA256, DeviceName, ActionType, FolderPath, Account = InitiatingProcessAccountName


// TOR Browser being silently installed

let VMName = "sjsentinel";
DeviceProcessEvents
| where DeviceName == "sjsentinel"
| where ProcessCommandLine has "tor-browser-windows-x86_64-portable-14.5.exe  /S"
| project Timestamp, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName


// TOR Browser or service was successfully installed and is present on the disk
DeviceFileEvents
let VMName = "sjsentinel";
DeviceProcessEvents
| where DeviceName == "sjsentinel"
| where FileName has_any ("tor.exe", "start-tor-browser.exe", "tor-browser.exe", "tor-browser-win64.exe", "tor-browser-win32.exe", "tor-browser-windows-x86_64-portable-14.5.exe", "Tor Browser Setup.exe", "firefox.exe",


// TOR Browser or service is being used and is actively creating network connections
let VMName = "sjsentinel";
DeviceNetworkEvents
| where DeviceName == "sjsentinel"
| project Timestamp, InitiatingProcessAccountName, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFolderPath,InitiatingProcessFileName
| order by Timestamp desc 
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessAccountName != "system"
| where RemotePort in (9001, 9050, 9150, 9051, 9040, 9030)


---

## Created By:
- **Author Name**: Semaj Jones
- **Author Contact**: www.linkedin.com/in/semajjames128
- **Date**: May 1, 2025

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
| 1.0         | Initial draft                  | `May  1, 2025`  | `Semaj Jones`   
