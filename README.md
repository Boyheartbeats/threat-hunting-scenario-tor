![image](https://github.com/user-attachments/assets/79dcd4db-e33a-4537-96e5-0e1dec28435b)<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Boyheartbeats/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

1.	Searched the DeviceFileEvents table for any file that had the string “tor” in it and discovered the user “DB-Windows-Admin” downloaded a tor installer, and did something that resulted in many tor-related files being copied to the desktop. There was also a creation of a file called “tor-shopping-list.txt” on the desktop. These events began at  `2025-05-19T13:29:28.2521635Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "db-defender-lab"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "dbwindowsadmin"
| where Timestamp >= datetime(2025-05-19T13:29:28.2521635Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/395dcc3e-c92a-4da7-a7c5-c291d5475444">




---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that started with  “tor-browser”. Based on the logs returned at  May 19, 2025, at 9:36:14 AM, the user account dbwindowsadmin on the device db-defender-lab executed the file tor-browser-windows-x86_64-portable-14.5.2.exe from the path C:\Users\DBWindowsadmin\Downloads\. The command used was tor-browser-windows-x86_64-portable-14.5.2.exe /S, indicating a silent installation of the Tor Browser. The SHA256 hash of the file is 3d55deb5dc8f0dc7fb694608ea15d255078e1087174d49d9a8fff6dc3f16b7ec.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "db-defender-lab"
| where ProcessCommandLine contains "tor-browser"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/58b3cda2-a0d5-4ad5-a281-1685a9092275">



---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution


Searched the DeviceProcessEvents table for any indication that user “DBWindowsadmin” actually opened the tor browser. There was evidence that they did open it at `2025-05-19T13:36:58.9091447Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "db-defender-lab"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/f44fdc8a-62ff-49c8-b12a-27c6f23e95d5">

![image](https://github.com/user-attachments/assets/f44fdc8a-62ff-49c8-b12a-27c6f23e95d5)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections




Searched the DeviceNetworkEvents table for any indication the TOR browser was used to establish connection using any of the known TOR ports. On May `19`, `2025`, at `9:37:12` AM, the user account dbwindowsadmin on the device db-defender-lab successfully initiated a network connection to the IP address `150.230.20.28` over TCP port `9001`. This connection was made using the executable `tor.exe`, located in the folder `C:\Users\DBWindowsadmin\Desktop\Tor Browser\Browser\TorBrowser\Tor\`. TCP port `9001` is commonly used by Tor relays for onion routing traffic, indicating that the Tor Browser was likely active on this system at the time. There were a couple connection to sites over `443` as well.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "db-defender-lab"
| where InitiatingProcessAccountName  != "system"
| where RemotePort  in ("9001", "9030", "9050", "9051", "9150", "9151")
| project Timestamp, DeviceName, ActionType, RemotePort, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/2814cfe1-da6e-47c5-882c-89c1a5bae94f">




---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-05-19T13:29:28.2521635Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.2.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\dbwindowsadmin\Downloads\tor-browser-windows-x86_64-portable-14.5.2.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-05-19T13:36:14.8762724Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.5.2.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.2.exe /S`
- **File Path:** `C:\Users\dbwindowsadmin\Downloads\tor-browser-windows-x86_64-portable-14.5.2.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-05-19T13:37:03.9446388Z`
- **Event:** User "dbwindowsadmin" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-05-19T13:37:12.0038799Z`
- **Event:** A network connection to IP `150.230.20.28` on port `9001` by user "dbwindowsadmin" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\dbwindowsadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-05-19T13:37:07.0890376Z` - Local connection to `127.0.0.1` on port `9151`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-05-19T13:46:49.4630826Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\dbwindowsadmin\Desktop\tor-shopping-list.txt`

---

## Summary

The user "dbwindowsadmin" on the "DB-Defender-Lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `DB-Defender-Lab` by the user `dbwindowsadmin`. The device was isolated, and the user's direct manager was notified.

---
