-- get number of devices that last time they ran a certain application it was of a a specific version
let targetVersion = "142.0.3595.69";
let EdgeRuns = DeviceFileEvents
| where FileName == "msedge.exe"
| where FolderPath startswith "C:\\Program Files (x86)\\Microsoft\\edge\\application"
| project DeviceId, DeviceName, Timestamp, InitiatingProcessVersionInfoProductVersion;
let LatestEdgeVersion = EdgeRuns
| summarize LatestTimestamp = arg_max(Timestamp, InitiatingProcessVersionInfoProductVersion) by DeviceId;
let DevicesWithTargetVersion = LatestEdgeVersion
| where InitiatingProcessVersionInfoProductVersion == targetVersion;
DevicesWithTargetVersion
| summarize DeviceCount = dcount(DeviceId)

-- get number of devices that ran a certain executable of a a specific version
DeviceFileEvents
| where ProcessVersionInfoOriginalFileName == "msedge.exe"
| where ProcessVersionInfoProductVersion == "142.0.3595.69"
| summarize dcount(DeviceId) by ProcessVersionInfoOriginalFileName

-- get the versions of a file present on a specific device
DeviceFileEvents
| where DeviceName startswith "WKS-s3sBzBviJax"
| where FileName == "msedge.exe"
| where FolderPath startswith "C:\\Program Files (x86)\\Microsoft\\edge\\application"
| project ActionType, FolderPath, Timestamp

-- get ASR device events
DeviceEvents
| where Timestamp > ago(1h)
| where ActionType startswith "Asr" // and ActionType endswith "Audited"
// | where ActionType contains "blocked"
| where DeviceName startswith "Gva-ras"
// | where FolderPath contains "Parallels"