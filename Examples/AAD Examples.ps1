#PROD Tenant ID: d49b07ca-2302-4e7c-b2cb-e12127852850
#PROD Enterprise App Id for automation: 9912e1b8-671f-47df-a451-18b587b1b937 
#UAT Tenant ID: 57af68cb-4a2c-40a6-91ae-01531dfde418
#UAT Enterprise App Id for automation: d1ad76ff-d8a1-493b-83b0-213bd33eb184
# Intune app id: 0000000a-0000-0000-c000-000000000000

#removing the AD object removes it in AAD at the next sync
#removing the device in SCCM does NOT remove the comanaged object in Intune
#enrolling the computer into Intune using the device token
%windir%\system32\deviceenroller.exe /c /AutoEnrollMDMUsingAADDeviceCredential

Install-Module Microsoft.Graph
Connect-MgGraph -NoWelcome -TenantId iloprod.onmicrosoft.com -ClientId "0c0f79bd-ca4a-4a93-925e-535acde2228d" -Certificate (Get-PfxCertificate "C:\Users\paladi\OneDrive - International Labour Office\_Scripts\AAD\TMSAzureCert.pfx") #WdU...
Connect-MSIntuneGraph -TenantID iloprod.onmicrosoft.com -Clientid "0c0f79bd-ca4a-4a93-925e-535acde2228d" -ClientCert (Get-PfxCertificate "C:\Users\paladi\OneDrive - International Labour Office\_Scripts\AAD\TMSAzureCert.pfx") #WdU...

$Response = Invoke-GraphRequest -Method "GET" -URI "/v1.0/me" -OutputType HttpResponseMessage
$Token = $Response.RequestMessage.Headers.Authorization.Parameter

Get-MgDevice -Filter ("displayName eq '{0}'" -f (hostname)) | select *
Get-MgDeviceManagementManagedDevice

# deprovision appx if it fails to upgrade
$AppName = 'Microsoft.MicrosoftOfficeHub'
if((Get-AppxPackage -AllUsers -Name $AppName).Version -lt [version]'19.0.0.0'){
	Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq $AppName} | Remove-AppxProvisionedPackage -Online -AllUsers
	Get-AppxPackage -AllUsers -Name $AppName | Remove-AppxPackage -Verbose -AllUsers -ErrorAction Ignore
	#after removing an appx, if still unable to install a newer version (event 493 'additional files that failed to be deleted under the folder \\?\C:\Program Files\WindowsApps\Deleted' in AppXDeployment-Server), run the AppxCleanupOrphanPackages task
	c:\windows\system32\rundll32.exe AppxDeploymentClient.dll,AppxCleanupOrphanPackages
}

# https://learn.microsoft.com/en-us/powershell/microsoftgraph/migration-steps?view=graph-powershell-1.0#upgrading-to-microsoft-graph-powershell
#deprecated: Install-Module azuread; Connect-AzureAD
#deprecated: Import-Module Microsoft.Graph.Intune; Connect-MSGraph
# here's the map of deprecated Azure AD PowerShell and MSOnline cmdlets to find the cmdlets that you need in the Microsoft Graph PowerShell SDK:
# https://learn.microsoft.com/en-us/powershell/microsoftgraph/azuread-msoline-cmdlet-map?view=graph-powershell-1.0

Install-Module -Name IntuneWin32App
#get all win32 apps
Connect-MSIntuneGraph -TenantID iloprod.onmicrosoft.com -Refresh
#get app dependencies
Get-IntuneWin32App | %{ $app = $_; Get-IntuneWin32AppDependency $_.id | ? targetType -eq 'child' | Select @{n="App";e={$app.displayName}}, @{n='Dependencies';e={$_.targetDisplayName}} }
#get app supercedence
Get-IntuneWin32App | %{ $app = $_; Get-IntuneWin32AppSupersedence $_.id | Select  @{n="App";e={$app.displayName}}, targetDisplayName, targetType }
#get applicability requirements for all apps
Get-IntuneWin32App | Select  displayName, @{n="Name";e={$_.requirementRules.displayName}}, @{n="fileOrFolderName";e={$_.requirementRules.fileOrFolderName}}, @{n="keyPath";e={$_.requirementRules.keyPath}}
#get all apps assigned to a specific Group
Get-IntuneWin32AppAssignment -GroupName AAD-Intune_Windows-RASVDI | ft AppName, Intent, GroupMode
#get all apps and their required assignments
$reqap = Get-IntuneWin32App | select -f 2 | %{$_ | Add-Member NoteProperty RequiredAssignments (Get-IntuneWin32AppAssignment -ID $_.id | ? intent -eq 'required').GroupName -PassThru}
#get apps assigned to All Devices as Required, along with their child dependencies
$allap = $reqap| %{ function Get-Children{param($app); Write-Debug "Processing $($app.id)"; Get-IntuneWin32AppDependency $app.id | ? targetType -eq 'child' | %{Write-debug "Found child $($_.targetid)"; Get-Children (Get-IntuneWin32App -ID $_.targetId | Add-Member NoteProperty Child $true -PassThru)}; $app}; Get-Children $_ } | sort displayName, Child -Unique
$allap | ft -auto ID, displayName, Exclusion, Child
#get restart behavior, notification behavior, grace period
$allap | %{ $app = $_; if($app.Child -Or !($ass = Get-IntuneWin32AppAssignment -ID $_.id | ?{$_.target.'@odata.type' -notlike '*.exclusion*'})){$ass = $app}; $ass | Select @{n="displayName";e={$app.displayName}}, @{n="reboot";e={$app.installExperience.deviceRestartBehavior}}, @{n="target";e={$_.target.'@odata.type'.split('.')[-1]}}, @{n="notifications";e={$_.Settings.notifications}}, @{n="grace";e={$_.Settings.restartSettings.gracePeriodInMinutes}}, @{n="TestDevice";e={($app.requirementrules|? fileOrFolderName -eq TestDevice).detectionType}}} | Out-GridView

#Defender settings
Get-MpPreference
#Defender status
Get-MpComputerStatus 
#Defender start capture https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/announcing-performance-analyzer-for-microsoft-defender-antivirus/ba-p/2713911?utm_source=pocket_mylist
New-MpPerformanceRecording -RecordTo <recording.etl>
#Defender analyze capture
Get-MpPerformanceReport -Path <recording.etl> -TopFiles 5

#Track app installs during Autopilot provisioning https://learn.microsoft.com/en-us/troubleshoot/mem/intune/device-enrollment/understand-troubleshoot-esp#check-the-registry-for-app-deployment-failures-during-esp
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics\Sidecar

#check for ongoing Autopilot deployments
1. Open Audit Logs https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Audit
2. Sort by Date descending
3. Find pre-provisioning deployments (WhiteGlove)
	a. Filter by "Target starts with APWG-" and "Initiated by actor Intune"
	b. Find latest activity that updated the property DisplayName
4. Find user-driving deployments (USB)
	a. Filter by "Service: Device Registration Service" and "Activity: Register device"
	b. Find latest activity that has [Additional Details\Scenario] = Autopilot

#microsoft graph queries
#find a device by Intune deviceId
https://graph.microsoft.com/beta/devices?$filter=deviceId eq 'c803301b-5799-48b4-a8fa-c16885338503'

#force AD Connect sync in UAT
Invoke-Command -ComputerName gva-adc-50 -ScriptBlock{ Start-ADSyncSyncCycle }

#delete Intune, Azure, or Autopilot devices in bulk
gc C:\Temp\to_delete.txt | %{ & "C:\Users\paladi\OneDrive - International Labour Office\_Scripts\Azure\Delete-AutopilotedDeviceRecords.ps1" -SerialNumber $_ -Intune}

#delete Autopilot devices (if not successful, delay for at least 30min between repeated attempts)
foreach ($serial in 'DVL36J3',	'2KD46J3',	'2YY46J3',	'JFF66J3',	'BJK36J3',	'12546J3',	'74V46J3',	'B2Z46J3',	'6ZY36J3',	'G4V46J3'){
	$URI = "beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$serial')"
	$AutopilotDevice = Invoke-MSGraphRequest -Url $uri -Method GET -ErrorAction Stop
	if($AutopilotDevice.value.Id){
		Write-host "   Deleting SerialNumber: $serial  |  Model: $($AutopilotDevice.value.model)  |  AAD Id: $($AutopilotDevice.value.azureAdDeviceId)  |  GroupTag: $($AutopilotDevice.value.groupTag) …" -NoNewline
		$URI = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/$($AutopilotDevice.value.Id)"
		Invoke-MSGraphRequest -Url $uri -Method DELETE -ErrorAction Stop
		Write-Host "Success" -ForegroundColor Green
	} else {
		Write-Host "$serial not found"
	}
}

#autopilot reset https://docs.microsoft.com/en-us/mem/autopilot/windows-autopilot-reset
locally: set DisableAutomaticReDeploymentCredentials, then can use Ctrl+Win+R on the target device to trigger local Autopilot Reset
remotely: Intune -> Devices -> Select Device -> Autopilot Reset

#command line for installing powershell scripts
powershell.exe -NoProfile -ExecutionPolicy Bypass -File script.ps1


#get the device identity hash to be imported in Autopilot later
netsh winhttp set proxy "proxyos.ilo.ch:8080" bypass-list="*.uat.ilo.org"
Set-ExecutionPolicy bypass
Install-Script Get-WindowsAutopilotInfo -Force
Get-WindowsAutopilotInfo.ps1 -OutputFile d:\computername.csv
#import right now
Get-WindowsAutopilotInfo.ps1 -Online -GroupTag ILODEFAULT

#autopilot diagnostics, run during ESP
mdmdiagnosticstool.exe -area DeviceEnrollment;DeviceProvisioning;Autopilot;Tpm –cab <pathToOutputCabFile>.cab 
#if asking a standard user to run the diagnostics, he can use Settings > Accounts > Access work or school > Export your management log files.

Install-Script -Name Get-AutopilotDiagnosticsCommunity; Set-ExecutionPolicy -ExecutionPolicy RemoteSigned; Get-AutopilotDiagnosticsCommunity

#intune reevaluate required apps
#	Go to HKLM:\Software\Microsoft\IntuneManagementExtension\Win32Apps
#	Delete App GUID key to reevaluate a specific app, or User GUID parent key to reevaluate all apps
Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension" -Recurse -Include *PartialAppId* | Remove-Item -Recurse
restart-service IntuneManagementExtension

#intune sync and check policies
(New-Object -ComObject Shell.Application).open("intunemanagementextension://syncapp")
restart-service IntuneManagementExtension
sls -Pattern 'Started app' -path 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log' -Context 20
Get-WinEvent -FilterHashTable @{LogName = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin" } -MaxEvents 150 | ? id -ge 800 | ft -w
#https://docs.microsoft.com/en-gb/mem/configmgr/comanage/how-to-monitor
#https://docs.microsoft.com/en-us/troubleshoot/mem/intune/troubleshoot-co-management-bootstrap#common-issues

net use i: \\gva-fil-49.ad.ilo.org\V-HQ-99-01-01-PRI /user:ilo\a-paladi
mkdir i:\autopilot\2023-03-25-1
copy C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\*.log i:\autopilot\2023-03-25-1
mdmdiagnosticstool.exe -area DeviceEnrollment;DeviceProvisioning;Autopilot;Tpm -cab i:\autopilot\2023-03-25-1\mdmdiag.cab

#check AD registration logs
Get-WinEvent -FilterHashTable @{LogName = 'Microsoft-Windows-User Device Registration/Admin'} -MaxEvents 30 | ft -w
#check dsregcmd output from the user context
Register-ScheduledTask -TaskName RunOnce -Force -Action (New-ScheduledTaskAction -Execute 'cmd' -Argument "/c dsregcmd /status > c:\temp\dsreg.log") -Principal (New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545') -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -MultipleInstances Parallel -DontStopIfGoingOnBatteries) | Start-ScheduledTask

# get AAD and enrolment related events
Get-WinEvent -FilterHashTable @{LogName = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin","Microsoft-Windows-AAD/Operational","Microsoft-Windows-User Device Registration/Admin"; StartTime=(Get-Date).adddays(-1)}

#### reenroll comanaged device to Intune remotely https://docs.microsoft.com/en-us/troubleshoot/mem/intune/troubleshoot-co-management-auto-enrolling
#detect broken enrollment by checking for incoming Intune policy messages
Get-WinEvent -FilterHashTable @{LogName = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"; id=202,847,813; StartTime=(Get-Date).adddays(-7)} -MaxEvents 1 -ErrorAction Ignore

# test for intune sync errors #https://call4cloud.nl/2022/10/intune-sync-debug-tool-the-last-royal-treasure/
install-module intunesyncdebugtool -force
test-intunesyncerrors

#fix broken MDM enrollment by resetting the enrollment locally on the device
	Stop-Service ccmexec
	$EnrollmentId = Get-Item -Path HKLM:\SOFTWARE\Microsoft\Enrollments\* | Get-ItemProperty | Where-Object -FilterScript {$null -ne $_.UPN} | Select -Exp PSChildName
	Get-ScheduledTask | ? TaskPath -eq "\Microsoft\Windows\EnterpriseMgmt\$EnrollmentId\" | Stop-ScheduledTask
	Get-ScheduledTask | ? TaskPath -eq "\Microsoft\Windows\EnterpriseMgmt\$EnrollmentId\" | Unregister-ScheduledTask -Confirm:$false
	Remove-Item "C:\ProgramData\Microsoft\DMClient\$EnrollmentId" -Force -Recurse
	### check that the AAD device object is gone
	### delete the Intune device object if present
	gci HKLM:\SOFTWARE\Microsoft\Enrollments -Recurse | ? PSChildName -eq $EnrollmentId | Remove-Item -Recurse -EA 0
	gci HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked -Recurse | ? PSChildName -eq $EnrollmentId | Remove-Item -Recurse -EA 0
	gci HKLM:\SOFTWARE\Microsoft\PolicyManager -Recurse | ? PSChildName -eq $EnrollmentId | Remove-Item -Recurse -EA 0
	gci HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM -Recurse | ? PSChildName -eq $EnrollmentId | Remove-Item -Recurse -EA 0
	gci cert:\localmachine\my -rec | ?{$_.IssuerName.Name -like '*Microsoft Intune MDM Device CA*'} | Remove-Item -EA 0
	### check that the SCCM device is in MDM-WKS-Enrollment collection
	### Now, either restart the computer, or try to autoenroll immediately:
	Register-ScheduledTask -TaskName Enroll -Force -Action (New-ScheduledTaskAction -Execute '%windir%\system32\deviceenroller.exe' -Argument '/c /AutoEnrollMDM') -Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-18') -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries) | %{ Start-ScheduledTask $_.TaskName; Unregister-ScheduledTask $_.TaskName -Confirm:$false}
	Start-Service CcmExec
	### log on with an AAD Premium user

#fix broken Azure PRT by resetting the AAD registration locally on the device
	#unjoin the device by removing the local registration information and delete the AAD object
	Register-ScheduledTask -TaskName AADLeave -Force -Action (New-ScheduledTaskAction -Execute 'dsregcmd' -Argument '/leave') -Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-18') -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries) | %{ Start-ScheduledTask $_.TaskName; Unregister-ScheduledTask $_.TaskName -Confirm:$false}
	### check that the AD computer object has the userCertificate attribute filled in
	### Wait up to 30min AD Connect sync to kick in and create the AAD device object
	### Restart and logon with domain access (user account with AAD Premium license)
	### or kickstart the registration manually (needs access to domain):
	Start-ScheduledTask Automatic-Device-Join -TaskPath "\Microsoft\Windows\workplace join\"
	Get-ScheduledTaskInfo -TaskName 'Automatic-Device-Join' -TaskPath '\Microsoft\Windows\Workplace Join'
	### can check that the registration is successful (SSO should start working)
	Get-WinEvent -FilterHashTable @{LogName = 'Microsoft-Windows-User Device Registration/Admin'} -MaxEvents 15 | ft -w	

case 1: the device has an Autopilot object linked to a (healthy) Intune object and a (stale) AAD object. However, the 2 are not interlinked, as the Intune one is linked to a different AAD object, which is in Pending state.
	- check that the AD computer object has the userCertificate attribute filled in
	- open the Autopilot object, delete the linked Intune object, then the Autopilot object itself, then the 2 AAD objects.
	- delete the SCCM device
	- reset the enrollment as above
	- restart and logon as the target user
case 2: the device has an Autopilot object linked to a (healthy) Intune object and a (pending) AAD object. 
	- check that the AD computer object has the userCertificate attribute filled in
	- delete the Intune and AAD objects
	- delete the SCCM device
	- reset the enrollment as above
	- restart and logon as the target user

#schedule to restart the computer after midnight
Register-ScheduledTask -TaskName Restart -Force -InputObject (
	( New-ScheduledTask `
		-Action (New-ScheduledTaskAction -Execute 'shutdown.exe' -Argument '/r /f') `
		-Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-18') `
		-Settings (New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter 1 -AllowStartIfOnBatteries -MultipleInstances Parallel) `
		-Trigger (New-ScheduledTaskTrigger -Once -At ($at = Get-Date (Get-Date).AddDays(1) -Hour 0))
	) | %{ $_.Triggers[0].EndBoundary = $at.AddHours(1).ToString('s'); $_ })

### after a while the device should appear in Intune

#[old] reset enrollment https://www.maximerastello.com/manually-re-enroll-a-co-managed-or-hybrid-azure-ad-join-windows-10-pc-to-microsoft-intune-without-loosing-current-configuration/
$id = Get-ChildItem -Path 'C:\Windows\System32\Tasks\Microsoft\Windows\EnterpriseMgmt\' -directory | ? {$_.Name -match '[0-9]' -And $_.Name.Length -eq 36} | Select -ExpandProperty name
$tp = "\Microsoft\Windows\EnterpriseMgmt\$id\"
Get-ScheduledTask -TaskPath $tp | Stop-ScheduledTask
Get-ScheduledTask -TaskPath $tp | Unregister-ScheduledTask -Confirm:$false
Remove-Item ('C:\Windows\System32\Tasks' + $tp)
"hklm:SOFTWARE\Microsoft\Enrollments\$id", "hklm:SOFTWARE\Microsoft\Enrollments\Status\$id", "hklm:SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$id", "hklm:SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$id", "hklm:SOFTWARE\Microsoft\PolicyManager\Providers\$id", "hklm:SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$id", "hklm:SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$id", "hklm:SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$id" | Remove-Item -Recurse
gci cert:\localmachine\my -rec | ?{$_.IssuerName.Name -like '*Microsoft Intune MDM Device CA*'} | Remove-Item
Register-ScheduledTask -TaskName RunOnce -Force -Action (New-ScheduledTaskAction -Execute '%windir%\system32\deviceenroller.exe' -Argument '/c /AutoEnrollMDM') -Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-18') -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries) | %{ Start-ScheduledTask $_.TaskName; Unregister-ScheduledTask $_.TaskName -Confirm:$false}

#read CSPs on Windows 10
Get-CimInstance -Namespace "root\cimv2\mdm\dmmap" -ClassName ...

#script to retrieve and document existing Intune configurations and policies
https://github.com/ThomasKur/IntuneDocumentation

#repair HAAD join
Invoke-Command "\\ad.ilo.org\configmgr\CONTENT\SOURCES\Applications\ILO\Apps\Repair MDM Cert\1.0\remediate.ps1" -ComputerName $pc -SessionOption ($opt=New-PSSessionOption -NoMachineProfile)

#set proxy for  the loganalytics monitoring agent
(New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg').SetProxyInfo('http://proxyos:8080','','')

#https://docs.microsoft.com/en-us/powershell/module/azuread/?view=azureadps-2.0
#Get the AAD Device Object
$pc = Get-AzureADDevice -Filter "displayName eq 'A0110218'" 
Get-AzureADDeviceRegisteredOwner -ObjectId $pc.ObjectId
Get-AzureADDevice -All $true | Select *
#remove the device owner in AAD
Remove-AzureADDeviceRegisteredOwner -ObjectId $pc.ObjectID -OwnerId (Get-AzureADDeviceRegisteredOwner -ObjectId $pc.ObjectID).ObjectId
#set the device owner in AAD
Add-AzureADDeviceRegisteredOwner -ObjectId $pc.ObjectID -RefObjectId (Get-AzureADUser -Filter "userPrincipalName eq 'itdemo@ilo.org'").ObjectId

#cannot remove device from AAD website, try command line:
Remove-AzureADDevice -ObjectId (Get-AzureADDevice -Filter "displayName eq 'A0110218'" ).ObjectId

#intune devices
Import-Module Microsoft.Graph.Intune; Connect-MSGraph
Get-IntunemanagedDevice | Get-MSGraphAllPages
Get-IntuneManagedDevice -filter "(Contains(deviceName, 'APWG'))" | Get-MSGraphAllPages | select devicename, userDisplayName, lastSyncDateTime | sort lastSyncDateTime -Desc
Get-IntunemanagedDevice | Get-MSGraphAllPages | where deviceEnrollmentType -eq 'windowsCoManagement'
#get all scope tags
Get-DeviceManagement_DeviceCategories

#set primary user to last logged on
# https://svdbusse.github.io/SemiAnnualChat/2020/03/21/Changing-Intune-Primary-User-To-Last-Logged-On-User.html

#To view details about the Microsoft 365 services that are available in all of your license plans
Get-MsolAccountSku | Select -ExpandProperty ServiceStatus
#to view your available licensing plans, also known as AccountSkuIds
Get-MsolAccountSku | Select AccountSkuId | Sort AccountSkuId
#Identify the undesirable services in the licensing plan
$LO = New-MsolLicenseOptions -AccountSkuId "litwareinc:ENTERPRISEPACK" -DisabledPlans "SHAREPOINTWAC", "SHAREPOINTENTERPRISE"
#disables the services for a user 
Set-MsolUserLicense -UserPrincipalName user@litwareinc.com -LicenseOptions $LO

#win32 app management
https://docs.microsoft.com/en-us/mem/intune/apps/apps-win32-app-management

#https://docs.microsoft.com/en-us/troubleshoot/mem/intune/troubleshoot-co-management-auto-enrolling
#Use the following log file on Windows 10 devices to troubleshoot co-management issues on the client:
%WinDir%\CCM\logs\CoManagementHandler.log

#https://learn.microsoft.com/en-us/troubleshoot/mem/intune/device-enrollment/understand-troubleshoot-esp
#normal win32app successful deployment sequence in the IntuneManagementExtension log:
---->>[Win32App] Processing app (id=b213bd21-8f4f-4711-81c6-558ef3c18a23, name = Cisco AnyConnect Secure Mobility Client) with mode = DetectInstall		11/06/2020 09:01:26	5 (0x0005)
----[Win32App] app with name = Cisco AnyConnect Secure Mobility Client dependency detect only is False		11/06/2020 09:01:26	5 (0x0005)
[Win32App] ===Step=== Start to Present app b213bd21-8f4f-4711-81c6-558ef3c18a23		11/06/2020 09:01:26	5 (0x0005)
[Win32App] ===Step=== Detection rules					11/06/2020 09:01:26	5 (0x0005)
[Win32App] ===Step=== Check applicability				11/06/2020 09:01:26	5 (0x0005)
[Win32App] ===Step=== Check Extended requirement rules		11/06/2020 09:01:26	5 (0x0005)
[Win32App] ===Step=== Check detection without existing AppResult		11/06/2020 09:01:26	5 (0x0005)
[Win32App] app 008d036d-af91-48be-98d1-48928c0368f1, name Install Driver Updates is a dependency, processed in Detect Only mode without checking intent and auto install flag, detection is done, finished processing.	IntuneManagementExtension	28/11/2022 08:26:23	5 (0x0005)
[Win32App] ===Step=== Download		11/06/2020 09:01:26	5 (0x0005)
[Win32App] CDN mode, content raw URL is http://swdb02.manage.microsoft.com/a1dc5114-
[Win32App] CDN mode, download completes.
[Win32App] ===Step=== ExecuteWithRetry		11/06/2020 09:01:41	5 (0x0005)
[Win32App] ===Step=== Execute retry 0
[Win32App] ===Step=== InstallBehavior
[Win32App] ===Step=== Detection rules after Execution		11/06/2020 09:01:52	5 (0x0005)
[Win32App] ===Step=== Set ComplianceStateMessage with applicationDetectedAfterExecution		11/06/2020 09:02:02	5 (0x0005)
[Win32App] removing content from cache C:\Program Files (x86)\Microsoft Intune Management Extension\Content\Incoming\b213bd21-8f4f-4711-81c6-558ef3c18a23_1.bin		11/06/2020 09:02:02	5 (0x0005)
[Win32App] ===Step=== Set EnforcementStateMessage		11/06/2020 09:02:02	5 (0x0005)
Cleaning up staged content C:\Windows\IMECache\b213bd21-8f4f-4711-81c6-558ef3c18a23_1		11/06/2020 09:02:07	5 (0x0005)
[Win32App] Completed detectionManager SideCarScriptDetectionManager, applicationDetectedByCurrentRule: True	IntuneManagementExtension	24/11/2022 01:56:31	5 (0x0005)
[Win32App] Post processed result for (b213bd21-8f4f-4711-81c6-558ef3c18a23,Cisco AnyConnect Secure Mobility Client) is Success		11/06/2020 09:02:07	5 (0x0005)
[Win32App] current ESP phase DeviceSetup	IntuneManagementExtension	28/11/2022 08:26:23	5 (0x0005)

#installation took longer than 60min
[Win32App] Installation is timeout, collecting result	IntuneManagementExtension	28/11/2022 08:23:04	5 (0x0005)
[Win32App] installer is running timeout, skip staged content clean up.	IntuneManagementExtension	28/11/2022 08:23:14	5 (0x0005)

#view the app installation log entries, using a partial app ID
sls C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log -Pattern 'removing.*8f1b78c097ff' -Context 40,0

sls C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension*.log -Pattern cb12b  | % line | sls -Pattern 'Get policies|ReportingCacheManager' -NotMatch

Dir 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs' -filter i*.log | Read-IMELog | sort time -desc | select -exp message | sls cb12b -con 2 | select -f 20 | sls 'ReportingManager|ReportingCacheManager|Get policies' -not 

#indication of failure, the app install is skipped with Error when a dependency hasn't been detected, causing ESP timeout:
[Win32App] app 40bfbc20-36a4-4462-bb11-ab9e5538c778, name Configuration Manager Client is a dependency, processed in Detect Only mode without checking intent and auto install flag, detection is done, finished processing.

# Intent:
0 –> Not Targeted
1 –> Available
3 –> Install/Required
4 –> Uninstall

#State 2 means InProgress, state 3 means the install was successful, 4 - not detected.  Right now, if an app install fails, the failure is not reported by ESP, so it will sit until the timeout happens.
sls C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log -Pattern 'installationStateString: 4'

#starting a session
EMS Agent Started	IntuneManagementExtension	28/11/2022 07:19:30	4 (0x0004)
#stopping a session
EMS Agent Stopped	IntuneManagementExtension	12/10/2022 12:56:54	167 (0x00A7)

#marker of successful end of ESP device setup
[Win32App] ESP Checking SidecarCspProvider status	IntuneManagementExtension	12/10/2022 12:40:39	5 (0x0005)
[Win32App] Got InstanceID: Sidecar, installationStateString: 3	IntuneManagementExtension	12/10/2022 12:40:39	5 (0x0005)
[Win32App] Got installationState: Completed	IntuneManagementExtension	12/10/2022 12:40:39	5 (0x0005)
[Win32App] GetHasProvisioningCompleted getting hasProvisioningCompleted with userSID 	IntuneManagementExtension	12/10/2022 12:40:39	5 (0x0005)
[Win32App] Got HasProvisioningCompletedWmi value as True	IntuneManagementExtension	12/10/2022 12:40:39	5 (0x0005)
[Win32App] GetSidecarTrackingPoliciesCreated getting trackingPoliciesCreated with userSID 	IntuneManagementExtension	12/10/2022 12:40:39	5 (0x0005)
[Win32App] Got SidecarTrackingPoliciesCreated value as True	IntuneManagementExtension	12/10/2022 12:40:39	5 (0x0005)
[Win32App] ESP got devicePolicyCreated True, deviceHasProvisioningCompleted True	IntuneManagementExtension	12/10/2022 12:40:39	5 (0x0005)
[Win32App] ESP CheckDeviceAndAccountSetupStateWithWmi all apps completed for device	IntuneManagementExtension	12/10/2022 12:40:39	5 (0x0005)
[Win32App] ESP got skipUserStatusPage True, return NotInEsp	IntuneManagementExtension	12/10/2022 12:40:39	5 (0x0005)

#Get-IntuneWin32App  | select id, displayName, displayversion
id                                   displayName                                         displayVersion
--                                   -----------                                         --------------
c5412996-3e08-4cf6-9a91-898c78074754 .NET Desktop Runtime 6.0.5                          6.0.5
47970d4a-bc55-4292-af4d-193926effa8f 7-Zip 21.07                                         21.07.00.0
f4fd64b0-ca75-487e-a815-9a1af3392b0f Acrobat Reader DC 2022.3                            2022.3
47c18267-b7b9-4ae3-8e73-cd6155770ff4 Adobe Reader DC - Extended Asian Language font pack
475cfed9-7650-4538-883e-d8f00d0e8f57 Adobe Reader DC - Extended Asian Language font pack 22.001.20085
6df2027f-eda8-43a8-a20c-aa6535488c39 Adobe Reader DC - Spelling Dictionaries             22.001.20085
a7b22d0c-18c0-41f7-9d34-355ac09ef4b1 Adobe Reader DC - Spelling Dictionaries Support
4cd22a97-cbe1-4ef3-9151-d841b93f2a16 App Installer                                       2022.927
1dfa1560-c1fd-4c4e-b8f2-f75c5028a015 Autopilot Branding 4.0                              4.0
392ad88f-3b82-421d-8ffe-c9f02d102595 Cisco AnyConnect Secure Mobility Client 4.10.05111  4.10.05111
aec23576-0890-497f-b20c-454ba9aed6b0 Configuration Manager Client                        2203
79808f20-d322-4574-9dee-d2ebd2bd94f6 Dell Command Update 4.7                             4.7
fbbb2ae1-9ccf-4dbc-a404-8f1b78c097ff Google Chrome 100.0.4896.60                         68.200.60
4e1f0e84-6ecc-4f17-853b-1b7c5c9261f4 ILO Start Layout                                    2022-03-30
008d036d-af91-48be-98d1-48928c0368f1 Install Driver Updates                              1.0
51f20522-b318-42e9-9456-078586c15582 Install OS Updates                                  1.0
7afd1628-c901-4fd4-8dc3-94b262c5c9c5 Java 8 Update 311                                   8.0.311.33
72ef6036-4ebe-4106-b2bc-b0ef00c002c1 Microsoft 365 Apps (14931.20724)                    16.0.14931.20724
7fb92275-4ab2-4849-8c11-385f3c902994 Microsoft Teams 1.5.0.28361                         1.5.0.28361
4a78cc84-7794-4285-ba6a-3e5da508f0c7 OneDrive 22.65.412.4                                22.65.412.4
d15a3ef6-9c6b-430d-b309-b2357661fccf PowerShell 7.2.4 x64                                7.2.4.0
b5da855d-0b35-4589-a450-961633871c40 Set Timezone                                        3.0
92bd136a-8001-455c-8ea4-64108bac2cfa TeamViewer                                          15.32.3.0
9fd80c65-2d65-4c61-8468-dc5d7759bc97 TreeSize Professional V8.3.1.1661                   8.3.1.1661
9b236ec7-6160-4940-9e43-5aee967e5e61 VC Redistributable 2022 x64 14.34                   14.34.31931
8f7410a7-04a2-4b39-b65d-c421cdba935d VC Redistributable 2022 x86 14.34                   14.34.31931
a3f2f8f0-bc7b-4654-9b0e-5f975c0e31ec vcredist2013_x64
4f0034ca-c1dc-4647-87dd-c910983c18b5 vcredist2013_x86
3c4c99ec-8229-4b34-9858-4c4d3289ccef Windows 10 Upgrade to 21H2
e50101b7-36ad-42cd-abb0-2f16e3cd7f4d Zotero 6.0.4 test                                   6.0.4

id                                   displayName                                         displayVersion
--                                   -----------                                         --------------
41b59918-b338-44d9-bf3e-f950c938f29b .NET Desktop Runtime                                6.0.11
47970d4a-bc55-4292-af4d-193926effa8f 7-Zip 21.07                                         21.07.00.0
f4fd64b0-ca75-487e-a815-9a1af3392b0f Acrobat Reader DC 2022.3                            2022.3
475cfed9-7650-4538-883e-d8f00d0e8f57 Adobe Reader DC - Extended Asian Language font pack 22.001.20085
6df2027f-eda8-43a8-a20c-aa6535488c39 Adobe Reader DC - Spelling Dictionaries             22.001.20085
4cd22a97-cbe1-4ef3-9151-d841b93f2a16 App Installer                                       2022.927
1dfa1560-c1fd-4c4e-b8f2-f75c5028a015 Autopilot Branding 4.0                              4.0
392ad88f-3b82-421d-8ffe-c9f02d102595 Cisco AnyConnect Secure Mobility Client 4.10.05111  4.10.05111
aec23576-0890-497f-b20c-454ba9aed6b0 Configuration Manager Client                        2203
8e63f523-37e2-46a8-8d59-e40c3927fb4a Dell Command Update                                 4.7.1
79808f20-d322-4574-9dee-d2ebd2bd94f6 Dell Command Update 4.7                             4.7
fbbb2ae1-9ccf-4dbc-a404-8f1b78c097ff Google Chrome 100.0.4896.60                         68.200.60
4e1f0e84-6ecc-4f17-853b-1b7c5c9261f4 ILO Start Layout                                    2022-03-30
33cdf0fc-4b08-47f8-94a7-d8c1c5d5884c Install Driver Baseline                             1.0
008d036d-af91-48be-98d1-48928c0368f1 Install Driver Updates                              1.0
51f20522-b318-42e9-9456-078586c15582 Install OS Updates Phase 1                          2.0
99335248-f7fb-4b2e-a9ef-31261a7ff8af Install OS Updates Phase 2                          2.0
7afd1628-c901-4fd4-8dc3-94b262c5c9c5 Java 8 Update 311                                   8.0.311.33
72ef6036-4ebe-4106-b2bc-b0ef00c002c1 Microsoft 365 Apps (14931.20724)                    16.0.14931.20724
7fb92275-4ab2-4849-8c11-385f3c902994 Microsoft Teams 1.5.0.28361                         1.5.0.28361
4a78cc84-7794-4285-ba6a-3e5da508f0c7 OneDrive 22.65.412.4                                22.65.412.4
d15a3ef6-9c6b-430d-b309-b2357661fccf PowerShell 7.2.4 x64                                7.2.4.0
b5da855d-0b35-4589-a450-961633871c40 Set Timezone                                        3.0
92bd136a-8001-455c-8ea4-64108bac2cfa TeamViewer                                          15.32.3.0
9fd80c65-2d65-4c61-8468-dc5d7759bc97 TreeSize Professional V8.3.1.1661                   8.3.1.1661
9b236ec7-6160-4940-9e43-5aee967e5e61 VC Redistributable 2022 x64 14.34                   14.34.31931
8f7410a7-04a2-4b39-b65d-c421cdba935d VC Redistributable 2022 x86 14.34                   14.34.31931
a3f2f8f0-bc7b-4654-9b0e-5f975c0e31ec vcredist2013_x64
4f0034ca-c1dc-4647-87dd-c910983c18b5 vcredist2013_x86
3c4c99ec-8229-4b34-9858-4c4d3289ccef Windows 10 Upgrade to 21H2
e50101b7-36ad-42cd-abb0-2f16e3cd7f4d Zotero 6.0.4 test                                   6.0.4

#find individual devices
Get-AzureADDevice -Filter "displayname eq 'SJO00707'"
Get-IntunemanagedDevice -Filter "devicename eq 'SJO00707'"
Get-MsolDevice -Name 'SJO00707'
#get all Hybrid AAD devices
Get-MsolDevice -All -IncludeSystemManagedDevices | where {($_.DeviceTrustType -eq 'Domain Joined') }

$d = [datetime]::Now.AddDays(-30) #cutoff date from which to consider a device active
#get windows Intune devices and eliminate duplicates by azureADDeviceId, leaving those with latest sync time
$di = Get-IntunemanagedDevice | Get-MSGraphAllPages | where deviceEnrollmentType -eq 'windowsCoManagement' | Group azureADDeviceId | %{$_.Group | Sort lastSyncDateTime -Desc | Select -f 1}
$di_ix = buildIndex $di 'azureADDeviceId'
$da = Get-AzureADDevice -All $true | Select * | Where DeviceOSType -eq 'Windows'
$da_ix = buildIndex $da 'DeviceId'
#get windows 10 SCCM devices and eliminate duplicates, leaving those with latest active time
$ds = Get-CMDevice | Where-Object {$_.LastActiveTime -gt $d -And $_.DeviceOS -like 'Microsoft Windows NT Workstation 10*' -And $_.IsObsolete -ne $True} | Group name | %{$_.Group | Sort LastActiveTime -Desc | Select -f 1}
$ds_ix = buildIndex ($ds|? AADDeviceID|group AADDeviceID|%{$_.Group|Sort LastActiveTime -Desc|Select -f 1}) 'AADDeviceID'

#get orphaned Intune device objects (the client stopped sync-ing)
#for each active SCCM device, find its Intune object by AAD ID, and select it if the Intune sync date is more than 2 weeks older than SCCM Active Date. 
$ds |? Name -notlike 'kiosk*' | %{
 $name = $_.Name
 if($_.AADDeviceID -match '[^0-]'){
	$dii = $di_ix[$_.AADDeviceID]
	$dai = $da_ix[$_.AADDeviceID]
 } else {$dii=$dai=$null}
 if($null -eq $dii){
	$dii = $di | ? Name -eq $Name | Group Name | %{$_.Group | Sort lastSyncDateTime -Desc | Select -f 1}
	if($dii.azureADDeviceId -match '[1-9]'){
		$dai = $da_ix[$dii.azureADDeviceId]
	} else {
		$dai = $da | ? DisplayName -eq $Name | Group DisplayName | %{$_.Group | Sort LastDirSyncTime -Desc | Select -f 1}
	}
 }
 if(($null -eq $dii -or $dii.lastSyncDateTime -lt $_.LastActiveTime.AddDays(-14)) -And $dii.complianceState -ne 'compliant'){
   [pscustomobject]@{
     'SCCM Name' = $_.name;
	 'SCCM CurrentLogonUser' = $_.CurrentLogonUser;
	 'SCCM LastLogonUser' = $_.LastLogonUser;
	 'SCCM Last Active' = $_.LastActiveTime;
     'Intune Name' = $dii.deviceName;
     'Intune Last Sync' = $dii.lastSyncDateTime;
     'Intune Enrolled' = $dii.enrolledDateTime;
     'Intune Compliance' = $dii.complianceState;
	 'Intune isEncrypted' = $dii.isEncrypted;
	 'Intune Enrolled By' = $dii.userDisplayName;
	 'Intune Model' = $dii.Model;
     'AAD Device ID' = $_.AADDeviceID;
	 'AAD Last Logon' = $dai.ApproximateLastLogonTimeStamp;
	 'AAD Last Sync' = $dai.LastDirSyncTime
 }}} | Export-Csv "C:\temp\sccm\not_in_sync$(Get-Date -F yyMMddHHmm).csv" -NoTypeInformation   

#get non-compliant but active Intune devices (last synced in the past 7 days)
$di | Where-Object { $_.azureADDeviceId -match '[^0-]' -And $_.lastSyncDateTime -gt [datetime]::Now.AddDays(-7) -And $_.complianceState -eq 'noncompliant' -And $_.DeviceName -notlike 'kiosk*'} | %{
 $dsi = $ds_ix[$_.azureADDeviceId]
 $dai = $da_ix[$_.azureADDeviceId];
   [pscustomobject]@{
     'SCCM Name' = $dsi.name;
	 'SCCM CurrentLogonUser' = $dsi.CurrentLogonUser;
	 'SCCM LastLogonUser' = $dsi.LastLogonUser;
	 'SCCM Last Active' = $dsi.LastActiveTime;
     'Intune Name' = $_.deviceName;
     'Intune Last Sync' = $_.lastSyncDateTime;
     'Intune Enrolled' = $_.enrolledDateTime;
     'Intune Compliance' = $_.complianceState;
	 'Intune isEncrypted' = $_.isEncrypted;
	 'Intune Enrolled By' = $_.userDisplayName;
	 'Intune Model' = $_.Model;
     'AAD Device ID' = $_.azureADDeviceId;
	 'AAD Last Logon' = $dai.ApproximateLastLogonTimeStamp;
	 'AAD Last Sync' = $dai.LastDirSyncTime
}} | Export-Csv "C:\temp\sccm\non-compliant_$(Get-Date -F yyMMddHHmm).csv" -NoTypeInformation   

#get sccm devices with Intune Primary User
$query = @"
SELECT RV.Netbios_Name0 as 'Computer'
	, CS.LastActiveTime as 'Last Active'
	, isnull(SCUM.TopConsoleUser0,isnull(CDR.CurrentLogonUser, isnull(RV.User_Domain0+'\'+RV.User_Name0,'n/a'))) as 'UserName'
FROM dbo.v_R_System_Valid as RV
left outer join dbo.v_CH_ClientSummary as CS on RV.ResourceID = CS.ResourceID
left outer join dbo.v_GS_SYSTEM_CONSOLE_USAGE_MAXGROUP SCUM on RV.ResourceID = SCUM.ResourceID
left outer join dbo.v_CombinedDeviceResources CDR on RV.ResourceID = CDR.MachineID
where CS.LastActiveTime In (
		Select Max(CS_All.LastActiveTime) 
		FROM dbo.v_CH_ClientSummary As CS_All
		INNER JOIN dbo.v_R_System_Valid as RV_Sub ON RV_Sub.ResourceID = CS_All.ResourceID
		WHERE RV_Sub.Netbios_Name0 = RV.Netbios_Name0
		Group By RV_Sub.Netbios_Name0)
"@
$sqlConnection = new-object System.Data.SqlClient.SqlConnection "server=$($SCCM_Site.ComputerName);database=CM_ILO;integrated security=true"
$results = new-object system.data.datatable; (new-object data.sqlclient.sqldataadapter($query, $sqlConnection)).fill($results)
$sd_ix = buildIndex $Results.Rows 'Computer'
$di = Get-IntunemanagedDevice | Get-MSGraphAllPages | where deviceEnrollmentType -eq 'windowsCoManagement' | Group deviceName | %{$_.Group | Sort lastSyncDateTime -Desc | Select -f 1}
$di_ix = buildIndex $di 'deviceName'
$results | %{ Add-Member -InputObject $_ -MemberType NoteProperty -Name 'Intune Primary User' -Value $di_ix[$_.Computer].userPrincipalName -PassThru -Force } |
	Export-Csv "C:\temp\sccm\SCCM_Devices_$(Get-Date -F yyMMddHHmm).csv" -NoTypeInformation
	
#get assets with invalid Intune Primary Users
Import-Csv 'C:\Temp\sccm\HQ Laptops.csv' | %{ $d = $di_ix[$_.'Asset Number']; $e = $_.'Email Address'; if($e -And (Get-ADUser -Filter {mail -eq $e -And enabled -eq $true}) -And $e -ne $d.userPrincipalName){[pscustomobject]@{Computer=$_.'Asset Number';IntuneUser=$d.userPrincipalName;AssetUser=$e}}} | Export-Csv -NoTypeInformation 'C:\Temp\sccm\HQ Laptops with wrong Intune User.csv'

Invoke-WebRequest -uri https://github.com/microsoftgraph/powershell-intune-samples/raw/master/ManagedDevices/Win10_PrimaryUser_Get.ps1 -OutFile Win10_PrimaryUser_Get.ps1
#set Intune primary user
Import-Csv '.\HQ Laptops with wrong Intune User.csv' | %{ & .\Win10_PrimaryUser_Set.ps1 -DeviceName $_.Computer -UserPrincipalName $_.AssetUser}

#get Intune primary user for devices in a SCCM collection
Get-CMCollectionMember -CollectionName GVA-AP-Office365-NotInstalled | ? {$_.AADDeviceID -match '[^0-]' -And $_.LastActiveTime -gt [datetime]::Now.AddDays(-30)} |  %{ Get-IntunemanagedDevice -Filter "azureADDeviceId eq '$($_.AADDeviceID)'" | select deviceName, emailAddress}

#check the OS Installation and OS Upgrade dates remotely
$pc='A0111838'; "OS Install: $((gcim -co $pc Win32_Directory -filter 'Drive="C:" and Path="\\Windows\\" and FileName="CSC"').CreationDate)"; "OS Upgrade: $((gcim -co $pc win32_operatingsystem).InstallDate)"

#cloned kiosk machines have same AAD ID so one Intune object for all: KIOSKW10GPOTST1 cd8092c6-f4e5-4f7d-8471-4df48eb98ca4 with lastSyncDateTime = 09/12/2020
A0111701: removed from Intune and SCCM 
A0118410: removed from Intune and SCCM
A0111908: removed from Intune and cleanup registry
		  gci HKLM:\SOFTWARE\Microsoft\Enrollments -Recurse | sort pspath -desc | remove-item -ea 0
			The device object with id '7b29701e-8e74-4f9b-b1ef-4872c00e1f9f' in tenant 'd49b07ca-2302-4e7c-b2cb-e12127852850' could not be removed from the store because it is managed by MDM application '54b943f8-d761-4f8d-951e-9cea1846db5a'
A0118729 (no object present in intune, mdmcertcheckandremediate.ps1 shows all is well): deleted the mdm cert and ran  mdmcertcheckandremediate.ps1 1

active sccm devices with old Intune sync date: 170
non-compliant but recently active Intune devices (14 days): 430
root cause for 80% of devices: windows upgrade broke the MDM registration, probably due to the certificate bug

potential fix: https://www.reddit.com/r/Intune/comments/apehk1/windows_10_client_does_not_reregister_reenroll_in/ehb6fe1/?utm_source=reddit&utm_medium=web2x&context=3

#convert pfx certificate to base64 string
[System.Convert]::ToBase64String(gc "C:\Users\paladi\OneDrive - International Labour Office\_Scripts\AAD\TMSAzureCert.pfx" -Encoding Byte)

#debug Intune detection and installation scripts, run from the staging folder
while($true){if(ls *.ps1){copy *.ps1 .. -Confirm:$false}; sleep -Milliseconds 200}

#reset onedrive
%localappdata%\Microsoft\OneDrive\onedrive.exe /reset

Register-ScheduledTask -TaskName AADLeave -Force -Action (New-ScheduledTaskAction -Execute 'dsregcmd' -Argument '/leave') -Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-18') -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries) | %{ Start-ScheduledTask $_.TaskName; Unregister-ScheduledTask $_.TaskName -Confirm:$false}
### check that the AAD device object is gone
### delete the Intune device object if present

#app requirement for ESP session during Autopilot
return [bool] (Get-Process -IncludeUserName -Name explorer -EA 0 | Where-Object UserName -match "defaultuser\d") 

#connect to Exchange Online
Install-Module ExchangeOnlineManagement -Repository PSGallery -AllowClobber -Force
Connect-ExchangeOnline
#connect to Azure Information Protection
Connect-AipService
#connect to Sharepoint Online
Connect-SPOService -Url https://ilouat-admin.sharepoint.com
#connect to Security and Compliance PowerShell
new-ItemProperty hklm:SOFTWARE\Policies\Microsoft\Windows\WinRM\Client -Name AllowBasic -Value 1 -PropertyType dword -Force
Connect-IPPSSession
#label troubleshooting
# https://techcommunity.microsoft.com/t5/security-compliance-and-identity/how-to-troubleshoot-sensitivity-labels-part-1/ba-p/3604557

#configure SPO site
Get-SPOSite -Identity https://ilouat.sharepoint.com/sites/UserSupport | %{$_.psobject.Properties} | sort name | select name,value
Set-SPOSite -Identity https://ilouat.sharepoint.com/teams/FileVault -ConditionalAccessPolicy AuthenticationContext -AuthenticationContextName "FileVault"
Set-SPOSite -Identity https://ilouat.sharepoint.com/teams/FileVault -ConditionalAccessPolicy AllowFullAccess
Set-SPOSite -Identity https://ilouat.sharepoint.com/sites/UserSupport -ConditionalAccessPolicy AllowLimitedAccess

#configure OneDrive sites
Get-SPOSite -IncludePersonalSite $true -Limit all -Filter "Url -like '-my.sharepoint.com/personal/'" | Set-SPOSite -ConditionalAccessPolicy AllowLimitedAccess
Get-SPOSite -Identity https://ilouat-my.sharepoint.com/personal/paladi_uat_ilo_org
Set-SPOSite -Identity https://ilouat-my.sharepoint.com/personal/paladi_uat_ilo_org -ConditionalAccessPolicy AllowLimitedAccess

#query security events from Sentinel Log Analytics
#https://portal.azure.com/#@iloprod.onmicrosoft.com/resource/subscriptions/e3ad0a5c-3c65-4745-8a60-0447e5dbd3fa/resourceGroups/rg-sentinel-logs/providers/Microsoft.OperationalInsights/workspaces/isas-sentinel/logs
SecurityEvent | summarize count() by EventID
SecurityEvent | where Account has "perdigao" | summarize count() by EventID
search in (SecurityEvent) "A0117502"
search "wks-5xqp1j3"  # only works when the time range is set to last hour
SecurityEvent | where EventID in (4756,4728,4732) and EventData has "GBL-ComputerToRetire" #group membership change

#get Azure Audit logs
Get-AzureADAuditSignInLogs -Filter "startsWith(userPrincipalName,'paladi')"

# Scripting the MDM WMI Bridge Provider to wipe the computer and do a factory reset (run as SYSTEM)
# $methodname can be either "doWipeMethod" or "doWipeProtectedMethod". The latter will also wipe all data from the fixed disks, especially if you want to refurbish the devices. The downside is that "doWipeProtectedMethod" can leave some clients (depending on configuration and hardware) in an unbootable state. However it's not needed if the disks were Bitlocker encrypted.
# Additionally, "doWipeMethod" can be canceled by the user (power cycle for example), but "doWipeProtectedMethod" cannot be canceled. It automatically resumes after a reboot until done. The higher risk is worth it most of the time. If you want to be sure that the devices will be in a usable state after the wipe, use "doWipeMethod" instead. 
$namespaceName = "root\cimv2\mdm\dmmap"; $className = "MDM_RemoteWipe"; $methodName = "doWipeMethod"
$session = New-CimSession
$params = New-Object Microsoft.Management.Infrastructure.CimMethodParametersCollection
$param = [Microsoft.Management.Infrastructure.CimMethodParameter]::Create("param", "", "String", "In")
$params.Add($param)
$instance = Get-CimInstance -Namespace $namespaceName -ClassName $className -Filter "ParentID='./Vendor/MSFT' and InstanceID='RemoteWipe'"
$session.InvokeMethod($namespaceName, $instance, $methodName, $params)

#add member to group
New-MgGroupMember -GroupId '872648e7-b23a-4328-bd46-f1bd431c2354' -DirectoryObjectId '8a7c50d3-fcbd-4727-a889-8ab232dfea01'
AAD-Intune_App-CompanyPortal 711f23c6-7b4d-44d1-8afc-3aa20c8b8da6
A0118376	44bef0aa-5509-4c34-86d6-6789b9c5b97b
Get-MgDeviceManagementManagedDevice 

#get the firewall rules installed by MDM	
Get-NetFirewallRule -PolicyStore MDM | Get-NetFirewallApplicationFilter

# devops https://dev.azure.com/
# Scroll down to Repos/Files, select the repository and the UAT branch at the top.
# edit/test code online or clone the repo locally (always make sure it's UAT !)
# when ready to update PROD, click on Pull Requests, tap Create, select UAT into PROD then submit
# approve the push to merge the changes into PROD
# if "Source Control" sync has been set up in the Automation Account, it will sync according to the configuration (check the Sync jobs)
# as DeviceManagement-Automation has Auto Sync enabled, so a minute or two later the runbooks will updated automatically
# if it doesn't sync automatically for some reason, go to Automation Account/Account Settings/Source Control, select VsoGit and click Start Sync

# to make Graph calls using Invoke-WebRequest need the header containing the Authorization Bearer code 
Invoke-WebRequest -UseBasicParsing -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps" -Headers $headers -Method Post -Body $body -ContentType "application/json"
# to get the Authorization code, connect to Intune in a browser, open the Developer Tools > Network, refresh the page, right click on one of the elements, select Copy > Copy as PowerShell
# paste into an editor and then create a $Headers hashtable with a copy of the Authorization key/value - to be used for Invoke-RestMethod calls

Invoke-RestMethod -Headers $headers -Method Get -Uri (
            "https://graph.microsoft.com/v1.0" +
            '/devices' + 
            "?`$filter=deviceId eq '0200e880-9693-4245-9866-088644fb7bbd'" +
            '&$select=id'
        )
		
# Invoke-RestMethod command is made for calling web APIs. It usually handles content types, and converting to/from json for you. It has additional parameters in pwsh:
$body = @{ name = 'testapi' ; emailAddress = '....'; }
Invoke-RestMethod -url $url -Method Post -Body $body -ea stop -SkipHttpErrorCheck -StatusCodeVariable 'rStatus'
switch($rStatus) {
    200 { 'good' }
    { $_ -in 400, 401, 403, 404 } { 'bad stuff' }
    default { throw "Unhandled HTTP Status code: $rStatus" }
}

# building Graph queries with complex filters
[int] $PreviousDays = 2
$request = [System.UriBuilder]"https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
$startTimeCutoff = [datetime]::UtcNow.AddDays(-$PreviousDays).ToString('o')
$endTimeCutoff = [datetime]::Today.ToUniversalTime().ToString('o')
$query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
$query['$filter'] = -join @(
    "activityDateTime ge $startTimeCutoff"
    " and activityDateTime le $endTimeCutoff"
    " and activityDisplayName eq 'Add member to group'"
    " or activityDisplayName eq 'Remove member from group'")
$request.query = $query.ToString()
Invoke-MgGraphRequest GET $request.uri

# using HttpUtility to build a query with multiple parameters
$query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
$query['$filter'] = 'foo'
$query['$select'] = 'bar'
$query['$top'] = 'baz'
$query['$expand'] = 'wow!'
[System.Web.HttpUtility]::UrlDecode($query.ToString())

########### to fix the SyncML 500 error in AV or Firewall compliance
#Trigger a sync on the device from Intune (can be done from the web portal, too)
Connect-MgGraph -scope DeviceManagementManagedDevices.PrivilegedOperations.All, DeviceManagementManagedDevices.ReadWrite.All,DeviceManagementManagedDevices.Read.All
$device = Get-MgDeviceManagementManagedDevice -Filter "contains(deviceName,'<DEVICENAME>')"
Sync-MgDeviceManagementManagedDevice -ManagedDeviceId $device.id
#Trigger a compliance check via local process on PC (use remote shell or execute locally)
Start-Process -FilePath "C:\Program Files (x86)\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe" -ArgumentList "intunemanagementextension://synccompliance"
#Trigger a sync via local scheduled task on PC (use remote shell or execute locally)
Get-ScheduledTask -TaskName 'Schedule #3 created by enrollment client' | Start-ScheduledTask

#querying Graph users in batches of 15
[System.Linq.Enumerable]::Chunk[object]($UserPrincipalNames, 15) | ForEach-Object {
    $uri = "v1.0/users?`$filter=userPrincipalName in ('$($_ -join "','")')&`$select=userPrincipalName, assignedLicenses"
    foreach ($user in Invoke-MgGraphRequest GET $uri) {
        [PSCustomObject]@{
            UserPrincipalName = $user.userPrincipalName
            SkuPartNumber     = $user.assignedLicenses.skuID -join '; '
         }
    }
} | Export-Csv ".\LicenseDetails.csv"

#send the win11 migration email using a webhook
$JobId = Invoke-RestMethod -Uri "https://eada3ab9-3370-4af6-8a11-5488bc5749e6.webhook.stzn.azure-automation.net/webhooks?token=WSCrulWpX9meeZ7SIkuf6e6lSeAayr63c0sTQMBRLkc%3d" -Method Post -Body (@{emails="paladi@ilo.org"}  | Convertto-json -Compress)

# Universal Print https://learn.microsoft.com/en-us/universal-print/fundamentals/universal-print-powershell
Connect-UPService
(Get-UPPrinter).Results
(Get-UPPrinterShare).Results
New-UPPrinterShare -PrinterId '0597d9a8-925b-45a4-b456-0e7c2ea565b6' -ShareName TNR-CANON-C3830i

# when lacking free space in the OneDrive, try clean up the Preservation Hold Library, if allowed. If not, then most probably an "eDiscovery Hold" is applied by IAO (due to an ongoing investigation).
https://iloprod-my.sharepoint.com/personal/%USERNAME%_ilo_org/PreservationHoldLibrary/Forms/AllItems.aspx
# also worth trying to find large files that have multiple versions and resetting them.

#query Autopilot devices
Connect-MgGraph -Scopes "DeviceManagementServiceConfig.ReadWrite.All"
$devices = Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -All

