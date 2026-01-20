(dir filesystem::"\\ad.ilo.org\configmgr\CONTENT\SOURCES\Applications\ILO\PSModules\SCCM").FullName.ForEach({. $_})
. \\ad.ilo.org\configmgr\CONTENT\SOURCES\Applications\ILO\PSModules\tmslib.ps1
#Connect to SCCM Server
Import-Module -Name "$(split-path $Env:SMS_ADMIN_UI_PATH)\ConfigurationManager.psd1"  
Set-Location -Path "$(Get-PSDrive -PSProvider CMSite):\"
$SCCM_Site = @{ Namespace="root/SMS/site_$((Get-CMSite).SiteCode)"; ComputerName = (Get-CMSite).ServerName }

#application troubleshooting using cmtrace, merge the following log files:
"AppDiscovery.log" "AppIntentEval.log" "AppDiscovery.log" "CAS.log" "ContentTransferManager.log" "DataTransferService.log" "ContentTransferManager.log" "CAS.log" "AppEnforce.log" "AppIntentEval.log"
#https://docs.microsoft.com/en-us/mem/configmgr/apps/understand/app-deployment-technical-reference
#https://deploymentparts.wordpress.com/2015/08/14/how-to-track-an-installation-through-client-log-files/
#https://support.microsoft.com/en-us/help/18408/troubleshoot-install-application-task-sequence

#updating the boot image in SCCM
1. prepare the boot image which is currently not in use by any TS
2. distribute the content to all locations
3. tick the box "enable pxe-boot" in the image properties
4. switch the TS to the new image

#copy boot ISO to HyperV host
Copy-Item "\\ad.ilo.org\configmgr\CONTENT\SOURCES\OSD\Autopilot\Media\autopilot_userdriven_v11.iso" d:\iso\ -ToSession (New-PSSession gva-usr-01) -Force

#get the list of all SCCM classes
Get-WmiObject -list * @SCCM_Site -Recurse -EA 0

#quickly get latest versions of all apps
Get-Wmiobject @SCCM_Site -Class SMS_ApplicationLatest -Filter "isExpired='false'"

#get app by CI_UniqueID
$ID='bf346356-e10c-4b0a-a87b-471eb4637188' #from the full string 'ScopeId_C001D0D1-74EB-46BE-B736-3667F92D22B8/Application_bf346356-e10c-4b0a-a87b-471eb4637188'
Get-Wmiobject @SCCM_Site -Class SMS_ApplicationLatest -Filter "CI_UniqueID like '%$($ID)%'"

(Get-CMCollectionMember -CollectionName "ADM-PRD-GBL-Q-Running-CM-Console").name

#sync/copy the user's primary device to AD Group
Add-ADGroupMember GVA-CG-INFOTEC -Members (Get-ADGroupMember GVA-OG-INFOTEC |%{Get-CMUserDeviceAffinity -UserName "ilo\$($_.SamAccountName)"}|%{Get-ADComputer -LDAPFilter "(name=$($_.ResourceName))"} | ? distinguishedName -Match "CN=[-\w]+,OU=(WKS|LPT|DSK|VM),OU=CPT,OU=GVA,OU=ORG,DC=ad,DC=ilo,DC=org") 

#return codes from PowerShell to SCCM
#http://serverfault.com/questions/716760/how-to-get-sccm-to-recognize-return-codes-from-powershell-script-completion

#list all Distribution Point Groups
gwmi @SCCM_Site -Query 'select * from sms_distributionpointgroup'

#list all packages distributed to DP Groups 
gwmi @SCCM_Site -Query 'select dpgci.*,dpg.name from sms_dpgroupcontentinfo as dpgci join sms_distributionpointgroup as dpg on dpg.groupid=dpgci.groupid' | Select @{n='PackageID';e={$_.dpgci.PackageID}},@{n='Package';e={$_.dpgci.Name}}, @{n='DP Group';e={$_.dpg.Name}}


#remove application content from ALL distribution points and groups, but ensure first it doesn't have any dependency
$app='Adobe Creative Cloud Desktop'
$DTs = [Microsoft.configurationmanagement.applicationmanagement.serialization.sccmserializer]::DeserializeFromString((Get-CMApplication $app).SDMPackageXML,$true).DeploymentTypes
if($DTs.Dependencies.Count -eq 0 -And $DTs.Supersedes -eq $null){
	Get-CMDistributionPoint | ?{ Get-CMDeploymentPackage -DistributionPointName $($_.NetworkOSPath.Trim('\')) -DeploymentPackageName $app } |
		%{Write-Host -NoNewline $_.NetworkOSPath; try{ Remove-CMContentDistribution -ApplicationName $app -DistributionPointName $($_.NetworkOSPath.Trim('\')) -Force -EA Stop; " ....success"}catch{" ....failed"}}
} else {throw "$app : remove any dependencies/supercedence first"}

#remove application content from distribution points and groups, except GVA-*
$app='Dell Command | Update'
Get-CMDistributionPoint | ? NetworkOSPath -notlike '\\GVA-*' | ?{ Get-CMDeploymentPackage -DistributionPointName $($_.NetworkOSPath.Trim('\')) -DeploymentPackageName $app } |
 %{Write-Host -NoNewline $_.NetworkOSPath; try{ Remove-CMContentDistribution -ApplicationName $app -DistributionPointName $($_.NetworkOSPath.Trim('\')) -Force -EA Stop; " ....success"}catch{" ....failed"}}

#remove driver package content from distribution points and groups
"Drivers Pack Latitude E7270 A12" |
  %{ "$(($PkgId=(Get-CMDriverPackage -Name $_ -Fast).PackageID)) $_"; Get-CMDistributionPoint | ? NetworkOSPath -notlike '\\GVA-MGT-04*' | 
   %{ ($dp=$_.NetworkOSPath.Trim('\')); Invoke-Command -ComputerName $dp -ScriptBlock {param([parameter(Mandatory)]$PkgId)
          gwmi -Namespace root\sccmdp -Class SMS_PackagesInContLib -Filter "PackageId='$PkgId'" | Remove-WmiObject -Verbose;
          dir "$((Get-ItemProperty HKLM:SOFTWARE\Microsoft\SMS\DP).ContentLibraryPath)\pkglib" -Filter "$PkgId.INI*" | Remove-Item -Verbose} -Arg $PkgId}}

#remove package content from distribution points and groups
"package name" | 
%{ $app=$_; Get-CMDistributionPoint |
 %{ if($dp = Get-CMDeploymentPackage -DistributionPointName $($_.NetworkOSPath.Trim('\')) -DeploymentPackageName $app){
     Write-Host -NoNewline $_.NetworkOSPath; try{ Remove-CMContentDistribution -PackageId $dp.PackageID -DistributionPointName $($_.NetworkOSPath.Trim('\')) -Force -EA Stop; " ....success"}catch{" ....failed"} } } }

#remove operatingsystem image content from distribution points and groups
"Win_10_1909 en-uk" | 
%{ $app=$_; Get-CMDistributionPoint |
 %{ if($dp = Get-CMDeploymentPackage -DistributionPointName $($_.NetworkOSPath.Trim('\')) -DeploymentPackageName $app){
     Write-Host -NoNewline $_.NetworkOSPath; try{ Remove-CMContentDistribution -OperatingSystemImageId $dp.PackageID -DistributionPointName $($_.NetworkOSPath.Trim('\')) -Force -EA Stop; " ....success"}catch{" ....failed"} } } }

#remove operatingsystem upgrade image content from distribution points and groups
"Win_10_1909 en-uk" | 
%{ $app=$_; Get-CMDistributionPoint |
 %{ if($dp = Get-CMDeploymentPackage -DistributionPointName $($_.NetworkOSPath.Trim('\')) -DeploymentPackageName $app){
     Write-Host -NoNewline $_.NetworkOSPath; try{ Remove-CMContentDistribution -OperatingSystemInstallerId $dp.PackageID -DistributionPointName $($_.NetworkOSPath.Trim('\')) -Force -EA Stop; " ....success"}catch{" ....failed"} } } }

#remove boot image image content from distribution points and groups
"MDT Boot Image x86", "Boot Win10 1809", "Boot Win10 1809 ver 2019-10" | 
%{ $app=$_; Get-CMDistributionPoint |
 %{ if($dp = Get-CMDeploymentPackage -DistributionPointName $($_.NetworkOSPath.Trim('\')) -DeploymentPackageName $app){
     Write-Host -NoNewline $_.NetworkOSPath; try{ Remove-CMContentDistribution -BootImageId $dp.PackageID -DistributionPointName $($_.NetworkOSPath.Trim('\')) -Force -EA Stop; " ....success"}catch{" ....failed"} } } }

#Delete all old revisions of the app, except the latest one
Get-CMApplication -ModelName 'ScopeId_C001D0D1-74EB-46BE-B736-3667F92D22B8/Application_34e9dfcc-24e3-418f-bafe-f22438c5d50a' 
$app='Dell Command | Update'
Get-CMApplication $app | Get-CMApplicationRevisionHistory | ? isLatest -eq $False | Remove-CMApplicationRevisionHistory -Force

#remove all expired apps from distribution points and groups	
$Expired = Get-CMApplication | ? IsExpired | select LocalizedDisplayName,PackageId
Get-CMDistributionPoint | %{ $dp=$_.NetworkOSPath.Trim('\'); Get-CMDeploymentPackage -DistributionPointName $dp | ?{$Expired.PackageId.Contains($_.PackageId)} | %{Write-Host -NoNewline "$dp : removing $($_.Name)"; try{ Remove-CMContentDistribution -ApplicationName $_.Name -DistributionPointName $dp -Force -EA Stop; " ....success"}catch{" ....failed"} } }

#Enable "Allow Clients To Use Fallback Source Location For Content" for all active apps
#build 1189 of cmdlet library recommends using Add/Set-TechnologyNameDeploymentType instead of Set-CMDeploymentType
#Get-CMApplication | Get-CMDeploymentType | Set-CMDeploymentType -MsiOrScriptInstaller -AllowClientsToUseFallbackSourceLocationForContent $true -Verbose
Get-CMApplication | ? IsExpired -eq $false | Get-CMDeploymentType | %{ $_ | & "Set-CM$($_.Technology)DeploymentType" -ContentFallback $true -Verbose }
Get-CMApplication | ? IsExpired -eq $false | Get-CMDeploymentType | %{ $_ | & "Set-CM$($_.Technology)DeploymentType" -SlowNetworkDeploymentMode Download -Verbose }

#Enable "Download from neighbor boundary group" for those deployment types that don't have it
Get-CMApplication | ? IsExpired -eq $false | Get-CMDeploymentType | ? IsExpired -eq $false |%{ 
	if($_.SDMPackageXML -ne ''){
		foreach ($dtxml in [Microsoft.ConfigurationManagement.ApplicationManagement.Serialization.SccmSerializer]::Deserialize($_.SDMPackageXML, $true).DeploymentTypes){
			$dtxml.Application.Title
			"`tDeployment type: $($dtxml.Title)"
			$OnSlowNetwork = $dtxml.Installer.Contents.OnSlowNetwork
			if($OnSlowNetwork -ne 'Download') {
				"`tOnSlowNetwork = $OnSlowNetwork"
				"`t...changing to Download"
				$_ | & "Set-CM$($_.Technology)DeploymentType" -SlowNetworkDeploymentMode Download 
			}
		}
	}
}
#Get the status of "Allow Clients To Use Fallback Source Location For Content" attribute
Get-CMApplication | %{ 
	$app = $_
	$appxml = [Microsoft.ConfigurationManagement.ApplicationManagement.Serialization.SccmSerializer]::Deserialize($app.SDMPackageXML, $true)
	$appxml.DeploymentTypes | %{
		[PSCustomObject] @{
			"SCCM Name" = $appxml.Title;
			"Catalog Name" = $appxml.DisplayInfo.Title;
			Retired = $app.IsExpired;
			"DT Name" = $_.Title;
			DeploymentTechnology = $_.Installer.Technology;
			RequiresLogOn = $_.Installer.RequiresLogOn
			Location = $_.Installer.Contents.Content.Location;
			AllowFallback = $_.Installer.Contents.FallbackToUnprotectedDP 
		}
	} } | Sort "SCCM Name"

#or simply
([xml]$app.SDMPackageXML).AppMgmtDigest.DeploymentType.Installer.Contents.Content.FallbackToUnprotectedDP
(Get-CMApplication|? IsExpired -eq $false).SDMPackageXML | %{([xml]$_).AppMgmtDigest.DeploymentType.Installer.Contents.Content.Location}

#get deployments of Software Update Groups that are not allowed to be downloaded from neighbor boundary groups
Get-CMSoftwareUpdateDeployment | ? Enabled | ? StartTime -gt 1/1/2018 | %{ if(-not( $_.DPLocality -band [math]::Pow(2,6) )){$_.AssignmentName; [convert]::ToString($_.DPLocality,2); ''} }
#get deployments of Software Update Groups that are not allowed to be downloaded from the Internet
Get-CMSoftwareUpdateDeployment | ? Enabled | ? StartTime -gt 1/1/2018 | %{ if(-not( $_.DPLocality -band [math]::Pow(2,18) )){$_.AssignmentName; [convert]::ToString($_.DPLocality,2); ''} }

#set the filter to get all user categories
$filter = "CategoryTypeName = 'CatalogCategories'"
#set the filter to get a specific user category
$filter = "CategoryTypeName = 'CatalogCategories' and LocalizedCategoryInstanceName = 'Admin Tools'"
#set the filter to get catalog categories of specific app
[XML]$SDMPackageXML=Get-CMApplication -name "ldap browser" | select SDMPackageXML -expandproperty SDMPackageXML
$filter = "CategoryTypeName = 'CatalogCategories' and CategoryInstance_UniqueID = '$($SDMPackageXML.AppMgmtDigest.Application.DisplayInfo.Info.UserCategories.Tag)'"
Get-WmiObject -query "select * from SMS_CategoryInstance where $filter" -ComputerName gva-mgt-04.ad.ilo.org -Namespace 'Root\SMS\Site_ILO'
#get catalog categories for all active apps
$allCat = Get-WmiObject -query "select * from SMS_CategoryInstance where CategoryTypeName = 'CatalogCategories'" -ComputerName gva-mgt-04.ad.ilo.org -Namespace 'Root\SMS\Site_ILO'
$app = Get-CMApplication | ? IsExpired -eq $false | %{ 
	[xml]$appxml = $_.SDMPackageXML
	[string[]]$UserCategories = @()
	$UserCategories += $allCat.Where({ $appxml.AppMgmtDigest.Application.DisplayInfo.Info.UserCategories.Tag -contains $_.CategoryInstance_UniqueID }).LocalizedCategoryInstanceName
	[PSCustomObject] @{
		ModelName = $_.ModelName;
		Name = $appxml.AppMgmtDigest.Application.Title.'#text';
		CatalogName = $appxml.AppMgmtDigest.Application.DisplayInfo.Info.Title;
		FolderPath = Get-ObjectLocation $_.ModelName;
		UserCategory1 = $UserCategories[0];
		UserCategory2 = $UserCategories[1];
	}
}
#refresh Catalog to display renamed categories by overwriting the UserCategory parameter with its current value
Get-CMApplication | ? IsExpired -eq $false | %{ 
	[xml]$appxml = $_.SDMPackageXML
	$Name = $appxml.AppMgmtDigest.Application.Title.'#text';
	$CatalogName = $appxml.AppMgmtDigest.Application.DisplayInfo.Info.Title;
	[string[]]$UserCat = $allCat.Where({ $appxml.AppMgmtDigest.Application.DisplayInfo.Info.UserCategories.Tag -contains $_.CategoryInstance_UniqueID }).LocalizedCategoryInstanceName;
	if($UserCat -like 'Dept -*'){ #this works even if UserCat is an array of strings
		Set-CMApplication $_ -UserCategory $UserCat 
		Write-Host "Updated $Name *** $CatalogName"
	}
}

#retire an app without removing distributed content
(Get-Wmiobject -ComputerName gva-mgt-01.ad.ilo.org -Namespace "root\SMS\site_ILO" -Class SMS_ApplicationLatest -Filter "LocalizedDisplayName='IE11-Windows6.1-KB3104002-x64'").SetIsExpired($true)

#get IDs of deployment types for all apps (useful for troubleshooting the logs)
Get-CMApplication | %{ 
	$dt = $_ | Get-CMDeploymentType
	$dep = $dt | Get-CMDeploymentTypeDependencyGroup | Get-CMDeploymentTypeDependency
	$sup = $dt | Get-CMDeploymentTypeSupersedence
	$Scope = 'ScopeId_C001D0D1-74EB-46BE-B736-3667F92D22B8/'
    [pscustomobject] @{
		App_LocalizedDisplayName=$_.LocalizedDisplayName
		App_CI_ID = $_.CI_ID
		IsEnabled = $_.IsEnabled
		IsLatest = $_.IsLatest
		IsExpired = $_.IsExpired
		App_CI_UniqueID=$_.CI_UniqueID.Replace($Scope,'')
		App_ModelName=$_.ModelName.Replace($Scope,'')
		App_PackageID=$_.PackageID
		DT_CI_UniqueID = $dt.CI_UniqueID.Replace($Scope,'')
		DT_LocalizedDisplayName = $dt.LocalizedDisplayName
		DT_ModelName = $dt.ModelName
		DT_ContentId = $dt.ContentId
		DependencyNames = $dep | Select -ExpandProperty LocalizedDisplayName
		DependencyModels= $dep | Select -ExpandProperty ModelName | %{$_.Replace($Scope,'')}
		SupercedenceNames = $sup | Select -ExpandProperty LocalizedDisplayName
		SupercedenceModels= $sup | Select -ExpandProperty ModelName | %{$_.Replace($Scope,'')}
	} } | Convert-OutputForCSV | Export-Csv -NoTypeInformation "c:\temp\sccm\apps+dt $(get-date -f filedatetime).csv"

#get IDs of deployment types for a specific app
Get-CMApplication 'app'| %{ $dt = $_ | Get-CMDeploymentType; "App_CI_UniqueID = $($_.CI_UniqueID)`nApp_PackageID = $($_.PackageID)`nDT_CI_UniqueID = $($dt.CI_UniqueID)`nDT_ContentId = $($dt.ContentId)" }

#set application admins
$apps = Import-Csv C:\Temp\apps.csv
Get-CMApplication | %{ 
	$appid = $_.PackageID
	$admins =  $apps | ? pid -eq $appid
	if($admins) { 
		"$appid $($us.($admins.pri)) $($us.($admins.back))"
		Set-CMApplication $_ -Owner $us.($admins.pri) -SupportContact $us.($admins.back)
	}
}

Set-ExecutionPolicy Bypass -Scope Process -Force
#import standard functions
(dir -Path filesystem::"\\ad.ilo.org\configmgr\CONTENT\SOURCES\Applications\ILO\PSModules\SCCM" -File).FullName.ForEach({. $_})
Import-Module ImportExcel
#usersupport colleagues
$us = @{ AP='a-paladi'; CT='a-tournier'; RBS='a-soares'; WZ='a-wei'; YH='a-humeau'; FD='a-dadaglio'; CB='a-bouchet'; SH='a-hagopian'; AD='a-dubois'; SW='a-walch'; TG='a-grange'; LC='a-caprini'; FO='a-ortais'}

#generate application admin report at C:\Temp\apps_excel.xlsx
$apps =  Get-Wmiobject @SCCM_Site -Class SMS_ApplicationLatest -Filter "isExpired='false'" -Property CI_ID | %{ 
	Get-CMApplication -id $_.CI_ID | %{ 
		[xml]$appxml = $_.SDMPackageXML
		Write-Host $appxml.AppMgmtDigest.Application.Title.'#text'
		$p = $appxml.AppMgmtDigest.Application.Publisher.'#text'
		$pri = $appxml.AppMgmtDigest.Application.Owners.User.Id
		$back = $appxml.AppMgmtDigest.Application.Contacts.User.id
		[PSCustomObject] @{
			#PackageID = $_.PackageID
			Name = $appxml.AppMgmtDigest.Application.Title.'#text'
			#CatalogName = $appxml.AppMgmtDigest.Application.DisplayInfo.Info.Title
			'PrimaryAdmin' = $(if($pri -in $us.Values){$pri})
			'BackupAdmin' = $(if($back -in $us.Values){$back})
			Publisher = if($p -like 'ilo*' -or $p -eq 'infotec'){'Internal'}elseif($p){'External'}else{''}
			Version = $_.SoftwareVersion
			'OSD' = $appxml.AppMgmtDigest.Application.AutoInstall
			#EOL = $_.IsExpired
			AdminComments = $appxml.AppMgmtDigest.Application.Description.'#text'
			FolderPath = (Get-ObjectLocation -InstanceKey $_.ModelName -SCCMSite $SCCM_Site).TrimStart('Root\')
		}
	}
}
$file = "filesystem::C:\Temp\apps_$(get-date -f yyyy-MM-dd@HHMM).xlsx"; rm $file -ea SilentlyContinue
$xls = $apps | Export-Excel $file -WorkSheetname AppsSheet -TableName Apps -FreezeTopRow -NoNumberConversion '*' -AutoNameRange -PassThru
$ws = $xls.Workbook.Worksheets['AppsSheet']
$ws.Cells.Style.VerticalAlignment = [OfficeOpenXml.Style.ExcelVerticalAlignment]::Top
$ws.Names['Primary Admin','Backup Admin','Publisher','Version','OSD'].ForEach({$_.Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center})
$ws.Names['Name','PrimaryAdmin','BackupAdmin','Publisher','Version','OSD','FolderPath'].AutoFitColumns()
$ws.Names['AdminComments'].Style.Font.Name = 'Arial Narrow'
$ws.Names['AdminComments'].Style.Font.Size = 9
$ws.Names['Name','AdminComments'].AutoFitColumns(10,50)
$ws.Names.Name | %{$ws.Names.Remove($_)}
Export-Excel -ExcelPackage $xls -show

#retire all apps from folder recursively
Get-CMApplication | %{ 
	$FolderPath = (Get-ObjectLocation $_.ModelName) -replace('^Root\\')
	If( $FolderPath -imatch '^Secure Remote Desktop Deployments' ) {
		[xml]$appxml = $_.SDMPackageXML
		"$FolderPath\$($appxml.AppMgmtDigest.Application.Title.'#text')"
		Retire-CMApplication $_
	}
}

#monitor app deployment with PowerShell
gc -Tail 20 C:\Windows\CCM\Logs\AppEnforce.log -Wait
gc -Tail 20 C:\Windows\CCM\Logs\AppDiscovery.log -Wait

#get members of device collection
Get-CMDevice -CollectionName 'APP-PPD-WKS-D-PreProd_Testers'
(Get-CMDevice -CollectionName 'ADM-PRD-GBL-Q-QA-WINDOWS-PATCHING').Name | Get-ADComputer

#sync/add device collection to AD computer group
Add-ADGroupMember SUP-WKS-W10-RING-01 -Members ((Get-CMDevice -CollectionName SUP-WKS-W10-RING-01).Name|Get-ADComputer -ea 0)

#add AD computers to Device Collection
$time = [DateTime]::Now.AddMonths(-3);
Get-ADComputer -SearchBase "OU=ORG,DC=AD,DC=ilo,DC=org" -fi 'enabled -eq $true -and (LastLogonTimeStamp -gt $time -or pwdLastSet -gt $time) -And operatingsystemversion -like "*17763*" -And OperatingSystem -like "Windows 10*"'| %{ Add-CMDeviceCollectionDirectMembershipRule -CollectionName OSD-WKS-WIN10-1809-ALL -Resource (Get-CMDevice -Name $_.Name) }

#add members of AD (distribution AND security) groups to one SCCM user collection 
$users = 'ALL_IT_FOCAL_POINT_FIELD','TMS-USER-SUPPORT','TMS-INFRA-SUPPORT' | Get-ADGroupMember | Get-ADUser | ? Enabled | Select -Exp SamAccountName
$users = 'GVA-FS-INFOTEC-TMS' | Get-ADGroupMember | Get-ADUser | ? Enabled | Select -Exp SamAccountName
$users = Get-ADUser -Filter {enabled -eq $true -AND department -eq 'TMS' -AND mail -like '*' } | ? Enabled | Select -Exp SamAccountName
$users += "marshallp"
foreach ($user in $users){$user; Add-CMUserCollectionDirectMembershipRule -CollectionName 'APP-PRD-G-Q-ENTVAULT-PILOT' -ResourceID (Get-CMUser -Name "ilo\$user").ResourceID }

#trigger update of machine policy
#https://blogs.technet.microsoft.com/charlesa_us/2015/03/07/triggering-configmgr-client-actions-with-wmic-without-pesky-right-click-tools/
#https://docs.microsoft.com/en-us/sccm/develop/reference/core/clients/client-classes/triggerschedule-method-in-class-sms_client
Invoke-WmiMethod -Namespace "Root\CCM" -Class SMS_Client -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000021}" #Machine Policy Request
Invoke-WmiMethod -Namespace "Root\CCM" -Class SMS_Client -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000022}" #Machine Policy Evaluation
Invoke-WmiMethod -Namespace "Root\CCM" -Class SMS_Client -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000121}" #Application manager policy action
$smsClient = [wmiclass]"\\.\root\ccm:sms_client"
$smsClient.RequestMachinePolicy()
$smsClient.EvaluateMachinePolicy()
(gwmi -Namespace "root\ccm" -Class sms_client -List).EvaluateMachinePolicy()

$sms = @{Namespace = 'ROOT\ccm'; Class = 'SMS_CLIENT'}; (Get-CimClass @sms).CimClassMethods
Invoke-CimMethod @sms -Name RequestMachinePolicy
Invoke-CimMethod @sms -Name EvaluateMachinePolicy
Invoke-CimMethod @sms -Name TriggerSchedule -Arguments @{sScheduleID = "{00000000-0000-0000-0000-000000000121}"}

$ComplianceHash = [hashtable]@{"0" = 'Non-Compliant'; "1" = 'Compliant'; "2" = 'Submitted'; "3" = 'Unknown'; "4" = 'Detecting'; "5" = 'Not Evaluated';}  
$EvalHash = [hashtable]@{"0" = 'Idle'; "1" = 'Evaluated'; "5" = 'Not Evaluated';} 
$dcm = @{Namespace = 'root\ccm\dcm'; Class = 'SMS_DesiredConfiguration'}
#list compliance status for all baselines
Get-CimInstance @dcm | Select DisplayName, LastComplianceStatus, LastEvalTime, Status, Version | ft -auto
#trigger unevaluated machine baselines 
Get-CimInstance @dcm | %{ if($_.IsMachineTarget -and $_.LastComplianceStatus -ne 1){$_.DisplayName; Invoke-CimMethod @dcm -Name TriggerEvaluation -Arguments @{Name = $_.Name; Version = $_.Version; IsEnforced = $true; IsMachineTarget = $true}}}
#trigger specific machine baseline
$dcm = @{Namespace = 'root\ccm\dcm'; Class = 'SMS_DesiredConfiguration'}
Get-CimInstance @dcm | Select DisplayName, LastComplianceStatus
Get-CimInstance @dcm | ? DisplayName -eq 'Baseline System Settings' | %{Invoke-CimMethod @dcm -Name TriggerEvaluation -Arguments @{Name = $_.Name; Version = $_.Version; IsEnforced = $true; IsMachineTarget = $true}}
#trigger all machine baselines
$dcm = @{Namespace = 'root\ccm\dcm'; Class = 'SMS_DesiredConfiguration'}
Get-CimInstance @dcm | %{ if($_.IsMachineTarget){$_.DisplayName; Invoke-CimMethod @dcm -Name TriggerEvaluation -Arguments @{Name = $_.Name; Version = $_.Version; IsEnforced = $true; IsMachineTarget = $true}}}
#trigger specific machine-only baseline
Get-CimInstance @dcm | %{ if($_.displayname -eq 'Baseline PowerShell'){$_.DisplayName; Invoke-CimMethod @dcm -Name TriggerEvaluation -Arguments @{Name = $_.Name; Version = $_.Version; IsEnforced = $true; IsMachineTarget = $true}}}
#run as logged on user, trigger any baseline
Register-ScheduledTask -TaskName RunOnce -Force -Action (
    New-ScheduledTaskAction -Execute 'powershell.exe' -Arg '-Com $dcm=@{Namespace = "root\ccm\dcm"; Class = "SMS_DesiredConfiguration"}; Get-CimInstance @dcm | %{ if($_.displayname -eq "Baseline PowerShell"){Invoke-CimMethod @dcm -Name TriggerEvaluation -Arguments @{Name = $_.Name; Version = $_.Version; IsEnforced = $true}}}') `
    -Principal (New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545') -Settings (New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -MultipleInstances Parallel -DontStopIfGoingOnBatteries) | Start-ScheduledTask

Register-ScheduledTask -TaskName RunOnce -Force -Action (
    New-ScheduledTaskAction -Execute 'powershell.exe' -Arg '-Com $dcm=@{Namespace = "root\ccm\dcm"; Class = "SMS_DesiredConfiguration"}; Get-CimInstance @dcm | %{ if(-NOT $_.IsMachineTarget){Invoke-CimMethod @dcm -Name TriggerEvaluation -Arguments @{Name = $_.Name; Version = $_.Version; IsEnforced = $true}}}') `
    -Principal (New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545') -Settings (New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -MultipleInstances Parallel -DontStopIfGoingOnBatteries) | Start-ScheduledTask

#check state of Package / TS deployments
Get-WmiObject -namespace root\ccm\clientsdk -class ccm_program | select fullname,evaluationstate

#two ways to query SCCM using WMI
Get-WmiObject @SCCM_Site -Query "select Name from sms_r_system where LastLogonUserName='paladi'" | Select Name
Get-WmiObject @SCCM_Site -Class sms_r_system -Filter "LastLogonUserName='paladi'" | Select Name

$query = @"
select * from SMS_R_System 
inner join SMS_G_System_SYSTEM_CONSOLE_USAGE on SMS_G_System_SYSTEM_CONSOLE_USAGE.ResourceID = SMS_R_System.ResourceId 
where UPPER(SMS_G_System_SYSTEM_CONSOLE_USAGE.TopConsoleUser) in (SELECT SMS_R_USER.UniqueUserName from SMS_R_User where SMS_R_User.UserGroupName = "ILO\\GBL-AP-QA-TMS-USER-SUPPORT")
"@
$Results = Get-WmiObject @SCCM_Site -Query $query
$Results.SMS_R_System.Name | Get-ADComputer

#get applications that depend on the specified app
$app = 'Visual C++ 2010 Redistributable x64'
Get-WmiObject @SCCM_Site -Query "Select SMS_Application.* from SMS_Application Inner Join SMS_AppDependenceRelation On FromApplicationCIID=SMS_Application.CI_ID Inner Join SMS_ApplicationLatest On ToApplicationCIID=SMS_ApplicationLatest.CI_ID Where SMS_ApplicationLatest.LocalizedDisplayName='$app'" | select LocalizedDisplayName, IsLatest, CIVersion
#cleanup dependent apps from the revision history
Get-WmiObject @SCCM_Site -Query "Select SMS_Application.* from SMS_Application Inner Join SMS_AppDependenceRelation On FromApplicationCIID=SMS_Application.CI_ID Inner Join SMS_ApplicationLatest On ToApplicationCIID=SMS_ApplicationLatest.CI_ID Where SMS_ApplicationLatest.LocalizedDisplayName='$app'" | ? IsLatest -eq $False | %{ Remove-CMApplicationRevisionHistory -Name $_.LocalizedDisplayName -Revision $_.CIVersion }

#get the application deployment statistics
$sqlquery = @"
select parentapp.displayname [Application Name],
parentapp.CreatedBy [Created By],
case when parentapp.IsEnabled='1' then 'Yes' else 'No' end as IsEnabled,
case when parentapp.IsDeployed='1' then 'Yes' else 'No' end as IsDeployed,
parentapp.NumberOfDeploymentTypes [No of DT],
parentapp.NumberOfDeployments [No of Deployments],
count(distinct ChildApp.DisplayName)  AS [No of Dependencies],
parentapp.NumberOfDevicesWithApp,
parentapp.NumberOfDevicesWithFailure
From fn_ListApplicationCIs(1033) ParentApp
	Left Join fn_ListDeploymentTypeCIs(1033) ParentApp_DT ON ParentApp_DT.AppModelName = ParentApp.ModelName
	Left Join vSMS_AppRelation_Flat R on R.FromApplicationCIID = ParentApp.CI_ID
	Left Join fn_ListApplicationCIs_List(1033) ChildApp on ChildApp.CI_ID = R.ToApplicationCIID And ChildApp.IsLatest = 1
where 
parentapp.IsLatest='1'
group by parentapp.DisplayName,parentapp.CreatedBy,parentapp.NumberOfDeploymentTypes,parentapp.NumberOfDeployments,
parentapp.NumberOfDevicesWithApp,
parentapp.NumberOfDevicesWithFailure,
parentapp.IsEnabled,
parentapp.IsDeployed
"@
$sqlConnection = new-object System.Data.SqlClient.SqlConnection "server=$($SCCM_Site.ComputerName);database=CM_ILO;integrated security=true"
$results = new-object system.data.datatable; (new-object data.sqlclient.sqldataadapter($sqlquery, $sqlConnection)).fill($results)

#trigger heartbeat
([WmiClass]"\\localhost\ROOT\ccm:SMS_Client").triggerschedule("{00000000-0000-0000-0000-000000000003}")
#trigger hw inventory
([WmiClass]"\\localhost\ROOT\ccm:SMS_Client").triggerschedule("{00000000-0000-0000-0000-000000000001}")
#check client is started up
([WmiClass]"\\localhost\ROOT\ccm:SMS_Client").getassignedsite()
#using CIM
Invoke-CimMethod -Namespace ROOT\ccm -Class SMS_CLIENT -Name RequestMachinePolicy
Invoke-CimMethod -Namespace ROOT\ccm -Class SMS_CLIENT -Name EvaluateMachinePolicy
Invoke-CimMethod -Namespace ROOT\ccm -Class SMS_CLIENT -Name TriggerSchedule -Arguments @{sScheduleID = '{00000000-0000-0000-0000-000000000121}'}

#list the methods of SMS_Client class
(Get-CimClass -Namespace ROOT\ccm -Class SMS_CLIENT).CimClassMethods


#RESET SCCM CLIENT POLICY
#WMIC /Namespace:\\root\ccm path SMS_Client CALL ResetPolicy 1 /NOINTERACTIVE
$returnvalue = ([wmiclass]"\\.\root\ccm:SMS_Client").ResetPolicy(1)
if ($returnvalue.Returnvalue) {
  Write-Warning "Error occurred while resetting the policy"
} else {
  Write-Host "Reset successful"
}

#listing content on DP
Get-WmiObject -Class "SMS_DPContentInfo" -Filter "NALPath LIKE '%GVA-MGT-04.ad.ilo.org%'" @SCCM_Site

#create a hash table that associates each driver ID with an array of their DriverPackageID
$DrvInPackages = @{}
Foreach ($Pkg in Get-CMDriverPackage){
    Foreach ($driver in (Get-CMDriver -DriverPackageId $Pkg.PackageID)){
        $DrvInPackages.($driver.CI_ID) += @($Pkg.PackageID)
    }
}
$DrvInPackages.Count

#get all orphaned drivers (without an associated package)
$orphaned = Compare-Object -ReferenceObject (Get-CMDriver).CI_ID -DifferenceObject $DrvInPackages.GetEnumerator().Name | Select -Exp InputObject
#list their names
$orphaned | %{ Get-CMDriver -CIId $_ } | Select -Exp LocalizedDisplayName
#delete them
$orphaned | %{ (Get-CMDriver -CIId $_).LocalizedDisplayName; Remove-CMDriver -Id $_ -Force}

#remove all drivers from a Package (will not delete them)
$PkgID = (Get-CMDriverPackage -Name 'Drivers Pack Optiplex 5040').PackageID
Get-CMDriver -DriverPackageId $PkgID | %{ Remove-CMDriverFromDriverPackage -DriverId $_.CI_ID -DriverPackageId $PkgID -Force -EA 0 }

#Execute a task sequence deployed to a device
$softwareCenter = New-Object -ComObject "UIResource.UIResourceMgr"
$taskSequence = $softwareCenter.GetAvailableApplications() | Where { $_.PackageName -eq "$Name" }
$softwareCenter.ExecuteProgram($taskSequence.PackageID,$taskSequence.ID,$true)
#get cache size
$softwareCenter.GetCacheInfo()

#find out if there's a pending reboot
Invoke-CimMethod -Namespace ROOT\ccm\ClientSDK -ClassName CCM_ClientUtilities -MethodName DetermineIfRebootPending

#find and open the remote pxe log
([char]'d')..([char]'z')|%{$p="\\abj-fil-01\$([char]$_)$\SMS_DP$\sms\logs\SMSPXE.log";if(test-path $p){C:\Windows\CCM\CMTrace.exe $p}}
#check if sccmpxe is listening
netstat -abn | sls sccmpxe -Context 1,0

#capture pxe packets
pktmon stop
pktmon filter list
pktmon filter remove
pktmon filter add UDP -p 67
pktmon filter add UDP -p 69
pktmon filter add UDP -p 4011
pktmon start --capture -m real-time

#manually creating Device for OSD in SCCM:
# 1. Import Computer Info with correct MAC address to create the device object, which will have a single agent called "Manual Machine Entry"
# 2. Update membership of "All Desktops" collection, wait until the new device is actually member
# 3. Update membership of ADM-PRD-GBL-Q-OSD-ALL-Devices, wait until the new device is actually member
# 4. Boot the Computer from PXE or the Boot image ISO, all Task Sequences should now be visible
#potential problems:	
# If device was created, booted, but for some reason never completed the image (eg memberships not updated so TS not visible) - it will disappear from the "All Desktops" collection.
# This is because on first contact SCCM updates the device object with an additional agent: "Heartbeat Discovery" which excludes it from "All Desktops" automatically (see the rules).
# It will still be member of "All Systems", but can only be deleted by an SCCM Administrator. If you delete it but just change the MAC - it will not work, SCCM uses the BIOS GUID.
# To fix this, "All Devices" membership rules must be changed: https://docs.microsoft.com/en-us/archive/blogs/cmpfekevin/import-computer-does-not-show-up-in-collection

#During an OS deployment task sequence, Configuration Manager places the client in provisioning mode. (An OS deployment task sequence includes in-place upgrade to Windows 10.) In this state, the client doesn't process policy from the site. This behavior allows the task sequence to run without risk of additional deployments running on the client. When the task sequence completes, either success or handled failure, it exits client provisioning mode.
#return the client to normal operation
Invoke-WmiMethod -Namespace root\CCM -Class SMS_Client -Name SetClientProvisioningMode -ArgumentList $false

#get application details for the specific Content ID
$sqlquery = @"
	declare @ContentID varchar (100) = 'Content_7d4ce51d-f497-46db-835b-7973b8cfcb2c'
	select * from v_Package where PackageID = (select PkgID from v_Content where Content_UniqueID = @ContentID)
"@
$sqlConnection = new-object System.Data.SqlClient.SqlConnection "server=$($SCCM_Site.ComputerName);database=CM_ILO;integrated security=true"
$results = new-object system.data.datatable; (new-object data.sqlclient.sqldataadapter($sqlquery, $sqlConnection)).fill($results)

#get all known logons
$sqlquery = @"
	SELECT dbo.v_HS_SYSTEM_CONSOLE_USER.TimeStamp, dbo.v_HS_SYSTEM_CONSOLE_USER.SystemConsoleUser0, dbo.v_R_System.Name0
	FROM dbo.v_R_System INNER JOIN dbo.v_HS_SYSTEM_CONSOLE_USER ON dbo.v_R_System.ResourceID = dbo.v_HS_SYSTEM_CONSOLE_USER.ResourceID
"@
$sqlConnection = new-object System.Data.SqlClient.SqlConnection "server=$($SCCM_Site.ComputerName);database=CM_ILO;integrated security=true"
$results = new-object system.data.datatable; (new-object data.sqlclient.sqldataadapter($sqlquery, $sqlConnection)).fill($results)
$results | Export-Csv -NoTypeInformation 'c:\temp\2020-06-24 logons.csv'

#downloading Third Party updates for further deployment https://docs.microsoft.com/en-us/mem/configmgr/sum/deploy-use/third-party-software-updates
#1. "All Software Updates" -> select the updates -> click "Publish Third Party Content"
#2. Monitoring -> Status Messages -> Component:SMS_ISVUPDATES_SYNC -> Successfully published content for...
#3. "All Software Updates" -> "Synchronize Software Updates" (or just wait overnight)
#4. Monitoring -> Status Messages -> Component:SMS_WSUS_SYNC_MANAGER -> WSUS Synchronization finished

#run a specific SCCM package program from the client, as user
([wmiclass]'ROOT\ccm\ClientSdk:CCM_ProgramsManager').ExecuteProgram("reboot system", "CM2000F3") | out-null
#run a specific SCCM task sequence from the client, as user
([wmiclass]'ROOT\ccm\ClientSdk:CCM_ProgramsManager').ExecuteProgram("*", "ILO00071") | out-null
#Use CIM
$CIMClass = (Get-CimClass -Namespace root\ccm\clientsdk -ClassName CCM_ProgramsManager)
$OSD = (Get-CimInstance -ClassName CCM_Program -Namespace 'root\ccm\clientSDK' | Where-Object {$_.Name -like "$OSDName"})
$Args = @{PackageID = $OSD.PackageID; ProgramID = $OSD.ProgramID}
Invoke-CimMethod -CimClass $CIMClass -MethodName 'ExecuteProgram' –Arguments $Args

#list all available programs, as admin
Get-WmiObject -Namespace "root\ccm\policy\machine\actualconfig" -Class "CCM_SoftwareDistribution"
#list all available programs and TS, as user
$SoftwareCenter = New-Object -ComObject "UIResource.UIResourceMgr"; $SoftwareCenter.GetAvailableApplications()

#trigger updates$CMMissingUpdates = @(Get-CimInstance -Query "SELECT * FROM CCM_SoftwareUpdate WHERE ComplianceState = '0'" -Namespace "ROOT\ccm\ClientSDK")
$CMMissingUpdates = @(Get-CimInstance -Query "SELECT * FROM CCM_SoftwareUpdate WHERE ComplianceState = '0'" -Namespace "ROOT\ccm\ClientSDK")
Invoke-CimMethod -Namespace 'ROOT\ccm\ClientSDK' -ClassName 'CCM_SoftwareUpdatesManager' -MethodName 'InstallUpdates' -Arguments @{ CCMUpdates = [ciminstance[]] $CMMissingUpdates }

#check all received policies
Get-CimInstance -ClassName ccm_policy_policy4  -Namespace 'Root\ccm\Policy\machine\RequestedConfig' | Select PolicyID, PolicyState, PolicyVersion, PolicyType, PolicyCategory

#clear pending advertisements or incomplete task sequences
Open WBEMTEST
Connect to Root\ccm
Query "Select * from sms_maintenancetaskrequests"
Remove/Delete all the entries that are displayed
restart CCMEXEC, now you should be able to rerun your advertisements..

Get-CimInstance -ClassName SMS_MaintenancetaskRequests -Namespace Root\CCM | Remove-CimInstance 
Get-CimInstance -ClassName CCM_TSExecutionRequest -Namespace Root\CCM\SoftMgmtAgent | Remove-CimInstance 
Restart-Service ccmexec

#determine if a reboot/restart is pending
([WmiClass]"\\.\ROOT\CCM\ClientSDK:CCM_ClientUtilities").DetermineIfRebootPending().RebootPending

#pause the task sequence in case of errors
SMSTSErrorDialogTimeout = 0
#run an action AFTER the TS has ended and SCCM is taken out of provisioning mode
SMSTSPostAction = gpupdate /force /boot & shutdown /r /t 10

#maintenance windows
#https://techcommunity.microsoft.com/t5/configuration-manager-archive/business-hours-vs-maintenance-windows-with-system-center-2012/ba-p/273032
#https://msdn.microsoft.com/en-us/library/jj155419.aspx
#https://msendpointmgr.com/2018/05/17/configmgr-1802-run-scripts-localadmins/
Get-CimInstance -Namespace root\ccm\clientsdk -ClassName CCM_ServiceWindow
	1	ALLPROGRAM_SERVICEWINDOW		All Deployment Service Window
	2	PROGRAM_SERVICEWINDOW			Program Service Window
	3	REBOOTREQUIRED_SERVICEWINDOW	Reboot Required Service Window
	4	SOFTWAREUPDATE_SERVICEWINDOW	Software Update Service Window
	5	OSD_SERVICEWINDOW				Task Sequences Service Window
	6	USER_DEFINED_SERVICE_WINDOW		Corresponds to non-working hours (effective only during the interval after deployment becomes Available AND before the Deadline)

#export the result of queries as CSV
& "\\ad.ilo.org\configmgr\CONTENT\SOURCES\Applications\ILO\PSModules\Export-CMQueryOutput.ps1"

#add devices to collection
Import-Csv C:\Temp\STATIC-LIST-SCCM.csv | ForEach-Object -Begin { if(!($col = Get-CMDeviceCollection -Name 'ADM-PRD-WKS-Q-ILO-McAfee Agent Current')){ $col = New-CMDeviceCollection -Name 'ADM-PRD-WKS-Q-ILO-McAfee Agent Current' -LimitingCollectionName 'All Desktops'}} -Process { Add-CMDeviceCollectionDirectMembershipRule -CollectionId $col.CollectionID -Resource (Get-CMDevice -Name $_.device)}

#load and test driver in WinPE
drvload xxxx.INF
sleep 10
wpeutil initializeNetwork

#continue the Task Sequence
x:\sms\bin\i386\TsmBootstrap.exe /env:WinPE /configpath:x:\sms\data

#copy drivers from one boot image to another
(Get-CMBootImage -Id $from).ReferencedDrivers | %{$boot = Get-CMBootImage -ID $to}{ 
	Write-Host "Copying $($_.Id) to $($to)"
	Set-CMDriver -Id $_.Id -AddBootImagePackage $boot -UpdateDistributionPointsforBootImagePackage $false 
    }

#copy drivers from a boot image to a driver package
(Get-CMBootImage -Id ILO0022F).ReferencedDrivers | %{$pkg = Get-CMDriverPackage -Id ILO00239 -Fast}{ 
	Write-Host "Copying $($_.Id) to $($to)"
	Set-CMDriver -Id $_.Id -AddDriverPackage $pkg -UpdateDriverDistributionPoint $false -EnableAndAllowInstall $true
    }

#compare drivers between two boot images
$b1 = (Get-CMBootImage -Id ilo001dd).ReferencedDrivers | %{$_|Add-Member Name (Get-CMDriver -id $_.id -fast | %{$_.LocalizedDisplayName + ' ' + $_.DriverVersion}) -PassThru} 
$b2 = (Get-CMBootImage -Id ilo00239).ReferencedDrivers | %{$_|Add-Member Name (Get-CMDriver -id $_.id -fast | %{$_.LocalizedDisplayName + ' ' + $_.DriverVersion}) -PassThru} 
Compare-Object $b1 $b2 -Property Name -PassThru | select id, name, sideindicator

#compare two driver packages
$b1 = Get-CMDriver -DriverPackageId ilo001dd -Fast | Select CI_ID, @{n='Name';e={$_.LocalizedDisplayName + ' ' + $_.DriverVersion}}
$b2 = Get-CMDriver -DriverPackageId ilo00239 -Fast | Select CI_ID, @{n='Name';e={$_.LocalizedDisplayName + ' ' + $_.DriverVersion}}
Compare-Object $b1 $b2 -Property Name -PassThru | select CI_ID, name, sideindicator

Compare-Object (Get-CMDriver -DriverPackageId ilo001dd -Fast) (Get-CMDriver -DriverPackageId ilo00239 -Fast) -Property LocalizedDisplayName,DriverVersion -IncludeEqual -PassThru | 
	select CI_ID, LocalizedDisplayName,DriverVersion, sideindicator

#Re-create Driver Package
$Name = 'Drivers Pack Autopilot 2021-06'; $Path="\\ad.ilo.org\configmgr\CONTENT\SOURCES\OSD\Drivers\$Name"; rmdir filesystem::$Path -recurse -force; mkdir filesystem::$Path; $dpkg = New-CMDriverPackage -Name $Name -Path $Path
#Get existing Driver Package
$Name = 'Drivers Pack Autopilot 2021-06'; $dpkg = Get-CMDriverPackage -Name $Name
#Get 2 latest versions of each network and storage drivers to import into a Driver Package
Get-CMDriver | ? driverClass -match 'Net|SCSIAdapter' | ? DriverDate -gt (Get-Date -year 2018) | Group LocalizedDisplayName | %{ $_.Group | sort {[version]$_.DriverVersion} -Descending -Unique | Select -f 2} |
	% -b{$dpkg_drv=Get-CMDriver -DriverPackageId $dpkg.PackageID}-p{$id=$_.CI_ID; if(-not($dpkg_drv | ? CI_ID -eq $id)){ $_.LocalizedDisplayName; Add-CMDriverToDriverPackage -DriverId $id -DriverPackage $dpkg}}

#delete drivers with missing content sources
Get-CMDriver -Fast | ? {-not(Test-Path filesystem::"$($_.ContentSourcePath)")} | %{$_.ContentSourcePath; Remove-CMDriver -id $_.ci_id -Force}

#copy unique drivers from one package to another
$SrcPkg = Get-CMDriverPackage -Name 'Drivers Pack WinPE A29' -Fast
$DstPkg = Get-CMDriverPackage -Name 'Drivers Pack WinPE A30' -Fast
$DstDrvIDs = (Get-CMDriver -InputObject $DstPkg -Fast).CI_ID
Get-CMDriver -InputObject $SrcPkg -Fast | 
	Group LocalizedDisplayName, DriverVersion, DriverINFFile, DriverDate | %{ $_.Group | Select -f 1} | 
	? {$DstDrvIDs -notcontains $_.CI_ID } | %{ $_.LocalizedDisplayName + ' ' + $_.DriverVersion; Add-CMDriverToDriverPackage -DriverId $_.CI_ID -DriverPackage $DstPkg } 

#add unique drivers of a specific category to a package
$SrcCat = Get-CMCategory -CategoryType DriverCategories -Name "WinPE A30"
$DstPkg = Get-CMDriverPackage -Name 'Drivers Pack WinPE A30' -Fast
$DstDrvIDs = (Get-CMDriver -InputObject $DstPkg -Fast).CI_ID
Get-CMDriver -AdministrativeCategory $SrcCat -Fast | 
	Group LocalizedDisplayName, DriverVersion, DriverINFFile, DriverDate | %{ $_.Group | Select -f 1} | 
	? {$DstDrvIDs -notcontains $_.CI_ID } | %{ $_.LocalizedDisplayName + ' ' + $_.DriverVersion; Add-CMDriverToDriverPackage -DriverId $_.CI_ID -DriverPackage $DstPkg } 

#get update status by Article Id
Get-CMSoftwareUpdate -ArticleId 7TFPK -Fast | select IsSuperseded, DateRevised, LocalizedDisplayName
#Add latest update to SUG
Get-CMSoftwareUpdate -ArticleId 7TFPK -Fast | ? IsSuperseded -eq $false | Add-CMSoftwareUpdateToGroup -SoftwareUpdateGroupId (Get-CMSoftwareUpdateGroup -Name 'Dell Drivers - All (Test)').CI_ID
#remove superceded updates from SUG
$SUG=(Get-CMSoftwareUpdateGroup -Name 'Dell Drivers - All (Test)').CI_ID; Get-CMSoftwareUpdate -UpdateGroupId $SUG -Fast | ? IsSuperseded -eq $true | Remove-CMSoftwareUpdateFromGroup -SoftwareUpdateGroupId $SUG


#SCCM launches script detection methods like this - use to test for unwanted output that could be misinterpreted
C:\WINDOWS\system32\WindowsPowerShell\v1.0\PowerShell.exe -NoLogo -Noninteractive -NoProfile -ExecutionPolicy Bypass --% & 'C:\WINDOWS\CCM\SystemTemp\b77e39eb-d025-4fc2-8756-40dbc5e155cf.ps1'

#read sccm logs
gc C:\Windows\CCM\Logs\CoManagementHandler.log -Tail 100 | %{if($_ -match '\<\!\[LOG\[(.+)\]LOG\]\!\><time=(".+") component'){ $Matches[2] + ' ' + $Matches[1]}}

#read sccm logs, sort entries by date and filter by text
gi C:\Windows\CCM\Logs\*.log | 
    %{  $file = [System.io.File]::Open($_.FullName, 'Open', 'Read', 'ReadWrite'); $reader = New-Object System.IO.StreamReader($file)
        ($reader.ReadToEnd()) -split "<!"
        $reader.Close(); $file.Close() } |
    ?{  $_ -match 'deploymenttype|contentid|deploymentid|app_ci_id' } |
    %{  $metadata = $_ -split "><"; $logtext = ($metadata[0]).Substring(0, ($metadata[0]).Length - 6).Substring(5); $metaarray = $metadata[1] -split '"'
        $logtext | Select-Object @{Label = "LogText"; Expression = { $logtext } }, @{Label = "Type"; Expression = { [LogType]$metaarray[9] } }, @{Label = "Component"; Expression = { $metaarray[5] } }, @{Label = "DateTime"; Expression = { [datetime]::ParseExact($metaarray[3] + ($metaarray[1]).Split("-")[0].Split("+")[0].ToString(), "MM-dd-yyyyHH:mm:ss.fff", $null) } }, @{Label = "Thread"; Expression = { $metaarray[11] } } } | 
    ? Component -ne StateMessage |
	Sort DateTime | ft DateTime,Component,LogText -wrap -auto

#copy deployments from one app to another
Get-CMApplicationDeployment -ApplicationName "Source App" | % -b{$TargetApp = Get-CMApplication -Name "Target App"; $collections = (Get-CMApplicationDeployment -Application $TargetApp).CollectionName} -p{
    if($_.CollectionName -notin $collections){
        New-CMApplicationDeployment -CollectionName $_.CollectionName -ApplicationId $TargetApp.CI_ID -DeployAction Install -DeployPurpose Available -AllowRepairApp $true             
    }
}

#force remove bits downloads
Register-ScheduledTask -TaskName BitsCleanup -Force -Action (New-ScheduledTaskAction -Execute 'c:\windows\system32\bitsadmin.exe' -Argument '/reset /allusers') -Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-18') -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries) | %{ Start-ScheduledTask $_.TaskName; Unregister-ScheduledTask $_.TaskName -Confirm:$false}
Register-ScheduledTask -TaskName BitsCleanup -Force -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-com Get-BitsTransfer -j d39a3ed2-d49e-4d65-aff5-4df64002f4e4 | Remove-BitsTransfer') -Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-18') -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries) | %{ Start-ScheduledTask $_.TaskName; Unregister-ScheduledTask $_.TaskName -Confirm:$false}

Register-ScheduledTask -TaskName BitsCleanup -Force -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-com Rename-Computer -NewName "WKS-859F4J3" -Force *>c:\temp\ren.log') -Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-18') -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries) | %{ Start-ScheduledTask $_.TaskName; Unregister-ScheduledTask $_.TaskName -Confirm:$false}


APWG-dCYoSujA3Q WKS-J5ZD4J3
APWG-3TPqGXdOt4 WKS-859F4J3 DONE

Import-Csv "C:\Users\paladi\OneDrive - International Labour Office\EssentialFiles\bios inventory.csv" | % -b{$minver = @{'Latitude 3301'='1.27';'Latitude 5420'='1.30';'Latitude 5430'='1.15';'Latitude 5431'='1.15';'Latitude 5440'='1.9.1';'OptiPlex 5090'='1.19';'Latitute 5421'='1.23';'OptiPlex 5000'='1.15'}} -p{ if([version]::TryParse($_."bios version",[ref]$null)){$c='n/a'; if($v=$minver.$($_.model)){$c=[version]$_."bios version" -ge $v }; $_ | Add-Member -Name BiosCompliant -Value $c -MemberType NoteProperty -PassThru }} | Export-Csv "C:\Users\paladi\OneDrive - International Labour Office\EssentialFiles\bios inventory with compliance.csv" -NoTypeInformation 

