(dir filesystem::"\\ad.ilo.org\configmgr\CONTENT\SOURCES\Applications\ILO\PSModules\SCCM").FullName.ForEach({. $_})
. \\ad.ilo.org\configmgr\CONTENT\SOURCES\Applications\ILO\PSModules\tmslib.ps1

$PROFILE | fl *User* -Force 
Start-Process -Verb runas notepad "$($PROFILE.AllUsersAllHosts)" #system profile for all PS host applications, including the shell console and ISE
Start-Process -Verb runas notepad "$($PROFILE.AllUsersCurrentHost)" #system profile for PS shell console
Start-Process notepad "$($PROFILE.CurrentUserAllHosts)" #user profile for all PS host applications, including the shell console and ISE
Start-Process notepad "$($PROFILE.CurrentUserCurrentHost)" #user profile for PS shell
#install PSGet in AllUsersAllHosts (only if current user cannot elevate)
(new-object Net.WebClient).DownloadFile("https://github.com/psget/psget/raw/master/PsGet/PsGet.psm1", (New-Item "$(Split-Path "$($PROFILE.AllUsersAllHosts)" -Parent)\Modules\PSGet" -ItemType Directory -Force).FullName+'\PsGet.psm1')

#Width of output when writing to a file
$PSDefaultParameterValues['out-file:width'] = 2000

#change PowerShell console encoding to Unicode - may be needed when running commands that output in UTF16
[Console]::OutputEncoding = [System.Text.Encoding]::Unicode

#Create the parameters with their default values when they are not bound in a function (i.e. $PSBoundParameters does not contain parameters with default values when they are not specified)
# https://gist.github.com/santisq/2b319c0e0776243fba7ddf6f3c5db5a5
[System.Management.Automation.CommandMetadata]::new($MyInvocation.MyCommand).Parameters.GetEnumerator() |
	Where-Object { -not $PSBoundParameters.ContainsKey($_.Key) } |
	ForEach-Object { $PSBoundParameters[$_.Key] = $PSCmdlet.SessionState.PSVariable.GetValue($_.Key) }

#install PSReadline for AllUsers, using PSGet
Install-Module PSReadLine -Force
#enable prediction
if ($host.Name -eq 'ConsoleHost' -or $host.Name -eq 'Visual Studio Code Host' ) { Set-PSReadLineOption -PredictionViewStyle ListView }
#get command line history
[Microsoft.PowerShell.PSConsoleReadLine]::GetHistoryItems()
[Microsoft.PowerShell.PSConsoleReadLine]::GetHistoryItems() | select -exp commandline | sls winget

#Check if running inside a console app
if ([Console]::LargestWindowWidth){'this is a console app'}

#set default domain controller, method 1
New-PSDrive -Name GVA -PSProvider ActiveDirectory -Root "DC=ad,DC=ilo,DC=org" -Server GVA-ADS-32.ad.ilo.org  | %{ CD "$($_.Name):" }
New-PSDrive -Name BKK -PSProvider ActiveDirectory -Root "DC=ad,DC=ilo,DC=org" -Server BKK-ADS-01.ad.ilo.org  | %{ CD "$($_.Name):" }
#set default domain controller, method 2
$PSDefaultParameterValues = @{"*-AD*:Server"="GVA-ADS-32"}

#get the script name, from anywhere in the script, no matter how it was called
$PSCommandPath

#check if $Target is an absolute path
[System.IO.Path]::IsPathRooted($target)

#enable Remote Desktop RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member ILO\paladi

#get active firewall policies set by MDM
Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.PolicyStoreSource -eq 'Mdm' } | Select-Object -Property DisplayName,Action,Direction

#join to domain
Add-Computer -domainname AD.ILO.ORG -OUPath "OU=WKS,OU=CPT,OU=BKK,OU=ORG,DC=ad,DC=ilo,DC=org" -PassThru -Credential ilo\a-paladi
Add-Computer -domainname uat.ilo.org -OUPath "OU=DSK,OU=CPT,OU=GVA,OU=ORG,DC=uat,DC=ilo,DC=org" -Credential uat\s-osdjoin -restart -force
Add-Computer -domainname ad.ilo.org -OUPath "OU=RAS_WKS-W11,OU=WKS,OU=CPT,OU=GVA,OU=ORG,DC=ad,DC=ilo,DC=org" -Credential ilo\s-osdjoin -restart -force
Oj<Uy9V)L72=<
rasdemo rxb71g7BtaOCT7tm
.\ilolocaladm1  ILOT€mpPa$$2022.
s-papercut k*eEzhuc@G(R24v7%IQm7J
s-webprint :m.ELM$jR4dAr{E
s-ldap-SharpMFP Lk47@KShr-9!1Pk@FRA
admin Admin-1 / !GreenILO27
i0{]L5^~u1M,pyz
Enter-PSSession (New-PSSession 10.21.0.241 -Credential (Get-Credential -username .\ilolocaladm1) -SessionOption (New-PSSessionOption -nomachineprofile))

#get installed dotNet version
[System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription

#configuring BITS to use proxy
c:\windows\system32\bitsadmin.exe /Util /SetIEProxy LocalSystem Manual_proxy http://<proxyserver>:<proxy port> "<any bypasses>"

#output to an alternate screen buffer to display temporary progress or debugging, using ANSI escape codes https://en.wikipedia.org/wiki/ANSI_escape_code
function Write-ProgressOnAlternate{
	Write-Host "`e[?1049h" # Enable alternative screen buffer
	1..10 | ForEach-Object -Parallel { 1..100 | ForEach-Object { Write-Progress -Id ([runspace]::DefaultRunspace.id) -Activity ([runspace]::DefaultRunspace.id) -Status $_ -PercentComplete $_ ; Start-Sleep -Milliseconds 100 } } -ThrottleLimit 100
	Write-Host "`e[?1049l" # Disable alternative screen buffer
}

# creating an implicit runspace
$powershell = [powershell]::Create()
$powershell.AddScript({})
$powershell.Invoke()

# creating an explicit runspace (can adjust options)
$runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
$runspace.Open()
$powershell = [System.Management.Automation.PowerShell]::Create()
$powershell.Runspace = $Runspace

#waiting for a file to be unlocked
$fileItem = Get-Item -LiteralPath $path
while ($true){try{$handle = $fileItem.OpenRead();break}catch{Sleep 1}finally{if($handle -is [IDisposable]){$handle.Dispose()}}}

#dotnet file naming functions
[IO.Path]::ChangeExtension(filepath, new_ext)
[IO.Path]::Combine(path, subfolder, filename)
[IO.path]::GetFileName(filepath)
[io.path]::GetFileNameWithoutExtension(filepath)
#get script file name
Split-Path $PSCommandPath -Leaf
#get the filepath of the host process
[System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
#rename the filename in the filepath without renaming the file
Join-Path $f.DirectoryName ($f.BaseName + '_suffix' + $f.Extension)

#create a random string (pwsh)
[System.Security.Cryptography.RandomNumberGenerator]::GetString((-join ('A'..'Z' + 'a'..'z' + 0..9)), 10)
#generate password (winps)
add-type -AssemblyName System.Web; [System.Web.Security.Membership]::GeneratePassword(15,0)

#update online passwords, as admin:
$NewPassU = Read-Host -Prompt 'enter new user password' -AsSecureString; $NewPass2 = Read-Host -Prompt 're-enter new password' -AsSecureString; if(([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassU))) -ne ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPass2)))){'passwords do not match'}
Set-ADAccountPassword paladi -Reset -NewPassword $NewPassU
$NewPassA = Read-Host -Prompt 'enter new admin password' -AsSecureString; $NewPass2 = Read-Host -Prompt 're-enter new password' -AsSecureString; if(([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassA))) -ne ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPass2)))){'passwords do not match'}
Set-ADAccountPassword a-paladi -Reset -NewPassword $NewPassA
Set-ADAccountPassword paladi -Reset -NewPassword $NewPassU -Server uat.ilo.org -Credential ($c=Get-Credential uat\a-paladi -Message "need the old admin password")
Set-ADAccountPassword a-paladi -Reset -NewPassword $NewPassA -Server uat.ilo.org -Credential $c

#update offline passwords, RUN AS USER:
New-Object System.Management.Automation.PSCredential ('ilo\a-paladi', (Read-Host -Prompt 'enter new a-password' -AsSecureString)) | Export-Clixml "$Env:AppData\a.xml"

#ways to convert from SecureString to plain text
[System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString))
[System.Net.NetworkCredential]::new('', $SecureString).Password #winps
convertfrom-securestring -asplaintext ... #pwsh

#get computer object modified recently
$time = [DateTime]::Now.AddMinutes(-10); Get-ADComputer -Filter 'Name -like "APWG-*" -And Modified -ge $time -And serialNumber -like "*"' -SearchBase "OU=LPT,OU=AUTOPILOT,OU=ORG,DC=ad,DC=ilo,DC=org"	

#remove old Autopilot objects
$cutover = [DateTime]::Now.AddMonths(-6); Get-ADComputer -Filter {Name -like "APWG-*" -And whenChanged -lt $cutover} -SearchBase "OU=LPT,OU=AUTOPILOT,OU=ORG,DC=ad,DC=ilo,DC=org" | Remove-ADObject -Recursive

# get enabled user accounts without an email address
Get-ADUser -LDAPFilter "(&(!mail=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" -SearchBase "OU=PRV,OU=USR,OU=GVA,OU=ORG,DC=ad,DC=ilo,DC=org"

# split the DN
[regex]::matches($dn, '^(?:(?<cn>CN=(?<name>.*?)),)?(?<parent>(?:(?<path>(?:CN=|OU=).*?),)?(?<domain>(?:DC=.*)+))$') | ForEach-Object Groups | Select-Object Name, Value
$dn -split '(?<!\\),' #this is safe, uses negative look-behind, split on commas without a backslash in front.
[regex]::matches($dn, '\bOU=[^,]+') | ForEach-Object Value
$dn -replace '^.+?,OU=|(?<!\\),.+' #get the first (parent) OU name (works even if it has commas)

#get AD users that are member of the same two groups
$da = Get-ADGroup -Filter 'Name -eq "Domain Admins"' | Select-Object -ExpandProperty DistinguishedName
$other = Get-ADGroup -Filter 'Name -eq "somerandomgroup"' | Select-Object -ExpandProperty DistinguishedName
Get-ADUser -Filter "memberOf -eq $da -and memberOf -eq $other"

#get AD attributes
$distinguishedName = (Get-ADUser -Identity username -Properties distinguishedName).distinguishedName
$ADUser = [ADSI]"LDAP://$distinguishedName" 
$TSProfilePath = $ADUser.psbase.InvokeGet('terminalservicesprofilepath')
$TSHomeDir = $ADUser.psbase.InvokeGet('TerminalServicesHomeDirectory')
$TSHomeDrive = $ADUser.psbase.InvokeGet('TerminalServicesHomeDrive')
$TSAllowLogOn = $ADUser.psbase.InvokeGet('allowLogon')

#get all AD Sites
[System.DirectoryServices.ActiveDirectory.Forest]::GetForest((new-object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", 'ad.ilo.org'))).sites

#search for any object using ADSI LDAP
([adsisearcher]'(samaccountname=name*)').findall()
([adsi]'').distinguishedName #get current domain
[adsi]'' #gets the currect domain root.
[adsisearcher]'' #gets the searcher.
([adsisearcher]'objectCategory=user').FindAll() #get all users
([adsisearcher]'samAccountName=john smith').FindOne()  #search for one user by samname
#get the distinguishedName of the host by computer name
([adsisearcher]"samAccountName=$(hostname)$").FindOne().properties.distinguishedname
#get domain SID of the local machine (run as system)
$sidbytes = Get-ItemPropertyValue HKLM:SECURITY\Policy\PolMachineAccountS -Name '(default)'
$sid = New-Object System.Security.Principal.SecurityIdentifier([byte[]]$sidbytes,0) | Select -exp Value
#get the distinguishedName of the host by its domain SID
([adsisearcher]"objectSid=$sid").FindOne().properties.distinguishedname
#find if computer is member of a group
function isMemberOf ([string] $string) {
   $dn = [adsisearcher]::new("(samAccountName=$string)", 'distinguishedName').FindOne().Properties['distinguishedname'][0]
   ([adsisearcher] "(&(name=$env:ComputerName)(memberof=$dn))").FindOne() -as [bool]
}

#convert byte array to hex string, in pwsh:
[System.Convert]::ToHexString($bytearray)
#in winps
($bytearray | ForEach-Object ToString -ArgumentList X2) -join ''

#convert string into int array
-split $string -as [int[]]

get-help about_ActiveDirectory_Filter   
Get-ADUser -Filter {samaccountname -eq "g18bkkmgmt" -or samaccountname -eq "ong"}
$searcher.Filter = "(&(objectCategory=User)(userAccountControl:1.2.840.113556.1.4.803:=2))"
#get all enabled objects
$s=([adsisearcher]"(&(objectCategory=person)(objectClass=User)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");$s.PageSize=10000;($s.FindAll().Properties|? distinguishedname -match 'OU=PRV,OU=USR').Count
$s=([adsisearcher]"(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");$s.PageSize=10000;($s.FindAll().Properties|? distinguishedname -match 'OU=(LPT|WKS|DSK|MTR),OU=CPT').Count
#https://docs.microsoft.com/en-us/windows/desktop/ADSI/search-filter-syntax
#https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx

# get enabled AD user accounts very fast
$searcher = [adsisearcher]::new(
    [adsi] 'LDAP://OU=ORG,DC=ad,DC=ilo,DC=org',
    '(&(objectclass=user)(objectcategory=person)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))',
    [string[]] 'distinguishedName')
$searcher.PageSize = 1000
foreach ($i in $searcher.FindAll()) { $i.Properties.distinguishedName }

#Remove Group from GPO Security Filtering:
Set-GPPermissions -Name "MyGPO" -PermissionLevel None -TargetName "Authenticated Users" -TargetType Group 

#### below requires NTFSSecurity module
#### must use UNC for some ACL modification operations
#reset inheritance of NTFS Permissions on a folder
#note this is recursive due to nature of inheritance
dir2 '\\localhost\e$\V-ASIA-00-00-01\DATA\BANGKOK' | Get-Inheritance | ? InheritanceEnabled | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules -PassThru | %{$_.FullName; Enable-Inheritance $_.item}
#or, shorter, without progress:
'\\localhost\e$\V-ASIA-00-00-01\DATA\BANGKOK' | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules -PassThru | Enable-NTFSAccessInheritance
#get list files/folders with disabled inheritance, regardless of full path length
dir2 '\\localhost\e$\V-ASIA-00-00-01\DATA' -Recurse -IncludeHidden -SkipSymbolicLinks -SkipMountPoints | Get-Inheritance | ? InheritanceEnabled -eq $false | out-gridview
dir e:\v* | dir2 -Recurse -IncludeHidden -SkipSymbolicLinks -SkipMountPoints | Get-Inheritance | ? InheritanceEnabled -eq $false | Export-Csv -Encoding unicode E:\V-ASIA-00-00-01\DATA\BANGKOK\COM\blocked_inheritance.csv
#add ACE
Add-NTFSAccess -Path "\\ad.ilo.org\gva..." -Account "ilo\gva-fs..." -AccessRights GenericRead,GenericExecute -AppliesTo ThisFolderOnly
#remove ACEs
Remove-NTFSAccess -Path "H:\V-EMEA-03-00-21\apps\APPS" -Account ilo\barakatn -AccessRights FullControl -AppliesTo ThisFolderSubfoldersAndFiles

#Logging Folders with Access Denied Errors
$result = Get-ChildItem -Path c:\Windows -Filter *.ps1 -Recurse -ErrorAction SilentlyContinue -ErrorVariable problems
Write-Warning 'Unable to access these folders:'
Write-Warning ($problems.TargetObject -join "`r`n")
#enable the backup and security privilege (win 8.1/2012) to overcome access denied problems (as administrator)
Enable-Privileges
#find files/folders matching any of the given regex patterns, recursively, at any folder depth
dir2 (dir 'E:\V*') -Recurse -IncludeHidden | ? Name -imatch '^(of...arc|media-01)$' | select fullname | Export-Csv 2016-02-gw-folders.csv -NoTypeInformation -Encoding UTF8

#find files matching any of the given patterns, recursively, but up to 250 characters full path length
# -Filter only accepts a single string. -Include accepts multiple values, but qualifies the -Path argument. 
#The trick is to append \* to the end of the path, and then use -Include to select multiple extensions (not needed if using -Recurse or -Depth).
Get-ChildItem $originalPath\* -Include *.gif, *.jpg, *.xls*, *.doc*, *.pdf*, *.wav*, .ppt*
Get-ChildItem $originalPath -Include *.gif, *.jpg, *.xls*, *.doc*, *.pdf*, *.wav*, .ppt* -Recurse
Get-ChildItem $originalPath -Include *.gif, *.jpg, *.xls*, *.doc*, *.pdf*, *.wav*, .ppt* -Depth 0
Get-ChildItem $originalPath -Filter *.gif -Recurse
#how the -Filter really works: https://stackoverflow.com/questions/60171057/specifying-xls-filter-in-get-childitem-also-returns-xlsx-results

#fastest way to find files is to use .NET EnumerateFiles which returns an enumerator
[IO.Directory]::EnumerateFiles($searchDir, $searchFile, [IO.EnumerationOptions] @{AttributesToSkip='Hidden,Device,Temporary,SparseFile'; RecurseSubdirectories=$true; IgnoreInaccessible=$true })
#keep in mind that assigning enumerators to variables is immediate as it does not actually enumerate anything, it only assigns the enumeration object without doing the enumeration job
#the job is only done when the object is output to the console or to a pipeline, an array, a foreach...
& {[CmdletBinding()]param() $PSCmdlet.WriteObject((gi .).EnumerateFiles()) } | gm
& {[CmdletBinding()]param() $PSCmdlet.WriteObject((gi .).EnumerateFiles(), $true) } | gm
#the advantage of enumerators is you can do additional processing/filtering in the pipeline during the enumeration job, so it's all done in one go - convenient for very large collections

# use Trace-Command to see where the parameter binding is failing
Trace-Command -PSHost -Name ParameterBinding -Expression { Get-Item *.txt | Remove-Item }

#show latest accessed files
gci "E:\V-ASIA-00-00-01\DATA\BANGKOK\COMMON\Units\Youth Employment" -recurse | sort LastAccessTime -Descending | select -First 5
#delete files not accessed for 2 weeks
gci "$env:windir\Temp" -File -Force -Recurse | ?{ $_.Length -ne $Null -and $_.LastAccessTime -lt ((Get-Date)-(New-TimeSpan -Days 14)) } | Remove-Item -Force -EA SilentlyContinue
#delete empty folders, may have to repeat if nested
gci "$env:windir\Temp" -Directory -Recurse | ?{(gci $_.fullName -force).count -eq 0} | Remove-Item -Force -ea SilentlyContinue

#link a GPO to all OUs with CPT
Get-ADOrganizationalUnit -SearchBase "OU=ORG,DC=ad,DC=ilo,DC=org" -SearchScope OneLevel -Filter * | %{ TRY{Get-ADOrganizationalUnit ("OU=CPT,"+$_.DistinguishedName) | %{New-GPLink -Guid (get-gpo -name ORG-Computer-NetworkProfile).Id -Target $_.DistinguishedName}}catch{} }

#get file associations, and group them
$lookup = Get-ItemProperty Registry::HKCR\.[a-f]?? | Select-Object -Property PSChildName, '(default)', ContentType, PerceivedType | Group-Object -Property PSChildName -AsHashTable -AsString
$lookup.'.avi'

#get computers last logged on earlier than $LastLogonCOMPUTER
$GetAsiaOU | %{ Get-ADComputer -filter {LastLogonTimeStamp -lt $LastLogonCOMPUTER} -Properties LastLogonTimeStamp -SearchBase $_.DistinguishedName -SearchScope subTree | Select-Object Name,@{Name="Last Logon"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp)}}}
#delete computers last logged on earlier than $LastLogonCOMPUTER
$GetAsiaOU | %{ Get-ADComputer -filter {LastLogonTimeStamp -lt $LastLogonCOMPUTER} -SearchBase $_.DistinguishedName -SearchScope subTree | Remove-ADObject -Recursive }
#get count of active computers with Enterprise edition
Get-AsiaOUs | % { Get-ADComputer -filter {enabled -eq $true -and OperatingSystem -like '*Enterprise'} -Properties OperatingSystem -SearchBase $_.DN } | Measure-Object

#delete folders with trailing spaces, run this in CMD:
rd "\\?\C:\holds bad subdir\20120530-04 "

#check if a name is used everywhere in 
$name='nuon'; Get-ADObject -LDAPFilter "(|(proxyaddresses=*:$name@*)(samaccountname=$name)(userPrincipalName=$name@*))"
"(|(proxyaddresses=*:" + SAM + "@*)(samaccountname=" + SAM + ")(userPrincipalName=" + SAM + "@*))"

#consider escaping variables used in LDAP filters
Install-Module PSOpenAD; $username = [PSOpenAD.LDAP.AttributeTypeAndValue]::EscapeAttributeValue('foo, bar')

# Escapes content so that it is safe for inclusion in a single-quoted string.
[System.Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent("'a', 'b', c")

#finding current filesystem path
$ExecutionContext.SessionState.Path.CurrentFileSystemLocation.Path

#connect to a remote share from a remote computer (second hop) https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ps-remoting-second-hop?view=powershell-7.4
Enter-PSSession RemoteComputer
$cred = Get-Credential ilo\paladi
New-PSDrive -Name Sources -PSProvider FileSystem -Root "\\gva-fil-49.ad.ilo.org\v-emea-98-00-21\Sources" -Credential $cred
ls Sources:

#start a process remotely (non-elevated), using current credentials - returns PID if successful, or raises exception if remote computer not accessible
([WMICLASS]"\\bkk-lab-03\ROOT\CIMV2:win32_process").create('cmd /c md "c:\Temp"')
#enable powershell remoting on remote computer
([WMICLASS]"\\ABJ00370\ROOT\CIMV2:win32_process").create('winrm quickconfig -force')
([WMICLASS]"\\ABJ00370\ROOT\CIMV2:win32_process").create('PowerShell -ExecutionPolicy Bypass -Command Enable-PSRemoting -Force -SkipNetworkProfileCheck')
#alternative way to enable remoting on multiple computers
$PrepJob = foreach($Computer in 'fld-lab-05','fld-lab-04'){
    Invoke-WmiMethod -ComputerName $Computer -Namespace root\cimv2 -Class Win32_Process -Name Create -ArgumentList "winrm quickconfig -quiet" -AsJob
    Invoke-WmiMethod -ComputerName $Computer -Namespace root\cimv2 -Class Win32_Process -Name Create -ArgumentList "PowerShell -ExecutionPolicy Bypass -Command Enable-PSRemoting -Force -SkipNetworkProfileCheck" -AsJob
}
do{"Waiting to complete";Start-Sleep -Seconds 5}until(-not($($PrepJob.State) -eq "Running"))
foreach($Job in $PrepJob.ChildJobs){ Write-Host "Result on $($Job.WmiJob) ID=$($Job.Id): $($Job.Location) - $($Job.State)"; Receive-Job -Job $Job -Keep}

#run Windows Remote Shell commands
winrs -r:A0110054 dir
$pc='a0110229'
schtasks /create /s $pc /tn \ilo\winrm /tr "winrm quickconfig -force" /ru system /rl highest /sc once /st 01:01 /f
schtasks /run /s $pc /tn \ilo\winrm
Invoke-Command $pc {dir c:\}
schtasks /delete /s $pc /tn \ilo\winrm /f

# using local admin account to connect with powershell remote
# (if necessary) run SCCM Script against the target device to enable winrm
$r = New-PSSession $pc -Credential (Get-Credential -username "$pc\administrator")
Enter-PSSession $pc
Copy-Item localsource remotetarget -toSession $r
#connect to powershell remote without creating a user profile
$np = New-PSSessionOption -nomachineprofile
Enter-PSSession COMPUTERNAME -SessionOption $np

#start a remote process with different credentials (elevation will not be allowed, anyway)
$cred = get-credential
$process = get-wmiobject -query "SELECT * FROM Meta_Class WHERE __Class = 'Win32_Process'" -namespace "root\cimv2" -computername $CompName -credential $cred
$results = $process.Create( "notepad.exe" )

####running 2-hop commands using CredSSP (double remote: use local console on A, then from A remote to B, then from B run remote commands on C)
#run on computer A (elevated):
winrm quickconfig -force
Enable-WSManCredSSP -Role Client -DelegateComputer *.ad.ilo.org -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -value *
#run on computer B (elevated, can use invoke-command from A):
Enable-WSManCredSSP -Role Server -force
#now open the first remote session on A to B:
Enter-PSSession -ComputerName B -Credential ilo\a-paladi -Authentication CredSSP
#from A, use the created remote session on B to run remote commands on computer C
[B]: PS C:\> Invoke-Command -ComputerName C {get-childitem c:\}
#http://powershell.com/cs/media/p/7257.aspx

#enable RDP remotely, as a-admin
$PC='bkk01732'
([WMICLASS]"\\$PC\ROOT\CIMV2:win32_process").create('cmd /c winrm quickconfig -force')
Invoke-Command $PC {$rp = 'registry::HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server'; New-ItemProperty $rp -Name fDenyTSConnections -PropertyType dword -Value 0 -Force}

#get an temp html file https://evotec.xyz/difference-between-gettempfilename-and-getrandomfilename-that-got-my-ass-kicked/
[io.path]::Combine([System.IO.Path]::GetTempPath(), "$($([System.IO.Path]::GetRandomFileName()).Split('.')[0]).html")

#copy files from remote session
Copy-Item -FromSession (New-PSSession A0112899.ad.ilo.org) -Path C:\ProgramData\GroupPolicy\Preference\Trace\*.* C:\Temp\gpp\A0112899\

#get direct AD Group memberships for a given user
Get-ADPrincipalGroupMembership sAMAccountName
#get nested AD Group memberships for a given user
Get-ADGroup -LDAPFilter "(member:1.2.840.113556.1.4.1941:=$((Get-ADUser username).DistinguishedName))" -ResultPageSize 2000
#get group memberships recursively
$group = Get-ADObject -LDAPFilter "(Name=RootGroup)"
Get-ADObject -Filter ('memberOf -recursivematch "{0}"' -f $group.DistinguishedName)

#run Powershell console as a-admin for network connections, and regular user for local operations:
#make a duplicate of "Windows PowerShell.lnk" shortcut, eg into "PowerShell - AD Admin.lnk", edit the colors
runas /netonly /user:ilo\a-paladi "cmd /c start \"\" \"C:\Users\paladi\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\PowerShell - AD Admin.lnk\""

#create shortcut in Start Menu
$shortcut = (New-Object -comObject WScript.Shell).CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\$ProgramName.lnk")
$shortcut.TargetPath = "C:\Path\To\Program.exe"
$shortcut.Save()

#error handling when launching Powershell as a task in CMD or Task Scheduler
#"exit 0" needed to return success by clearing the $LastExitCode or $? if somehow it was set to non-zero (http://stackoverflow.com/questions/10666101/lastexitcode-0-but-false-in-powershell-redirecting-stderr-to-stdout-gives-n/12679208#12679208)
#the payload code must throw a terminating exception in order to quit with error (use "throw" or "write-error")
#the command MUST be enclosed in double quotes
powershell.exe -exe bypass -nop -com "START-transcript $env:TEMP'\test 1.log'; TRY{dir c:\D -ea stop; exit 0}CATCH{$Error[0];exit 1}FINALLY{STOP-transcript}" && (echo SUCCESS) || echo ERROR

#launching commands with arguments with spaces - pwsh will quote them automatically:
$arguments = @(
     '--option'
     'value with a space'
)
& 'C:\temp\print_argv.exe' @arguments

#launching commands with arguments with literal quotes - may need to be escaped:
$arguments = @(
     '--option'
     'value with spaces and \"quotes\"'
)
& 'C:\temp\print_argv.exe' @arguments

#contents of print_argv.exe - paste 
Add-Type -OutputType ConsoleApplication -OutputAssembly print_argv.exe -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PrintArgv
{
    class Program
    {
        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetCommandLineW();

        static void Main(string[] args)
        {
            IntPtr cmdLinePtr = GetCommandLineW();
            string cmdLine = Marshal.PtrToStringUni(cmdLinePtr);

            Console.WriteLine(cmdLine);
            for (int i = 0; i < args.Length; i++)
            {
                Console.WriteLine("[{0}] {1}", i, args[i]);
            }
        }
    }
}
'@

# the Start-ProcessWith cmdlet from the ProcessEx module can start a process with a different user, similar to a scheduled task

#while in a remote session, use scheduled tasks to run something as logged on user
Register-ScheduledTask -TaskName RunOnce -Force -Action (New-ScheduledTaskAction -Execute 'DeviceEnroller.exe' -Argument "/c /AutoEnrollMDM") -Principal (New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545') -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -MultipleInstances Parallel -DontStopIfGoingOnBatteries) | Start-ScheduledTask
Register-ScheduledTask -TaskName RunOnce -Force -Action (New-ScheduledTaskAction -Execute 'cmd' -Argument "/c dsregcmd /status > c:\temp\dsreg.log") -Principal (New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545') -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -MultipleInstances Parallel -DontStopIfGoingOnBatteries) | Start-ScheduledTask
Register-ScheduledTask -TaskName RunOnce -Force -Action (New-ScheduledTaskAction -Execute 'wscript.exe' -Argument "//nologo //b ffsys.vbs" -WorkingDirectory "c:\programdata\Office") -Principal (New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545') -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -MultipleInstances Parallel -DontStopIfGoingOnBatteries) | ForEach-Object { Start-ScheduledTask $_.TaskName; Unregister-ScheduledTask $_.TaskName -Confirm:$false }

# creating custom scheduled task triggers
# New-ScheduledTaskTrigger.ps1 		https://gist.github.com/jborean93/d9459f4f871f287a01a6b76ccbe224db

#run something as built-in administrator account
$pc = 'A0117720'
$p = ConvertTo-SecureString -String (Get-ADComputer $pc -pr ms-Mcs-AdmPwd | Select-Object -exp ms-Mcs-AdmPwd) -AsPlainText -Force
Register-ScheduledTask -TaskName RunOnce -Force -Action (
    New-ScheduledTaskAction -Execute 'POWERSHELL.exe' -Argument '"$(Get-Certificate -Template ILO-WorkStationAuth-PKI-03 -CertStoreLocation cert:\LocalMachine\My) *>&1 > c:\temp\out.log"'
    ) -Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-18') -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -MultipleInstances Parallel -DontStopIfGoingOnBatteries) | 
    ForEach-Object { Start-ScheduledTask $_.TaskName; Unregister-ScheduledTask $_.TaskName -Confirm:$false }


#use scheduled tasks to run something as SYSTEM
Register-ScheduledTask -TaskName RunOnce -Force -Action (
    New-ScheduledTaskAction -Execute 'POWERSHELL.exe' -Argument '"$(Get-Certificate -Template ILO-WorkStationAuth-PKI-03 -CertStoreLocation cert:\LocalMachine\My) *>&1 > c:\temp\out.log"'
    ) -Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-18') -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -MultipleInstances Parallel -DontStopIfGoingOnBatteries) | 
    ForEach-Object { Start-ScheduledTask $_.TaskName; Unregister-ScheduledTask $_.TaskName -Confirm:$false }

#use scheduled tasks to run something as SYSTEM
Register-ScheduledTask -TaskName RunOnce -Force -Action (
    New-ScheduledTaskAction -Execute 'POWERSHELL.exe' -Argument '"Get-BitsTransfer -AllUsers | ? JobState -eq Error | Remove-BitsTransfer"'
    ) -Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-18') -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -MultipleInstances Parallel -DontStopIfGoingOnBatteries) | 
    ForEach-Object { Start-ScheduledTask $_.TaskName; Unregister-ScheduledTask $_.TaskName -Confirm:$false }

#run scheduled task once in half an hour from now then delete it
Register-ScheduledTask -TaskName "AAD Join" -Force `
	-Action (New-ScheduledTaskAction -Execute '%COMSPEC%' -Argument '/C DSREGCMD /join') `
	-Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-18') `
	-Settings (New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter 0 -AllowStartIfOnBatteries) `
	-Trigger $($t=New-ScheduledTaskTrigger -Once -At ($e=(Get-Date).AddMinutes(30)); $t.EndBoundary=[Xml.XmlConvert]::ToString($e.AddMinutes(1)); $t)

#use scheduled tasks to restart computer once at midnight
Register-ScheduledTask -TaskName Restart -Force `
	-Action (New-ScheduledTaskAction -Execute 'shutdown.exe' -Argument '/r /f') `
	-Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-18') `
	-Settings (New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter 0 -AllowStartIfOnBatteries) `
	-Trigger $($t=New-ScheduledTaskTrigger -Once -At ($e=[datetime]::Today.AddDays(1)); $t.EndBoundary=[Xml.XmlConvert]::ToString($e.AddMinutes(1)); $t)

Register-ScheduledTask -TaskName "AAD Join" -Force `
	-Action (New-ScheduledTaskAction -Execute '%COMSPEC%' -Argument '/C DSREGCMD /join') `
	-Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-18') `
	-Settings (New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter 0 -AllowStartIfOnBatteries) `
	-Trigger $($t=New-ScheduledTaskTrigger -Once -At ($e=(Get-Date).AddMinutes(30)); $t.EndBoundary=[Xml.XmlConvert]::ToString($e.AddMinutes(1)); $t)

#use scheduled tasks to run remote file as SYSTEM 
Register-ScheduledTask -TaskName RunOnce -Force -Action (
    New-ScheduledTaskAction -Execute 'POWERSHELL.exe' -Arg '-exe bypass -file "\\ad.ilo.org\configmgr\CONTENT\SOURCES\Applications\VENDORS\Oracle\Java8\1.8.0_311-b33.x86 - NoCert\install_java8.ps1"'
    ) -Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-18') -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -MultipleInstances Parallel -DontStopIfGoingOnBatteries) | 
    ForEach-Object { Start-ScheduledTask $_.TaskName; Unregister-ScheduledTask $_.TaskName -Confirm:$false }

#cleanup old files in Temp
gci $env:temp -Recurse -ea Ignore | ? PSIsContainer -eq $false | ? LastWriteTime -lt (Get-Date).AddDays(-30) | del -Force -ea Ignore

#measure sizes of all subfolders in the current folder, using NTFSSecurity
Enable-Privileges; dir -Force -Directory | %{ "$((dir2 $_.fullname -Force -File -Recurse -SkipSymbolicLinks -SkipMountPoints | measure -Sum -Property Length).Sum / 1Mb) $($_.Name)" }
#using dotnet
[System.Linq.Enumerable]::Sum( ([System.IO.DirectoryInfo] (Convert-Path .)).EnumerateFiles(), [System.Func[System.IO.FileInfo, long]] { $args[0].Length } )

#get folder size recursively fast, with exclusions
robocopy C:\Windows\System32 NULL /L /S /NJH /BYTES /NC /NDL /NFL /XJ /R:0 /W:0 /XD drivers DriverStore
#delete a folder recurisvely, fast
robocopy ($d=mkdir "$env:Temp\$(New-Guid)") path\to\delete /MIR /R:0 /W:0; rmdir $d

#get a Guid without hyphens
(New-Guid).ToString('N')

#run a command and trace every step by displaying the debug info
trace-command -name CommandDiscovery -command childitem -PSHost

#list all the security patches that I�ve installed in the last 90 days?
Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.InstalledOn -gt (Get-Date).AddMonths(-3) }

#search Active Directory without the installed AD cmdlets
https://blogs.technet.microsoft.com/fieldcoding/2012/10/19/searching-2003-2012-ad/

#search Windows updates for supercedence
http://www.catalog.update.microsoft.com/Search.aspx?q=

#show all field RODC
([adsisearcher]'(primaryGroupID=521)').FindAll() | ? Path -like '*-rsh-*' | ? Path -NotLike '*gva-*'
#show all field RSH objects
Get-ADObject -Filter 'name -like "*-rsh-*"' -SearchBase "OU=ORG,DC=ad,DC=ilo,DC=org"

#list all registry values of a key
Get-Item 'registry::hkcu\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers' | Select-Object Property
#get data of a registry value
(Get-item "HKCU:\Software\dtSearch Corp.\dtSearch\PlugIns\dtswebhits.api").GetValue("Enabled")
(Get-itemProperty "HKCU:\Software\dtSearch Corp.\dtSearch\PlugIns\dtswebhits.api" -ErrorAction Ignore).Enabled	#does not throw on missing key or value
Get-ItemPropertyValue "HKCU:\Software\dtSearch Corp.\dtSearch\PlugIns\dtswebhits.api" -Name Enabled #will throw on missing key or value
#get an expandstring value without expanding it
(Get-Item 'registry::HKEY_USERS\S-1-5-21-525788414-1921020387-24915789-17744\software\policies\microsoft\office\16.0\common\security\trusted locations\all applications\location1\').GetValue('path',$null,'DoNotExpandEnvironmentNames')
Get-ChildItem 'registry::HKEY_USERS\S-1-5-21-525788414-1921020387-24915789-17744\software\policies\microsoft\office\16.0\common\security\trusted locations\all applications' | % GetValue 'path' $null 'DoNotExpandEnvironmentNames'
#get data type of a registry value
(get-item "HKCU:\Software\dtSearch Corp.\dtSearch\PlugIns\dtswebhits.api").GetValueKind("Enabled")
(get-itemProperty "HKCU:\Software\dtSearch Corp.\dtSearch\PlugIns\dtswebhits.api").Enabled.GetTypeCode()
#get values and types for all properties of a registry key
($key=Get-Item registry::'HKEY_CURRENT_USER\Control Panel\Quick Actions\Pinned').GetValueNames() | %{ [pscustomobject]@{Name=$_;Value=$key.GetValue($_);Type=$key.GetValueKind($_)}}#
#get network driver details
(Gci HKLM:"\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}" -ea Ignore) | %{ $key=$_; $n=@{Index=$key.PSChildName}; $key.Property|%{$n.$_=$key.GetValue($_)};[pscustomobject]$n }
#create new registry value
New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name EnableLegacyAutoProxyFeatures  -Value 1 -PropertyType DWord|String|Binary|ExpandString

#USER SUPPORT admin accounts
$us = @{ AP='a-paladi'; CT='a-tournier'; RBS='a-soares'; WZ='a-wei'; YH='a-humeau'; FD='a-dadaglio'; CB='a-bouchet'; SH='a-hagopian'; AD='a-dubois'; SW='a-walch'; TG='a-grange'; LC='a-caprini'}

#test Internet access via proxy
Invoke-WebRequest "https://www.microsoft.com" -Proxy "http://10.3.3.16:8080" | Select -ExpandProperty StatusCode

#remove proxy to go direct (PS7)
[System.Net.Http.HttpClient]::DefaultProxy = New-Object System.Net.WebProxy($null)
#set proxy (PS7) should work for most cmdlets
[System.Net.Http.HttpClient]::DefaultProxy = New-Object System.Net.WebProxy('http://PROXY_IP:PROXY_PORT', $true)

#to open dsa.msc for a different domain, run this in an elevated command prompt:
runas /netonly /user:uat\a-paladi "mmc dsa.msc /server=uat.ilo.org"

#check if running elevated (really elevated, not only if eligible)
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
#check if  member of the local admin group (so it can elevate), works only if direct member
[Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
#check if  member of the local admin group (so it can elevate), works even if nested member
WHOAMI /GROUPS /FO CSV | ConvertFrom-Csv | ? SID -eq [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
#check if running elevated in a CMD batch


#get the SID of the Administrators group
[System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
#get the list of all well known SIDs
[Enum]::GetValues([System.Security.Principal.WellKnownSidType])

#list members of a local group
@(([ADSI]"WinNT://./Administrators,group").Invoke("Members")) | %{$_.GetType().InvokeMember("Name", "GetProperty", $null, $_, $null)}

## Create a Scheduled Task
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-Command "c:\temp\systemrename.ps1"'
$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -Action $action -TaskName 'mytask' -TaskPath '\' -Principal $principal -Trigger $trigger

## When using Scheduled Tasks in GPP, ensure the user principal is resolvable. For example, BUILTIN\SYSTEM must by changed into NT AUTHORITY\SYSTEM.
## https://maddog2050.wordpress.com/2014/09/11/gpo-issue-deploying-a-scheduled-task-running-as-system/

#Get GPOs linked to OUs
Get-GPOReport -all -ReportType xml | %{([xml]$_).gpo | select name,@{n="SOMName";e={$_.LinksTo | % {$_.SOMName}}},@{n="SOMPath";e={$_.LinksTo | %{$_.SOMPath}}}} | ? {-not $_.SOMPath} | Select -exp Name
#Get GPOs linked to Sites
$SiteLinks = Get-ADObject -LDAPFilter '(objectClass=site)' -SearchBase "CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel -Properties name, distinguishedName, gPLink, gPOptions | ? gPlink | %{ $_.gPLink -split {$_ -in ('[',']') } }
#Get GPOs with no OU links
$NoOULinks = Get-GPOReport -all -ReportType xml | %{([xml]$_).gpo | ?{-not $_.LinksTo} }
#Get GPOs with no OU links and no Site links
$NoOULinks | ?{ $a=$_; -not ($siteLinks|?{ $_ -like "*$($a.Identifier.Identifier.'#text')*"}) } | select name, @{n='Modified';e={Get-Date $_.ModifiedTime}} | Sort Modified
#Get GPLink attributes of all GPOs in specific OU
function Convert-True2Yes([bool]$s){switch($s){$True{"Yes"}$False{"No"}}}
(Get-GPInheritance -Target 'OU=ORG,DC=ad,DC=ilo,DC=org').gpolinks | select @{n='Name';e={$_.DisplayName}},GpoID,@{n='Enabled';e={Convert-True2Yes $_.Enabled}},@{n='Enforced';e={Convert-True2Yes $_.Enforced}},Order | Export-Csv -UseCulture -NoTypeInformation org.csv

#return result when the current user is member of a specific AD group
$group = 'GVA-OG-INFOTEC'
$searcher = [adsisearcher]"(samaccountname=$env:USERNAME)"
$searcher.FindOne().Properties.memberof | ?{$_} | Where-Object {$_.StartsWith("CN=$Group,","CurrentCultureIgnoreCase")}

#get list of special folders
[Environment+SpecialFolder]::GetNames([Environment+SpecialFolder])
[Environment+SpecialFolder]::GetNames([Environment+SpecialFolder]) | %{"$_ = $([Environment]::GetFolderPath($_))"}
[Environment]::GetFolderPath("DesktopDirectory")
(New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path
#get default profile path
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' Default).Default

#get the new line character sequence
[Environment]::NewLine
# when newline is used for splitting, better use a regex
$rawcontents -split '\r?\n'

# Reload all environment variables from the registry
$envVars = [System.Environment]::GetEnvironmentVariables('Machine')
foreach ($key in $envVars.Keys) { [System.Environment]::SetEnvironmentVariable($key, $envVars[$key], 'Process') }
$envVars = [System.Environment]::GetEnvironmentVariables('User')
foreach ($key in $envVars.Keys) { [System.Environment]::SetEnvironmentVariable($key, $envVars[$key], 'Process') }

# ForEach-Object can be replaced with .{process{...}}. The latter works 4x faster and does not obfuscate information of potential errors. https://github.com/nightroman/PowerShellTraps/tree/424d9179733367a785913baa3ca05a378c87a6e7/Cmdlets/ForEach-Object

#open a powershell session under UAT credentials
runas /netonly /user:uat\a-paladi powershell.exe
#run commands against UAT AD
$PSDefaultParameterValues['*-AD*:server']='uat.ilo.org'
Get-ADUser -fi *

#clone a complex Powershell object (e.g. multilevel arrays). (For some reason PSObject.Copy() doesn't work for all object types)
$Clone = $Original | ConvertTo-Json -depth 100 | ConvertFrom-Json

#search for a registry value recursively
gci hklm:SOFTWARE\Classes\Installer\Products\ -Recurse | ?{ $_.GetValue('ProductName') -like 'Microsoft Visual C++ 2012*' }
gci "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | ?{ $_.GetValue('DisplayName') -match 'Cisco Secure Client' }
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select DisplayName, UninstallString, InstallLocation, InstallDate

Get-InstalledSoftware #Get all installed from the Uninstall keys in the registry
#https://gist.github.com/indented-automation/32efb05a5fb67ef9eed02bbb8fe90691

#Query WMI using WMIC
wmic /NameSpace:\\root\WMI Path MSNdis_PhysicalMediumType Get InstanceName,NdisPhysicalMediumType
#get list of available WMI Aliases
WMIC /NameSpace:\\root\CLI Path MSFT_CliAlias Get FriendlyName,Target
#cannot select properties of type array.
WMIC Path Win32_NetworkAdapter Where ( Manufacturer = "Realtek" And PhysicalAdapter = TRUE ) Get 

#get current username 
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
#get current user SID
[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
#get SID of the currently logged on console user (for non-unicode usernames only)
(New-Object -ComObject Microsoft.DiskQuota).TranslateLogonNameToSID((Get-CimInstance -Class Win32_ComputerSystem).Username)

#get user profile using SID
$sid = [System.Security.Principal.NTAccount]::new($username).Translate([System.Security.Principal.SecurityIdentifier]).Value
Get-CimInstance -Query ('SELECT * FROM Win32_UserProfile WHERE Special = "FALSE" AND SID = "{0}"' -f $sid)

#get element values from an xml
$xml.SelectNodes("//value[starts-with(text(), 'http')]").InnerText	# get URLs from all elements that are named "value", e.g. <parameters version="1.0"><parameter name="URL"><value displayName="displayname1">http://test.com/test/test</value><value displayname="displayname2">http://testing.com/test/test</value> [some have up to about 8 urls] </parameter></parameters>
$xml.SelectNodes('//value').InnerText	# get data for all elements that are named "value"

#instruct PowerShell NOT to unroll the result into an array:
Write-Output -NoEnumerate $object
#this is the same as using the array constructor operator (unary comma)
,$object

# force enumeration of a potentially unenumerated collection
$results | Write-Output | Where-Object <condition to test against each item>

#keep arrays declared as @() static. Avoid += for dynamic expansion, just assign the output of the foreach loop to the array variable directly, as a bulk
$array = foreach ($item in $items){ if(..){$item} }
#if bulk assignment is not possible, use lists
$array = [System.Collections.Generic.List[string]]::new()
$array.Add($item)

# use StringBuilder class when joining large strings https://learn.microsoft.com/en-us/powershell/scripting/dev-cross-plat/performance/script-authoring-considerations?view=powershell-7.4#string-addition
$PsPrompt = [StringBuilder]::new().
      Append("[").
      Append($PSStyle.Foreground.BrightCyan).
      Append($Computer.UserName).
      ToString()

#arraylists are not recommended https://learn.microsoft.com/en-us/dotnet/api/system.collections.arraylist?view=netframework-4.8#remarks
#use List<T> instead

#use dotnet Linq for high performance processing of large datasets https://www.red-gate.com/simple-talk/development/dotnet-development/high-performance-powershell-linq/

#Collections, Hashtables, Arrays and Strings
#https://www.red-gate.com/simple-talk/sysadmin/powershell/powershell-one-liners-collections-hashtables-arrays-and-strings/

#Hashset is what you are looking for if you want to store only unique values in an unordered array with relatively faster add, remove and find operations:
$StringSet = [Collections.Generic.HashSet[string]]@('a','b','c')
$StringSet = [Collections.Generic.HashSet[String]]::new([StringComparer]::InvariantCultureIgnoreCase)
$StringSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$StringSet = [Collections.Generic.HashSet[String]]::new($myArray, [StringComparer]::InvariantCultureIgnoreCase)
$position = [HashSet[int]]::new()

#for a sorted HashSet use SortedSet #https://stackoverflow.com/questions/65960853/in-powershell-how-do-i-sort-a-collections-generic-list-of-directoryinfo
$set = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::InvariantCultureIgnoreCase)
[System.Collections.Generic.SortedSet[string]] $set = 'a','b','c'

#Lists are faster and easier than arrays, but when using strings they are case sensitive!
[Collections.Generic.List[Object]]$items = @( gci ~ -Depth 1 )
[Collections.Generic.List[Int]]$Nums     = '0'..'9'
,$items | gm

#when creating array of strings, create them as list of objects [List[Object]] instead of [List[String]] to avoid type cast errors when adding array ranges (which are array of objects in PS)
[Collections.Generic.List[object]] $ValidOption = @(); $ValidOption.AddRange(@( '/c', 'echo', 'test' )); $ValidOption -join ' '; & cmd @ValidOption

#when building a large array of objects, it's faster to use [ordered]@{} to build each item then cast it to [PSCustomObject] to be added to the array https://learn.microsoft.com/en-us/powershell/scripting/dev-cross-plat/performance/script-authoring-considerations
#merging hashtables https://www.powershellgallery.com/packages/MergePSCustomObject/0.0.2/Content/Public%5CMerge-PSCustomObject.ps1

#casting data types
$MyInt = try { [Int]::Parse($MyValue) } catch { ... }
$myInt = $myValue -as [int]
New-Variable a; if([System.Int32]::TryParse('123', [ref] $a)){ $a }

#using Dictionary
$dict = [Dictionary[char,hashtable]]::new()
$dict.Add($char, @{})

#splitting an array in chunks (subarrays of fixed length) needs pwsh and .net core - must be a string array
[System.Linq.Enumerable]::Chunk([string[]] $array, 3) | foreach-object { $_ -join ' ' }

#sorting an array of hashtables
$myArray = 1..10 |ForEach-Object { @{ ID = $_; Birthdate = (Get-Date).AddDays(-(Get-Random -Minimum 5 -Maximum 3000))} }
[System.Linq.Enumerable]::OrderBy[hashtable,datetime]([hashtable[]]$myArray, {param($s) $s.Birthdate})

#determining if a hashtable is case sensitive or not
($i = @{}).GetType().GetField('_keycomparer', [System.Reflection.BindingFlags] 'Instance, NonPublic') | % GetValue($i)

#create a ordered case insesitive hashtable
$foo = [hashtable]::new([ordered]@{FOO = 2; BAR = 1 }, [System.StringComparer]::InvariantCultureIgnoreCase)

#get all filesystem driveletters
Get-PSDrive | Where-Object { $_.Provider.ImplementingType -eq [Microsoft.PowerShell.Commands.FileSystemProvider] -and $_.Used -gt 1gb }

#install chocolatey intergration in powershell
rmdir 'c:\Program Files\PackageManagement\ProviderAssemblies\chocolatey' -Force
Install-Package ChocolateyGet -ProviderName PowerShellGet
Install-Package Chocolatey -ProviderName Chocolatey
Install-Package chocolatey-core.extension -ProviderName Chocolatey
Get-PackageProvider Chocolatey
install-package skype

#get the original download location of files downloaded with IE/Chrome
dir . -File | gc -Stream Zone.Identifier

#null coalescing operator (if $c is not null -> output $a, otherwise output $b)
($a, $b, $c -ne $null)[0]

#get local accounts and their validity and last logon
([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
	$user = ([ADSI]$_.Path)
	$enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
	$lastLogin = $user.Properties.LastLogin.Value
	if ($lastLogin -eq $null) {$lastLogin = 'Never'}
	Write-Host $user.Name $lastLogin $enabled 
}

#Dumping Personal Passwords from Credential Vault
[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
(New-Object Windows.Security.Credentials.PasswordVault).RetrieveAll() | %{$_.RetrievePassword();$_} | Select Username, Password, Resource | Out-GridView
#Clearing Personal Passwords from Windows
$p = New-Object Windows.Security.Credentials.PasswordVault; $p.RetrieveAll() | %{$p.Remove($_)}

# edit ACL on Registry Key
$acl = Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity\AllowedBuses"
$idRef = [System.Security.Principal.NTAccount]("EVERYONE")
$regRights = [System.Security.AccessControl.RegistryRights]::FullControl
$inhFlags = [System.Security.AccessControl.InheritanceFlags]::None
$prFlags = [System.Security.AccessControl.PropagationFlags]::None
$acType = [System.Security.AccessControl.AccessControlType]::Allow
$rule = New-Object System.Security.AccessControl.RegistryAccessRule ($idRef, $regRights, $inhFlags, $prFlags, $acType)
$acl.AddAccessRule($rule)
$acl | Set-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity\AllowedBuses"

# get the ACL of an AD Group
Get-ADGroup MyGroup -Properties nTSecurityDescriptor | % nTSecurityDescriptor | % getsecuritydescriptorsddlform -ArgumentList ([System.Security.AccessControl.AccessControlSections]::All)

#scanning for, and installing individual Windows 10 updates
Install-Module PSWindowsUpdate
Get-WUList
Get-WUInstall -KBArticleID KBxxxxxxx
wmic qfe list

#get all ProgIDs (32bit and 64bit)
Get-ChildItem @("REGISTRY::HKEY_CLASSES_ROOT\CLSID","REGISTRY::HKEY_CLASSES_ROOT\Wow6432Node\CLSID") -include VersionIndependentPROGID -recurse | %{$_.GetValue("")}
#or, see the ProgID of each App for each supported protocol/association by browsing to 
#  HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\%App%\*\Capabilities\FileAssociations
Get-Item 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\Microsoft.MicrosoftEdge_*\*\Capabilities\FileAssociations'
#current associations:
Get-ItemProperty  registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts\

#query all DCs to get the user's lastlogon for each of them
$Username = "paladi"
[DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers | ForEach-Object {
	try{ 
		$Server = $_.Name
		$SearchRoot = [ADSI]"LDAP://$Server"
		$Searcher = New-Object DirectoryServices.DirectorySearcher($SearchRoot, "(sAMAccountName=$Username)")
		$Searcher.FindOne() | Select-Object `
			@{n='Name';e={ $_.Properties["name"][0] }},
			@{n='lastLogon';e={ (Get-Date "01/01/1601").AddTicks($_.Properties["lastlogon"][0]) }},
			@{n='Server';e={ $Server }}
	} catch {} #keep quiet on unreachable DCs
}

cmd /c assoc .7z=7-Zip.7z
cmd /c ftype 7-Zip.7z=C:\Program Files\7-Zip\7zFM.exe

#enable reading the remote Event log
netsh advfirewall firewall set rule group="Remote Event Log Management" new enable=yes

#collect network trace into nettrace.cab file
netsh trace start scenario=internetClient_dbg capture=yes persistent=yes
netsh trace stop

#search AD groups by wildcard
Get-ADGroup -Filter {name -like '*tms*'}

#add users from CSV to AD Group by first and last name
Import-Csv onedrive_users.csv | %{ $gn=$_.'First name'; $sn=$_.Surname; Get-ADUser -filter {sn -like $sn -and givenname -like $gn} | %{Add-ADGroupMember -Identity 'gbl-ap-onedrive' -Members $_}}

#testing for pending reboot
Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"

#check quickly if a software is installed, using 32bit+64bit registry
Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.GetValue("DisplayName") -like 'Microsoft Visual C++ 2012*'}
Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.GetValue("DisplayName") -like 'Microsoft Visual C++ 2012*'} | %{[pscustomobject]@{Name=$_.GetValue('DisplayName');Version=$_.GetValue('DisplayVersion');ProductID=$_.PSChildName}}
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*" | Select-Object -ExpandProperty '(Default)' -ErrorAction Ignore | Where-Object { $_ } | Sort-Object 

#capturing stderr from external command
$stderr = & {
    $ErrorActionPreference = 'Continue' # if you don't want it to stop at the first error
    external_command.exe | Set-Variable stdout
} 2>&1 | ForEach-Object ToString

$stdErr = $(
    $stdOut = powershell -Command "'stdout'; `$host.UI.WriteErrorLine('stderr')"
) 2>&1 | % ToString

#get users and commandlines for all processes
Get-CimInstance win32_process | select @{n='Owner';e={$_|Invoke-CimMethod -MethodName GetOwner|%{"$($_.Domain)\$($_.User)"}}},commandline | Out-GridView

#get HKCU data of logged on users (local/rdp), while running as SYSTEM
$SID = Get-CimInstance -ClassName win32_process -Filter "name = 'explorer.exe'" | Invoke-CimMethod -MethodName GetOwner | %{ (New-Object System.Security.Principal.NTAccount($_.User)).Translate([System.Security.Principal.SecurityIdentifier]).value }
Get-ChildItem "Registry::HKEY_Users\$SID\Software"
#while running as SYSTEM, remap HKCU drive to logged on user. Affects the current PS session only. Does not affect HKEY_CURRENT_USER hive.
Remove-PSDrive HKCU; New-PSDrive -PSProvider Registry -Name HKCU -Root HKEY_USERS\$SID > $null

#run tasks as user even if not logged on (replace the line <LogonType>InteractiveToken</LogonType> with <LogonType>S4U</LogonType>) needs "Logon as batch job" policy:
#https://www.scriptjunkie.us/2013/01/running-code-from-a-non-elevated-account-at-any-time/

#get file version
(Get-Item "C:\Users\paladi\Downloads\TeamViewer_Setup.exe" ).VersionInfo.FileVersionRaw

#Get application publisher and hash (signature)
Get-AppLockerFileInformation -path 'C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\acrord32.exe' |format-list

#query for logged on domain accounts (rdp and console)
(Get-CimInstance win32_loggedonuser).Antecedent | ? Domain -eq 'ILO'

$quser = & $env:comspec /c "query user 2>nul"
if($quser){Write-Output "Logons exist"}else{Restart-Computer -Force}

#parse the $LogonTime variable if it is assumed to contain the respective LOGON TYME string from the quser / query user output, taking into account the current locale:
# (doesn't work correctly in WinPS)
$ShortDate = [System.Threading.Thread]::CurrentThread.CurrentCulture.DateTimeFormat.ShortDatePattern;
$ShortTime = [System.Threading.Thread]::CurrentThread.CurrentCulture.DateTimeFormat.ShortTimePattern;
[datetime]::ParseExact($LogonTime, "$ShortDate $ShortTime", [CultureInfo]::InvariantCulture);
# in WinPS:
$ShortDate = (Get-ItemProperty -Path 'HKCU:\Control Panel\International').sShortDate
$ShortTime = (Get-ItemProperty -Path 'HKCU:\Control Panel\International').sShortTime

# cheat sheet to format datetime to string: https://learn.microsoft.com/en-us/dotnet/standard/base-types/custom-date-and-time-format-strings
(Get-Date).ToString( 'yyyy\\MMMM\\dd' )

# for native quser calls, use wtsapi32, for example https://gist.github.com/trackd/5e469a3f96cf42505848fdbc7b48ab85
iwr https://gist.github.com/trackd/5e469a3f96cf42505848fdbc7b48ab85/raw/84560daec042f997e8ee79bf49960e0bc9299fc7/tmp_experiment.ps1 | iex
Get-WTSSessionInfo | Get-WTSInfo

#get installed date of the latest windows updates
Get-HotFix | Sort-Object -Property @{Expression = { if ($_.InstalledOn) { [datetime]::Parse($_.InstalledOn, [CultureInfo]::InvariantCulture) } else { [datetime]::MinValue } }} | Select-Object -Last 1 -ExpandProperty InstalledOn

#get the list of installed power plans
gcim -N root/cimv2/power -Class Win32_PowerPlan

#aggregate event logs https://github.com/guyrleech/Microsoft/blob/master/event%20aggregator.ps1

#enable a Windows log
$log = Get-WinEvent -ListLog * | Where LogName -match "WMI"; $log.set_isEnabled($true); $log.SaveChanges()

#get the latest events
Get-WinEvent $log.LogName | Sort TimeCreated |  Select -last 20 |  ft -Wrap -Autosize

#get system errors from 2 days ago
Get-WinEvent -FilterHashtable @{logname="system";level=2,3;starttime=(Get-Date).adddays(-2)} | format-table id,timecreated,message -auto

#get all errors from 1 hour ago
Get-WinEvent -ListLog * | ? LogName -notlike *powershell* | %{Get-WinEvent -FilterHashtable @{logname=$_.LogName;level=2,3;starttime=(Get-Date).addhours(-1)} -ea 0} | sort -desc timecreated | format-table logname,timecreated,message -auto -Wrap

#get all events during a specific interval https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable
Get-WinEvent -ListLog * | %{Get-WinEvent -FilterHashtable @{logname=$_.LogName;starttime=(Get-Date "10:00:00");endtime=(Get-Date "10:00:10")} -ea 0} | sort -desc timecreated | format-table logname,timecreated,message -auto -Wrap

#get power/reboot events 
Get-WinEvent -FilterHashTable @{LogName = "System"; Providername = "Microsoft-Windows-Kernel-Power"; StartTime = (get-date).AddDays(-1)}
Get-WinEvent -FilterHashtable @{logname='System'; id = 1074, 6005, 6006, 6008, 507, 506} -MaxEvents 50 | %{$_ | Select TimeCreated,Message} | ft -w
#Note: XPath wildcard '*' support is intended only for the Node Names and not for values

$ht = @{     # https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
    12 = 'startup'
    13 = 'shutdown'
    41 = 'unclean startup'
    1001 = 'bugcheck'
    1074 = 'user initiated shutdown'
    6005 = 'computer startup'
    6006 = 'computer shutdown'
    6008 = 'unexpected shutdown'
}
Get-WinEvent -FilterHashtable @{LogName = 'System'; Id = @($ht.keys) } | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Id          = $_.Id
        Event       = $ht[$_.Id]
		Message 	= $_.Message
    }
} | Sort-Object -Property TimeCreated -Descending

#get 30 sec of latest events from all logs except powershell
Get-WinEvent -ListLog * | ForEach-Object {Get-WinEvent @{'LogName' = $_.logname; 'StartTime' = (get-date).AddSeconds(-30)} -ea 0 | ? ProviderName -notlike *powershell* |select timecreated,logname,@{n='m';e={$_.message.replace("`n",' ')}} }  | Export-Csv C:\Temp\events.csv -Force

#get latest gpo operational events
Get-WinEvent @{LogName = "Microsoft-Windows-GroupPolicy/Operational"; 'StartTime' = (get-date).AddMinutes(-30)} -ea 0 | select timecreated,@{n='m';e={$_.message.replace("`n",' ')}} | sort timecreated | ft -auto -wrap

#get the description of the error code
[ComponentModel.Win32Exception]0x80041032

#set security acl on scheduled task
$ts = New-Object -ComObject "Schedule.Service"
$ts.Connect("localhost")
$task = $ts.GetFolder("ILO").GetTask("Run bgInfo")
$sddl = $task.GetSecurityDescriptor(0xF)
#add ACE for Builtin\Users with Read+Delete allowed
$task.SetSecurityDescriptor($sddl+'(A;;FRSD;;;BU)', 0)
#read the SDDL
[System.Security.AccessControl.CommonSecurityDescriptor]::new(
    $false,    # isContainer
    $false,    # isDS
    (Get-Printer -Name "printername" -Full).PermissionSDDL
)

#allow Authenticated Users to see and run system tasks
$Scheduler = New-Object -ComObject "Schedule.Service"
$Scheduler.Connect(); $GetTask = $Scheduler.GetFolder($TaskPath).GetTask($TaskName)
$GetSecurityDescriptor = $GetTask.GetSecurityDescriptor(0xF)
if ($GetSecurityDescriptor -notmatch 'A;;0x1200a9;;;AU') { # use '(A;;FA;;;AU)' for full access
    $GetSecurityDescriptor = $GetSecurityDescriptor + '(A;;GRGX;;;AU)'
    $GetTask.SetSecurityDescriptor($GetSecurityDescriptor, 0)
}

#download file into memory, encode to Base64 and save it to disk
$req = Invoke-WebRequest 'https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf'
[System.IO.File]::WriteAllBytes('somepdf.pdf', $req.RawContentStream.ToArray())

#get OS version of computers in an OU
Get-ADComputer -SearchBase "OU=MTR,OU=CPT,OU=GVA,OU=ORG,DC=AD,DC=ilo,DC=org" -fi * -Properties operatingsystemversion | select operatingsystemversion
Get-ADComputer -SearchBase "OU=MTR,OU=CPT,OU=GVA,OU=ORG,DC=AD,DC=ilo,DC=org" -fi * -Properties operatingsystemversion, description | ? operatingsystemversion -like '10.0 (17763)' | select OperatingSystemVersion, description

#get OS version of computers in a Collection
(Get-CMCollectionMember -CollectionName "OSD-DSK-HQ-05-All").name | Get-ADComputer -Properties operatingsystemversion | select name, operatingsystemversion
#get OS version and Network location of computers in a Collection
(Import-Csv C:\Temp\upgrade\5th.csv).name | Get-ADComputer -Properties operatingsystemversion -ea 0 | ? operatingsystemversion -like '*17763*' | %{ [pscustomobject]@{name = $_.Name; NetworkLocation = Get-Wmiobject @SCCM_Site -Class SMS_R_System -Filter "name='$($_.Name)'" -Property NetworkLocation | Select -ExpandProperty NetworkLocation} }

#get top 10 processes by overall CPU utilization
(Get-Counter '\Process(*)\% Processor Time').Countersamples |  Sort cookedvalue -Desc | select -f 10 instancename, CookedValue 
#reproduce a linux top command 
While(1) { $(Get-Counter '\230(*)\6' -ea 0; cls).countersamples | Select instancename, cookedvalue| ? instanceName -notmatch "^(idle|_total|system)$" | Sort cookedvalue -Descending| Select -First 10| ft InstanceName,@{L='CPU';E={($_.Cookedvalue/100/$env:NUMBER_OF_PROCESSORS).toString('P')}} -Auto}

#get top 5 processes by CPU utilization
(Get-Counter '\Process(*)\% Processor Time').CounterSamples | sort CookedValue -desc | Select -f 5 -skip 1

#disable unattended system sleep
powercfg /SETACVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20 UNATTENDSLEEP 0

#find paths to executables
cmd /c "where notepad"

#get file version
[System.Diagnostics.FileVersionInfo]::GetVersionInfo("somefilepath").FileVersion

#Exit Codes
#to return a code, end the script with the "Exit $ExitCode" when the script is called as a file (using the explicit -file parameter)
#otherwise, if called with -command (or, like SCCM, without the explicit -file), then set the return code with $host.SetShouldExit($ExitCode), otherwise it will return 0 or 1
#another workaround for commands: powershell -Command '.\exit.ps1; exit $LASTEXITCODE'
if([System.Environment]::GetCommandLineArgs() -contains '-file'){Exit $ExitCode}else{$host.SetShouldExit($ExitCode)}

#configure your PowerShell session so that it doesn't truncate the values when formatting a table
$FormatEnumerationLimit=-1

#to remove a corrupted task from the scheduler
#delete the entry under Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
#delete the entry under Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree
#delete the file under C:\Windows\system32\tasks
#restart service 'schedule'

#minimize a specific app window
(Add-Type -MemberDefinition "[DllImport(`"user32.dll`")]`npublic static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);" -Name Win32ShowWindowAsync -Namespace Win32Functions -PassThru)::ShowWindowAsync((Get-Process scclient).MainWindowHandle, 6)

#suppress all errors
& {[Net.DNS]::GetHostEntry('notPresent')} 2>$null
 
#to ensure the system doesn't go into standby when running a lengthy script
presentationsettings /start
presentationsettings /stop

#turning user properties into a hash table
Get-ADUser paladi -Properties * -PV user | Get-Member -MemberType *property | ? Name -notlike ms* | ? Name -notlike object* | ? name -notlike *created | ? name -notlike *changed | select -ExpandProperty name | %{ @{ $_ = $user.$_ } }

#using queues for recursion
[System.Collections.Queue]$queue = [System.Collections.Queue]:: new()
$queue.Enqueue('c:\')
while ($queue.Count -gt 0){
        $currentDirectory = $queue.Dequeue()
		[IO.Directory]::GetDirectories($currentDirectory) | ForEach-Object {$queue.Enqueue($_)}
		[IO.Directory]::GetFiles($currentDirectory, '*.ps1' )
}

$queue = [System.Collections.Generic.Queue[PSObject]]::new()
$queue.Enqueue([PSCustomObject]@{
    Url     = "https://api.github.com/repos/$Owner/$Repo/contents?ref=$Branch"
    RelPath = ''
})

# for thread-safe queues, use ConcurrentQueue

#from powershell, set onedrive file attribute to "always keep on this device"
attrib  --% -U +P /s "C:\Users\paladi\OneDrive - International Labour Office\Desktop\*.url"
#from powershell, set onedrive file attribute to "free up space"
attrib  --% +U -P /s "C:\Users\paladi\OneDrive - International Labour Office\Desktop\*.url"

#stop command line parsing symbol in powershell https://social.technet.microsoft.com/wiki/contents/articles/7703.powershell-running-executables.aspx
--%

#search for an object in AD, matching various name attributes, without errors
Get-ADObject -LDAPFilter "(|(name=$($_.DisplayName))(samaccountname=$($_.DisplayName))(userPrincipalName=$($_.DisplayName)))"

#regex advanced matching
[regex]::Matches( 'ab23 foo49 314', '\d+', 'Ignorecase') | Join-String Value -sep ', '  
#regex matching using named groups
'http://google.com/some.exe', 'some/path/file.exe','https://url.com/path/to/installer.exe' | % { 
  [regex]::match($_, '.*/(?<file>.+\.exe)\b').Groups['file'].Value 
} 
#regex multiline match https://www.regular-expressions.info/refmodifiers.html
-match '(?ms).*'
-match '(?s).*'
#or just make sure the input is a single multi line string and not an array of strings

#regex lookahead and lookbehind
https://devblogs.microsoft.com/scripting/powershell-regex-crash-course-part-4-of-5/

#regex using scriptblocks for custom replace
[Regex]::Replace( 'asSDFdf werfDsA', '\w+', {$args[0].Value.Substring(0, 1).ToUpper() + $args[0].Value.Substring(1).ToLower()})
[Regex]::Replace($originalText, '(?<=\bChapter\s+)[\w\s]+?(?=>\r?\n)', [System.Text.RegularExpressions.MatchEvaluator]{
  param($m)  
  switch ($m.Value) {
    'one' { return '1' }
    'two' { return '2' }
    'three' { return '3' }
    default { return "[[ERROR - NO TERMS FOR '$($m.Value)' at offset $($m.Index)]]" }
  }
})
#replace using named capture groups
$SearchExp = '^(?<DomainName>[\w-.]+)\\(?<Username>[\w-.]+)$'
$ReplaceExp = '${Username}@${DomainName}'
'Contoso.local\John.Doe' -replace $SearchExp, $ReplaceExp

#convert to title case
(Get-Culture).TextInfo.ToTitleCase('foo bar cat')
[CultureInfo]::new('de-de').TextInfo.ToTitleCase('foo bar cat')

#filter file access events for non-read opeartiongs
Get-WinEvent -Path "\\ad.ilo.org\gva\INFOTEC\TMS\USER SUPPORT\Incident Reports\IM103484\GVA-fil-10-last7days-Filtered.evtx" -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing']][EventID=4663 or EventID=4656 or EventID=4658 or EventID=4659 or EventID=4660]]" | ? Message -like "*ixlib.ilb*" | ?{($_.message -split "`n") | ?{$_ -match 'Accesses:\s*(\w+.*)$' -And $matches[1] -notlike 'read*'}} | ft -w

#get serial numbers of all VMs on HyperV host
gwmi -comp gva-usr-02 -namespace root\virtualization\v2 -class msvm_virtualsystemsettingdata | ? BIOSSerialnumber | select-object elementname, BIOSSerialnumber

[System.IO.Path]::GetFileNameWithoutExtension("Test Config.xlsx")
[System.IO.Path]::GetExtension("Test Config.xlsx")

#free space on system drive
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
vssadmin delete shadows /all /quiet
Clear-RecycleBin
[__comobject]$CCMComObject = New-Object -ComObject 'UIResource.UIResourceMgr'
$CacheInfo = $CCMComObject.GetCacheInfo().GetCacheElements()
ForEach ($CacheItem in $CacheInfo) {if($CacheItem.Location -notlike '*\2u'){$null = $CCMComObject.GetCacheInfo().DeleteCacheElement([string]$($CacheItem.CacheElementID))}}

#confirm that the bitlocker key is saved in AD (run as account that can access all bitlocker keys)
$dn = (([adsisearcher]"samAccountName=$(hostname)$").FindOne() | select -ExpandProperty properties).distinguishedname
$drive = Get-BitLockerVolume | ? volumetype -eq operatingsystem | ? {$_.KeyProtector | ? KeyProtectorType -eq RecoveryPassword} 
$key = $drive | Select -exp KeyProtector | ? KeyProtectorType -eq RecoveryPassword
($a=[adsisearcher]"(&(objectclass=msFVE-RecoveryInformation)(name=*$($key.KeyProtectorId)))").SearchRoot="LDAP://$dn"; $a.findOne()
Backup-BitLockerKeyProtector $drive.MountPoint $key.KeyProtectorId

$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=A0115578,OU=LPT,OU=CPT,OU=GVA,OU=ORG,DC=ad,DC=ilo,DC=org")
$objSearcher.SearchScope = "oneLevel"
$objSearcher.Filter = "objectclass=msFVE-RecoveryInformation"
$objSearcher.FindOne()

#reset Windows Store
Add-AppxPackage -DisableDevelopmentMode -Register ((Get-AppxPackage Microsoft.WindowsStore).InstallLocation + '\AppxManifest.xml')
#reset driver store
rundll32.exe pnpclean.dll,RunDLL_PnpClean /DRIVERS /MAXCLEAN
#reset component store
Dism /Online /Cleanup-Image /RestoreHealth

# install Windows 11 using DISM https://gist.github.com/pratyakshm/f19c106205f9327e9f1d538fb91fce65
# boot from Windows 11 USB in UEFI mode, press Shift+F10 to get the console, partition the disk using diskpart: format and assign A: to EFI part, and C: to primary part
# query the available OS editions on the USB: dism /Get-ImageInfo /ImageFile:X:\sources\install.wim
# copy the OS files for the required edition: dism /Apply-Image /ImageFile:X:\sources\install.wim /Index:6 /ApplyDir:C:
# copy the boot files: bcdboot C:\Windows /s A: /f ALL

#get the physical disk behind the logical disk
Get-CimInstance Win32_LogicalDisk |% {
  Write-Host "$($_.VolumeSerialNumber) ($($_.DeviceID)) underlying media:"
  $_ |Get-CimAssociatedInstance -ResultClassName Win32_DiskPartition -KeyOnly |Get-CimAssociatedInstance -ResultClassName Win32_DiskDrive | Format-List
}

#get active driver versions
Get-WmiObject Win32_PnPSignedDriver| select devicename, driverversion | where {$_.devicename -like "*audio*"}
Get-WmiObject Win32_PnPSignedDriver| select DeviceClass, devicename, driverversion | where DeviceClass -like display
#get all installed drivers
Get-WindowsDriver -Online -All | select * | Export-Csv C:\Temp\all_drivers.txt -NoTypeInformation
Import-Csv C:\Temp\all_drivers.txt | ? classname -like display | select providername, driver, version
#get available drivers and HardwareIds from the installed INF file
Get-WindowsDriver -Online -Driver oem279.inf

#check if running in a 64bit process (SCCM packages and Intune Win32app Powershell scripts run 32bit by default)
[Environment]::Is64BitProcess

#get tpm version
Get-CimInstance -Namespace root\cimv2\security\microsofttpm -ClassName win32_tpm | %{ (Invoke-Expression $_.SpecVersion)[0] }
#tpm troubleshooting
$pc='A0111361';if((Test-NetConnection $pc).pingsucceeded){ Enter-PSSession $pc -SessionOption ($opt=New-PSSessionOption -NoMachineProfile)}
Get-BitLockerVolume; Get-WindowsImage -Mounted
gcim win32_computersystem | select Model
gcim win32_operatingsystem | select BuildNumber, InstallDate, LastBootUpTime
Get-ComputerInfo -property OsVersion
Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ubr #get the OS patch level
$dcm = @{Namespace = 'root\ccm\dcm'; Class = 'SMS_DesiredConfiguration'}; Get-CimInstance @dcm | Select DisplayName,LastComplianceStatus,LastEvalTime,Version
Get-CimInstance @dcm | %{ if($_.displayname -LIKE '*Encryption*'){$_.DisplayName; Invoke-CimMethod @dcm -Name TriggerEvaluation -Arguments @{Name = $_.Name; Version = $_.Version; IsEnforced = $true; IsMachineTarget = $true}}}
Get-WinEvent -FilterHashTable @{LogName = "system"; providername='tpm' } -MaxEvents 20 | ft -w
Get-WinEvent -FilterHashTable @{LogName = 'Microsoft-Windows-BitLocker/BitLocker Management'} -MaxEvents 20 | ft -w
Get-WinEvent -FilterHashTable @{LogName = 'System'; providername ='Microsoft-Windows-BitLocker-Driver'} -MaxEvents 20 | ft -w
get-tpm
#winre must be enabled for bitlocker to activate
(reAgentc.exe /info)[3].Split()[-1] #for win10/11
Get-BcdEntry | Select-Object -ExpandProperty Elements | Where-Object name -eq recoveryenabled | Select-Object -ExpandProperty Value #for win11

#enable encryption and backup the recovery key to Entra
Enable-BitLocker -MountPoint 'C:' -UsedSpaceOnly -TpmProtector
Add-BitLockerKeyProtector -MountPoint 'C:' -RecoveryPasswordProtector
BackupToAAD-BitLockerKeyProtector 'C:' -KeyProtectorId (Get-BitLockerVolume 'C:').KeyProtector.Where{$_.KeyProtectorType -eq "RecoveryPassword"}.KeyProtectorId

Import-Module -Name DellBIOSProvider; Gci DellSmbios:\TPMSecurity
gi hklm:SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -ea 0
gci hklm:SOFTWARE\Policies\Microsoft\FVE\ -rec
Confirm-SecureBootUEFI
dsregcmd /status
#force encryption manually
Invoke-Command '\\ad.ilo.org\gva\INFOTEC\TMS\USER SUPPORT\projects\2020 - Laptop Encryption\03 Dev\remediate-bitlocker.ps1' -ComputerName $pc -SessionOption $opt

#change the TPM Platform Validation profile on the go
########## https://www.dell.com/support/kbdoc/en-uk/000129334/bitlocker-fails-to-turn-on-or-prompts-for-the-recovery-key-rebooting-with-windows-10-uefi-and-the-tpm-1-2-firmware
########## https://windowstech.net/change-bitlocker-tpm-platform-validation-profile-on-the-go/
manage-bde -protectors -get c:
$volume = Get-WMIObject -Namespace "root/CIMV2/Security/MicrosoftVolumeEncryption" -Class 'Win32_EncryptableVolume' -Filter "DriveLetter='C:'"
$TPMprotectorID = $volume.getkeyprotectors().VolumeKeyProtectorID | where {$volume.getkeyprotectortype($_).keyprotectortype -eq 1}
$PlatformValidationProfile = $volume.GetKeyProtectorPlatformValidationProfile($TPMprotectorID).PlatformValidationProfile
write-host "Platform Validation Profile = $PlatformValidationProfile"
$TPMver = Get-CimInstance -Namespace root\cimv2\security\microsofttpm -ClassName win32_tpm | %{ (Invoke-Expression $_.SpecVersion)[0] }
if($TPMver -eq 1.2){
	write-host -foreground red 'Setting new validation profile'
	Set-ItemProperty hklm:SOFTWARE\Policies\Microsoft\FVE\ usetpm 0
	manage-bde -protectors -delete -type TPM c:
	Set-ItemProperty hklm:SOFTWARE\Policies\Microsoft\FVE\ usetpm 1
	$volume.ProtectKeyWithTPM("ProtectWithTPM", (0,2,4,11))
	manage-bde -protectors -get c:
}

#display dialog in front/top of all other windows
Add-Type -AssemblyName Microsoft.VisualBasic; [Microsoft.VisualBasic.Interaction]::MsgBox('My message', 'YesNo,SystemModal,Information', 'MyTitle')

#display a certificate selection window
Add-Type -AssemblyName System.Security; using namespace System.Security.Cryptography.X509Certificates
[X509Certificate2UI]::SelectFromCollection([X509Certificate2Collection]::new((ls cert:\localMachine\my)), 'choose wisely', 'Select a certificate', 'SingleSelection')

#display folder selection window in front of all other windows
Add-Type -AssemblyName System.Windows.Forms
[Windows.Forms.FolderBrowserDialog] $FolderBrowser = @{ Description = 'Select the folder containing the data' }
[System.Windows.Forms.Form] $form = @{TopMost = $true }
$result = $FolderBrowser.ShowDialog($form)
if($result -eq [Windows.Forms.DialogResult]::OK){$FolderBrowser.SelectedPath}

# create buttons using modern syntax (without New-Object)
[Windows.Forms.Button] $exitButton = @{
    Location = [Drawing.Point]@{ x = 10; y = 30; }
    Padding  = [Windows.Forms.Padding]@{ all = 8 }
    Name     = 'ExitButton'
    Text     = 'button text...'
    TabIndex = 4
    UseVisualStyleBackColor = $false
}
# $exitButton.add_ ... etc

#get all available types from the loaded assemblies
[AppDomain]::CurrentDomain.GetAssemblies() | %{$_.Location; $_.GetExportedTypes()}

#display messagebox
Add-Type -AssemblyName System.Windows.Forms | Out-Null
$Return = [System.Windows.Forms.MessageBox]::Show("Message", "Title", [System.Windows.Forms.MessageBoxButtons]::OKCancel, [System.Windows.Forms.MessageBoxIcon]::Warning)

#get icon from exe
[System.Drawing.Icon]::ExtractAssociatedIcon("C:\Program Files\Evolis Card Printer\Evolis Premium Suite\EvoPCUI.exe").ToBitmap().Save(($i="$((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path)\icon.png"),'Png');explorer.exe "/select,$i"

#search for AD users using raw user identification data in a file (names, emails), one per line
$email = '(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))'
Get-Content .\project.txt -Encoding UTF8 | ForEach-Object { 
    $u = $_.Trim(); [array]$acc = @()
    if($null -eq ($acc = Get-ADObject -LDAPFilter "(|(name=$u)(samaccountname=$u)(displayName=$u)(userPrincipalName=$u))")){
        if($u -match $email){
            $acc = Get-ADObject -LDAPFilter "(mail=$($Matches[0]))"
        }
    }
    if ($acc.Count -eq 1) {
        Write-Host "$_ = $($acc.name)" -ForegroundColor Green
        #Add-ADGroupMember -Identity GBL-AP-M365-Project-Licensed -Members $acc
    } elseif ($acc.Count -gt 1) {
        Write-Host "$_ = multiple matches found" -ForegroundColor Yellow
    } else {
        Write-Host "$_ = not found" -ForegroundColor Red
    }
}

#send mail
Send-MailMessage -SmtpServer "hq.ilo.ch" -From "noreplyto@ilo.org" -To "paladi@ilo.org" -Subject "[$([System.Net.Dns]::GetHostName())\$($MyInvocation.MyCommand.Name)] Errors occurred" -Body "body of mail" 

#tshoot windows upgrades
$pc='A0118669';$logs="\\ad.ilo.org\configmgr\CONTENT\SOURCES\OSD\WIN10\Issues\upgrade\$pc-$(get-date -Format filedatetime)"
Copy-Item -FromSession (New-PSSession $pc -SessionOption (New-PSSessionOption -nomachineprofile)) 'C:\$WINDOWS.~BT\Sources\Panther' "$logs\Panther" -Force -Recurse -include *.log,*.xml
Copy-Item -FromSession (New-PSSession $pc -SessionOption (New-PSSessionOption -nomachineprofile)) 'C:\$WINDOWS.~BT\Sources\Rollback' "$logs\Rollback" -Force -Recurse -include *.log,*.xml
Copy-Item -FromSession (New-PSSession $pc -SessionOption (New-PSSessionOption -nomachineprofile)) 'C:\ILO\Logs\install-os.log' "$logs" -Force -Recurse
Copy-Item -FromSession (New-PSSession $pc -SessionOption (New-PSSessionOption -nomachineprofile)) 'C:\WINDOWS\logs\SetupDiag\SetupDiagResults.xml' "$logs" -Force -Recurse
cd $logs; & ..\SetupDiag.exe /LogsPath:. ; notepad SetupDiagResults.log

& "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe" --% /applyUpdates -updateType=bios,driver -reboot=disable

#schedule to restart the computer after midnight
Register-ScheduledTask -TaskName Restart -Force -InputObject (
	( New-ScheduledTask `
		-Action (New-ScheduledTaskAction -Execute 'shutdown.exe' -Argument '/r /f') `
		-Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-18') `
		-Settings (New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter 1 -AllowStartIfOnBatteries -MultipleInstances Parallel) `
		-Trigger (New-ScheduledTaskTrigger -Once -At ($at = Get-Date (Get-Date).AddDays(1) -Hour 0))
	) | %{ $_.Triggers[0].EndBoundary = $at.AddHours(1).ToString('s'); $_ })

#get printer driver version
Get-PrinterDriver -Name 'brother*' -ErrorAction Ignore | Select-Object Name, @{n = "DriverVersion"; e = {$ver = $_.DriverVersion;(3..0 | ForEach-Object { ($ver -shr ($_ * 16)) -band 0xffff }) -join '.'}}

#clone printers
Import-Csv .\ILC.csv | ?{$_.Name} | %{$p=Get-PrinterPort HST_cit-test.ilo.ch}{Add-PrinterPort -Name "HSTP_$($_.Name).ilo.ch" -PrinterHostAddress "$($_.Name).ilo.ch" -SNMP $p.SNMPIndex -SNMPCommunity $p.SNMPCommunity -Verbose }
CIT-S17.ilo.ch

#writing to a shared dictionary object (hash table) using running thread jobs that call a function defined externally
$threadSafeDictionary = [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new()
function MyFunction { param($MyParam) "MyFunction: $MyParam" }
$FunctionDefintion = $function:MyFunction.ToString()
1..100 | ForEach-Object -Parallel { 
	$function:MyFunction= $using:FunctionDefintion #cannot call external function directly using $using, so need to recreate it by reusing the its definition
    $dict = $using:threadSafeDictionary
    $dict.TryAdd($(New-Guid), (MyFunction -MyParam $_)) |Out-Null
} -AsJob -throttlelimit 5 | Receive-Job -AutoRemoveJob -Wait
$threadSafeDictionary

# using parallel jobs in winps
$jobs += Start-Job -ScriptBlock {param($arg1,$arg2) ..} -ArgumentList $arg1, $arg2
$results = $jobs | Receive-Job -Wait -AutoRemoveJob

# a better way to do parallel pipeline using multithreading in winps is using PSParallelPipeline (Invoke-Parallel) https://github.com/santisq/PSParallelPipeline/tree/main

############   PARALLEL OPERATIONS
#mass ping (pwsh)
11..40 | % -parallel { ping -n 2 "172.20.32.$_" | sls "pinging" -Context 2 } -ThrottleLimit 20
1..210 | % -parallel { $ProgressPreference=0; Test-NetConnection "10.2.$_.12" -wa 0 | ? PingSucceeded -eq $true | Select RemoteAddress } -ThrottleLimit 20
Get-ADComputer -Filter {enabled -eq $true} | ? distinguishedName -like "*OU=CAI*" | % -Parallel {if(($t = Test-NetConnection $_.name).PingSucceeded){Write-host $_.name $t.RemoteAddress.IPAddressToString }} -ThrottleLimit 10
Get-Content "\\ad.ilo.org\configmgr\CONTENT\SOURCES\Applications\VENDORS\Microsoft\IRTK\Manual\all.txt" | % -Parallel {if(($t = Test-NetConnection $_).PingSucceeded){Write-host $_ $t.RemoteAddress.IPAddressToString }} -ThrottleLimit 10
#find reachable printers from a remote host (winps)
Invoke-Command -ComputerName tnr-fil-01 -ScriptBlock {
    $MyIp = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Get-NetIPAddress -AddressFamily IPv4).IPAddress | Select-Object -First 1
    200..210 | ForEach-Object { 
        Start-Job -ScriptBlock { param($IP); $ProgressPreference = 0; Test-NetConnection $IP -Port 9100 -wa 0} -ArgumentList ($MyIp -replace '\.\d+?$', ".$_")
    } | Receive-Job -Wait -AutoRemoveJob  
}
#using background jobs in winps and gathering the results
$results = Start-Job -ScriptBlock {param($arg1,$arg2) ..} -ArgumentList $arg1, $arg2 | Receive-Job -Wait -AutoRemoveJob

#get current IP address - One of the better ways is to get one of those that'll let you route to 0.0.0.0. e.g. 
(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Get-NetIPAddress -AddressFamily IPv4).IPAddress

#Test if a computer is locked
Get-Process logonui -ea 0
#Locked with a local user session:
if(Get-CimInstance Win32_process -filter "name = 'logonui.exe'" | ? Commandline -match '\s/flags:0x0\b'){'locked'}
#Locked with remote (RDP) user or none:
if(Get-CimInstance Win32_process -filter "name = 'logonui.exe'" | ? Commandline -match '\s/flags:0x2\b'){'locked'}

#find reachable Autopilot-provisioned computers
Get-ADComputer -Filter 'serialnumber -like "*"' -prop serialnumber | % -Parallel {if((Test-NetConnection $name).PingSucceeded){Write-host $name }} -ThrottleLimit 10
gc "\\gva-ats-02.ad.ilo.org\EndPointDevices-PROD\Autopilot\ADOUremediation\ADOUremediation.log" | % -Parallel {if($_ -match '(wks-\S+)'){ if((Test-NetConnection $Matches[0]).PingSucceeded){Write-host $matches[0]} }} -ThrottleLimit 30
#disable User ESP if the device configuration profile hasn't been installed
gci registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\ -Recurse | ? PSChildName -eq DMClient | %{$p="$($_.PSParentPath)\FirstSync"; if(-not(Test-Path $p)){New-Item $p}; New-ItemProperty -Path $p -name SkipUserStatusPage -PropertyType Dword -Value -1 -Force }

# folder size
"{0} MB" -f ((dir C:\users\ -Rec -fo | Measure -P Length -Sum).Sum / 1MB)

# when you need to f-string something with a lot of both kinds of quotes
{'"{0}"'''} -f 'foo'
 
#enable history list view
Set-PSReadLineOption -PredictionViewStyle ListView

#stop a foreach-object pipeline correctly (do NOT use return/break/continue)
class CustomStopUpstreamException : Exception {}
try {
    0..3 | foreach-object {
        if ($_ -eq 2) { throw [CustomStopUpstreamException]::new() }
        $_
    }
} catch [CustomStopUpstreamException] { }
# "foreach" is good if using an IEnumerable result (.NET methods mostly)
# "foreach" is faster at looping but unless you have an IEnumerable above it'll use more memory
# "ForEach-Object" is usually good if dealing with data from other cmdlets/functions as you can stream them
# "foreach" also has a builtin way to break whereas "ForEach-Object" only really has a continue mechanism (you can use "return" to mimick it) and break needs to be manually implemented

# when catching an error, add an object to the error record and pass it on
catch { throw [System.Management.Automation.ErrorRecord]::new(
                $_.Exception, # The exception from the error record caught
                'RequestFailed', # An error ID
                'InvalidOperation', # The ErrorCategory
                $myObject # TargetObject
)}

#check if not connected to AC Power but on Battery power - works both for desktops and laptops
$OnBattery = (Get-WmiObject -Class Win32_Battery | Select-Object -First 1).BatteryStatus -in 1,4,5

#catch uncatchable errors
Do-Something -ea 0 -ev load_error
if(-not $?){Throw $load_error}

#ternary operation in powershell 5
$var = ( "value if False", "value if True" )[$condition]
#ternary operation in powershell 7
$var = $condition ? "value if True" : "value if False"

#get reparsepoint file/dir target 
$path=(Get-Command winget).source;([System.Text.Encoding]::Unicode.GetChars((fsutil.exe reparsepoint query $path | Select-String "[0-9a-f]{4}:\s\s(?:([0-9a-f]{2})\s*)+" -AllMatches | ForEach-Object {$_.Matches.Groups[1].Captures | ForEach-Object {[Convert]::ToInt32($_.Value,16)}})) -join '' -split "`0").TrimEnd("0") | Where {$_} | Select -Last 1

#winget exit codes (in addition to std msi/msix) https://github.com/microsoft/winget-cli/blob/master/src/AppInstallerCommonCore/Public/AppInstallerErrors.h
if (-not ($winget = (Get-Command "winget.exe" -ErrorAction Ignore | Select-Object -First 1).Source)) {if ($wingetPath = Resolve-Path "${env:ProgramFiles}\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe") {Set-Location Filesystem::$(Split-Path $($wingetPath[-1].Path) -Parent);$winget = '.\winget.exe'}}
& $winget list --accept-source-agreements
& $winget install --silent --exact --id Microsoft.Teams --scope machine --accept-package-agreements --accept-source-agreements --log C:\ILO\Logs\install-teams.log
& $winget install --silent --exact --id Microsoft.VCRedist.2015+.x86 --scope machine --accept-package-agreements --accept-source-agreements --log C:\ILO\Logs\Microsoft.VCRedist.2015+.x86.log
& $winget upgrade --silent --exact --id Microsoft.Edge --accept-package-agreements --accept-source-agreements #returns 0x8A15002B if nothing to update
& $winget install --silent --exact --id Microsoft.PowerBI --scope machine --accept-package-agreements --accept-source-agreements --log C:\ProgramData\ILO\Microsoft.PowerBI.log
Invoke-Command -ComputerName $pc -SessionOption (New-PSSessionOption -NoMachineProfile) "\\ad.ilo.org\configmgr\CONTENT\SOURCES\Applications\VENDORS\Dell\Dell BIOS Settings\collect.ps1"

# trigger an immediate update of the Store apps (run as system? or as Entra user?)
Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" | Invoke-CimMethod -MethodName UpdateScanMethod

#for apps that don't install from the system context, create a shortcut with the winget commandline and run it from explorer:
explorer.exe install.lnk

#return an array from a function without unrolling it
return Write-Output -NoEnumerate $array
#or alternatively
return (, $array)

#list user certificates and their cryptographic provider 
certutil -store -user my
#renew user certificate using its serial number
certreq -enroll -user -q -cert 70000338A0CAE690EE3144DF050000000338A0 renew
#pulse autoenrollment event to get the user certificate
certreq -pulse -user
#list available cryptographic providers
certutil -csplist

Get-DeliveryOptimizationStatus �| Select-Object -Property PredefinedCallerApplication,Status,CacheHost,PercentPeerCaching,NumPeers,`
� � @{Name = 'TotalMBytesDownloaded'; Expression = {[math]::Round($_.TotalBytesDownloaded/1MB,2)}},`
� � @{Name = 'MBytesFromPeers'; Expression = {[math]::Round($_.BytesFromPeers/1MB,2)}},`
� � @{Name = 'MBytesFromHttp'; Expression = {[math]::Round($_.BytesFromHttp/1MB,2)}},`
� � @{Name = 'MBytesFromCacheServer'; Expression = {[math]::Round($_.BytesFromCacheServer/1MB,2)}},`
� � @{Name = 'MBytesFromLanPeers'; Expression = {[math]::Round($_.BytesFromLanPeers/1MB,2)}},`
� � @{Name = 'MBytesToLanPeers'; Expression = {[math]::Round($_.BytesToLanPeers/1MB,2)}} | ft

#get and install latest windows updates
$null = Install-Module PSWindowsUpdate -Force
Get-WindowsUpdate -Install -NotTitle "Feature|Preview|Removal" -MicrosoftUpdate -AcceptAll -Verbose 

#get all built-in variables
[PowerShell].Assembly.GetType('System.Management.Automation.SpecialVariables').GetFields('Static,NonPublic') |
    Where-Object FieldType -eq ([string]) |
    ForEach-Object GetValue($null)
	
#enable verbose to see when a module imports implicitly
$PSDefaultParameterValues['Import-Module:Verbose'] = $true

#Get the OU of an account (works even for accounts with comma in the name)
$OU = (Get-ADUser paladi).DistinguishedName -replace '^CN=.+?,(?=(CN|OU|DC)=)'
#another way
$null, $OU = (Get-ADUser paladi).DistinguishedName -split '(?<!\\),', 2

#get the full path to a file without actually resolving it (without testing the actual existance)
$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($relativepath) #use in the global scope, or on the command line
$PSCmdlet.GetUnresolvedProviderPathFromPSPath($relativepath) #in a script, function, or script block with either [CmdletBinding()] or [Parameter()]

#find unreachable field FILE servers (pwsh)
Get-ADComputer -Filter {name -like "*-fil-*"} | ? distinguishedname -notmatch "(OU=GVA)|(OU=EMEA)" | % -Parallel { if(-not(Test-NetConnection $_.name -WarningAction Ignore).pingsucceeded){write-host $_.name}}
#find reachable computers in OU (pwsh)
Get-ADComputer  -Filter {enabled -eq $true} -SearchBase "OU=CPT,OU=MZR,OU=ORG,DC=ad,DC=ilo,DC=org" | % -Parallel { if((Test-NetConnection $_.name -WarningAction Ignore).pingsucceeded){write-host $_.name}}

#check all paths in ENV:PATH (pwsh) for existance
@($env:path.Split([IO.Path]::PathSeparator, [StringSplitOptions]'RemoveEmptyEntries, TrimEntries')).ForEach({ if($_) {$result = 'MISSING |';if(Test-Path -path $_) { $result = '     OK |'};-join($result, ' ', $_); }})

#get play duration of media files using ffprobe, more reliable than COM API
gci | % {ffprobe -i $($_.FullName) -show_entries format=duration -v quiet -of csv="p=0"}

#replace text in file
#  case sensitive
(Get-Content -path $file -Raw).replace($CaseSensitiveTextToBeReplaced, $NewText) | Set-Content -Path $file
#  case insensitive
(Get-Content -path $file -Raw) -replace $RegexToBeReplaced, $NewText | Set-Content -Path $file
(Get-Content -path $file -Raw) -replace [regex]::escape($TextToBeReplaced), $NewText | Set-Content -Path $file
$psHomePath = "$($PSHome.Replace("\syswow64\", "\system32\"), [StringComparison]::OrdinalIgnoreCase))\Modules"
# careful when using -replace : avoid having $$ in the newtext https://stackoverflow.com/a/40683667/7557791
(Get-Content -path $file -Raw) -replace $RegexToBeReplaced, $NewText.replace('$','$$')
# when using WinPS, make sure the you use UTF8 with BOM
$Utf8WithBOM = [System.Text.UTF8Encoding]::new($true)
[System.IO.File]::WriteAllText($TargetFile, ([System.IO.File]::ReadAllText($TargetFile, $Utf8WithBOM) -replace $ReplacePattern, $str.replace('$','$$')) , $Utf8WithBOM)

#list all network connections and ports and owner services
Get-NetTCPConnection | select Local*, Remote*, State,@{n="ProcessName";e={(Get-Process -Id $_.OwningProcess).ProcessName}},@{n="ProcessPath";e={(Get-Process -Id $_.OwningProcess).Path}} | Out-GridView
$p=Get-Process; Get-NetTCPConnection | select Local*, Remote*, State,@{n="ProcessName";e={($p|? Id -eq $_.OwningProcess).ProcessName}},@{n="ProcessPath";e={($p|? Id -eq $_.OwningProcess).Path}} | Out-GridView

#processing AD objects in Parallel (pwsh)
$ADUsers = [System.Collections.Concurrent.ConcurrentBag[psobject]]( Get-ADUser -Filter "enabled -eq 'true'" )
1..6 | Foreach-Object -ThrottleLimit 6 -Parallel {
    $ThreadUsers = $using:ADUsers
    while ( $ThreadUsers.Count ) {
        $item = $null
        $null = $ThreadUsers.TryTake( [ref]$item )
        if ( $null -ne $item ) {
            Set-ADUser $item.ObjectGuid -SetSomeAttribute $ToSomething
        }
    }
}

#ways to get a substring regardless of the length
('1234567890'.ToCharArray() | Select-Object -First 15) -join ''
'1234567890'[0..14] -join ''

#disable Credential Guard https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure?tabs=reg#disable-credential-guard
Set-ItemProperty HKLM:SYSTEM\CurrentControlSet\Control\Lsa LsaCfgFlags 0
Set-ItemProperty HKLM:SOFTWARE\Policies\Microsoft\Windows\DeviceGuard LsaCfgFlags 0


#get all field servers
Get-ADComputer -Filter "OperatingSystem -Like '*Windows Server*' -and Enabled -eq 'True'" | Where-Object DistinguishedName -NotMatch '(OU=GVA,)|(OU=EMEA,)|(OU=Domain)|(OU=FIELDDMZ,)|(OU=FLD,)' | select Name, DistinguishedName

#compressing streams (pwsh 7+)
$inputStream = $destStream = $deflateStream = $null
try {
    $data = [byte[]]::new(16)
    $inputStream = [System.IO.MemoryStream]::new($data)
    Write-Host "Input: $([Convert]::ToHexString($data))"
    $destStream = [System.IO.MemoryStream]::new()
    $deflateStream = [System.IO.Compression.DeflateStream]::new($destStream, [System.IO.Compression.CompressionMode]::Compress)
    $inputStream.CopyTo($deflateStream)
    $deflateStream.Flush()
    Write-Host "Output: $([Convert]::ToHexString($destStream.ToArray()))"
} finally {
    ${deflateStream}?.Dispose()
    ${destStream}?.Dispose()
    ${inputStream}?.Dispose()
}

#cannot pass array parameters to remote sessions, instead do $using: or pass the array inside a hashtable
#to use a function in a remote session, do $using:function
Invoke-Command -Session $DestinationSession -ScriptBlock {
        ${function:Get-InfPath} = ${using:function:Get-InfPath}
        Foreach ($Printer in $using:Printers) {
			Get-InfPath $Printer ...
		}
}

#test if a file name is valid and, if not, remove invalid characters.
$pattern = '[' + [regex]::Escape([string]::new([System.IO.Path]::GetInvalidFileNameChars())) + ']'
$filename = 'file\name"/"<2.txt?'
try { [System.IO.Path]::GetFileName($filename) } catch { [System.IO.Path]::GetFileName($filename -replace $pattern) }

#open the Start menu
add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait("^{Esc}")

#create an array of bytes with random values
([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes(($bytes = [byte[]]::new(32))); $bytes

# launch an app using AppId
## run shell:AppsFolder
## go to View->Details and tick AppUserModelId
## now can launch any app using its Id: "explorer shell:AppsFolder\%AppUserModelId%"

# write a wrapper around a cmdlet while exposing the same parameters 
[System.Management.Automation.ProxyCommand]::Create((Get-Command Get-Command))
# or dynamically
https://github.com/PacktPublishing/Mastering-Windows-PowerShell-Scripting-Fourth-Edition/blob/a771cbea56f7b03ccf6abfb88dc545dc998bc32d/Chapter18/6.3.1.UsingDynamicParams.ps1#L3

#get drivers for installed printer queues
$p=(Get-Printer).driverName;Get-PrinterDriver | ? Name -in $p | Select Name, MajorVersion

#get all printer drivers from the driver store
$all = Get-WindowsDriver -Online -All | ? ClassName -eq Printer | %{Get-WindowsDriver -Online -Driver $($_.OriginalFileName)}
$all | select HardwareDescription, Driver -Unique

#remove printer driver from installed drivers AND DriverStore
Remove-PrinterDriver -Name "HP Universal Printing PCL 6" -RemoveFromDriverStore

#remove printer driver inf from the DriverStore
pnputil.exe /delete-driver oem7.inf /uninstall /force
#check if it was removed successfully
Get-WindowsDriver -Online -Driver oem7.inf

#set proxy for git
git config --global http.proxy http://proxyos:8080
git config --global https.proxy http://proxyos:8080

#get Defender threats
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -FilterXPath "*[System[Level=3]]" | Where-Object { $_.Message -match 'path:' }

#display a check characater
Write-Host ([CHAR]10004) -ForegroundColor Green

#get all available primitive types
[object].Assembly.GetTypes().Where({$_.IsPrimitive})
#get all available enum types
[object].Assembly.GetTypes().Where({$_.IsPublic -and $_.IsEnum})

#get the base64 of a cert
$cert = "C:\Users\paladi\Documents\1.cer"
[System.Convert]::ToBase64String(([System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromCertFile($cert)).Export('Cert'), 'None') | clip.exe
#get the thumbprint/hash of a cert 
([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)).thumbprint

#convert string or script to base64
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Script))

#get the executable type by checking the header
$pe = [System.Reflection.PortableExecutable.PEReader]::new(($s = (gi C:\Windows\System32\regsvr32.exe).OpenRead()))
Write-Host $pe.PEHeaders.PEHeader.Subsystem
$pe.Dispose(); $s.Dispose()

# pwsh uses .NET 5+ (Core). If you need .NET Framework, do this:
$session = New-PSSession -UseWindowsPowerShell
Invoke-Command -Session $session {
    # do the stuff you need net framework for in here
}

#passing functions to external scopes (e.g. foreach -parallel, invoke-command -computername xxx -ScriptBlock {asdf})
function foo{<body>}; function bar{<body>}
Invoke-Command ..... {
    ${function:foo}, ${function:bar} = ${using:function:foo}, ${using:function:bar}
    # you can use foo and bar here
    foo -arg 123 -otherarg hi
}

#convert hex representation (REG_MULTI_SZ) to BYTES then to string (pwsh)
$bytes = [System.Convert]::FromHexString('5c,00,5c,00,3f,00,5c,00,43,00,3a,00,5c,00,55,00,73,00,65,00'.Replace(',', ''))
[text.encoding]::Unicode.GetString($bytes)
#same but for WinPS
[byte[]] $Bytes = '5c,00,5c,00,3f,00,5c,00,43,00,3a,00,5c,00,55,00,73,00,65,00'.Split(',').ForEach{[byte]::parse($_, 'HexNumber')}

#as opposed to Out-File -Enconding UTF8 -Append, Add-Content defaults to UTF8

# comprehensive overview of PowerShell's error handling: https://github.com/MicrosoftDocs/PowerShell-Docs/issues/1583
# "Throw" creates a script-terminating (runspace-terminating) error
# $PScmdlet.ThrowTerminatingError() generates a pipeline terminating error rather than a call stack terminating error. It cancels the remaining pipeline statements. However, if it is called from a try block directly, i.e. not from another command in it, then the catch is not called https://github.com/nightroman/PowerShellTraps/tree/424d9179733367a785913baa3ca05a378c87a6e7/Basic/ThrowTerminatingError/Catch-is-not-called
#   ... Write-Error -ErrorAction Stop may be used as a workaround
# also, 'throw' sometimes does not terminate, so it is best to prefer 'Write-Error -ErrorAction Stop' https://github.com/nightroman/PowerShellTraps/tree/424d9179733367a785913baa3ca05a378c87a6e7/Basic/Throw-may-not-terminate
# A deep dive into exception handling: https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-exceptions
# $PSCmdlet.WriteError() obeys ErrorActionPreference and it is used when there's an error but you don't want the pipeline to stop (typically the input process has a problem)

#test if a file can be open for reading (it is closed or if another process has opened it with FILE_SHARE_READ)
[System.IO.File]::Open($path, 'Open', 'Read', 'ReadWrite').Dispose()

# reset group policy gpo on local computer https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/modern-inbox-store-apps-troubleshooting-guidance#bad-permissions-being-set-on-registry-keys-or-folders
RD /S /Q "%WinDir%\System32\GroupPolicyUsers" && RD /S /Q "%WinDir%\System32\GroupPolicy" 
gpupdate /force

# Windows troubleshooting https://learn.microsoft.com/en-us/troubleshoot/windows-client/welcome-windows-client

# change channel Office 365
"C:\Program Files\Common Files\microsoft shared\ClickToRun\officec2rclient.exe" /changesetting Channel=SemiAnnual
"C:\Program Files\Common Files\microsoft shared\ClickToRun\officec2rclient.exe" /update admin
# downgrade Office 365
"C:\Program Files\Common Files\microsoft shared\ClickToRun\officec2rclient.exe" /update user updatetoversion=16.0.17726.20160

# using __COMPAT_LAYER variable to set compatibility layers when launching an executable https://stackoverflow.com/questions/37878185/what-does-compat-layer-actually-do
cmd /C set __COMPAT_LAYER=WIN7RTM&&start "" %1

ErrorActionPreference enum: Break:6; Continue:2; Ignore:4; Inquire:3; SilentlyContinue:0; Stop:1

# convert hex to utf encoded string
$bytes = [convert]::FromHexString( '686920F09F909220776F726C64' )
$enc8  = [Text.Encoding]::GetEncoding('utf-8') 
$enc8.GetString( $bytes )

# get all types available in the current PS session
[AppDomain]::CurrentDomain.GetAssemblies().GetTypes()

# get all exception types
[System.AppDomain]::CurrentDomain.GetAssemblies().GetTypes() | Where-Object { $_.IsPublic -and -not $_.IsAbstract -and $_.IsSubclassOf([System.Exception]) -and $_.GetConstructors() }

# using regex to normalize a MacAddress
$address -replace '[^a-f0-9]' -replace '.{2}(?!$)', '$0:'

# to do changes on capture groups using the replace operator use a scriptblock as substitute argument, match object is bound to $_
'a b c' -replace '\w',{ $_.Value.ToUpper() }

# wait for user input
$Host.UI.PromptForChoice('Restart?','Would you like to restart now?',('&Yes', '&No'),0)

# modify/read local security policies
https://www.powershellgallery.com/packages?q=Indented.SecurityPolicy

# use the Humanizer library (shipped with pwsh) to convert strings into int
Update-TypeData -TypeName System.String -MemberType ScriptMethod -MemberName AsInt -Value {
    [Humanizer.StringDehumanizeExtensions]::Dehumanize($this) -as [int]
}
'100_000'.AsInt()

# using anonymous (local-only) pipes for interprocess communication
# https://learn.microsoft.com/en-us/dotnet/standard/io/how-to-use-anonymous-pipes-for-local-interprocess-communication

# get volume/partition GUIDs and list their file contents
Get-Partition | ForEach-Object {gci -LiteralPath "\\?\Volume$($_.Guid)\" -Force}
Get-Volume | ForEach-Object {gci -LiteralPath $_.Path -Force}

# start a process as a child of another process
Install-Module -Name ProcessEx
$parentProc = Get-Process -Name SystemSettings
$si = New-StartupInfo -ParentProcess $parentProc
Start-ProcessEx "C:\Program Files (x86)\Microsoft\Edge\Application\*\Installer\setup.exe" -StartupInfo $si -ArgumentList @(
    "--uninstall"
    "--msedge"
    "--channel=stable"
    "--system-level"
    "--verbose-logging"
)

#get certificates and their key usages
Get-ChildItem -Path Cert:\CurrentUser\My -Recurse | ? -not PSIsContainer | %{[pscustomobject]@{keyusage=$_.Extensions.KeyUsages;extendedusage=$_.EnhancedKeyUsageList;subject=$_.Subject}}

#byte comparison of two files
try {
    $bufferSize = 1kb
    $a = (Get-Item .\pathFileA).OpenRead(); $b = (Get-Item .\pathFileB).OpenRead()
    $bufferA = [byte[]]::new($bufferSize); $bufferB = [byte[]]::new($bufferSize)
    while (0 -notin ($lenA = $a.Read($bufferA, 0, $bufferSize)), ($lenB = $b.Read($bufferB, 0, $bufferSize))) {
        $max = [System.Math]::Max($lenA, $lenB)
        for ($i = 0; $i -lt $max; $i++) {
            if ($bufferA[$i] -ne $bufferB[$i]) {
                # handle the difference here, but careful when the tail is different length
            }
        }
    }
} finally { $a.Dispose(); $b.Dispose() }

#check if the session is noninteractive
-not [System.Environment]::UserInteractive -or [System.Environment]::GetCommandLineArgs() -match 'NonInteractive' -or $env:GITHUB_ACTIONS -eq 'true' -or $env:GITLAB_CI -eq 'true'

#capturing non-UTF8 output from native commands 
$origEncoding = [Console]::OutputEncoding; [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
$(try {	& wsl @($InputCommand) } finally { [Console]::OutputEncoding = $origEncoding } ) | Select-String 'default'

#various functions for manipulating windows, their state and position and clicking controls from powershell
https://gist.github.com/indented-automation/cbad4e0c7e059e0b16b4e42ba4be77a1

#get modification datetime of a registry key
using namespace System.Runtime.InteropServices
Import-Module Ctypes
$advapi = New-CtypesLib Advapi32.dll
$reg = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{C2526B3B-B6BC-3684-80FE-8EFD4B1ACF98}\'
$ft = [ComTypes.FILETIME]::new()
$hr = $advapi.CharSet('Unicode').SetLastError().RegQueryInfoKey(
    $reg.Handle,
    <# lpClass: #> $null,
    <# lpcchClass: #> $null,
    <# lpReserved: #> $null,
    <# lpcSubKeys: #> $null,
    <# lpcbMaxSubKeyLen: #> $null,
    <# lpcbMaxClassLen #> $null,
    <# lpcValues: #> $null,
    <# lpcbMaxValueNameLen: #> $null,
    <# lpcbMaxValueLen: #> $null,
    <# lpcbSecurityDescriptor: #> $null,
    [ref] $ft)
if ($hr -ne 0) { 
    throw [System.ComponentModel.Win32Exception]::new($hr) 
} else {
    $ftLow = [System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes($ft.dwLowDateTime), 0)
    $ftHigh = [System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes($ft.dwHighDateTime), 0)
    [datetime]::FromFileTime(([uint64]$ftHigh -shl 32) -bor $ftLow)
}

# COM and dotnet cleanup
[System.runtime.interopservices.marshall]::ReleaseCOMObject($ComObject)
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

# cleanup/rename locked files (in use) at reboot
$Kernel32 = Add-Type -Name Kernel32 -Namespace Win32 -PassThru -MemberDefinition @'
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
if(-Not($Kernel32::MoveFileEx("C:\temp\good.txt", [NullString]::Value, 4))){ # 1st Call to delete the locked original file first!
    throw [ComponentModel.Win32Exception]::new()
}
if(-Not($Kernel32::MoveFileEx("C:\temp\temp.txt", "C:\temp\good.txt", 4))){ # 2nd Call to rename the new temporary file with the old original file name.
    throw [ComponentModel.Win32Exception]::new()
}
# check that the delete and rename operations have been recorded in the session manager and will be acted upon on next reboot
(Get-ItemProperty registry::"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager").PendingFileRenameOperations

# call native APIs in PInvoke in pwsh
# https://github.com/jborean93/PowerShell-ctypes
Install-PSResource -Name Ctypes -Scope AllUsers
$k32 = New-CtypesLib Kernel32.dll
$fs = [IO.File]::Open("$pwd\test.txt", 'Create', 'ReadWrite','None') # opening file handle exclusively
$k32.CharSet('Unicode').SetLastError().DeleteFileW[bool]("$pwd\test.txt")  # attempt to delete file when a handle is still open
$k32.LastErrorMessage # open handles exist, access denied
$fs.Dispose()
$fs = [IO.File]::Open("$pwd\test.txt", 'Create', 'ReadWrite','Delete') # opening file handle witth the FileShare.Delete flag set
$k32.CharSet('Unicode').SetLastError().DeleteFileW[bool]("$pwd\test.txt") # Remove-Item then also works
$k32.LastErrorMessage # success, file is hidden until all handles are closed
$fs.Dispose() # closing the last handle, file gets deleted

#play sound
$player = [System.Media.SoundPlayer]::new()
$player.SoundLocation = 'C:\Windows\Media\Alarm01.wav'
$player.PlaySync()
$player.SoundLocation = 'C:\Windows\Media\Alarm02.wav'
$player.PlaySync()
if ($player -is [IDisposable]) {
  $player.Dispose()
}

# test for valid email address
$Email -match "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

# test for valid IP Addresses (pwsh)
$ip = [System.Net.IPAddress]::Parse("192.168.1.123")
$net = [System.Net.IPNetwork]::Parse("192.168.1.0/24")
$net.Contains($ip)
# for WinPS need to import type first [System.Net.IPNetwork2]
Invoke-WebRequest https://www.nuget.org/api/v2/package/IPNetwork2 -OutFile IPNetwork2.zip
Expand-Archive .\IPNetwork2.zip
Add-Type -Path .\IPNetwork2\lib\netstandard2.0\System.Net.IPNetwork.dll

# get open ports with process owner info
netstat -bano

# get all available type accelerators
[ref].Assembly.GetType('System.Management.Automation.TypeAccelerators')::get.GetEnumerator() | Sort-Object Key

# GUI for PowerShell:
# https://github.com/mdgrs-mei/WinUIShell
# https://gitlab.com/poshAJ/PoshGUIExample

# check valid user accounts with email addresses
$Users = Get-ADObject -LDAPFilter "(&(objectCategory=person)(objectClass=User)(!samaccountname=a-*)(!samaccountname=s-*)(!samaccountname=mr-*)(mail=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" | 
    Where-Object DistinguishedName -match ',OU=PRV,OU=USR,'
# add them to a group
Compare-Object -ReferenceObject $Users -DifferenceObject (Get-ADGroupMember -Identity GVA-AP-SigningCertificate) -Property ObjectGUID -PassThru | 
    Where-Object SideIndicator -eq '<=' |
    Add-ADPrincipalGroupMembership -MemberOf GVA-AP-SigningCertificate -Verbose

# load script online and run it with parameters
[powershell]::Create().AddScript((irm https://christitus.com/win)).AddParameters(@{
    Config = 'C:\User\ctt.json'
    Run    = $true
}).BeginInvoke()

# without parameters (iex does not create new scope)
iwr -UseB https://raw.githubusercontent.com/PowershellFrameworkCollective/PSFramework.NuGet/refs/heads/master/bootstrap.ps1 | iex

# convert Windows timezone into IANA (https://en.wikipedia.org/wiki/Tz_database) (https://en.wikipedia.org/wiki/List_of_tz_database_time_zones)
[System.TimeZoneInfo]::TryConvertWindowsIdToIanaId("W. Europe Standard Time", [ref] $t)
[System.TimeZoneInfo]::TryConvertWindowsIdToIanaId("W. Europe Standard Time", 'AT', [ref] $t)

# get the param block of a cmdlet
[System.Management.Automation.ProxyCommand]::GetParamBlock((Get-Command Get-ChildItem))
# then use it to create a proxy 
function Get-ChildItem2 {
    param(
        # paste the original param block here
    )
    Get-ChildItem @PSBoundParameters
}

# convert unicode bytes in a registry value to string
filter RegString { if ($_ -is [string]) { $_ } else { [Text.Encoding]::UTF8.GetString($_) } }
Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" -Name "HardwareInformation.*" -ErrorAction Ignore | 
Select @{Name="Adapter";Expr={ ,$_.'HardwareInformation.AdapterString' | RegString}},
         @{Name="Memory";Expr={ $_."HardwareInformation.qwMemorySize" }} | 
Out-String -Input { "{0} {1:0}GB" -f $_.Adapter, ($_.Memory/1gb) }

# download zip file to memory and decompress it
$response = Invoke-RestMethod -Uri $apiUrl -Headers @{ 'User-Agent' = 'PowerShell' }
$asset = $response.assets | Where-Object { $_.name -like '*.zip' }
Invoke-WebRequest $asset.browser_download_url | Get-ZipEntry | Expand-ZipEntry $targetDir

#compact a path using shlwapi.dll PathCompactPathEx function
$shl = New-CtypesLib Shlwapi.dll
$out = [Text.StringBuilder]::new( 61 )
$shl.CharSet('Unicode').SetLastError().PathCompactPathEx[bool]( $out, 'C:\users\matt\OneDrive - My Company Name\Main\MyApp\MyAppPackage\myProcess.exe', 60, 0 )
$out.ToString() # C:\users\matt\OneDrive - My Company Name\M...\myProcess.exe


Gargamel@19!
Admin-1
Sharp!5070

sn55068761.ilo.ch
sn4509684y.ilo.ch

Fix "download pending" in the Company Portal:
 I get this issue sometimes when testing out apps. I’ve had to fix it by going into Apps and Features, do Advanced Settings for Company Portal,and then do Terminate, Repair, and Reset. All 3 settings.
 Then what I tend to do is restart the Microsoft Intune Management Extension in services.msc, then open company portal, logout and log back in.
