--- https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-sql-for-wmi
--- Anytime you see a piece of data shown in the console that you want to use then your first stop is smsprov.log on the MP server. 
---  In there you will find the WQL and SQL queries for everything you see in the console. So open it up in cmtrace, do something in the console to show that data, then stop cmtrace's autoupdate, and find your query.

-- Wildcards	
% - any number of characters
_ - one character

-- SMS_R_System and SMS_G_System: The first one is a discovery class, so it exists of every discovered device and the second is a inventory class and only exists of installed clients that ran an inventory.

-- export the result of queries as CSV: "\\ad.ilo.org\configmgr\CONTENT\SOURCES\Applications\ILO\PSModules\Export-CMQueryOutput.ps1"

-- get devices with secure boot disabled
select SMS_R_System.Name, SMS_G_System_FIRMWARE.SecureBoot, SMS_R_System.SystemOUName, SMS_G_System_OPERATING_SYSTEM.BuildNumber, SMS_G_System_OPERATING_SYSTEM.Name
from SMS_R_System 
inner join SMS_G_System_FIRMWARE on SMS_G_System_FIRMWARE.ResourceID = SMS_R_System.ResourceId 
inner join SMS_G_System_WORKSTATION_STATUS on SMS_G_System_WORKSTATION_STATUS.ResourceId = SMS_R_System.ResourceId 
inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId
where SMS_G_System_FIRMWARE.SecureBoot = 0
    And SMS_G_System_OPERATING_SYSTEM.Name LIKE "%Windows 10%"
	And SMS_G_System_WORKSTATION_STATUS.LastHardwareScan > DateAdd(dd,-30,GetDate())
	
-- get devices with a specific deployment (AssignmentID) in error status
select SYS.Name,offer.AppName,offer.ComplianceState,offer.EnforcementState,offer.ErrorCode,offer.ExtendedInfoID,offer.StatusType,offer.AppStatusType
	from sms_r_system as sys 
	inner join SMS_AppDeploymentErrorAssetDetails as offer on sys.ResourceID=offer.MachineID
where offer.AssignmentID=16779149 And (offer.ComplianceState=4 Or offer.ExtendedInfoID=5002)

-- get devices with topconsoleusers from a specific OU
select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client 
from SMS_R_System 
	inner join SMS_G_System_SYSTEM_CONSOLE_USAGE on SMS_G_System_SYSTEM_CONSOLE_USAGE.ResourceID = SMS_R_System.ResourceId 
	inner join SMS_R_User on Upper(SMS_R_User.UniqueUserName) = Upper(SMS_G_System_SYSTEM_CONSOLE_USAGE.TopConsoleUser)  
where SMS_R_User.UserOUName like "%MNL/USR%"

-- get devices with topconsoleusers from specific departments
select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client 
from SMS_R_System       
	inner join SMS_G_System_SYSTEM_CONSOLE_USAGE on SMS_G_System_SYSTEM_CONSOLE_USAGE.ResourceID = SMS_R_System.ResourceId      
	inner join SMS_R_User on Upper(SMS_R_User.UniqueUserName) = Upper(SMS_G_System_SYSTEM_CONSOLE_USAGE.TopConsoleUser)  
where SMS_R_User.Department = "TMS"  or SMS_R_User.Department = "AMS"  or SMS_R_User.Department = "PGMS"  or SMS_R_User.Department = "INFOTEC"

-- Emails of TopConsoleUsers from a specific Department whose devices reported an old BIOS version within the last 3 weeks
select SMS_R_System.Name, SMS_R_System.LastLogonUserName
        , SMS_G_System_PC_BIOS.SMBIOSBIOSVersion
        , SMS_G_System_WORKSTATION_STATUS.LastHardwareScan
        , SMS_G_System_SYSTEM_CONSOLE_USAGE.TopConsoleUser
        , SMS_R_User.mail, SMS_R_User.Department
from SMS_R_System 
    inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceId 
    inner join SMS_G_System_PC_BIOS on SMS_G_System_PC_BIOS.ResourceID = SMS_R_System.ResourceId 
    inner join SMS_G_System_WORKSTATION_STATUS on SMS_G_System_WORKSTATION_STATUS.ResourceID = SMS_R_System.ResourceId 
    inner join SMS_G_System_SYSTEM_CONSOLE_USAGE on SMS_G_System_SYSTEM_CONSOLE_USAGE.ResourceID = SMS_R_System.ResourceId
    inner join SMS_R_User on Upper(SMS_R_User.UniqueUserName) = Upper(SMS_G_System_SYSTEM_CONSOLE_USAGE.TopConsoleUser)
where SMS_G_System_COMPUTER_SYSTEM.Model LIKE "Latitude 7_80" 
    and (SMS_G_System_PC_BIOS.SMBIOSBIOSVersion < "1.18" OR SMS_G_System_PC_BIOS.SMBIOSBIOSVersion LIKE "1._.%")
    and SMS_R_User.Department = "TMS"
    and SMS_G_System_WORKSTATION_STATUS.LastHardwareScan > DateAdd(dd,-21,GetDate())	

--- TopConsoleUser and LastLogonUser for all devices
select SMS_R_System.Name, SMS_R_System.LastLogonUserName
        , SMS_G_System_WORKSTATION_STATUS.LastHardwareScan
        , SMS_G_System_SYSTEM_CONSOLE_USAGE.TopConsoleUser
from SMS_R_System 
    inner join SMS_G_System_WORKSTATION_STATUS on SMS_G_System_WORKSTATION_STATUS.ResourceID = SMS_R_System.ResourceId 
    inner join SMS_G_System_SYSTEM_CONSOLE_USAGE on SMS_G_System_SYSTEM_CONSOLE_USAGE.ResourceID = SMS_R_System.ResourceId
    inner join SMS_R_User on Upper(SMS_R_User.UniqueUserName) = Upper(SMS_G_System_SYSTEM_CONSOLE_USAGE.TopConsoleUser)

	
select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client 
	from SMS_R_System inner join SMS_G_System_SYSTEM on SMS_G_System_SYSTEM.ResourceID = SMS_R_System.ResourceId 
	where SMS_G_System_SYSTEM.Name like 'BKK-LAB%'

--- get devices whose TopConsoleUser is in a specific user collection
select * from  SMS_R_System 
inner join SMS_G_System_SYSTEM_CONSOLE_USAGE 
	on SMS_G_System_SYSTEM_CONSOLE_USAGE.ResourceID = SMS_R_System.ResourceId
inner join SMS_CM_RES_COLL_GVA002A3
	on SMS_CM_RES_COLL_GVA002A3.SMSID = SMS_G_System_SYSTEM_CONSOLE_USAGE.TopConsoleUser

--- get TopConsoleUsers for each device in a specific collection
select SMS_R_User.Mail, SMS_R_User.l, SMS_R_User.department, SMS_R_User.displayName, SMS_R_User.title, SMS_R_System.Name from SMS_R_User 
	inner join SMS_G_System_SYSTEM_CONSOLE_USAGE on Upper(SMS_G_System_SYSTEM_CONSOLE_USAGE.TopConsoleUser)=SMS_R_User.UniqueUserName
	inner join SMS_R_System on SMS_R_System.ResourceId=SMS_G_System_SYSTEM_CONSOLE_USAGE.ResourceId
	inner join SMS_FullCollectionMembership on SMS_FullCollectionMembership.ResourceId=SMS_R_System.ResourceId
where
	SMS_FullCollectionMembership.CollectionID = "ILO00492"

--- get Primary Users for each device in a specific collection
select SMS_R_User.Mail, SMS_R_User.l, SMS_R_User.department, SMS_R_User.displayName, SMS_R_User.title, SMS_R_System.Name from SMS_R_User 
	left JOIN SMS_UserMachineRelationship ON SMS_UserMachineRelationship.UniqueUserName = SMS_R_User.UniqueUserName 
	inner join SMS_R_System on SMS_R_System.ResourceId=SMS_UserMachineRelationship.ResourceID
	inner join SMS_FullCollectionMembership on SMS_FullCollectionMembership.ResourceId=SMS_R_System.ResourceId
where
	SMS_FullCollectionMembership.CollectionID = "ILO00492"
	AND SMS_UserMachineRelationship.IsActive = 1




--- get LastlogonUser for each device in a specific collection
select SMS_R_User.Mail, SMS_R_User.l, SMS_R_User.department, SMS_R_User.displayName, SMS_R_User.title, SMS_R_System.Name from SMS_R_User 
	inner join SMS_R_System on SMS_R_System.LastLogonUserName=SMS_R_User.UserName
	inner join SMS_FullCollectionMembership on SMS_FullCollectionMembership.ResourceId=SMS_R_System.ResourceId
where
	SMS_FullCollectionMembership.CollectionID = "ILO003B5"

--- get LastlogonUser and TopConsoleUsers combined for each device in a specific collection
select Distinct SMS_R_User.UserName, SMS_R_User.Mail, SMS_R_User.l, SMS_R_User.department, SMS_R_User.displayName, SMS_R_User.title from SMS_R_User 
where ResourceId in (
	select ResourceId from SMS_R_User 
		inner join SMS_G_System_SYSTEM_CONSOLE_USAGE on Upper(SMS_G_System_SYSTEM_CONSOLE_USAGE.TopConsoleUser)=SMS_R_User.UniqueUserName
		inner join SMS_R_System on SMS_R_System.ResourceId=SMS_G_System_SYSTEM_CONSOLE_USAGE.ResourceId
		inner join SMS_FullCollectionMembership on SMS_FullCollectionMembership.ResourceId=SMS_R_System.ResourceId
	where
		SMS_FullCollectionMembership.CollectionID = "ILO003B5"
	) 
OR ResourceId in (
	select ResourceId from SMS_R_User 
		inner join SMS_R_System on SMS_R_System.LastLogonUserName=SMS_R_User.UserName
		inner join SMS_FullCollectionMembership on SMS_FullCollectionMembership.ResourceId=SMS_R_System.ResourceId
	where
		SMS_FullCollectionMembership.CollectionID = "ILO003B5"
	)

---- get devices with last logon user present in a user collection
select *  from  SMS_R_System as Sys where Sys.LastLogonUserName in (select UserName from SMS_R_User Users
		inner join SMS_CM_RES_COLL_ILO00356 Col on Col.ResourceID = Users.ResourceID)

---- get devices with primary user present in a user collection
SELECT *  FROM SMS_R_System
  INNER JOIN SMS_UserMachineRelationship ON SMS_UserMachineRelationship.ResourceId = SMS_R_System.ResourceId
  INNER JOIN SMS_R_User Users ON SMS_UserMachineRelationship.UniqueUserName = Users.UniqueUserName
  INNER JOIN SMS_CM_RES_COLL_ILO00356 Col on Col.ResourceID = Users.ResourceID
  WHERE
   SMS_UserMachineRelationship.Types = 1

		
----- get primary users for all devices
SELECT SMS_R_System.name, SMS_R_User.UniqueUserName
  FROM SMS_R_System
  INNER JOIN SMS_UserMachineRelationship ON SMS_UserMachineRelationship.ResourceId = SMS_R_System.ResourceId
  INNER JOIN SMS_R_User ON SMS_UserMachineRelationship.UniqueUserName = SMS_R_User.UniqueUserName
  WHERE
   SMS_UserMachineRelationship.Types = 1
   
---- get PrimaryUser, CurrentLogonUser, LastLogonUser, UserName
select Name, PrimaryUser, CurrentLogonUser, LastLogonUser, UserName from SMS_CombinedDeviceResources
	
--- get devices whose TopConsoleUser is in a specific AD group	
select * from SMS_R_System 
inner join SMS_G_System_SYSTEM_CONSOLE_USAGE on SMS_G_System_SYSTEM_CONSOLE_USAGE.ResourceID = SMS_R_System.ResourceId 
where UPPER(SMS_G_System_SYSTEM_CONSOLE_USAGE.TopConsoleUser) in (SELECT SMS_R_USER.UniqueUserName from SMS_R_User where SMS_R_User.UserGroupName = "ILO\\GBL-AP-QA-TMS-USER-SUPPORT")

--- get active devices with a specific 32bit app installed having the version lower than required
select * from SMS_R_System 
inner join SMS_G_System_ADD_REMOVE_PROGRAMS on SMS_G_System_ADD_REMOVE_PROGRAMS.ResourceID = SMS_R_System.ResourceId 
inner join SMS_G_System_CH_ClientSummary on SMS_G_System_CH_ClientSummary.ResourceId = SMS_R_System.ResourceId 
where 
	SMS_G_System_ADD_REMOVE_PROGRAMS.DisplayName LIKE "%Cisco AnyConnect Secure Mobility Client%" 
	and SMS_G_System_ADD_REMOVE_PROGRAMS.Version < "4.5.05030"
	and SMS_G_System_CH_ClientSummary.ClientActiveStatus = 1

--- get active devices with a specific 64bit app installed having the version lower than required
select * from SMS_R_System 
inner join SMS_G_System_ADD_REMOVE_PROGRAMS_64 on SMS_G_System_ADD_REMOVE_PROGRAMS_64.ResourceId = SMS_R_System.ResourceId
inner join SMS_G_System_CH_ClientSummary on SMS_G_System_CH_ClientSummary.ResourceId = SMS_R_System.ResourceId 
where 
	SMS_G_System_ADD_REMOVE_PROGRAMS_64.DisplayName LIKE "%Cisco AnyConnect Secure Mobility Client%" 
	and SMS_G_System_ADD_REMOVE_PROGRAMS.Version < "4.5.05030"
	and SMS_G_System_CH_ClientSummary.ClientActiveStatus = 1

--- get active devices with a specific 32bit app installed having been scanned recently
select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client 
from SMS_R_System 
inner join SMS_G_System_LastSoftwareScan on SMS_G_System_LastSoftwareScan.ResourceId = SMS_R_System.ResourceId 
inner join SMS_G_System_ADD_REMOVE_PROGRAMS on SMS_G_System_ADD_REMOVE_PROGRAMS.ResourceID = SMS_R_System.ResourceId 
inner join SMS_G_System_CH_ClientSummary on SMS_G_System_CH_ClientSummary.ResourceId = SMS_R_System.ResourceId 
where SMS_G_System_LastSoftwareScan.LastScanDate > DateAdd(dd,-7,GetDate())	
	and SMS_G_System_ADD_REMOVE_PROGRAMS.ProdID = '{0C8D5FDB-111E-4F8C-B469-5F330066410E}'
	and SMS_G_System_CH_ClientSummary.ClientActiveStatus = 1

select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client 
from SMS_R_System 
inner join SMS_G_System_ADD_REMOVE_PROGRAMS on SMS_G_System_ADD_REMOVE_PROGRAMS.ResourceID = SMS_R_System.ResourceId 
where SMS_G_System_ADD_REMOVE_PROGRAMS.ProdID = '{90150000-0011-0000-0000-0000000FF1CE}'
	

----Machines Which Has Last Software Scan ( WQL Query)
select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client 
from SMS_R_System 
inner join SMS_G_System_LastSoftwareScan on SMS_G_System_LastSoftwareScan.ResourceId = SMS_R_System.ResourceId 
where SMS_G_System_LastSoftwareScan.LastScanDate < DateAdd(dd,-30,GetDate())	

--- get devices that are members of 2 collections at the same time
select * from SMS_R_System 
where 
	ResourceID in (select ResourceID from SMS_FullCollectionMembership Where CollectionID = "GVA000C5") 
	AND	ResourceID in (select ResourceID from SMS_FullCollectionMembership Where CollectionID = "GVA0028A")

--- get users that are members of a specific AD group
select * from SMS_R_User where SMS_R_User.UserGroupName = "ILO\\GVA-AP-ALL-CCLEANER"

--- get systems with specific software, prompting the user for the name
select distinct SMS_R_System.Name, SMS_G_System_SYSTEM_CONSOLE_USAGE.TopConsoleUser, SMS_G_System_INSTALLED_SOFTWARE.ProductName, SMS_G_System_INSTALLED_SOFTWARE.ProductVersion from  SMS_R_System 
inner join SMS_G_System_SYSTEM_CONSOLE_USAGE on SMS_G_System_SYSTEM_CONSOLE_USAGE.ResourceID = SMS_R_System.ResourceId 
inner join SMS_G_System_INSTALLED_SOFTWARE on SMS_G_System_INSTALLED_SOFTWARE.ResourceID = SMS_R_System.ResourceId 
where 
	SMS_G_System_INSTALLED_SOFTWARE.ProductName like ##PRM:SMS_G_System_INSTALLED_SOFTWARE.ProductName##
order by SMS_R_System.Name

select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System 
inner join SMS_G_System_SoftwareProduct on SMS_G_System_SoftwareProduct.ResourceId = SMS_R_System.ResourceId 
inner join SMS_G_System_WORKSTATION_STATUS on SMS_G_System_WORKSTATION_STATUS.ResourceId = SMS_R_System.ResourceId 
where SMS_G_System_SoftwareProduct.ProductName like "Java(TM) 6 %" and 
	  SMS_G_System_WORKSTATION_STATUS.LastHardwareScan > DateAdd(dd,-21,GetDate())


---- query the networkprinters which is collecgted from the registry
select SMS_R_System.Name, SMS_G_System_NETWORKPRINTERS.* from  SMS_R_System 
inner join SMS_G_System_NETWORKPRINTERS on SMS_G_System_NETWORKPRINTERS.ResourceID = SMS_R_System.ResourceId 
where 
	(DATEDIFF(day, SMS_G_System_NETWORKPRINTERS.DateInventoried, getdate()) < 40)

---- TESTs

select * from SMS_R_System 
inner join SMS_G_System_SYSTEM_CONSOLE_USAGE on SMS_G_System_SYSTEM_CONSOLE_USAGE.ResourceID = SMS_R_System.ResourceId 
left outer join SMS_CM_RES_COLL_ILO002EC on SMS_G_System_SYSTEM_CONSOLE_USAGE.TopConsoleUser = SMS_CM_RES_COLL_ILO002EC.SMSID
inner join SMS_G_System_INSTALLED_SOFTWARE on SMS_G_System_INSTALLED_SOFTWARE.ResourceID = SMS_R_System.ResourceId 
where 
	SMS_CM_RES_COLL_ILO002EC.ResourceID is Null
	AND SMS_G_System_INSTALLED_SOFTWARE.ProductName = "Microsoft Office Professional Plus 2013"

select * from SMS_R_System 
inner join SMS_G_System_SYSTEM_CONSOLE_USAGE on SMS_G_System_SYSTEM_CONSOLE_USAGE.ResourceID = SMS_R_System.ResourceId 
inner join SMS_G_System_INSTALLED_SOFTWARE on SMS_G_System_INSTALLED_SOFTWARE.ResourceID = SMS_R_System.ResourceId 
where 
 SMS_G_System_INSTALLED_SOFTWARE.ProductName = "Microsoft Office Professional Plus 2013"
