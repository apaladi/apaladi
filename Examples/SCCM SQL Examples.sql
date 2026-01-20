--- initialize standard Report Server variables to be able to test the queries by running them from the SQL Management Studio directly
Declare @UserSIDs as nvarchar(250) = 'disabled'
Declare @locale as nvarchar(250) = 'en-us'
Declare @lcid as int set @lcid = dbo.fn_LShortNameToLCID(@locale)

--- supported SCCM SQL views
https://learn.microsoft.com/en-us/mem/configmgr/develop/core/understand/sqlviews/create-custom-reports-using-sql-server-views
https://docs.microsoft.com/en-us/mem/configmgr/develop/core/understand/sqlviews/create-custom-reports-using-sql-server-views
https://www.recastsoftware.com/resources/what-are-the-supported-sql-server-views-to-use-with-sccm-reporting/

--- v_R_System_Valid : Lists all discovered system resources that are not in an obsolete or decommissioned state. This view is a subset of the v_R_System view

--- get the result/output from a specific action step of a Task Sequence that ran on client computers
SELECT  
 Rsys.Netbios_Name0,
 ExecutionTime, 
 ActionName,
 LastStatusMessageID, 
 LastStatusMessageIDName, 
 ExitCode, 
 ActionOutput 
FROM fn_rbac_TaskExecutionStatus(@UserSIDs)  tse 
JOIN fn_rbac_R_System(@UserSIDs) Rsys ON tse.ResourceID=Rsys.ResourceID 
WHERE AdvertisementID='ILO200D9' AND ActionName='Save to AD if no backup'

--- get devices with user information, excluding duplicates by selecting those with latest Active Time
SELECT RV.Netbios_Name0 as 'Computer'
	, CS.LastActiveTime as 'Last Active'
	, isnull(SCUM.TopConsoleUser0,isnull(CDR.CurrentLogonUser, isnull(RV.User_Domain0+'\'+RV.User_Name0,'n/a'))) as 'UserName'  --'
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

--- get history of devices using a given IP address
SELECT SYS.Netbios_Name0, Netcard.Description0, Netcard.MACAddress0, Netconfig.IPAddress0, Netconfig.TimeStamp
FROM 
	dbo.v_HS_NETWORK_ADAPTER_CONFIGUR AS Netconfig INNER JOIN 
    dbo.v_GS_NETWORK_ADAPTER AS Netcard ON 
			Netcard.ResourceID = Netconfig.ResourceID AND
			Netcard.MACAddress0 = Netconfig.MACAddress0 LEFT JOIN 
	dbo.v_R_System AS SYS ON SYS.ResourceID = Netcard.ResourceID 
WHERE Netconfig.IPAddress0 LIKE '%10.216.8.104%'
ORDER BY Netconfig.TimeStamp

--- notification and software center gui settings for each application/deployment
SELECT AssignmentName ,CollectionName ,NotifyUser ,UserUIExperience , ApplicationName FROM v_ApplicationAssignment

--- devices with Software Products which don't have an exe file present
SELECT RS.[Name0]
	  ,[AD_Site_Name0]
      ,RS.[User_Name0]
	  ,RS.Last_Logon_Timestamp0
	  ,SP.DisplayName0
	  ,SP.Version0
	  ,SP.ProdID0
  FROM [CM_ILO].[dbo].[v_R_System] RS
  inner join [v_Add_Remove_Programs] SP on SP.ResourceID = RS.ResourceID
  LEFT JOIN (
	SELECT ResourceID FROM [v_GS_SoftwareFile] 
	WHERE [FileName] ='DellCommandUpdate.exe' 
		AND ( [FilePath] = 'C:\Program Files\WindowsApps\DellInc.DellCommandUpdate_3.1.111.0_x64__htrsf667h5kn2\Main\'
			OR [FilePath] = 'C:\Program Files (x86)\Dell\CommandUpdate\' )
  ) SF on SF.ResourceID = RS.ResourceID 
  WHERE SP.DisplayName0 LIKE 'Dell Command%'
	AND SP.Version0 LIKE '3.%'
	AND SF.ResourceID is null

'--- OU paths
Select sys.name0 as 'Computer Name', MAX(cs.system_ou_name0) as 'OU Path'
from v_R_System sys
LEFT JOIN dbo.v_RA_System_SystemOUName cs on sys.ResourceID = cs.ResourceID
GROUP BY sys.name0

---Users of this device in the last 90 days
SELECT SD.Name0 as 'Name', CUD.LastConsoleUse00, CUD.SystemConsoleUser00, CUD.TotalUserConsoleMinutes00 
FROM dbo.System_DISC as SD
JOIN dbo.SYSTEM_CONSOLE_USER_DATA as CUD on CUD.MachineID = SD.ItemKey
Where CUD.LastConsoleUse00 >= (GetDate() - 90)
ORDER BY SD.Name0

-- get users from a collection that use computers with specific software
SELECT vrs.Name0 as 'Name'
	, vscu.[TimeStamp] AS 'Last Logon'
	, vscu.TopConsoleUser0
FROM [dbo].v_R_System as vrs
INNER join [dbo].v_CH_ClientSummary as CS on CS.ResourceID = vrs.ResourceID 
INNER JOIN [dbo].[v_GS_SYSTEM_CONSOLE_USAGE_MAXGROUP] as vscu on vrs.ResourceID = vscu.ResourceID
INNER JOIN [dbo].[_RES_COLL_ILO001A4] as col on col.SMSID = vscu.TopConsoleUser0
inner join [dbo].v_Add_Remove_Programs varp on vrs.ResourceID = varp.ResourceID 
where 
	varp.ProdID0 = '{AC76BA86-1033-FFFF-7760-0E0F06755100}' 
	and cs.ClientActiveStatus = 1
ORDER BY vrs.Name0

--- get devices with topconsoleuser and lastlogon
SELECT vrs.Name0 as 'Computer'
	, cs.LastActiveTime AS 'Last Active'
	, vscu.TopConsoleUser0 As 'Top Console User'
	, vrs.User_Name0 As 'Last Logged On User'
FROM [dbo].v_R_System as vrs
INNER join [dbo].v_CH_ClientSummary as CS on CS.ResourceID = vrs.ResourceID 
INNER JOIN [dbo].[v_GS_SYSTEM_CONSOLE_USAGE_MAXGROUP] as vscu on vrs.ResourceID = vscu.ResourceID


---- SQL query that compares product versions correctly (same as PowerShell "version", not as string)
---- doesn't work for versions that have a leading zero 18.011.200400
SELECT v_R_System.Name0, v_GS_INSTALLED_SOFTWARE.ProductName0, v_GS_INSTALLED_SOFTWARE.ProductVersion0
FROM v_R_System
INNER JOIN v_GS_INSTALLED_SOFTWARE ON v_R_System.ResourceID = v_GS_INSTALLED_SOFTWARE.ResourceID
WHERE
	(v_GS_INSTALLED_SOFTWARE.ProductName0 LIKE N'citrix receiver 4%')
	AND (cast('/' + v_GS_INSTALLED_SOFTWARE.ProductVersion0 + '/' AS HIERARCHYID) < cast('/14.9.0.2539/' AS HIERARCHYID))
ORDER BY v_R_System.Name0

---- All logons for all devices
SELECT v_HS_SYSTEM_CONSOLE_USER.TimeStamp
	, v_HS_SYSTEM_CONSOLE_USER.SystemConsoleUser0
	, v_R_System.Name0, dbo.v_R_System.AD_Site_Name0
	, v_GS_PC_BIOS.Manufacturer0
	, v_GS_PC_BIOS.SerialNumber0
	, v_GS_COMPUTER_SYSTEM.Model0
FROM  v_R_System 
	INNER JOIN v_HS_SYSTEM_CONSOLE_USER ON v_R_System.ResourceID = v_HS_SYSTEM_CONSOLE_USER.ResourceID
	JOIN v_GS_PC_BIOS on v_R_System.ResourceID =  v_GS_PC_BIOS.ResourceID 
	JOIN v_GS_COMPUTER_SYSTEM on v_R_System.ResourceID = v_GS_COMPUTER_SYSTEM.ResourceID

----- devices with logon
SELECT v_R_System.Last_Logon_Timestamp0
	, User_Name0
	, v_R_System.Name0
	, v_R_System.AD_Site_Name0
	, v_GS_PC_BIOS.Manufacturer0
	, v_GS_PC_BIOS.SerialNumber0
	, v_GS_COMPUTER_SYSTEM.Model0
FROM     dbo.v_R_System 
	JOIN v_GS_PC_BIOS on v_R_System.ResourceID =  v_GS_PC_BIOS.ResourceID 
	JOIN v_GS_COMPUTER_SYSTEM on v_R_System.ResourceID = v_GS_COMPUTER_SYSTEM.ResourceID

---- superceded apps referenced in Task Sequences which then fail during deployments
---- https://www.asquaredozen.com/2018/04/18/task-sequence-failure-the-software-could-not-be-found-on-any-servers-at-this-time-caused-by-retired-superseded-applications/
Declare @TaskSequenceID char(8); 
set @TaskSequenceID = 'ilo000e4'

SELECT
    CI.CI_ID,
    CI.CI_UniqueID,
    CI.Manufacturer,
    CI.DisplayName,
    CI.SoftwareVersion,
    ARF.ToApplication as RetiredSupersededApp
FROM
    v_TaskSequenceAppReferencesInfo INNER JOIN
    fn_ListLatestApplicationCIs(1033) CI ON CI.CI_ID = v_TaskSequenceAppReferencesInfo.RefAppCI_ID INNER JOIN
    (
        select 
            locpropFromapp.CI_ID as FromAppCI,
            locpropFromapp.DisplayName as FromApp,
            locpropFromDT.DisplayName as FromDeploymentType,
            locpropToapp.DisplayName as ToApplication, 
            locpropToDT.DisplayName as ToDeploymentType 
        from  
            vSMS_AppRelation_Flat as appflat
            JOIN v_LocalizedCIProperties as locpropFromapp ON locpropFromapp.CI_ID = appflat.FromApplicationCIID
            JOIN v_LocalizedCIProperties as locpropFromDT ON locpropFromDT.CI_ID = appflat.FromDeploymentTypeCIID
            JOIN v_LocalizedCIProperties as locpropToapp ON locpropToapp.CI_ID = appflat.ToApplicationCIID
            JOIN v_LocalizedCIProperties as locpropToDT ON locpropToDT.CI_ID = appflat.ToDeploymentTypeCIID
            JOIN v_ConfigurationItems as ciFrom ON locpropFromapp.CI_ID = ciFrom.CI_ID
            JOIN v_ConfigurationItems as ciTo ON locpropToapp.CI_ID = ciTo.CI_ID
        where 
        appflat.RelationType=15
        --AND ciFrom.IsTombstoned = 0
        AND ciFrom.IsLatest = 1
        AND ciFrom.IsExpired = 0
        --AND 
        --ciTo.IsTombstoned = 1
        --AND ciTo.IsLatest = 1
        AND ciTo.IsExpired = 1
    ) ARF ON ARF.FromAppCI = CI.CI_ID
WHERE 
    v_TaskSequenceAppReferencesInfo.PackageID = @TaskSequenceID AND
    CI.ISSuperseding = 1
	
---- search for tables and views containing a certain column name
SELECT      COLUMN_NAME AS 'ColumnName'
            ,TABLE_NAME AS  'TableName'
FROM        INFORMATION_SCHEMA.COLUMNS
WHERE       COLUMN_NAME LIKE '%AD_Site%'
ORDER BY    TableName
            ,ColumnName;
			
----Supported SQL Server Views
----https://www.enhansoft.com/what-are-the-supported-sql-server-views-to-use-with-sccm-reporting/
SELECT Distinct
	Case So.type
	When 'V' then 'View'
	When 'U' then 'Table'
	When 'FN' then 'SQL scalar function'
	When 'IF' then 'Table Function (RBA)'
	When 'TF' then 'Table Function (RBA??)'
	When 'P' Then 'SQL Stored Procedure'
	When 'SQ' then 'Service queue'
	When 'FS' then 'Assembly (CLR) scalar-function'
	When 'S' then 'System base table'
	When 'FT' then 'Assembly (CLR) table-valued function'
	Else so.type
	end as 'Object type',
	CASE
	WHEN SO.name like 'v[_]RA[_]%' THEN 'Resource Array'
	WHEN SO.name like 'v[_]R[_]%' THEN 'Resource'
	WHEN SO.name like 'v[_]HS[_]%' THEN 'Inventory History'
	WHEN SO.name like 'v[_]GS[_]%' THEN 'Inventory'
	WHEN SO.name like 'v[_]CM[_]%' THEN 'Collection'
	WHEN SO.name like '%Summ%' THEN 'Status Summarizer'
	WHEN SO.name like '%Stat%' THEN 'Status'
	WHEN SO.name like '%Permission%' THEN 'Security'
	WHEN SO.name like '%Secured%' THEN 'Security'
	WHEN SO.name like '%Map%' THEN 'Schema'
	WHEN SO.name = 'v_SchemaViews' THEN 'Schema'
	ELSE 'Other'
	END As 'Type',
	SO.name As 'ViewName'
FROM
	--Role/member associations
	sys.database_role_members members
JOIN sys.database_principals roleprinc ON roleprinc.principal_id = members.role_principal_id
--Roles
LEFT JOIN sys.database_permissions perm ON perm.grantee_principal_id = roleprinc.principal_id
--Permissions
LEFT JOIN sys.columns col on col.object_id = perm.major_id AND col.column_id = perm.minor_id
--Table columns
LEFT JOIN sys.objects obj ON perm.major_id = obj.object_id
Left join sysobjects so on perm.major_id = SO.id
WHERE
	-- SO.name like 'v_ApplicationAssignment'
	-- and
	So.type in ('IF','V')
	and SO.name not like 'v_CM_RES_COLL%'
	and SO.name not like 'fn_RBAC_CM_RES_COLL%'
	and roleprinc.name = 'smsschm_users'
order by 1, SO.name


--OUTPUT on 17/01/2020 with SCCM 1806
fn_AllDTRelationships
fn_AppClientSummarizedState
fn_AppDeploymentAssetDetails
fn_AppDeploymentErrorAssetDetails
fn_AppDeploymentErrorStatus
fn_AppDeploymentLaunchErrorAssetDetails
fn_AppDeploymentRNMAssetDetails
fn_AppDeploymentRNMStatus
fn_AppDeploymentStatus
fn_AppDTClientSummarizedState
fn_AppDTDeploymentSummary
fn_AppEvalErrors
fn_AppLaunchSummary
fn_ApplicationsTargetedToUser
fn_AppModelDeploymentsTargetedToUser
fn_AppModelDeploymentsTargetedToUserFiltered
fn_AuthListInfo
fn_BgbResWithNewCriticalPolicyMap
fn_CategoryInfo
fn_CICategoryInfo
fn_CICategoryInfo_All
fn_CIDeploymentUnknownAssetDetails
fn_CIDeploymentUnknownStatus
fn_ClientDownloadStatsPerBG
fn_CMPivotFavorite
fn_ComputerThreats
fn_dcmdeploymentcompliantassetdetails
fn_dcmdeploymentcompliantciassetdetails
fn_DCMDeploymentCompliantDetailsPerAsset
fn_DCMDeploymentCompliantStatus
fn_DCMDeploymentErrorAssetDetails
fn_DCMDeploymentErrorDetailsPerAsset
fn_DCMDeploymentErrorStatus
fn_DCMDeploymentNonCompliantAssetDetails
fn_DCMDeploymentNonCompliantDetailsPerAsset
fn_DCMDeploymentNonCompliantStatus
fn_DeploymentSummary
fn_DriverPlatform
fn_GetAADUserResourceTable
fn_GetAllAssignedMPList
fn_GetAppInstallationState
fn_GetAvailableScope
fn_GetDomainUserResourceTable
fn_GetDPUpgradeStatus
fn_GetUserResourceTable
fn_LatestInstalledPackageFeatures
fn_ListAdminCategories
fn_ListAdvancedThreatProtectionSettings
fn_ListAfwAppConfigSettings
fn_ListAllCMUpdatePackages
fn_listAllowOrDenyApps_List
fn_ListAppClientState
fn_ListAppConflictsData
fn_ListAppDependencyData
fn_listappFailedVEsdata
fn_listAppleVppTokenSettings
fn_ListApplicationCIs
fn_ListApplicationCIs_List
fn_ListApplicationCIsForPortal
fn_ListApplicationCIsWithLatestTime
fn_ListApplicationConditions
fn_ListApplicationPublishingItemCIs
fn_ListAppRequirementsData
fn_listAppRestrictionSettings_List
fn_ListAppTechnologyCIs
fn_ListAuthListCIs
fn_ListCategoryInstances
fn_ListCFDFeatures
fn_ListCI_ComplianceState
fn_ListCICategories
fn_ListCICategoriesAll
fn_ListCIRules
fn_ListCIs
fn_ListCIs_List
fn_ListCISettingReferences
fn_ListCISettings
fn_listClientAuthCertificateSettings_List
fn_ListCMUpdateAllDownloadMonitoringStatus
fn_ListCMUpdateAllInstallRepMonitoringStatus
fn_ListCMUpdateAllPrereqMonitoringStatus
fn_ListCMUpdateAllTopLevelMonitoring
fn_ListCMUpdateAllTopLevelMonitoringStatus
fn_ListCMUpdateFeatures
fn_ListCMUpdatePackageFeaturesAll
fn_ListCMUpdatePackages
fn_listCoManagementSettings_List
fn_listCommunicationsProvisioningSettings_List
fn_ListComplianceNotificationSettings
fn_ListCompliancePolicySettings
fn_ListConfigurationBaselineInfo
fn_ListConfigurationBaselineInfo_List
fn_ListConfigurationPolicy
fn_ListConfigurationPolicy_List
fn_ListCustomCISettings
fn_ListCustomConfigurationSettings_List
fn_ListDCMCIs
fn_ListDCMCIs_List
fn_ListDCMCIsLatest
fn_ListDCMCIsLatest_List
fn_ListDeployments
fn_ListDeploymentTypeCIs
fn_listDeviceGuardSettings_List
fn_ListDPContents
fn_ListDPGroupContents
fn_ListDPGroupDistributionStatusDetails
fn_ListDriverCIs
fn_ListDriverCIs_List
fn_listEdgeBrowserSettings_List
fn_listEditionUpgradeSettings_List
fn_ListExploitGuardSettings
fn_listFirewallComplianceSettings_List
fn_ListFirewallPolicy
fn_ListFirewallPolicy_List
fn_ListFirewallSettings
fn_listFirewallSettings_List
fn_listGenericAppConfiguration
fn_ListGlobalConditions
fn_ListGlobalConditions_List
fn_ListLatestApplicationCIs
fn_ListLatestApplicationCIs_List
fn_listM365ASettings_List
fn_ListMAMPolicyTemplates_List
fn_ListNAPRestrictionSummary
fn_ListObjectContentData
fn_ListObjectContentExtraInfo
fn_ListObjectContentInfo
fn_ListPackageDeployment
fn_listPassportForWorkProfileSettings_List
fn_ListPfxCertificateSettings
fn_ListPlatformCIs
fn_ListRelatedVEs
fn_listRemoteConnectionSettings_List
fn_ListSettingsDefinition
fn_ListTaskSequencePackageReferences
fn_ListTaskSequencePackageReferences_Fast
fn_ListTaskSequencePackageReferences_Flat
fn_ListTermsAndConditionsSettings
fn_listTrustedRootCertificateSettings_List
fn_listUacComplianceSettings_List
fn_listUnManagedApps_List
fn_ListUpdateCategoryInstances
fn_ListUpdateCIs
fn_ListUpdateComplianceStatus
fn_ListUpdatePackageDetailedSiteStatus
fn_ListUsmSettings
fn_listUsmSettings_List
fn_ListVirtualEnvironments
fn_ListVirtualEnvironments_List
fn_listVpnConnectionSettings_List
fn_listWindowsDefenderAntimalwareSettings_List
fn_listWindowsDefenderApplicationGuard_List
fn_listWirelessProfileSettings_List
fn_listWUfBConfigurationSettings_List
fn_LocaleFallback
fn_LocalizedAppProperties
fn_LocalizedCategories
fn_LocalizedCFDProperties
fn_LocalizedCIData
fn_LocalizedCIProperties
fn_LocalizedCMUpdateFeatureData
fn_LocalizedCMUpdateFeatureDataEx
fn_LocalizedCMUpdatePackageData
fn_LocalizedDatabaseResources
fn_LocalizedManagementInsightRuleGroupsData
fn_LocalizedManagementInsightsData
fn_LocalizedUpdatePackageDetailedSiteStatus
fn_ManagementInsightRuleGroups
fn_ManagementInsightRules_Relation
fn_ManagementInsights
fn_MIG_ClientKeyData
fn_rbac_AAD_Statistics
fn_rbac_Add_Remove_Programs
fn_rbac_Admins
fn_rbac_Advertisement
fn_rbac_AdvertisementStatusInformation
fn_rbac_AgentDiscoveries
fn_rbac_AI_MVLS
fn_rbac_AI_MVLS_ReconcileReport
fn_rbac_AI_NON_MS_LICENSE
fn_rbac_Alert
fn_rbac_AlertValidFeatureArea
fn_rbac_AlertVariable_G
fn_rbac_AllItems
fn_rbac_AllowOrDenyListViolationData
fn_rbac_AMTMachineInfo
fn_rbac_AndroidInstallActivity
fn_rbac_AppDeploymentAssetDetails
fn_rbac_AppDeploymentErrorAssetDetails
fn_rbac_AppDeploymentErrorStatus
fn_rbac_AppDeploymentLaunchErrorAssetDetails
fn_rbac_AppDeploymentRNMAssetDetails
fn_rbac_AppDeploymentRNMStatus
fn_rbac_AppDeploymentStatus
fn_rbac_AppDeploymentSummary
fn_rbac_AppDTDeploymentSummary
fn_rbac_AppIntentAssetData
fn_rbac_AppInTSDeployment
fn_rbac_AppLaunchSummary
fn_rbac_ApplicationAssignment
fn_rbac_ApplicationIdToNameMap
fn_rbac_AssignmentState_Combined
fn_rbac_AssignmentStatePerTopic
fn_rbac_AssignmentTargetedCIs
fn_rbac_AuthListInfo
fn_rbac_BGB_Statistics
fn_rbac_BootImagePackage
fn_rbac_BootImagePackage_References
fn_rbac_BundledConfigurationItems
fn_rbac_CAL_INSTALLED_SOFTWARE_DATA
fn_rbac_CAL_Processor_Count
fn_rbac_CategoryInfo
fn_rbac_CategoryMembershipsWithCollection
fn_rbac_CategoryPermissions
fn_rbac_CH_ClientSummary
fn_rbac_CH_ClientSummaryHistory
fn_rbac_CH_EvalResults
fn_rbac_CH_HealthCheckInfo
fn_rbac_CH_PolicyRequestHistory
fn_rbac_CI_ApplicablePlatforms
fn_rbac_CI_CurrentComplianceStatus
fn_rbac_CI_CurrentErrorDetails
fn_rbac_CI_DriverHardwareIDs
fn_rbac_CI_DriversCIs
fn_rbac_CIAssignment
fn_rbac_CIAssignmentStatus
fn_rbac_CIAssignmentTargetedCollections
fn_rbac_CIAssignmentTargetedMachines
fn_rbac_CIAssignmentToCI
fn_rbac_CIAssignmentToGroup
fn_rbac_CICategories
fn_rbac_CICategories_All
fn_rbac_CICategoryInfo
fn_rbac_CICategoryInfo_All
fn_rbac_CIComplianceHistory
fn_rbac_CIComplianceStatusComplianceDetail
fn_rbac_CIComplianceStatusConflictsDetail
fn_rbac_CIComplianceStatusDetail
fn_rbac_CIComplianceStatusErrorDetail
fn_rbac_CIComplianceStatusReificationDetail
fn_rbac_CIComplianceSummary
fn_rbac_CIConfigPointTypes
fn_rbac_CIConflictCode
fn_rbac_cicontentpackage
fn_rbac_CICurrentComplianceStatus
fn_rbac_CICurrentRuleDetail
fn_rbac_CIDeploymentUnknownAssetDetails
fn_rbac_CIDeploymentUnknownStatus
fn_rbac_CIDriverCategories
fn_rbac_CIErrorDetails
fn_rbac_CIRelation
fn_rbac_CIRelation_All
fn_rbac_CIRules
fn_rbac_CIRulesAll
fn_rbac_CISettingReferences
fn_rbac_CISettings
fn_rbac_CITargetedCollections
fn_rbac_CITargetedMachines
fn_rbac_CIToContent
fn_rbac_ClassicDeploymentAssetDetails
fn_rbac_ClientAdvertisementStatus
fn_rbac_ClientCollectionMembers
fn_rbac_ClientDeploymentState
fn_rbac_ClientHealthState
fn_rbac_ClientMachines
fn_rbac_ClientMode
fn_rbac_ClientModeReadiness
fn_rbac_ClientRestrictionHistory
fn_rbac_CMG_Statistics
fn_rbac_Collection
fn_rbac_CollectionExpandedUserMembers
fn_rbac_Collections
fn_rbac_CombinedDeviceResources
fn_rbac_ConfigurationItems
fn_rbac_ConfigurationItemsOSD
fn_rbac_Content
fn_rbac_CP_Machine
fn_rbac_CurrentAdvertisementAssignments
fn_rbac_CustomInventoryReport
fn_rbac_dcmdeploymentresourcesuser
fn_rbac_DeploymentSummary2
fn_rbac_DeviceClientDeploymentState
fn_rbac_DeviceClientHealthState
fn_rbac_DistributionPoint
fn_rbac_DistributionPointInfo
fn_rbac_DistributionPoints
fn_rbac_DM_WipeRecords
fn_rbac_DPGroupMembers
fn_rbac_DpGroupPackages
fn_rbac_DriverContentToPackage
fn_rbac_DriverPackage
fn_rbac_DrsSendHistorySummary
fn_rbac_EAS_Property_S
fn_rbac_EN_CertificateAuthorities
fn_rbac_en_clientcertificaterecords
fn_rbac_EndpointProtectionCollections
fn_rbac_EndpointProtectionHealthStatus
fn_rbac_EndpointProtectionHealthStatus_History
fn_rbac_EndpointProtectionStatus
fn_rbac_FileUsageSummary
fn_rbac_FileUsageSummaryIntervals
fn_rbac_FolderRedirectionState
fn_rbac_FullCollectionMembership
fn_rbac_FullCollectionMembership_Valid
fn_rbac_GetSecuredCollectionObjects
fn_rbac_GetSecuredObjects
fn_rbac_GS_1394_CONTROLLER
fn_rbac_GS_ACTIVESYNC_CONNECTED_DEVICE
fn_rbac_GS_ACTIVESYNC_SERVICE
fn_rbac_GS_ADD_REMOVE_PROGRAMS
fn_rbac_GS_ADD_REMOVE_PROGRAMS_64
fn_rbac_GS_ADVANCED_CLIENT_PORTS
fn_rbac_GS_ADVANCED_CLIENT_SSL_CONFIGURATIONS
fn_rbac_GS_AMT_AGENT
fn_rbac_GS_AntimalwareHealthStatus
fn_rbac_GS_AntimalwareInfectionStatus
fn_rbac_GS_APPV_CLIENT_APPLICATION
fn_rbac_GS_APPV_CLIENT_PACKAGE
fn_rbac_GS_AUTOSTART_SOFTWARE
fn_rbac_GS_BASEBOARD
fn_rbac_GS_BATTERY
fn_rbac_GS_BOOT_CONFIGURATION
fn_rbac_GS_BROWSER_HELPER_OBJECT
fn_rbac_GS_CCM_RECENTLY_USED_APPS
fn_rbac_GS_CDROM
fn_rbac_GS_ClientEvents
fn_rbac_GS_COMPUTER_SYSTEM
fn_rbac_GS_COMPUTER_SYSTEM_PRODUCT
fn_rbac_GS_DEFAULT_BROWSER
fn_rbac_GS_DESKTOP
fn_rbac_GS_DESKTOP_MONITOR
fn_rbac_GS_DEVICE_BLUETOOTH
fn_rbac_GS_DEVICE_CAMERA
fn_rbac_GS_DEVICE_CERTIFICATES
fn_rbac_GS_DEVICE_CLIENT
fn_rbac_GS_DEVICE_CLIENTAGENTVERSION
fn_rbac_GS_DEVICE_COMPUTERSYSTEM
fn_rbac_GS_DEVICE_DISPLAY
fn_rbac_GS_DEVICE_EMAIL
fn_rbac_GS_DEVICE_ENCRYPTION
fn_rbac_GS_DEVICE_EXCHANGE
fn_rbac_GS_DEVICE_INFO
fn_rbac_GS_DEVICE_INSTALLEDAPPLICATIONS
fn_rbac_GS_DEVICE_IRDA
fn_rbac_GS_DEVICE_MEMORY
fn_rbac_GS_DEVICE_MEMORY_ADDRESS
fn_rbac_GS_DEVICE_OSINFORMATION
fn_rbac_GS_DEVICE_PASSWORD
fn_rbac_GS_DEVICE_POLICY
fn_rbac_GS_DEVICE_POWER
fn_rbac_GS_DEVICE_WINDOWSSECURITYPOLICY
fn_rbac_GS_DEVICE_WLAN
fn_rbac_GS_DISK
fn_rbac_GS_DMA_CHANNEL
fn_rbac_GS_DRIVER_VXD
fn_rbac_GS_EMBEDDED_DEVICE_INFO
fn_rbac_GS_ENCRYPTABLE_VOLUME
fn_rbac_GS_ENVIRONMENT
fn_rbac_GS_EPDeploymentState
fn_rbac_GS_FIRMWARE
fn_rbac_GS_FOLDER_REDIRECTION_HEALTH
fn_rbac_GS_IDE_CONTROLLER
fn_rbac_GS_ILO_CurrentVersion0
fn_rbac_GS_ILO_CurrentVersion640
fn_rbac_GS_ILO_SavedCredentials0
fn_rbac_GS_ILOUSER0
fn_rbac_GS_INSTALLED_EXECUTABLE
fn_rbac_GS_INSTALLED_SOFTWARE
fn_rbac_GS_INSTALLED_SOFTWARE_CATEGORIZED
fn_rbac_GS_INSTALLED_SOFTWARE_MS
fn_rbac_GS_IRQ
fn_rbac_GS_JAVALOGS0
fn_rbac_GS_KEYBOARD_DEVICE
fn_rbac_GS_LastSoftwareScan
fn_rbac_GS_LOAD_ORDER_GROUP
fn_rbac_GS_LOGICAL_DISK
fn_rbac_GS_MDM_DEVDETAIL_EXT01
fn_rbac_GS_MDM_RemoteFind
fn_rbac_GS_MDM_SecurityStatus
fn_rbac_GS_MODEM_DEVICE
fn_rbac_GS_MONITORDETAILS
fn_rbac_GS_MOTHERBOARD_DEVICE
fn_rbac_GS_NAPCLIENT
fn_rbac_GS_NETWORK_ADAPTER
fn_rbac_GS_NETWORK_ADAPTER_CONFIGURATION
fn_rbac_GS_NETWORK_CLIENT
fn_rbac_GS_NETWORK_DRIVERS
fn_rbac_GS_NETWORK_LOGIN_PROFILE
fn_rbac_GS_NETWORKPRINTERS0
fn_rbac_GS_NT_EVENTLOG_FILE
fn_rbac_GS_OFFICE365PROPLUSCONFIGURATIONS
fn_rbac_GS_OPERATING_SYSTEM
fn_rbac_GS_OPTIONAL_FEATURE
fn_rbac_GS_OS_RECOVERY_CONFIGURATION
fn_rbac_GS_PAGE_FILE_SETTING
fn_rbac_GS_PARALLEL_PORT
fn_rbac_GS_PARTITION
fn_rbac_GS_PC_BIOS
fn_rbac_GS_PCMCIA_CONTROLLER
fn_rbac_GS_PHYSICAL_MEMORY
fn_rbac_GS_PNP_DEVICE_DRIVER
fn_rbac_GS_POINTING_DEVICE
fn_rbac_GS_PORT
fn_rbac_GS_PORTABLE_BATTERY
fn_rbac_GS_POWER_MANAGEMENT_CAPABILITIES
fn_rbac_GS_POWER_MANAGEMENT_CLIENTOPTOUT_SETTINGS
fn_rbac_GS_POWER_MANAGEMENT_CONFIGURATION
fn_rbac_GS_POWER_MANAGEMENT_DAY
fn_rbac_GS_POWER_MANAGEMENT_MONTH
fn_rbac_GS_POWER_MANAGEMENT_SETTINGS
fn_rbac_GS_POWER_MANAGEMENT_SUSPEND_ERROR
fn_rbac_GS_POWER_SUPPLY
fn_rbac_GS_PRINT_JOB
fn_rbac_GS_PRINTER_CONFIGURATION
fn_rbac_GS_PRINTER_DEVICE
fn_rbac_GS_PROCESS
fn_rbac_GS_PROCESSOR
fn_rbac_GS_PROTECTED_VOLUME_INFO
fn_rbac_GS_PROTOCOL
fn_rbac_GS_QUICK_FIX_ENGINEERING
fn_rbac_GS_RAX_APPLICATION
fn_rbac_GS_REGISTRY
fn_rbac_GS_SCSI_CONTROLLER
fn_rbac_GS_SERIAL_PORT
fn_rbac_GS_SERIAL_PORT_CONFIGURATION
fn_rbac_GS_SERVER_FEATURE
fn_rbac_GS_SERVICE
fn_rbac_GS_SHARE
fn_rbac_GS_SMS_ADVANCED_CLIENT_CACHE0
fn_rbac_GS_SMS_ADVANCED_CLIENT_STATE
fn_rbac_GS_SOFTWARE_LICENSING_PRODUCT
fn_rbac_GS_SOFTWARE_LICENSING_SERVICE
fn_rbac_GS_SOFTWARE_SHORTCUT
fn_rbac_GS_SOFTWARE_TAG
fn_rbac_GS_SoftwareFile
fn_rbac_GS_SoftwareProduct
fn_rbac_GS_SOUND_DEVICE
fn_rbac_GS_SYSTEM
fn_rbac_GS_SYSTEM_ACCOUNT
fn_rbac_GS_SYSTEM_CONSOLE_USAGE
fn_rbac_GS_SYSTEM_CONSOLE_USAGE_MAXGROUP
fn_rbac_GS_SYSTEM_CONSOLE_USER
fn_rbac_GS_SYSTEM_DEVICES
fn_rbac_GS_SYSTEM_DRIVER
fn_rbac_GS_SYSTEM_ENCLOSURE
fn_rbac_GS_SYSTEM_ENCLOSURE_UNIQUE
fn_rbac_GS_SYSTEMHEALTHAGENT
fn_rbac_GS_TAPE_DRIVE
fn_rbac_GS_Threats
fn_rbac_GS_TIME_ZONE
fn_rbac_GS_TPM
fn_rbac_GS_TPM_STATUS
fn_rbac_GS_TS_ISSUED_LICENSE
fn_rbac_GS_TS_LICENSE_KEY_PACK
fn_rbac_GS_USB_CONTROLLER
fn_rbac_GS_USB_DEVICE
fn_rbac_GS_USER_PROFILE
fn_rbac_GS_VIDEO_CONTROLLER
fn_rbac_GS_VIRTUAL_APPLICATION_PACKAGES
fn_rbac_GS_VIRTUAL_APPLICATIONS
fn_rbac_GS_VIRTUAL_MACHINE
fn_rbac_GS_VIRTUAL_MACHINE_64
fn_rbac_GS_VIRTUAL_MACHINE_EXT
fn_rbac_GS_VOLUME
fn_rbac_GS_WEBAPP_APPLICATION
fn_rbac_GS_WINDOWS8_APPLICATION
fn_rbac_GS_WINDOWS8_APPLICATION_USER_INFO
fn_rbac_GS_WINDOWSUPDATE
fn_rbac_GS_WINDOWSUPDATEAGENTVERSION
fn_rbac_GS_WORKSTATION_STATUS
fn_rbac_GS_WRITE_FILTER_STATE
fn_rbac_GS_X86_PC_MEMORY
fn_rbac_HS_1394_CONTROLLER
fn_rbac_HS_ACTIVESYNC_CONNECTED_DEVICE
fn_rbac_HS_ACTIVESYNC_SERVICE
fn_rbac_HS_ADD_REMOVE_PROGRAMS
fn_rbac_HS_ADD_REMOVE_PROGRAMS_64
fn_rbac_HS_ADVANCED_CLIENT_PORTS
fn_rbac_HS_ADVANCED_CLIENT_SSL_CONFIGURATIONS
fn_rbac_HS_AMT_AGENT
fn_rbac_HS_APPV_CLIENT_APPLICATION
fn_rbac_HS_APPV_CLIENT_PACKAGE
fn_rbac_HS_AUTOSTART_SOFTWARE
fn_rbac_HS_BASEBOARD
fn_rbac_HS_BATTERY
fn_rbac_HS_BOOT_CONFIGURATION
fn_rbac_HS_BROWSER_HELPER_OBJECT
fn_rbac_HS_CDROM
fn_rbac_HS_ClientEvents
fn_rbac_HS_COMPUTER_SYSTEM
fn_rbac_HS_COMPUTER_SYSTEM_PRODUCT
fn_rbac_HS_DEFAULT_BROWSER
fn_rbac_HS_DESKTOP
fn_rbac_HS_DESKTOP_MONITOR
fn_rbac_HS_DEVICE_BLUETOOTH
fn_rbac_HS_DEVICE_CAMERA
fn_rbac_HS_DEVICE_CERTIFICATES
fn_rbac_HS_DEVICE_CLIENT
fn_rbac_HS_DEVICE_CLIENTAGENTVERSION
fn_rbac_HS_DEVICE_COMPUTERSYSTEM
fn_rbac_HS_DEVICE_DISPLAY
fn_rbac_HS_DEVICE_EMAIL
fn_rbac_HS_DEVICE_ENCRYPTION
fn_rbac_HS_DEVICE_EXCHANGE
fn_rbac_HS_DEVICE_INSTALLEDAPPLICATIONS
fn_rbac_HS_DEVICE_IRDA
fn_rbac_HS_DEVICE_MEMORY
fn_rbac_HS_DEVICE_MEMORY_ADDRESS
fn_rbac_HS_DEVICE_OSINFORMATION
fn_rbac_HS_DEVICE_PASSWORD
fn_rbac_HS_DEVICE_POLICY
fn_rbac_HS_DEVICE_POWER
fn_rbac_HS_DEVICE_WINDOWSSECURITYPOLICY
fn_rbac_HS_DEVICE_WLAN
fn_rbac_HS_DISK
fn_rbac_HS_DMA_CHANNEL
fn_rbac_HS_DRIVER_VXD
fn_rbac_HS_EMBEDDED_DEVICE_INFO
fn_rbac_HS_ENCRYPTABLE_VOLUME
fn_rbac_HS_ENVIRONMENT
fn_rbac_HS_FIRMWARE
fn_rbac_HS_IDE_CONTROLLER
fn_rbac_HS_ILO_CurrentVersion0
fn_rbac_HS_ILO_CurrentVersion640
fn_rbac_HS_ILO_SavedCredentials0
fn_rbac_HS_ILOUSER0
fn_rbac_HS_INSTALLED_EXECUTABLE
fn_rbac_HS_INSTALLED_SOFTWARE
fn_rbac_HS_IRQ
fn_rbac_HS_JAVALOGS0
fn_rbac_HS_KEYBOARD_DEVICE
fn_rbac_HS_LOAD_ORDER_GROUP
fn_rbac_HS_LOGICAL_DISK
fn_rbac_HS_MDM_DEVDETAIL_EXT01
fn_rbac_HS_MDM_RemoteFind
fn_rbac_HS_MDM_SecurityStatus
fn_rbac_HS_MODEM_DEVICE
fn_rbac_HS_MONITORDETAILS
fn_rbac_HS_MOTHERBOARD_DEVICE
fn_rbac_HS_NAPCLIENT
fn_rbac_HS_NETWORK_ADAPTER
fn_rbac_HS_NETWORK_ADAPTER_CONFIGURATION
fn_rbac_HS_NETWORK_CLIENT
fn_rbac_HS_NETWORK_DRIVERS
fn_rbac_HS_NETWORK_LOGIN_PROFILE
fn_rbac_HS_NETWORKPRINTERS0
fn_rbac_HS_NT_EVENTLOG_FILE
fn_rbac_HS_OFFICE365PROPLUSCONFIGURATIONS
fn_rbac_HS_OPERATING_SYSTEM
fn_rbac_HS_OPTIONAL_FEATURE
fn_rbac_HS_OS_RECOVERY_CONFIGURATION
fn_rbac_HS_PAGE_FILE_SETTING
fn_rbac_HS_PARALLEL_PORT
fn_rbac_HS_PARTITION
fn_rbac_HS_PC_BIOS
fn_rbac_HS_PCMCIA_CONTROLLER
fn_rbac_HS_PHYSICAL_MEMORY
fn_rbac_HS_POINTING_DEVICE
fn_rbac_HS_PORT
fn_rbac_HS_PORTABLE_BATTERY
fn_rbac_HS_POWER_SUPPLY
fn_rbac_HS_PRINT_JOB
fn_rbac_HS_PRINTER_CONFIGURATION
fn_rbac_HS_PRINTER_DEVICE
fn_rbac_HS_PROCESS
fn_rbac_HS_PROCESSOR
fn_rbac_HS_PROTECTED_VOLUME_INFO
fn_rbac_HS_PROTOCOL
fn_rbac_HS_QUICK_FIX_ENGINEERING
fn_rbac_HS_RAX_APPLICATION
fn_rbac_HS_REGISTRY
fn_rbac_HS_SCSI_CONTROLLER
fn_rbac_HS_SERIAL_PORT
fn_rbac_HS_SERIAL_PORT_CONFIGURATION
fn_rbac_HS_SERVER_FEATURE
fn_rbac_HS_SERVICE
fn_rbac_HS_SHARE
fn_rbac_HS_SMS_ADVANCED_CLIENT_CACHE0
fn_rbac_HS_SMS_ADVANCED_CLIENT_STATE
fn_rbac_HS_SOFTWARE_LICENSING_PRODUCT
fn_rbac_HS_SOFTWARE_LICENSING_SERVICE
fn_rbac_HS_SOFTWARE_SHORTCUT
fn_rbac_HS_SOFTWARE_TAG
fn_rbac_HS_SOUND_DEVICE
fn_rbac_HS_SYSTEM
fn_rbac_HS_SYSTEM_ACCOUNT
fn_rbac_HS_SYSTEM_CONSOLE_USAGE
fn_rbac_HS_SYSTEM_CONSOLE_USER
fn_rbac_HS_SYSTEM_DRIVER
fn_rbac_HS_SYSTEM_ENCLOSURE
fn_rbac_HS_SYSTEMHEALTHAGENT
fn_rbac_HS_TAPE_DRIVE
fn_rbac_HS_TIME_ZONE
fn_rbac_HS_TPM
fn_rbac_HS_TPM_STATUS
fn_rbac_HS_TS_ISSUED_LICENSE
fn_rbac_HS_TS_LICENSE_KEY_PACK
fn_rbac_HS_USB_CONTROLLER
fn_rbac_HS_USB_DEVICE
fn_rbac_HS_VIDEO_CONTROLLER
fn_rbac_HS_VIRTUAL_APPLICATION_PACKAGES
fn_rbac_HS_VIRTUAL_APPLICATIONS
fn_rbac_HS_VIRTUAL_MACHINE
fn_rbac_HS_VIRTUAL_MACHINE_64
fn_rbac_HS_VIRTUAL_MACHINE_EXT
fn_rbac_HS_VOLUME
fn_rbac_HS_WEBAPP_APPLICATION
fn_rbac_HS_WINDOWS8_APPLICATION
fn_rbac_HS_WINDOWS8_APPLICATION_USER_INFO
fn_rbac_HS_WINDOWSUPDATE
fn_rbac_HS_WINDOWSUPDATEAGENTVERSION
fn_rbac_HS_WRITE_FILTER_STATE
fn_rbac_HS_X86_PC_MEMORY
fn_rbac_INSTALLED_SOFTWARE_DATA_Summary
fn_rbac_inventoryreportclass
fn_rbac_LastUsageSummary
fn_rbac_LicenseKeyStatus
fn_rbac_ListAppDependencyData
fn_rbac_ListApplicationCIs
fn_rbac_ListAppRequirementsData
fn_rbac_ListCategoryInstances
fn_rbac_ListCI_ComplianceState
fn_rbac_ListDeploymentTypeCIs
fn_rbac_ListLatestApplicationCIs
fn_rbac_ListUpdateCategoryInstances
fn_rbac_ListVirtualEnvironments
fn_rbac_LocalizedCategories
fn_rbac_LocalizedCategories_SiteLoc
fn_rbac_LocalizedCIProperties
fn_rbac_LocalizedCIProperties_SiteLoc
fn_rbac_LocalizedCIProperties2
fn_rbac_LU_CAL_ProductList
fn_rbac_LU_Category
fn_rbac_LU_Category_Editable
fn_rbac_LU_HardwareReadiness
fn_rbac_LU_LicensedProduct
fn_rbac_LU_SoftwareList_Editable
fn_rbac_LU_SoftwareList_Local
fn_rbac_LU_Tags
fn_rbac_mdmclientidentity
fn_rbac_MDMDeviceCategory
fn_rbac_MDMDeviceManagementStates
fn_rbac_mdmdeviceproperty
fn_rbac_MDMDeviceThreat
fn_rbac_MDMUserPolicyAssignment
fn_rbac_MeteredFiles
fn_rbac_MeteredProductRule
fn_rbac_MeteredUser
fn_rbac_MeterRuleInstallBase
fn_rbac_MIG_Clients
fn_rbac_MIG_Entities
fn_rbac_MIG_EntityReference
fn_rbac_MIG_Job
fn_rbac_MIG_JobEntity
fn_rbac_MonthlyUsageSummary
fn_rbac_NAPErrorCodeDescription
fn_rbac_NAPRestrictionSummary
fn_rbac_NAPSystemInfo
fn_rbac_Network_DATA_Serialized
fn_rbac_ObjectsAssignedToOneCategory
fn_rbac_Package
fn_rbac_Package2
fn_rbac_PackageStatus
fn_rbac_PackageStatusDistPointsSumm
fn_rbac_PackageStatusRootSummarizer
fn_rbac_Permissions
fn_rbac_ProductFileInfo
fn_rbac_Program
fn_rbac_ProgramOffers
fn_rbac_R_IPNetwork
fn_rbac_R_NetworkInfo
fn_rbac_R_System
fn_rbac_R_System_Valid
fn_rbac_R_UnknownSystem
fn_rbac_R_User
fn_rbac_R_UserGroup
fn_rbac_R_WarrantyEntitlements
fn_rbac_RA_System_IPAddresses
fn_rbac_RA_System_IPSubnets
fn_rbac_RA_System_IPv6Addresses
fn_rbac_RA_System_IPv6Prefixes
fn_rbac_RA_System_MACAddresses
fn_rbac_RA_System_ResourceNames
fn_rbac_RA_System_SMS_Resident
fn_rbac_RA_System_SMSAssignedSites
fn_rbac_RA_System_SMSInstalledSites
fn_rbac_RA_System_System_Group_Name
fn_rbac_RA_System_SystemContainerName
fn_rbac_RA_System_SystemGroupName
fn_rbac_RA_System_SystemOUName
fn_rbac_RA_System_SystemRoles
fn_rbac_RA_Unknown_System_SMS_Assig
fn_rbac_RA_User_Group_Group_OU_Name
fn_rbac_RA_User_User_Group_Name_F
fn_rbac_RA_User_UserContainerName
fn_rbac_RA_User_UserGroupName
fn_rbac_RA_User_UserOUName
fn_rbac_RA_UserGroupADContainerName
fn_rbac_replicationdata
fn_rbac_Report_StatusMessageDetail
fn_rbac_Roles
fn_rbac_SecuredCategories
fn_rbac_securedobjecttypes
fn_rbac_ServerComponents
fn_rbac_ServiceWindow
fn_rbac_Site
fn_rbac_SMS_Alert
fn_rbac_SMS_CIRelation
fn_rbac_SMS_DistributionPointGroup
fn_rbac_SMS_SC_SysResUse
fn_rbac_SMS_SC_SysResUse_Properties
fn_rbac_SMSCICurrentComplianceStatus
fn_rbac_SMSConfigurationItems
fn_rbac_SmsPackage
fn_rbac_SoftwareProduct
fn_rbac_SoftwareUpdateSource
fn_rbac_StateMigration
fn_rbac_StateNames
fn_rbac_StatMsgAttributes
fn_rbac_StatMsgInsStrings
fn_rbac_StatMsgModuleNames
fn_rbac_StatMsgWithInsStrings
fn_rbac_StatusMessage
fn_rbac_StatusMessagesAlerts
fn_rbac_SummarizationInterval
fn_rbac_SummarizerSiteStatus
fn_rbac_SupportedPlatforms
fn_rbac_System_SMS_Assign_ARR
fn_rbac_SystemInventoryChanges
fn_rbac_SystemResourceList
fn_rbac_TaskExecutionStatus
fn_rbac_tasksequenceappreferencesinfo
fn_rbac_TaskSequencePackage
fn_rbac_TaskSequenceReferencesInfo
fn_rbac_ThreatCatalog
fn_rbac_ThreatCategories
fn_rbac_ThreatDefaultActions
fn_rbac_ThreatSeverities
fn_rbac_ThreatSummary
fn_rbac_Update_ComplianceStatusAll
fn_rbac_Update_ComplianceSummary_Live
fn_rbac_UpdateAssignmentStatus_Live
fn_rbac_UpdateCIs
fn_rbac_UpdateComplianceStatus
fn_rbac_UpdateContents
fn_rbac_UpdateInfo
fn_rbac_UpdateScanStatus
fn_rbac_UpdateState_Combined
fn_rbac_UpdateSummaryPerCollection
fn_rbac_UserHealthProfileState
fn_rbac_UserMachineIntelligence
fn_rbac_usermachinerelation
fn_rbac_UserMachineRelationship
fn_rbac_UserMachineSourceRelation
fn_rbac_UserMachineTypeRelation
fn_rbac_Users
fn_rbac_vSMS_DistributionDPStatus
fn_rbac_WakeupProxyDeploymentState
fn_rbac_WOLClientTimeZones
fn_rbac_WOLCommunicationErrorStatus
fn_rbac_WOLCommunicationHistory
fn_rbac_WOLEnabledAdvertisements
fn_rbac_WOLEnabledAssignments
fn_rbac_WOLEnabledObjects
fn_rbac_WOLEnabledTaskSequences
fn_rbac_WOLGetPendingObjectSchedules
fn_rbac_WOLGetSupportedObjects
fn_rbac_WOLGetWOLEnabledSites
fn_rbac_WOLSUMTargetedClients
fn_rbac_WOLSWDistTargetedClients
fn_rbac_WOLTargetedClients
fn_UpdateInfo
fn_UpdatePackageDownloadProgressSubStageLocalizedData
fn_UpdatePackageMonitoringSubstagesLocalizedData
fn_UpdatePackageMonitoringTopLevelLocalizedData
fn_UpdatePackagePrereqLocalizedData
fn_UpdatePackageSiteStatus
fn_UpdateSummaryPerCollection
fnInventoriedLicensedProduct
fnInventoriedSoftware
v_ActiveClients
v_Add_Remove_Programs
v_Admins
v_Advertisement
v_AdvertisementInfo
v_AdvertisementStatusInformation
v_AgentDiscoveries
v_AI_MVLS
v_AI_NON_MS_LICENSE
v_AIProxy
v_Alert
v_AlertEvents
v_AlertValidFeatureArea
v_AlertVariable_G
v_AllItems
v_AllowOrDenyListViolationData
v_AM_NormalizedDetectionHistory
v_AMTMachineInfo
v_AppDeploymentSummary
v_AppDTDeploymentSummary
v_AppDTLaunchSummary
v_AppEvalErrors
v_AppInTaskSequenceDeployment
v_AppIntentAssetData
v_AppInTSDeployment
v_ApplicationAssignment
v_ApplicationIdToNameMap
v_ApplicationModelInfo
v_AppModelTargetingDeploymentInfo
v_AppModelTargetingInfo
v_AssignmentEnforcementSummaryPerUpdateAndState
v_AssignmentState_Combined
v_AssignmentStatePerTopic
v_AssignmentSummaryPerTopic
v_AssignmentTargetedCIs
v_AuthListInfo
v_BaselineTargetedComputers
v_BGB_ResTask
v_BGB_ResTaskPush
v_BGB_Task
v_BgbMP
v_BgbServerCurrent
v_BootImagePackage
v_BootImagePackage_References
v_BoundarySiteCode
v_BoundarySiteSystems
v_BundledConfigurationItems
v_BundledConfigurationItems_All
v_CAL_INSTALLED_SOFTWARE_DATA
v_CAL_Processor_Count
v_CatalogAppModelProperties
v_CatalogClassicAppProperties
v_Categories
v_CategoryInfo
v_CategoryInstances
v_CategoryMembershipsWithCollection
v_CategoryPermissions
v_CertificateHistory
v_CertificateStatus
v_CH_ClientSummary
v_CH_ClientSummaryCurrent
v_CH_ClientSummaryHistory
v_CH_EvalResults
v_CH_HealthCheckInfo
v_CH_HealthCheckSummary
v_CH_PendingPolicyRequests
v_CH_PolicyRequestHistory
v_CH_Settings
v_CI_ApplicablePlatforms
v_CI_CurrentComplianceStatus
v_CI_CurrentErrorDetails
v_CI_DriverHardwareIDs
v_CI_DriverModels
v_CI_DriversCIs
v_CIAppDependenceRelations
v_CIAssignment
v_CIAssignmentStatus
v_CIAssignmentStatusSummary
v_CIAssignmentSummary
v_CIAssignmentTargetedCollections
v_CIAssignmentTargetedMachines
v_CIAssignmentToCI
v_CIAssignmentToGroup
v_CICategories
v_CICategories_All
v_CICategoryInfo
v_CICategoryInfo_All
v_CIComplianceHistory
v_CIComplianceStatusComplianceDetail
v_CIComplianceStatusConflictsDetail
v_CIComplianceStatusDetail
v_CIComplianceStatusErrorDetail
v_CIComplianceStatusReificationDetail
v_CIComplianceSummary
v_CIConfigPointTypes
v_CIConflictCode
v_CIContentPackage
v_CIContents
v_CIContents_All
v_CICurrentComplianceStatus
v_CICurrentRuleDetail
v_CICurrentSettingsComplianceStatusDetail
v_CIErrorDetails
v_CIEULA_LocalizedContent
v_CIRelation
v_CIRelation_All
v_CIRelationEx
v_CIRelationTypeMapping
v_CIRelationTypes
v_CIRules
v_CIRulesAll
v_CISettingReferences
v_CISettings
v_CITargetedCollections
v_CITargetedMachines
v_CIToContent
v_CITypes
v_CIValidationSeverity
v_ClassicAppTargetingDeploymentInfo
v_ClassicAppTargetingInfo
v_ClassicDeploymentAssetDetails
v_ClientAction
v_ClientActionImportance
v_ClientActionResult
v_ClientActionResultOfPolicy
v_ClientActionResultOfTask
v_ClientActionSequence
v_ClientAdvertisementStatus
v_ClientBaselineStatus
v_ClientCollectionMembers
v_ClientCollectionMembersWithAgentEdition
v_ClientCoManagementState
v_ClientDeploymentCollBucket
v_ClientDeploymentState
v_ClientDeploymentStateDetailsView
v_ClientDownloadHistoryDP_BG
v_ClientHealthState
v_ClientMachines
v_ClientMessageStatistics
v_ClientMode
v_ClientModeReadiness
v_ClientOfferSummary
v_ClientOperationInProcessing
v_ClientOperationLinkedObjects
v_ClientOperationTargets
v_ClientRestrictionHistory
v_CMConsoleUsageData
v_Collection
v_CollectionExpandedUserMembers
v_CollectionMemberClientBaselineStatus
v_CollectionRuleDirect
v_CollectionRuleQuery
v_Collections
v_Collections_G
v_CollectionSettings
v_CollectionVariable
v_CombinedDeviceResources
v_ComponentSummarizer
v_ConfigurationItems
v_ContDistStatSummary
v_Content
v_ContentDistribution
v_ContentDistributionHighlights
v_ContentDistributionMessages
v_ContentDistributionReport
v_ContentDistributionReport_DP
v_ContentDistributionVersions
v_ContentInfo
v_CP_Machine
v_CurrentAdvertisementAssignments
v_CurrentThreatOutbreak
v_CustomInventoryReport
v_DCMClientStatusInformation
v_DCMDeploymentResourcesUser
v_Default_Browser
v_DeploymentSummary
v_DeviceClientDeploymentState
v_DeviceClientHealthState
v_DeviceClientUpdateState
v_DeviceJailBrokenStatus
v_DeviceSettingItems
v_DeviceSettingPackageItems
v_DiscItemAgents
v_DistributionPoint
v_DistributionPointDriveInfo
v_DistributionPointInfo
v_DistributionPointInfoBase
v_DistributionPointMessages
v_DistributionPoints
v_DistributionStatus
v_DM_RetireRecords
v_DM_WipeRecords
v_DPGroupContentDetails
v_DPGroupContentInfo
v_DPGroupMembers
v_DPGroupPackages
v_DPStatusSummary
v_DPUsageSummary
v_DriverContentToPackage
v_DriverPackage
v_DrsSendHistorySummary
v_EAS_Organization
v_EAS_Property
v_EAS_Property_S
v_EN_CertificateAuthorities
v_EN_ClientCertificateRecords
v_EN_EnrollmentProfiles
v_EN_EnrollmentRecords
v_EndpointProtectionCollections
v_EndpointProtectionHealthStatus
v_EndpointProtectionHealthStatus_History
v_EndpointProtectionStatus
v_EULAContent
v_FailedImageUpdate
v_FileUsageSummary
v_FileUsageSummaryIntervals
v_FolderRedirectionState
v_FullCollectionMembership
v_FullCollectionMembership_Valid
v_GroupAttributeMap
v_GroupMap
v_GS_1394_CONTROLLER
v_GS_ACTIVESYNC_CONNECTED_DEVICE
v_GS_ACTIVESYNC_SERVICE
v_GS_ADD_REMOVE_PROGRAMS
v_GS_ADD_REMOVE_PROGRAMS_64
v_GS_ADVANCED_CLIENT_PORTS
v_GS_ADVANCED_CLIENT_SSL_CONFIGURATIONS
v_GS_AMT_AGENT
v_GS_AntimalwareHealthStatus
v_GS_AntimalwareInfectionStatus
v_GS_APPV_CLIENT_APPLICATION
v_GS_APPV_CLIENT_PACKAGE
v_GS_AUTOSTART_SOFTWARE
v_GS_BASEBOARD
v_GS_BATTERY
v_GS_BOOT_CONFIGURATION
v_GS_BROWSER_HELPER_OBJECT
v_GS_CCM_RECENTLY_USED_APPS
v_GS_CDROM
v_GS_ClientEvents
v_GS_CollectedFile
v_GS_COMPUTER_SYSTEM
v_GS_COMPUTER_SYSTEM_PRODUCT
v_GS_DEFAULT_BROWSER
v_GS_DESKTOP
v_GS_DESKTOP_MONITOR
v_GS_DEVICE_BLUETOOTH
v_GS_DEVICE_CAMERA
v_GS_DEVICE_CERTIFICATES
v_GS_DEVICE_CLIENT
v_GS_DEVICE_CLIENTAGENTVERSION
v_GS_DEVICE_COMPUTERSYSTEM
v_GS_DEVICE_DISPLAY
v_GS_DEVICE_EMAIL
v_GS_DEVICE_ENCRYPTION
v_GS_DEVICE_EXCHANGE
v_GS_DEVICE_INFO
v_GS_DEVICE_INSTALLEDAPPLICATIONS
v_GS_DEVICE_IRDA
v_GS_DEVICE_MEMORY
v_GS_DEVICE_MEMORY_ADDRESS
v_GS_DEVICE_OSINFORMATION
v_GS_DEVICE_PASSWORD
v_GS_DEVICE_POLICY
v_GS_DEVICE_POWER
v_GS_DEVICE_WINDOWSSECURITYPOLICY
v_GS_DEVICE_WLAN
v_GS_DISK
v_GS_DMA_CHANNEL
v_GS_DRIVER_VXD
v_GS_EMBEDDED_DEVICE_INFO
v_GS_ENCRYPTABLE_VOLUME
v_GS_ENVIRONMENT
v_GS_EPDeploymentState
v_GS_FIRMWARE
v_GS_FOLDER_REDIRECTION_HEALTH
v_GS_IDE_CONTROLLER
v_GS_ILO_CurrentVersion0
v_GS_ILO_CurrentVersion640
v_GS_ILO_SavedCredentials0
v_GS_ILOUSER0
v_GS_INSTALLED_EXECUTABLE
v_GS_INSTALLED_SOFTWARE
v_GS_INSTALLED_SOFTWARE_CATEGORIZED
v_GS_INSTALLED_SOFTWARE_MS
v_GS_IRQ
v_GS_JAVALOGS0
v_GS_KEYBOARD_DEVICE
v_GS_LastSoftwareScan
v_GS_LOAD_ORDER_GROUP
v_GS_LOGICAL_DISK
v_GS_Mapped_Add_Remove_Programs
v_GS_MDM_DEVDETAIL_EXT01
v_GS_MDM_RemoteFind
v_GS_MDM_SecurityStatus
v_GS_MODEM_DEVICE
v_GS_MONITORDETAILS
v_GS_MOTHERBOARD_DEVICE
v_GS_NAPCLIENT
v_GS_NETWORK_ADAPTER
v_GS_NETWORK_ADAPTER_CONFIGURATION
v_GS_NETWORK_CLIENT
v_GS_NETWORK_DRIVERS
v_GS_NETWORK_LOGIN_PROFILE
v_GS_NETWORKPRINTERS0
v_GS_NT_EVENTLOG_FILE
v_GS_OFFICE365PROPLUSCONFIGURATIONS
v_GS_OPERATING_SYSTEM
v_GS_OPTIONAL_FEATURE
v_GS_OS_RECOVERY_CONFIGURATION
v_GS_PAGE_FILE_SETTING
v_GS_PARALLEL_PORT
v_GS_PARTITION
v_GS_PC_BIOS
v_GS_PCMCIA_CONTROLLER
v_GS_PHYSICAL_MEMORY
v_GS_PNP_DEVICE_DRIVER
v_GS_POINTING_DEVICE
v_GS_PORT
v_GS_PORTABLE_BATTERY
v_GS_POWER_MANAGEMENT_CAPABILITIES
v_GS_POWER_MANAGEMENT_CLIENTOPTOUT_SETTINGS
v_GS_POWER_MANAGEMENT_CONFIGURATION
v_GS_POWER_MANAGEMENT_DAY
v_GS_POWER_MANAGEMENT_MONTH
v_GS_POWER_MANAGEMENT_SETTINGS
v_GS_POWER_MANAGEMENT_SUSPEND_ERROR
v_GS_POWER_SUPPLY
v_GS_PRINT_JOB
v_GS_PRINTER_CONFIGURATION
v_GS_PRINTER_DEVICE
v_GS_PROCESS
v_GS_PROCESSOR
v_GS_PROTECTED_VOLUME_INFO
v_GS_PROTOCOL
v_GS_QUICK_FIX_ENGINEERING
v_GS_RAX_APPLICATION
v_GS_REGISTRY
v_GS_SCSI_CONTROLLER
v_GS_SERIAL_PORT
v_GS_SERIAL_PORT_CONFIGURATION
v_GS_SERVER_FEATURE
v_GS_SERVICE
v_GS_SHARE
v_GS_SMS_ADVANCED_CLIENT_CACHE0
v_GS_SMS_ADVANCED_CLIENT_STATE
v_GS_SOFTWARE_LICENSING_PRODUCT
v_GS_SOFTWARE_LICENSING_SERVICE
v_GS_SOFTWARE_SHORTCUT
v_GS_SOFTWARE_TAG
v_GS_SoftwareFile
v_GS_SoftwareProduct
v_GS_SoftwareUsageData
v_GS_SOUND_DEVICE
v_GS_SYSTEM
v_GS_SYSTEM_ACCOUNT
v_GS_SYSTEM_CONSOLE_USAGE
v_GS_SYSTEM_CONSOLE_USAGE_MAXGROUP
v_GS_SYSTEM_CONSOLE_USER
v_GS_SYSTEM_DEVICES
v_GS_SYSTEM_DRIVER
v_GS_SYSTEM_ENCLOSURE
v_GS_SYSTEM_ENCLOSURE_UNIQUE
v_GS_SYSTEMHEALTHAGENT
v_GS_TAPE_DRIVE
v_GS_Threats
v_GS_TIME_ZONE
v_GS_TPM
v_GS_TPM_STATUS
v_GS_TS_ISSUED_LICENSE
v_GS_TS_LICENSE_KEY_PACK
v_GS_UnknownFile
v_GS_USB_CONTROLLER
v_GS_USB_DEVICE
v_GS_USER_PROFILE
v_GS_VIDEO_CONTROLLER
v_GS_VIRTUAL_APPLICATION_PACKAGES
v_GS_VIRTUAL_APPLICATIONS
v_GS_VIRTUAL_MACHINE
v_GS_VIRTUAL_MACHINE_64
v_GS_VIRTUAL_MACHINE_EXT
v_GS_VOLUME
v_GS_WEBAPP_APPLICATION
v_GS_WINDOWS8_APPLICATION
v_GS_WINDOWS8_APPLICATION_USER_INFO
v_GS_WINDOWSUPDATE
v_GS_WINDOWSUPDATEAGENTVERSION
v_GS_WORKSTATION_STATUS
v_GS_WRITE_FILTER_STATE
v_GS_X86_PC_MEMORY
v_HS_1394_CONTROLLER
v_HS_ACTIVESYNC_CONNECTED_DEVICE
v_HS_ACTIVESYNC_SERVICE
v_HS_ADD_REMOVE_PROGRAMS
v_HS_ADD_REMOVE_PROGRAMS_64
v_HS_ADVANCED_CLIENT_PORTS
v_HS_ADVANCED_CLIENT_SSL_CONFIGURATIONS
v_HS_AMT_AGENT
v_HS_APPV_CLIENT_APPLICATION
v_HS_APPV_CLIENT_PACKAGE
v_HS_AUTOSTART_SOFTWARE
v_HS_BASEBOARD
v_HS_BATTERY
v_HS_BOOT_CONFIGURATION
v_HS_BROWSER_HELPER_OBJECT
v_HS_CDROM
v_HS_ClientEvents
v_HS_COMPUTER_SYSTEM
v_HS_COMPUTER_SYSTEM_PRODUCT
v_HS_DEFAULT_BROWSER
v_HS_DESKTOP
v_HS_DESKTOP_MONITOR
v_HS_DEVICE_BLUETOOTH
v_HS_DEVICE_CAMERA
v_HS_DEVICE_CERTIFICATES
v_HS_DEVICE_CLIENT
v_HS_DEVICE_CLIENTAGENTVERSION
v_HS_DEVICE_COMPUTERSYSTEM
v_HS_DEVICE_DISPLAY
v_HS_DEVICE_EMAIL
v_HS_DEVICE_ENCRYPTION
v_HS_DEVICE_EXCHANGE
v_HS_DEVICE_INSTALLEDAPPLICATIONS
v_HS_DEVICE_IRDA
v_HS_DEVICE_MEMORY
v_HS_DEVICE_MEMORY_ADDRESS
v_HS_DEVICE_OSINFORMATION
v_HS_DEVICE_PASSWORD
v_HS_DEVICE_POLICY
v_HS_DEVICE_POWER
v_HS_DEVICE_WINDOWSSECURITYPOLICY
v_HS_DEVICE_WLAN
v_HS_DISK
v_HS_DMA_CHANNEL
v_HS_DRIVER_VXD
v_HS_EMBEDDED_DEVICE_INFO
v_HS_ENCRYPTABLE_VOLUME
v_HS_ENVIRONMENT
v_HS_FIRMWARE
v_HS_IDE_CONTROLLER
v_HS_ILO_CurrentVersion0
v_HS_ILO_CurrentVersion640
v_HS_ILO_SavedCredentials0
v_HS_ILOUSER0
v_HS_INSTALLED_EXECUTABLE
v_HS_INSTALLED_SOFTWARE
v_HS_IRQ
v_HS_JAVALOGS0
v_HS_KEYBOARD_DEVICE
v_HS_LOAD_ORDER_GROUP
v_HS_LOGICAL_DISK
v_HS_MDM_DEVDETAIL_EXT01
v_HS_MDM_RemoteFind
v_HS_MDM_SecurityStatus
v_HS_MODEM_DEVICE
v_HS_MONITORDETAILS
v_HS_MOTHERBOARD_DEVICE
v_HS_NAPCLIENT
v_HS_NETWORK_ADAPTER
v_HS_NETWORK_ADAPTER_CONFIGURATION
v_HS_NETWORK_CLIENT
v_HS_NETWORK_DRIVERS
v_HS_NETWORK_LOGIN_PROFILE
v_HS_NETWORKPRINTERS0
v_HS_NT_EVENTLOG_FILE
v_HS_OFFICE365PROPLUSCONFIGURATIONS
v_HS_OPERATING_SYSTEM
v_HS_OPTIONAL_FEATURE
v_HS_OS_RECOVERY_CONFIGURATION
v_HS_PAGE_FILE_SETTING
v_HS_PARALLEL_PORT
v_HS_PARTITION
v_HS_PC_BIOS
v_HS_PCMCIA_CONTROLLER
v_HS_PHYSICAL_MEMORY
v_HS_POINTING_DEVICE
v_HS_PORT
v_HS_PORTABLE_BATTERY
v_HS_POWER_SUPPLY
v_HS_PRINT_JOB
v_HS_PRINTER_CONFIGURATION
v_HS_PRINTER_DEVICE
v_HS_PROCESS
v_HS_PROCESSOR
v_HS_PROTECTED_VOLUME_INFO
v_HS_PROTOCOL
v_HS_QUICK_FIX_ENGINEERING
v_HS_RAX_APPLICATION
v_HS_REGISTRY
v_HS_SCSI_CONTROLLER
v_HS_SERIAL_PORT
v_HS_SERIAL_PORT_CONFIGURATION
v_HS_SERVER_FEATURE
v_HS_SERVICE
v_HS_SHARE
v_HS_SMS_ADVANCED_CLIENT_CACHE0
v_HS_SMS_ADVANCED_CLIENT_STATE
v_HS_SOFTWARE_LICENSING_PRODUCT
v_HS_SOFTWARE_LICENSING_SERVICE
v_HS_SOFTWARE_SHORTCUT
v_HS_SOFTWARE_TAG
v_HS_SOUND_DEVICE
v_HS_SYSTEM
v_HS_SYSTEM_ACCOUNT
v_HS_SYSTEM_CONSOLE_USAGE
v_HS_SYSTEM_CONSOLE_USER
v_HS_SYSTEM_DRIVER
v_HS_SYSTEM_ENCLOSURE
v_HS_SYSTEMHEALTHAGENT
v_HS_TAPE_DRIVE
v_HS_TIME_ZONE
v_HS_TPM
v_HS_TPM_STATUS
v_HS_TS_ISSUED_LICENSE
v_HS_TS_LICENSE_KEY_PACK
v_HS_USB_CONTROLLER
v_HS_USB_DEVICE
v_HS_VIDEO_CONTROLLER
v_HS_VIRTUAL_APPLICATION_PACKAGES
v_HS_VIRTUAL_APPLICATIONS
v_HS_VIRTUAL_MACHINE
v_HS_VIRTUAL_MACHINE_64
v_HS_VIRTUAL_MACHINE_EXT
v_HS_VOLUME
v_HS_WEBAPP_APPLICATION
v_HS_WINDOWS8_APPLICATION
v_HS_WINDOWS8_APPLICATION_USER_INFO
v_HS_WINDOWSUPDATE
v_HS_WINDOWSUPDATEAGENTVERSION
v_HS_WRITE_FILTER_STATE
v_HS_X86_PC_MEMORY
v_Identification
v_ImagePackage
v_ImageUpdateStatus
v_INSTALLED_SOFTWARE_DATA_Summary
v_IntuneAccountInfo
v_InventoryClass
v_InventoryClassProperty
v_InventoryReport
v_InventoryReportClass
v_LastPXEDeployment
v_LastUsageSummary
v_LifecycleDetectedGroups
v_LifecycleDetectedProducts
v_LocalizedCategories
v_LocalizedCategories_SiteLoc
v_LocalizedCIProperties
v_LocalizedCIProperties_SiteLoc
v_LocalizedConfigPointType
v_LocalizedErrorType
v_LocalizedNameLookup
v_LocalizedNameValue
v_LocalizedSettingType
v_LocalizedUpdatePackageMetaData_SiteLoc
v_LU_CAL_ProductList
v_LU_Category
v_LU_Category_Editable
v_LU_Family
v_LU_HardwareReadiness
v_LU_LicensedProduct
v_LU_LifecycleProductGroups
v_LU_LifecycleProductHashes
v_LU_MSProd
v_LU_SoftwareCode
v_LU_SoftwareHash
v_LU_SoftwareList
v_LU_SoftwareList_Editable
v_LU_SoftwareList_Local
v_LU_Tags
v_MachineSettings
v_MDMApplications
v_MDMCorpEnrollmentProfiles
v_MDMCorpOwnedDevices
v_MDMDeviceCategory
v_MDMDeviceEnrollmentManagers
v_MDMDeviceProperty
v_MDMUserCompanyTermAcceptance
v_MDMUserPolicyAssignment
v_MeterData
v_MeteredFiles
v_MeteredProductRule
v_MeteredUser
v_MeterRuleInstallBase
v_MIG_ClientGroupState
v_MIG_Clients
v_MIG_ClientState
v_MIG_Collections
v_MIG_Dashboard
v_MIG_Entities
v_MIG_EntityReference
v_MIG_EntityState
v_MIG_Job
v_MIG_JobEntity
v_MIG_MigratedDPs
v_MIG_SiteMapping
v_MIG_SiteRelation
v_MonthlyUsageSummary
v_NAPErrorCodeDescription
v_NAPRestrictionErrorSummary
v_NAPRestrictionSummary
v_NAPSystemInfo
v_Network_DATA_Serialized
v_ObjectsAssignedToOneCategory
v_OS_Details
v_OverallThreatActivity
v_OverallThreatActivity_History
v_Package
v_PackageStatus
v_PackageStatusDetailSumm
v_PackageStatusDistPointsSumm
v_PackageStatusRootSummarizer
v_PeerDPStatusInfo
v_PeerSourceBoundaryGroup
v_PeerSourceRejectionData
v_PerfCounter
v_PowerConfig
v_ProductFileInfo
v_Program
v_ProgramOffers
v_Query
v_R_IPNetwork
v_R_NetworkInfo
v_R_System
v_R_System_Valid
v_R_UnknownSystem
v_R_User
v_R_UserGroup
v_R_WarrantyEntitlements
v_RA_System_IPAddresses
v_RA_System_IPSubnets
v_RA_System_IPv6Addresses
v_RA_System_IPv6Prefixes
v_RA_System_MACAddresses
v_RA_System_ResourceNames
v_RA_System_SMS_Resident
v_RA_System_SMSAssignedSites
v_RA_System_SMSInstalledSites
v_RA_System_System_Group_Name
v_RA_System_SystemContainerName
v_RA_System_SystemGroupName
v_RA_System_SystemOUName
v_RA_System_SystemRoles
v_RA_Unknown_System_SMS_Assig
v_RA_User_Group_Group_OU_Name
v_RA_User_User_Group_Name_F
v_RA_User_UserContainerName
v_RA_User_UserGroupName
v_RA_User_UserOUName
v_RA_UserGroupADContainerName
v_RBAC_WinRTSideLoadingKeys
v_ReplicationData
v_Report_StatusMessageDetail
v_ReportViewSchema
v_ResourceAttributeMap
v_ResourceMap
v_Roles
v_SC_SiteDefinition
v_ScannedUpdates
v_SCCMAutoUpdates
v_SCCMAutoUpdateStatus
v_SCCMAutoUpdateStatusStr
v_SchemaViews
v_SDMErrorCategories
v_SDMLocalizedData_SiteLoc
v_SecuredObjectTypes
v_SecuredScopePermissions
v_ServerComponents
v_ServerMessageStatistics
v_ServiceWindow
v_Site
v_SiteAndSubsites
v_SiteDetailSummarizer
v_SiteSystemSummarizer
v_SMS_Alert
v_SMS_CIRelation
v_SMS_DistributionPointGroup
v_SMSCICurrentComplianceStatus
v_SMSConfigurationItems
v_SmsPackage
v_SoftwareConversionRules
v_SoftwareFile
v_SoftwareProduct
v_SoftwareUpdateSource
v_StateMessageStatistics
v_StateMigration
v_StateNames
v_StatMsgAttributes
v_StatMsgInsStrings
v_StatMsgModuleNames
v_StatMsgWithInsStrings
v_StatusMessage
v_StatusMessagesAlerts
v_SummarizationInterval
v_SummarizerRootStatus
v_SummarizerSiteStatus
v_SummaryTasks
v_SuperPeers
v_SupportedPlatforms
v_System_SMS_Assign_ARR
v_SystemInventoryChanges
v_SystemResourceList
v_TargetedClientOperationPolicies
v_TargetedClientOperationTasks
v_TaskExecutionStatus
v_TaskSequenceAppReferenceDps
v_TaskSequenceAppReferencesInfo
v_TaskSequencePackage
v_TaskSequencePackageReferences
v_TaskSequenceReferenceDps
v_TaskSequenceReferencesInfo
v_ThreatCatalog
v_ThreatCategories
v_ThreatDefaultActions
v_ThreatSeverities
v_ThreatSummary
v_TopThreatsDetected
v_TS_AppReferences_Flat
v_TS_References_Flat
v_UAComputer
v_Update_ComplianceStatus
v_Update_ComplianceStatusAll
v_Update_ComplianceStatusReported
v_Update_ComplianceSummary
v_Update_ComplianceSummary_Live
v_Update_DeploymentSummary_Live
v_UpdateAssignmentStatus
v_UpdateAssignmentStatus_Live
v_UpdateCategoryInstances
v_UpdateCIs
v_UpdateComplianceStatus
v_UpdateContents
v_UpdateDeploymentClientSummary
v_UpdateDeploymentSummary
v_UpdateEnforcementSummaryPerCollection
v_UpdateGroupStatus_Live
v_UpdateInfo
v_UpdateScanStatus
v_UpdateState_Combined
v_UpdateSummaryPerCollection
v_UserAndGroupsDiscovered
v_UserAppRequests
v_UserAppsLocalizedPropsForCatalog
v_UserHealthProfileState
v_UserMachineIntelligence
v_UserMachineRelation
v_UserMachineRelationship
v_UserMachineSourceRelation
v_UserMachineTypeRelation
v_Users
v_UserSettings
v_UsersPrimaryMachines
v_UserStateMigration
v_UserTargetedApps
v_UserTargetedClassicApps
v_WakeupProxyDeploymentState
v_WindowsServicingStates
v_WOLClientTimeZones
v_WOLCommunicationErrorStatus
v_WOLCommunicationHistory
v_WOLEnabledAdvertisements
v_WOLEnabledAssignments
v_WOLEnabledObjects
v_WOLEnabledTaskSequences
v_WOLGetPendingObjectSchedules
v_WOLGetSupportedObjects
v_WOLGetWOLEnabledSites
v_WOLSUMTargetedClients
v_WOLSWDistTargetedClients
v_WOLTargetedClients
v_WOLTSTargetedClients
v_WOLWorkstationInfo
vInventoriedLicensedProduct


