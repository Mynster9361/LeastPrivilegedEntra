function Get-ActivityData {
    <#
    .SYNOPSIS
        Returns the least-privileged Microsoft Entra RBAC role and Microsoft Graph permission required for an audit log activity.
    .DESCRIPTION
        Looks up a Microsoft Entra ID audit log Category, and optionally a specific Activity display name, in the
        built-in activity-to-permission map and returns the least privileged Entra RBAC role and Microsoft Graph
        permission needed to perform that activity.
    .PARAMETER Category
        The audit log Category to look up (e.g. "AdministrativeUnit", "UserManagement", "GroupManagement").
        Supports wildcards; pass "*" to return every category.
    .PARAMETER Name
        The audit log Activity display name to look up (e.g. "Add administrative unit"). Supports wildcards.
        If omitted, every activity in the category is returned.
    .EXAMPLE
        Get-ActivityData -Category AdministrativeUnit -Name "Add administrative unit"

        Returns the least privileged RBAC role and Graph permission for adding an administrative unit.
    .EXAMPLE
        Get-ActivityData -Category UserManagement -Name "*password*"

        Returns the least privileged permissions for every UserManagement activity whose name contains "password".
    .EXAMPLE
        Get-ActivityData -Category * | Where-Object Relevant

        Returns every activity, across all categories, that is flagged as relevant.
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]$Category,

        [Parameter(Mandatory = $false, Position = 1)]
        [SupportsWildcards()]
        [string]$Name
    )

    begin {
        $activityData = @{
            AdministrativeUnit = @{ 
                Description = "Administrative units are containers for resources that can be managed as a single entity."
                Activity = @(
                    @{
                        DisplayName = "Bulk add members to administrative unit - started (bulk)"
                        Description = ""
                        Id = "administrativeUnit"
                        Type = "Microsoft.Directory/administrativeUnits"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "AdministrativeUnit.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Bulk remove members to administrative unit - finished (bulk)"
                        Description = ""
                        Id = "administrativeUnit"
                        Type = "Microsoft.Directory/administrativeUnits"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "AdministrativeUnit.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add administrative unit"
                        Description = ""
                        Id = "administrativeUnit"
                        Type = "Microsoft.Directory/administrativeUnits"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "AdministrativeUnit.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to administrative unit"
                        Description = ""
                        Id = "administrativeUnit"
                        Type = "Microsoft.Directory/administrativeUnits"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "AdministrativeUnit.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to restricted management administrative unit"
                        Description = ""
                        Id = "administrativeUnit"
                        Type = "Microsoft.Directory/administrativeUnits"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete administrative unit"
                        Description = ""
                        Id = "administrativeUnit"
                        Type = "Microsoft.Directory/administrativeUnits"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "AdministrativeUnit.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Hard Delete administrative unit"
                        Description = ""
                        Id = "administrativeUnit"
                        Type = "Microsoft.Directory/administrativeUnits"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "AdministrativeUnit.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from administrative unit"
                        Description = ""
                        Id = "administrativeUnit"
                        Type = "Microsoft.Directory/administrativeUnits"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "AdministrativeUnit.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from restricted management administrative unit"
                        Description = ""
                        Id = "administrativeUnit"
                        Type = "Microsoft.Directory/administrativeUnits"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore administrative unit"
                        Description = ""
                        Id = "administrativeUnit"
                        Type = "Microsoft.Directory/administrativeUnits"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "AdministrativeUnit.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update administrative unit"
                        Description = ""
                        Id = "administrativeUnit"
                        Type = "Microsoft.Directory/administrativeUnits"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "AdministrativeUnit.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Bulk add members to administrative unit - finished (bulk)"
                        Description = ""
                        Id = "administrativeUnit"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "started (bulk)"
                        Description = ""
                        Id = "administrativeUnit"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    }
                )
            }
            DeviceManagement = @{ 
                Description = "Device management is the process of managing and securing devices within an organization."
                Activity = @(
                    @{
                        DisplayName = "Add device management configuration"
                        Description = ""
                        Id = "deviceManagement"
                        Type = "Microsoft.Intune/deviceManagement"
                        LeastPrivilegeRBAC = "Microsoft Intune Service Administrator"
                        LeastPrivilegedMSGraph = "DeviceManagementConfiguration.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete device management configuration"
                        Description = ""
                        Id = "deviceManagement"
                        Type = "Microsoft.Intune/deviceManagement"
                        LeastPrivilegeRBAC = "Microsoft Intune Service Administrator"
                        LeastPrivilegedMSGraph = "DeviceManagementConfiguration.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update device management configuration"
                        Description = ""
                        Id = "deviceManagement"
                        Type = "Microsoft.Intune/deviceManagement"
                        LeastPrivilegeRBAC = "Microsoft Intune Service Administrator"
                        LeastPrivilegedMSGraph = "DeviceManagementConfiguration.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Bulk add authentication devices - finished (bulk)"
                        Description = ""
                        Id = "deviceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Download devices - finished (bulk)"
                        Description = ""
                        Id = "deviceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "started (bulk)"
                        Description = ""
                        Id = "deviceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    }
                )
            }
            DirectoryManagement = @{
                Description = "Directory management involves managing and maintaining the directory services within an organization, including user accounts, groups, and other directory objects."
                Activity = @(
                    @{
                        DisplayName = "Bulk download hardware tokens - finished (bulk)"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.Read.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Download registration and reset events - finished (bulk)"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Reports Reader"
                        LeastPrivilegedMSGraph = "Reports.Read.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Download role assignments - finished (bulk)"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = "RoleManagement.Read.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Download service principals - finished (bulk)"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = "Application.Read.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Download user registration details - finished (bulk)"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Reports Reader"
                        LeastPrivilegedMSGraph = "Reports.Read.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Download users - finished (bulk)"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = "User.Read.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Export summary data - finished (bulk)"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Reports Reader"
                        LeastPrivilegedMSGraph = "Reports.Read.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Export summary data new - finished (bulk)"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Reports Reader"
                        LeastPrivilegedMSGraph = "Reports.Read.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "started (bulk)"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create program"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.AAD/accessReviews"
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Link program control"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.AAD/accessReviews"
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Unlink program control"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.AAD/accessReviews"
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update program"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.AAD/accessReviews"
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Disable Desktop Sso"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "OnPremisesPublishingProfiles.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Disable Desktop Sso for a specific domain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/domains"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "OnPremisesPublishingProfiles.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Disable application proxy"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "OnPremisesPublishingProfiles.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Disable passthrough authentication"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "OnPremisesPublishingProfiles.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Enable Desktop Sso"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "OnPremisesPublishingProfiles.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Enable Desktop Sso for a specific domain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/domains"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "OnPremisesPublishingProfiles.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Enable application proxy"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "OnPremisesPublishingProfiles.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Enable passthrough authentication"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "OnPremisesPublishingProfiles.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "DELETE Subscription.DeleteProviders"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "DELETE Tenant.DeleteAgentStatuses"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "DELETE Tenant.DeleteCaches"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "DELETE Tenant.DeleteGreetings"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "PATCH Tenant.Patch"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "PATCH Tenant.PatchCaches"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "POST SoundFile.Post"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "POST Subscription.CreateProvider"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "POST Subscription.CreateSubscription"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "POST Tenant.CreateBlockedUser"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "POST Tenant.CreateBypassedUser"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "POST Tenant.CreateCacheConfig"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "POST Tenant.CreateGreeting"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "POST Tenant.CreateTenant"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "POST Tenant.GenerateNewActivationCredentials"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "POST Tenant.RemoveBlockedUser"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "POST Tenant.RemoveBypassedUser"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Dismiss recommendation"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/recommendations"
                        LeastPrivilegeRBAC = "Reports Reader"
                        LeastPrivilegedMSGraph = "DirectoryRecommendations.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Mark recommendation as complete"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/recommendations"
                        LeastPrivilegeRBAC = "Reports Reader"
                        LeastPrivilegedMSGraph = "DirectoryRecommendations.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Postpone recommendation"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/recommendations"
                        LeastPrivilegeRBAC = "Reports Reader"
                        LeastPrivilegedMSGraph = "DirectoryRecommendations.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "DeleteDataFromBackend"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "DeleteDataFromCosmosDb"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "ExportDataFromBackend"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "ExportDataFromCosmosDb"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get age gating configuration"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get list of tenants"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get resources properties of a tenant"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get tenant details"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get tenant domains"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Initialize tenant"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update age gating configuration"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update tenant metadata"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Verify if tenant is B2C"
                        Description = ""
                        Id = "directoryManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add partner to company"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.CrossTenantAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add sharedEmailDomainInvitation"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add unverified domain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/domains"
                        LeastPrivilegeRBAC = "Domain Name Administrator"
                        LeastPrivilegedMSGraph = "Domain.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add verified domain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/domains"
                        LeastPrivilegeRBAC = "Domain Name Administrator"
                        LeastPrivilegedMSGraph = "Domain.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create Company"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Tenant Creator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create company settings"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete company allowed data location"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete company settings"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete subscription"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Deleting Source Tenant subscriptions"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Demote partner"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Directory deleted"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Directory deleted permanently"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Directory scheduled for deletion (Lifecycle)"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Directory scheduled for deletion (UserRequest)"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get cross-cloud verification code for domain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/domains"
                        LeastPrivilegeRBAC = "Domain Name Administrator"
                        LeastPrivilegedMSGraph = "Domain.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Hard Delete Domain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/domains"
                        LeastPrivilegeRBAC = "Domain Name Administrator"
                        LeastPrivilegedMSGraph = "Domain.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Promote company to partner"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Promote sub domain to root domain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/domains"
                        LeastPrivilegeRBAC = "Domain Name Administrator"
                        LeastPrivilegedMSGraph = "Domain.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove partner from company"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove unverified domain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/domains"
                        LeastPrivilegeRBAC = "Domain Name Administrator"
                        LeastPrivilegedMSGraph = "Domain.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove verified domain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/domains"
                        LeastPrivilegeRBAC = "Domain Name Administrator"
                        LeastPrivilegedMSGraph = "Domain.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Schedule Add sharedEmailDomain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Schedule Remove sharedEmailDomain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Set Company Information"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Set DirSync feature"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Set DirSyncEnabled flag"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Set Partnership"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Set accidental deletion threshold"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Set company allowed data location"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Set company multinational feature enabled"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Set directory feature on tenant"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Set domain authentication"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/domains"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Domain.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Set federation settings on domain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/domains"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Domain.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Set password policy"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Authentication Policy Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Soft Delete Domain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/domains"
                        LeastPrivilegeRBAC = "Domain Name Administrator"
                        LeastPrivilegedMSGraph = "Domain.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Suspending Source Tenant Subscriptions"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update Domain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/domains"
                        LeastPrivilegeRBAC = "Domain Name Administrator"
                        LeastPrivilegedMSGraph = "Domain.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update company"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update company settings"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update domain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/domains"
                        LeastPrivilegeRBAC = "Domain Name Administrator"
                        LeastPrivilegedMSGraph = "Domain.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update sharedEmailDomain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update sharedEmailDomainInvitation"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Verify domain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/domains"
                        LeastPrivilegeRBAC = "Domain Name Administrator"
                        LeastPrivilegedMSGraph = "Domain.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Verify email verified domain"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/domains"
                        LeastPrivilegeRBAC = "Domain Name Administrator"
                        LeastPrivilegedMSGraph = "Domain.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Disable password writeback for directory"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Enable password writeback for directory"
                        Description = ""
                        Id = "directoryManagement"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    }
                )
            }
            GroupManagement = @{ 
                Description = "Group management covers creating and modifying security and Microsoft 365 groups, membership and ownership changes, PIM role assignments on groups, and self-service group operations from the MyGroups portal."
                Activity = @(
                    @{
                        DisplayName = "Bulk import group members - finished (bulk)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "GroupMember.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Bulk remove group members - finished (bulk)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "GroupMember.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Download group members - finished (bulk)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.Read.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Download groups - finished (bulk)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = "Group.Read.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "started (bulk)"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add app role assignment to group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "AppRoleAssignment.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "GroupMember.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add owner to group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Assign label to group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create group settings"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete group settings"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Finish applying group based license to user"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "License Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Grant contextual consent to application"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "DelegatedPermissionGrant.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Hard Delete group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove app role assignment from group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "AppRoleAssignment.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove eligible member from group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove eligible owner from group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove label from group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Remove member from group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "GroupMember.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove owner from group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Set group license"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "License Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Set group to be managed by user"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Start applying group based license to users"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "License Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Trigger group license recalculation"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "License Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update group settings"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM canceled (renew)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM canceled (timebound)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM completed (permanent)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM completed (timebound)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM requested (permanent)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM requested (renew)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM requested (timebound)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role approval requested (PIM activation)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role canceled (PIM activation)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add member to role completed (PIM activation)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role in PIM canceled (permanent)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add member to role in PIM canceled (renew)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add member to role in PIM canceled (timebound)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add member to role in PIM completed (permanent)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role in PIM completed (timebound)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role in PIM requested (permanent)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role in PIM requested (renew)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role in PIM requested (timebound)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role request approved (PIM activation)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role request denied (PIM activation)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add member to role requested (PIM activation)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Cancel request"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Cancel request for role removal"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Cancel request for role update"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Offboarded resource from PIM"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Onboarded resource to PIM"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "PIM activation request expired"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "PIM policy removed"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Process request"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Process role removal request"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Remove eligible member from role in PIM completed (permanent)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove eligible member from role in PIM completed (timebound)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove eligible member from role in PIM requested (permanent)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove eligible member from role in PIM requested (timebound)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role (PIM activation expired)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Remove member from role completed (PIM deactivate)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Remove member from role in PIM completed (permanent)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role in PIM completed (timebound)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role in PIM requested (permanent)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role in PIM requested (timebound)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role requested (PIM deactivate)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Remove permanent direct role assignment"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove permanent eligible role assignment"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove request"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Resource updated"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Restore eligible member from role in PIM completed"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore member from role"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore member from role in PIM completed"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore permanent direct role assignment"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update eligible member in PIM canceled (extend)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update eligible member in PIM requested (extend)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update member in PIM approved by admin (extend/renew)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update member in PIM canceled (extend)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update member in PIM denied by admin (extend/renew)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update member in PIM requested (extend)"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update role setting in PIM"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureADGroup"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "ApprovalNotification_Create"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Approval_Act"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Approval_Get"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Approval_GetAll"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Approvals_Post"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Approve a pending request to join a group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Cancel a pending request to join a group"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create lifecycle management policy"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete a pending request to join a group"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete lifecycle management policy"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Device_Create"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Device_Delete"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Device_Get"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Device_GetAll"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Features_GetFeaturesAsync"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Features_IsFeatureEnabledAsync"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Features_UpdateFeaturesAsync"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "GroupLifecyclePolicies_Get"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "GroupLifecyclePolicies_addGroup"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "GroupLifecyclePolicies_removeGroup"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Group_AddMember"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "GroupMember.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Group_AddOwner"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Group_BatchValidateDynamicMembership"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Group_Create"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Group_Delete"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Group_Get"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Group_GetAll"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Group_GetDynamicGroupProperties"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Group_GetDynamicMembershipDeviceAttributes"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Group_GetDynamicMembershipOperators"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Group_GetDynamicMembershipUserBaseAttributes"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Group_GetExpiryNotificationDate"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Group_GetMembers"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Group_GetOwners"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Group_RemoveMember"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "GroupMember.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Group_RemoveOwner"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Group_Restore"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Group_Update"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Group_ValidateDynamicMembership"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "GroupsODataV4_Get"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "GroupsODataV4_GetgroupLifecyclePolicies"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "GroupsODataV4_evaluateDynamicMembership"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Groups_CreateLink"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Groups_Get"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "LcmPolicy_Get"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "LcmPolicy_RenewGroup"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Reject a pending request to join a group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Renew group"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Request to join a group"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "set dynamic group properties"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Settings_GetSettingsAsync"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update lifecycle management policy"
                        Description = ""
                        Id = "groupManagement"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "User_Create"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "User_Delete"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "User_Get"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "User_GetAll"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "User_GetMemberOf"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "User_GetOwnedObjects"
                        Description = ""
                        Id = "groupManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    }
                )
            }
            Policy = @{ 
                Description = "Policy management covers Conditional Access policies, identity risk policies, access review decisions, Terms of Use, and other directory-wide policy configurations."
                Activity = @(
                    @{
                        DisplayName = "Add blocked user"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add bypass user"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Clear block on user"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove bypassed user"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update Sign-In Risk Policy"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.ConditionalAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update User Risk and MFA Registration Policy"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.ConditionalAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Access review ended"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Apply decision"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Approve decision"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Bulk Approve decisions"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Bulk Deny decisions"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Bulk Reset decisions"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Bulk mark decisions as don't know"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Cancel request"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create access review"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create request"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete access review"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete approvals"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Deny decision"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Don't know decision"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Request expired"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Reset decision"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update access review"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update partner directory settings"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.ExternalIdentities"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update request"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add AuthenticationContextClassReference"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.ConditionalAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add Conditional Access policy"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.ConditionalAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add named location"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.ConditionalAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete AuthenticationContextClassReference"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.ConditionalAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete Conditional Access policy"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.ConditionalAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete named location"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.ConditionalAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update AuthenticationContextClassReference"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.ConditionalAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update Conditional Access policy"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.ConditionalAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update continuous access evaluation"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.ConditionalAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update named location"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.ConditionalAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update security defaults"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.ConditionalAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add owner to policy"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add policy"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete policy"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Hard Delete policy"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove owner from policy"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove policy credentials"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore policy"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update policy"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Set device registration policies"
                        Description = ""
                        Id = "policy"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.DeviceConfiguration"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Accept Terms Of Use"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create Terms Of Use"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Agreement.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Decline Terms Of Use"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete Consent"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Agreement.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete Terms Of Use"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Agreement.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Edit Terms Of Use"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Agreement.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Publish Terms Of Use"
                        Description = ""
                        Id = "policy"
                        Type = ""
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Agreement.ReadWrite.All"
                        Relevant = $true
                    }
                )
            }
            UserManagement = @{ 
                Description = "User management covers user lifecycle operations, password management, authentication method registration, MFA fraud reports, and B2B guest invitation workflows."
                Activity = @(
                    @{
                        DisplayName = "Bulk create users - finished (bulk)"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Bulk delete users - finished (bulk)"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Bulk invite users - finished (bulk)"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Guest Inviter"
                        LeastPrivilegedMSGraph = "User.Invite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Bulk restore deleted users - finished (bulk)"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Download users - finished (bulk)"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = "User.Read.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "started (bulk)"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Apply review"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Approve all requests in business flow"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Auto review"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Auto apply review"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create business flow"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create governance policy template"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete access review"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete business flow"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete governance policy template"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Deny all decisions"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Deny all requests in business flow"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Request approved"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Request denied"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update business flow"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update governance policy template"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Identity Governance Administrator"
                        LeastPrivilegedMSGraph = "AccessReview.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Admin deleted security info"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Admin registered security info"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Admin started password reset"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Admin updated security info"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Get passkey creation options"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Restore multifactor authentication on all remembered devices"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update per-user multifactor authentication state"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "User canceled security info registration"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "User changed default security info"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "User deleted security info"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "User registered all required security info"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "User registered security info"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "User reviewed security info"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "User started password change"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "user started password reset"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "User started security info registration"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "User updated security info"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Fraud reported - no action taken"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Fraud reported - user is blocked for MFA"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Suspicious activity reported"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Redeem extern user invite"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add Windows Hello for Business credential"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add passwordless phone sign-in credential"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete Windows Hello for Business credential"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete passwordless phone sign-in credential"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add app role assignment to group"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "AppRoleAssignment.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add user"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add user sponsor"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Change user license"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "License Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Change user password"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Convert federated user to managed"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create application password for user"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete application password for user"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete user"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Disable Strong Authentication"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Disable account"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Enable Strong Authentication"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Enable account"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Hard Delete user"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove OrganizationalUnit assigned to a user"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Remove app role assignment from user"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "AppRoleAssignment.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove user sponsor"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Reset password"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore user"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Set force change user password"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Set user manager"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Takeover user cloned"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update OrganizationalUnit assigned to a user"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update StsRefreshTokenValidFrom Timestamp"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update external secrets"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update user"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add Passkey (device-bound)"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add platform credential"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete Passkey (device-bound)"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete platform credential"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete external user"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Email not sent, user unsubscribed"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Invitation Email"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Invite external user"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Guest Inviter"
                        LeastPrivilegedMSGraph = "User.Invite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Invite external user with reset invitation status"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Guest Inviter"
                        LeastPrivilegedMSGraph = "User.Invite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Invite internal user to B2B collaboration"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Guest Inviter"
                        LeastPrivilegedMSGraph = "User.Invite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Redeem external user invite"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "User Password Registration"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "User Password Reset"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Updated ConvergedUXV2 feature value"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Updated MyApps feature value"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update MyStaff feature value"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Updated SSPRConvergence feature value"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Updated SignInReports feature value"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Blocked from self-service password reset"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Change password (self-service)"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Reset password (by admin)"
                        Description = ""
                        Id = "userManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "User.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Reset password (self-service)"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Security info saved for self-service password reset"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Self-service password reset flow activity progress"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Unlock user account (self-service)"
                        Description = ""
                        Id = "userManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    }
                )
            }
            ProvisioningManagement = @{ 
                Description = "Provisioning management covers configuration and runtime events for HR inbound provisioning, application outbound provisioning, and cross-tenant synchronization."
                Activity = @(
                    @{
                        DisplayName = "Add provisioning configuration"
                        Description = "A new provisioning configuration has been created."
                        Id = "provisioningManagement"
                        Type = "Microsoft.Directory/synchronization"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Synchronization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete provisioning configuration"
                        Description = "The provisioning configuration has been deleted."
                        Id = "provisioningManagement"
                        Type = "Microsoft.Directory/synchronization"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Synchronization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Disable/pause provisioning configuration"
                        Description = "The provisioning job has been disabled / paused."
                        Id = "provisioningManagement"
                        Type = "Microsoft.Directory/synchronization"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Synchronization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Enable/restart provisioning configuration"
                        Description = "The provisioning job as been restarted."
                        Id = "provisioningManagement"
                        Type = "Microsoft.Directory/synchronization"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Synchronization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Enable/start provisioning configuration"
                        Description = "The provisioning job has been started."
                        Id = "provisioningManagement"
                        Type = "Microsoft.Directory/synchronization"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Synchronization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Execution"
                        Description = "The provisioning job is executing. There are various events that can be emitted including ProvisioningJobStartedInitialSync, ProvisioningJobStartedIncrementalSync, ProvisioningJobComplete and ProvisioningJobDisabled."
                        Id = "provisioningManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Export"
                        Description = "The provisioning job has exported a change to the target system (ex: create a user)."
                        Id = "provisioningManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Import"
                        Description = "The provisioning job imported the object from the source system (ex: import the user properties in Entra before provisioning the account into Salesforce)."
                        Id = "provisioningManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Other"
                        Description = ""
                        Id = "provisioningManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Process escrow"
                        Description = "The provisioning service was unable to export a change to the target application and is retrying the operation."
                        Id = "provisioningManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Quarantine"
                        Description = "The provisioning job is executing at a reduced frequency due to issues such as a lack of connectivity to the target application. [Learn more](~/identity/app-provisioning/application-provisioning-quarantine-status.md)"
                        Id = "provisioningManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Synchronization rule action"
                        Description = "The provisioning service evaluated the object and did not export a change to the target system. This even is most often emitted when a user is skipped due to being out of scope for provisioning."
                        Id = "provisioningManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update attribute mappings or scope"
                        Description = "The attribute mappings or scoping rules for the provisioning job have been updated."
                        Id = "provisioningManagement"
                        Type = "Microsoft.Directory/synchronization"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Synchronization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update provisioning setting or credentials"
                        Description = "The settings on your provisioning job (ex: notification email change, sync all vs. sync assigned users and groups, accidental deletions prevention) have been updated. The credentials for your provisioning job (ex: add a new bearer token) have been updated."
                        Id = "provisioningManagement"
                        Type = "Microsoft.Directory/synchronization"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Synchronization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "User Provisioning"
                        Description = "The schema for the provisioning job has been restored to the default."
                        Id = "provisioningManagement"
                        Type = "Microsoft.Directory/synchronization"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Synchronization.ReadWrite.All"
                        Relevant = $false
                    }
                )
            }
            ApplicationManagement = @{ 
                Description = "Application management covers the lifecycle of applications and service principals, permission grants, PIM role assignments, and authentication method policy administration."
                Activity = @(
                    @{
                        DisplayName = "Add application"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete application"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update application"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Assign Hardware Oath Token"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Authentication Methods Policy Reset"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/authenticationMethodsPolicy"
                        LeastPrivilegeRBAC = "Authentication Policy Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.AuthenticationMethod"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Authentication Methods Policy Update"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/authenticationMethodsPolicy"
                        LeastPrivilegeRBAC = "Authentication Policy Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.AuthenticationMethod"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Authentication Strength Combination Configuration Create"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/authenticationStrengthPolicies"
                        LeastPrivilegeRBAC = "Authentication Policy Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.AuthenticationMethod"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Authentication Strength Combination Configuration Delete"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/authenticationStrengthPolicies"
                        LeastPrivilegeRBAC = "Authentication Policy Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.AuthenticationMethod"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Authentication Strength Combination Configuration Update"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/authenticationStrengthPolicies"
                        LeastPrivilegeRBAC = "Authentication Policy Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.AuthenticationMethod"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Authentication Strength Policy Create"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/authenticationStrengthPolicies"
                        LeastPrivilegeRBAC = "Authentication Policy Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.AuthenticationMethod"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Authentication Strength Policy Delete"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/authenticationStrengthPolicies"
                        LeastPrivilegeRBAC = "Authentication Policy Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.AuthenticationMethod"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Authentication Strength Policy Update"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/authenticationStrengthPolicies"
                        LeastPrivilegeRBAC = "Authentication Policy Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.AuthenticationMethod"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Bulk upload Hardware Oath Token"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create Hardware Oath Token"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete Hardware Oath Token"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "MFA Service Policy Update"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/policies"
                        LeastPrivilegeRBAC = "Authentication Policy Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.AuthenticationMethod"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "PATCH UserAuthMethod.PatchSignInPreferencesAsync"
                        Description = ""
                        Id = "applicationManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "PATCH UserAuthMethod.ResetQRPinAsync"
                        Description = ""
                        Id = "applicationManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "PATCH UserAuthMethod.UpdateQRPinAsync"
                        Description = ""
                        Id = "applicationManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "POST UserAuthMethod.SoftwareOathProofupRegistration"
                        Description = ""
                        Id = "applicationManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update Hardware Oath Token"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/users"
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add app role assignment to service principal"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/servicePrincipals"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "AppRoleAssignment.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add delegated permission grant"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/oauth2PermissionGrants"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "DelegatedPermissionGrant.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add owner to application"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add owner to service principal"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/servicePrincipals"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add policy to application"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add policy to service principal"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/servicePrincipals"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add service principal"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/servicePrincipals"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add service principal credentials"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/servicePrincipals"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.OwnedBy"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Cancel application update with safe rollout"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Complete application update after safe rollout"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Consent to application"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/oauth2PermissionGrants"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "DelegatedPermissionGrant.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Hard Delete application"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Hard delete service principal"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/servicePrincipals"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove app role assignment from service principal"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/servicePrincipals"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "AppRoleAssignment.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove delegated permission grant"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/oauth2PermissionGrants"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "DelegatedPermissionGrant.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove owner from application"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove owner from service principal"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/servicePrincipals"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove policy from application"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove policy from service principal"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/servicePrincipals"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove service principal"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/servicePrincipals"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove service principal credentials"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/servicePrincipals"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.OwnedBy"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore application"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore service principal"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/servicePrincipals"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore consent"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/oauth2PermissionGrants"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "DelegatedPermissionGrant.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Set verified publisher"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Unset verified publisher"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update application with safe rollout"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update application - Certificates and secrets management"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.OwnedBy"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update external secrets"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update service principal"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/servicePrincipals"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create Certificate"
                        Description = ""
                        Id = "applicationManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete Certificate"
                        Description = ""
                        Id = "applicationManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update Certificate"
                        Description = ""
                        Id = "applicationManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create application collection"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete application collection"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update application collection"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update application collection order"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update preview settings"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add member to role approval requested (PIM activation)"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role in PIM completed (timebound)"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role in PIM requested (timebound)"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Approve request - direct role assignment"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "PIM activation request expired"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "PIM policy removed"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role in PIM completed (timebound)"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove request"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Role definition created"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/roleDefinitions"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update role setting in PIM"
                        Description = ""
                        Id = "applicationManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    }
                )
            }
            Authentication = @{ 
                Description = "Authentication covers feature rollout policies for hybrid authentication, B2C user flow execution events, sign-in processing, and mobility management confirmation actions."
                Activity = @(
                    @{
                        DisplayName = "Add a group to feature rollout"
                        Description = ""
                        Id = "authentication"
                        Type = "Microsoft.Directory/featureRolloutPolicies"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.FeatureRollout"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create rollout policy for feature"
                        Description = ""
                        Id = "authentication"
                        Type = "Microsoft.Directory/featureRolloutPolicies"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.FeatureRollout"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete rollout policy of feature"
                        Description = ""
                        Id = "authentication"
                        Type = "Microsoft.Directory/featureRolloutPolicies"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.FeatureRollout"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove a group from feature rollout"
                        Description = ""
                        Id = "authentication"
                        Type = "Microsoft.Directory/featureRolloutPolicies"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.FeatureRollout"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove user from feature rollout"
                        Description = ""
                        Id = "authentication"
                        Type = "Microsoft.Directory/featureRolloutPolicies"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.FeatureRollout"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update rollout policy of feature"
                        Description = ""
                        Id = "authentication"
                        Type = "Microsoft.Directory/featureRolloutPolicies"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.FeatureRollout"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "A self-service sign-up request was completed"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "An API was called as part of a user flow"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete all available strong authentication devices"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = "Authentication Administrator"
                        LeastPrivilegedMSGraph = "UserAuthenticationMethod.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Evaluate Conditional Access policies"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Exchange token"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Federate with an identity provider"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get available strong authentication devices"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Issue a SAML assertion to the application"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Issue an access token to the application"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Issue an authorization code to the application"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Issue an id_token to the application"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Make phone call to verify phone number"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Register TOTP secret"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Remediate user"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "IdentityRiskyUser.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Send SMS to verify phone number"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Send verification email"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Validate Client Credentials"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Validate local account credentials"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Validate user authentication"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Verify email address"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "verify one time password"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Verify phone number"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Test audit log"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add user to feature rollout"
                        Description = ""
                        Id = "authentication"
                        Type = "Microsoft.Directory/featureRolloutPolicies"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.FeatureRollout"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "User confirmed unusual sign-in event as legitimate"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "User reported unusual sign-in event as not legitimate"
                        Description = ""
                        Id = "authentication"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    }
                )
            }
            Authorization = @{ 
                Description = "Authorization covers B2C tenant resource management via Azure Resource Manager, including identity provider management, user flows, custom policies, policy keys, and authentication event extensions."
                Activity = @(
                    @{
                        DisplayName = "User authorization for application access"
                        Description = ""
                        Id = "authorization"
                        Type = "Microsoft.Directory/servicePrincipals"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add v2 application permissions"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Check whether the resource name is available"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create API connector"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Administrator"
                        LeastPrivilegedMSGraph = "APIConnectors.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create Identity Provider"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity Provider Administrator"
                        LeastPrivilegedMSGraph = "IdentityProvider.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create authenticationEventListener"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "EventListener.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create authenticationEventsFlow"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "AuthenticationEventsFlow.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create custom identity provider"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity Provider Administrator"
                        LeastPrivilegedMSGraph = "IdentityProvider.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create custom policy"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Policy Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.TrustFramework"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create customAuthenticationExtension"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "CustomAuthenticationExtension.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create or update a B2C directory resource"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create or update a B2C directory tenant and resource"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create or update a CIAM directory tenant and resource"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create or update a Guest Usages resource"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create or update localized resource"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Policy Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create policy key"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create starter pack"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create user attribute"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Attribute Administrator"
                        LeastPrivilegedMSGraph = "IdentityUserFlowAttribute.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create user flow"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Administrator"
                        LeastPrivilegedMSGraph = "IdentityUserFlow.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create v2 application"
                        Description = ""
                        Id = "authorization"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete API connector"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Administrator"
                        LeastPrivilegedMSGraph = "APIConnectors.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete B2C Tenant where the caller is an administrator"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete B2C directory resource"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete CIAM directory resource"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete Guest Usages resource"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete Identity Provider"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity Provider Administrator"
                        LeastPrivilegedMSGraph = "IdentityProvider.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete authenticationEventlistener"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "EventListener.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete authenticationEventsFlow"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "AuthenticationEventsFlow.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete custom policy"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Policy Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.TrustFramework"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete customAuthenticationExtension"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "CustomAuthenticationExtension.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete localized resource"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Policy Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete policy key"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete user attribute"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Attribute Administrator"
                        LeastPrivilegedMSGraph = "IdentityUserFlowAttribute.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete user flow"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Administrator"
                        LeastPrivilegedMSGraph = "IdentityUserFlow.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete v2 application"
                        Description = ""
                        Id = "authorization"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete v2 application permission grant"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "DelegatedPermissionGrant.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Generate key"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Get API connector"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get API connectors"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get B2C Tenants where the caller is an administrator"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get B2C directory resource"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get B2C directory resources in a resource group"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get B2C directory resources in a subscription"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get CIAM directory resource"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get CIAM directory resources in a resource group"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get CIAM directory resources in a subscription"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get Guest Usages resources"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get Guest Usages resources in a subscription"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get Identity Provider"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get Identity Providers"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get OnAttributeCollectionStartCustomExtension"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get OnAttributeCollectionSubmitCustomExtension"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get OnPageRenderStartCustomExtension"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get active key metadata from policy key"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get age gating configuration"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get authentication flows policy"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get authenticationEventListener"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get authenticationEventsFlow"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get authenticationEventsFlows"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get available output claims"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get configured custom identity providers"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get configured identity providers"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get configured local identity providers"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get custom domains"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get custom identity provider"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get custom policies"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get custom policy"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get custom policy metadata"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get customAuthenticationExtension"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get customAuthenticationExtensions"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get identity provider types"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get list of tenants"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get localized resource"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get operation status for an async operation"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get operations of Microsoft.AzureActiveDirectory resource provider"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get policy key"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get policy keys"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get resource properties of a tenant"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get supported cultures"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get supported identity providers"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get supported page contracts"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get tenant details"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get tenant domains"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get the authenticationEventsPolicy"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get user attribute"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get user attributes"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get user flow"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get user flows"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get v1 and v2 applications"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get v1 applications"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get v2 application"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Initialize tenant"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Move resources"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Restore policy key"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Retrieve v2 application permissions grants"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Retrieve v2 application service principals"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update API connector"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Administrator"
                        LeastPrivilegedMSGraph = "APIConnectors.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update Identity Provider"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity Provider Administrator"
                        LeastPrivilegedMSGraph = "IdentityProvider.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update OnAttributeCollectionStartCustomExtension"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "CustomAuthenticationExtension.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update OnAttributeCollectionSubmitCustomExtension"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "CustomAuthenticationExtension.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update OnPageRenderStartCustomExtension"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "CustomAuthenticationExtension.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update a B2C directory resource"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update a CIAM directory resource"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update a Guest Usages resource"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update age gating configuration"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update authentication flows policy"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Administrator"
                        LeastPrivilegedMSGraph = "IdentityUserFlow.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update authenticationEventListener"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "EventListener.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update authenticationEventsFlow"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "AuthenticationEventsFlow.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update authenticationEventsPolicy"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "AuthenticationEventsFlow.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update custom identity provider"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity Provider Administrator"
                        LeastPrivilegedMSGraph = "IdentityProvider.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update custom policy"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Policy Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.TrustFramework"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update customAuthenticationExtension"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "CustomAuthenticationExtension.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update identity provider"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity Provider Administrator"
                        LeastPrivilegedMSGraph = "IdentityProvider.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update local identity provider"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity Provider Administrator"
                        LeastPrivilegedMSGraph = "IdentityProvider.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update policy key"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update subscription status"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update tenant metadata"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update user attribute"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Attribute Administrator"
                        LeastPrivilegedMSGraph = "IdentityUserFlowAttribute.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update user flow"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Administrator"
                        LeastPrivilegedMSGraph = "IdentityUserFlow.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Upload certificate to policy key"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Upload key to policy key"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Upload secret into policy key"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Validate customExtension authenticationConfiguration"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Validate move resources"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Verify if tenant is B2C"
                        Description = ""
                        Id = "authorization"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    }
                )
            }
            ResourceManagement = @{ 
                Description = "Resource management covers App Proxy connectors, B2C and Global Secure Access resource configuration, PIM Azure resource role assignments, and Verified ID authority management."
                Activity = @(
                    @{
                        DisplayName = "Add connector Group"
                        Description = ""
                        Id = "resourceManagement"
                        Type = "Microsoft.Directory/connectorGroups"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add a Connector to Connector Group"
                        Description = ""
                        Id = "resourceManagement"
                        Type = "Microsoft.Directory/connectorGroups"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add application SSL certificate"
                        Description = ""
                        Id = "resourceManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete Connector Group"
                        Description = ""
                        Id = "resourceManagement"
                        Type = "Microsoft.Directory/connectorGroups"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete SSL binding"
                        Description = ""
                        Id = "resourceManagement"
                        Type = "Microsoft.Directory/applications"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Register connector"
                        Description = ""
                        Id = "resourceManagement"
                        Type = "Microsoft.Directory/connectorGroups"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update Connector Group"
                        Description = ""
                        Id = "resourceManagement"
                        Type = "Microsoft.Directory/connectorGroups"
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "Application.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Check whether the resource name is available"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create API connector"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Administrator"
                        LeastPrivilegedMSGraph = "APIConnectors.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create Identity Provider"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity Provider Administrator"
                        LeastPrivilegedMSGraph = "IdentityProvider.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create custom identity provider"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity Provider Administrator"
                        LeastPrivilegedMSGraph = "IdentityProvider.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create custom policy"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Policy Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.TrustFramework"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create or update a B2C directory resource"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create or update a B2C directory tenant and resource"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create or update a CIAM directory tenant and resource"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create or update a Guest Usages resource"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create or update a localized resource"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Policy Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create policy key"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create user attribute"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Attribute Administrator"
                        LeastPrivilegedMSGraph = "IdentityUserFlowAttribute.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create user flow"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Administrator"
                        LeastPrivilegedMSGraph = "IdentityUserFlow.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete API connector"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Administrator"
                        LeastPrivilegedMSGraph = "APIConnectors.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete B2C Tenant where the caller is an administrator"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete B2C directory resource"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete CIAM directory resource"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete Guest Usages resource"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete Identity Provider"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity Provider Administrator"
                        LeastPrivilegedMSGraph = "IdentityProvider.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete custom policy"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Policy Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.TrustFramework"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete localized resource"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Policy Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete policy key"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete user attribute"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Attribute Administrator"
                        LeastPrivilegedMSGraph = "IdentityUserFlowAttribute.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete user flow"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Administrator"
                        LeastPrivilegedMSGraph = "IdentityUserFlow.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Generate key"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Get API connector"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get API connectors"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get B2C Tenant where the caller is an administrator"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get B2C directory resource"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get B2C directory resources in a resource group"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get B2C directory resources in a subscription"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get CIAM directory resource"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get CIAM directory resources in a resource group"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get CIAM directory resources in a subscription"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get Guest Usages resource"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get Guest Usages directory resources in a resource group"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get Guest Usages directory resources in a subscription"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get Identity Provider"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get Identity Providers"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get active key metadata from policy key"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get authentication flows policy"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get available output claims"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get configured custom identity providers"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get configured identity providers"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get configured local identity providers"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get custom identity provider"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get custom policies"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get custom policy"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get custom policy metadata"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get identity provider"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get identity provider types"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get identity providers"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get localized resource"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get operation status of an async operation"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get operations of Microsoft.AzureActiveDirectory resource provider"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get policy key"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get policy keys"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get supported cultures"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get supported identity providers"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get supported page contracts"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get user attribute"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get user attributes"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get user flow"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get user flows"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Move resources"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update API connector"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Administrator"
                        LeastPrivilegedMSGraph = "APIConnectors.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Identity Provider"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity Provider Administrator"
                        LeastPrivilegedMSGraph = "IdentityProvider.Read.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update B2C directory resource"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update CIAM directory resource"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update Guest Usages resource"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update authentication flows policy"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Administrator"
                        LeastPrivilegedMSGraph = "IdentityUserFlow.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update custom identity provider"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity Provider Administrator"
                        LeastPrivilegedMSGraph = "IdentityProvider.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update custom policy"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Policy Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.TrustFramework"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update identity provider"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity Provider Administrator"
                        LeastPrivilegedMSGraph = "IdentityProvider.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update local identity provider"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity Provider Administrator"
                        LeastPrivilegedMSGraph = "IdentityProvider.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update policy key"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update subscription status"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Contributor"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update user attribute"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Attribute Administrator"
                        LeastPrivilegedMSGraph = "IdentityUserFlowAttribute.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update user flow"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "External Identity User Flow Administrator"
                        LeastPrivilegedMSGraph = "IdentityUserFlow.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update certificate to policy key"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update secret into policy key"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Validate move resources"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create Registration of Security Provider"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM canceled (permanent)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM canceled (renew)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM canceled (timebound)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM completed (permanent)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM completed (timebound)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM requested (permanent)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM requested (renew)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM requested (timebound)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role approval requested (PIM activation)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role canceled (PIM activation)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add member to role completed (PIM activation)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role in PIM canceled (renew)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add member to role in PIM canceled (timebound)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add member to role in PIM completed (permanent)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role in PIM completed (timebound)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role in PIM requested (permanent)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role in PIM requested (renew)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role in PIM requested (timebound)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role outside of PIM (permanent)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role request approved (PIM activation)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role request denied (PIM activation)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add member to role requested (PIM activation)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Cancel request"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Cancel request for role removal"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Cancel request for role update"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Deactivate PIM alert"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Disable PIM alert"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Enable PIM alert"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Offboarded resource from PIM"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Onboarded resource from PIM"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "PIM activation request expired"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "PIM policy removed"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Process request"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Process role removal request"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Process role update request"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Remove eligible member from role in PIM completed (permanent)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove eligible member from role in PIM completed (timebound)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove eligible member from role in PIM requested (permanent)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove eligible member from role in PIM requested (timebound)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role (PIM activation expired)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Remove member from role completed (PIM deactivate)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Remove member from role in PIM completed (permanent)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role in PIM completed (timebound)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role in PIM requested (permanent)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role in PIM requested (timebound)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role requested (PIM deactivate)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Remove permanent direct role assignment"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove permanent eligible role assignment"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove request"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Resolve PIM alert"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Resource updated"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Restore eligible member from role in PIM completed"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore member from role"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore member from role in PIM completed"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore permanent direct role assignment"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore permanent eligible role assignment"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Tenant offboarded from PIM"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Triggered PIM alert"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update eligible member in PIM canceled (extend)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update eligible member in PIM requested (extend)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update member in PIM approved by admin (extend/renew)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update member in PIM canceled (extend)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update member in PIM denied by admin (extend/renew)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update member in PIM requested (extend)"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update role setting in PIM"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "User Access Administrator"
                        LeastPrivilegedMSGraph = "PrivilegedAccess.ReadWrite.AzureResources"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create authority"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Verified ID Authority"
                        LeastPrivilegedMSGraph = "VerifiedIdAuthority.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create authorization policy"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Verified ID Authority"
                        LeastPrivilegedMSGraph = "VerifiedIdAuthority.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create contract"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Verified ID Authority"
                        LeastPrivilegedMSGraph = "VerifiableCredential.Create.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create issuance policy"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Verified ID Authority"
                        LeastPrivilegedMSGraph = "VerifiableCredential.Create.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete issuance policy"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Verified ID Authority"
                        LeastPrivilegedMSGraph = "VerifiableCredential.Create.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Process POST /authorities/:issuerId/didInfo/signingKeys/rotate request"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Verified ID Authority"
                        LeastPrivilegedMSGraph = "VerifiedIdAuthority.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Process POST /authorities/:issuerId/didInfo/signingKeys/synchronizeWithDidDocument request"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Verified ID Authority"
                        LeastPrivilegedMSGraph = "VerifiedIdAuthority.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Revoke credential"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Verified ID Authority"
                        LeastPrivilegedMSGraph = "VerifiableCredential.Create.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Rotate signing key"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Verified ID Authority"
                        LeastPrivilegedMSGraph = "VerifiedIdAuthority.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Tenant onboarding"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Tenant opt-out"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update MyAccount settings"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Verified ID Authority"
                        LeastPrivilegedMSGraph = "VerifiedIdAuthority.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update authority"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Verified ID Authority"
                        LeastPrivilegedMSGraph = "VerifiedIdAuthority.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update contract"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Verified ID Authority"
                        LeastPrivilegedMSGraph = "VerifiableCredential.Create.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update issuance policy"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Verified ID Authority"
                        LeastPrivilegedMSGraph = "VerifiableCredential.Create.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update linked domains"
                        Description = ""
                        Id = "resourceManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Verified ID Authority"
                        LeastPrivilegedMSGraph = "VerifiedIdAuthority.ReadWrite.All"
                        Relevant = $true
                    }
                )
            }
            PolicyManagement = @{ 
                Description = "Policy management covers the authentication events framework (listeners, flows, custom extensions) and Global Secure Access network security policy administration."
                Activity = @(
                    @{
                        DisplayName = "POST UserAuthMethod.SecurityInfoRegistrationCallback"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create authenticationEventListener"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "EventListener.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create authenticationEventsFlow"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "AuthenticationEventsFlow.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create customAuthenticationExtension"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "CustomAuthenticationExtension.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete authenticationEventListener"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "EventListener.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete authenticationEventsFlow"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "AuthenticationEventsFlow.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete customAuthenticationExtension"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "CustomAuthenticationExtension.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Get OnAttributeCollectionStartCustomExtension"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get OnAttributeCollectionSubmitCustomExtension"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get OnPageRenderStartCustomExtension"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get authenticationEventListener"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get authenticationEventListeners"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get authenticationEventsFlow"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get authenticationEventsFlows"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get customAuthenticationExtension"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get customAuthenticationExtensions"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get the authenticationEventsPolicy"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Reader"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update OnAttributeCollectionStartCustomExtension"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "CustomAuthenticationExtension.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update OnAttributeCollectionSubmitCustomExtension"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "CustomAuthenticationExtension.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update OnPageRenderStartCustomExtension"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "CustomAuthenticationExtension.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update authenticationEventListener"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "EventListener.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update authenticationEventsFlow"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "AuthenticationEventsFlow.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update authenticationEventsPolicy"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "AuthenticationEventsFlow.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update customAuthenticationExtension"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Application Administrator"
                        LeastPrivilegedMSGraph = "CustomAuthenticationExtension.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Validate customExtension authenticationConfiguration"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create Filtering Policy"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create Filtering Policy Profile"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create Remote Network"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Create Security Provider Policy"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete Filtering Policy"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete Filtering Policy Profile"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete Forwarding Policy"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete Private Access Policy"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete Remote Network"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete Security Provider Policy"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update Filtering Policy"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update Filtering Policy Profile"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update Filtering Profile"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update Forwarding Options Policy"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update Forwarding Policy"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update Forwarding Profile"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update Forwarding Rule"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update Private Access Policy"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update Remote Network"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update Security Provider Policy"
                        Description = ""
                        Id = "policyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Secure Access Administrator"
                        LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                        Relevant = $true
                    }
                )
            }
            AzureRBACRoleManagementElevateAccess = @{ 
                Description = "Azure RBAC elevated access tracks when Global Administrators elevate themselves to User Access Administrator for Azure resources."
                Activity = @(
                    @{
                        DisplayName = "The role assignment of User Access Administrator has been removed from the user"
                        Description = ""
                        Id = "azureRBACRoleManagementElevateAccess"
                        Type = "Microsoft.Authorization/roleAssignments"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "User has elevated their access to User Access Administrator for their Azure Resources"
                        Description = ""
                        Id = "azureRBACRoleManagementElevateAccess"
                        Type = "Microsoft.Authorization/roleAssignments"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    }
                )
            }
            Device = @{ 
                Description = "Device management covers device registration, ownership and compliance state changes, and LAPS (local administrator password solution) operations."
                Activity = @(
                    @{
                        DisplayName = "Delete pre-created device"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "Device.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Pre-create device"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "Device.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Recover device local administrator password"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "DeviceLocalCredential.Read.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Register device"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "Device.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Unregister device"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "Device.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update device local administrator password"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "DeviceLocalCredential.ReadBasic.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add device"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "Device.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add registered owner to device"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "Device.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add registered users to device"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "Device.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete device"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "Device.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Device no longer compliant"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Device no longer managed"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Hard Delete device"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "Device.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove registered owner from device"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "Device.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove registered users from device"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "Device.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Restore device"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "Device.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update device"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "Device.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update local administrator password"
                        Description = ""
                        Id = "device"
                        Type = "Microsoft.Directory/devices"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "DeviceLocalCredential.ReadBasic.All"
                        Relevant = $false
                    }
                )
            }
            IdentityProtection = @{ 
                Description = "Identity Protection covers risk policy configuration, user risk remediation, and notification settings for risky sign-in events."
                Activity = @(
                    @{
                        DisplayName = "Evaluate Conditional Access policies"
                        Description = ""
                        Id = "identityProtection"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Remediate user"
                        Description = ""
                        Id = "identityProtection"
                        Type = ""
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "IdentityRiskyUser.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update IdentityProtectionPolicy"
                        Description = ""
                        Id = "identityProtection"
                        Type = "Microsoft.IdentityProtection"
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.IdentityProtection"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update NotificationSettings"
                        Description = ""
                        Id = "identityProtection"
                        Type = "Microsoft.IdentityProtection"
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.IdentityProtection"
                        Relevant = $false
                    }
                )
            }
            KeyManagement = @{ 
                Description = "Key management covers BitLocker device recovery key operations and B2C IEF trust framework key set management."
                Activity = @(
                    @{
                        DisplayName = "Add BitLocker key"
                        Description = ""
                        Id = "keyManagement"
                        Type = "Microsoft.Directory/bitLockerRecoveryKey"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "BitlockerKey.ReadBasic.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create policy key"
                        Description = ""
                        Id = "keyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete BitLocker key"
                        Description = ""
                        Id = "keyManagement"
                        Type = "Microsoft.Directory/bitLockerRecoveryKey"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "BitlockerKey.ReadBasic.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete policy key"
                        Description = ""
                        Id = "keyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Get active key metadata from policy key"
                        Description = ""
                        Id = "keyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.Read.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get policy key"
                        Description = ""
                        Id = "keyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.Read.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Get policy keys"
                        Description = ""
                        Id = "keyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.Read.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Read BitLocker key"
                        Description = ""
                        Id = "keyManagement"
                        Type = "Microsoft.Directory/bitLockerRecoveryKey"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "BitlockerKey.Read.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore policy key"
                        Description = ""
                        Id = "keyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update policy key"
                        Description = ""
                        Id = "keyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Upload key to policy key"
                        Description = ""
                        Id = "keyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Upload secret into policy key"
                        Description = ""
                        Id = "keyManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "B2C IEF Keyset Administrator"
                        LeastPrivilegedMSGraph = "TrustFrameworkKeySet.ReadWrite.All"
                        Relevant = $true
                    }
                )
            }
            Other = @{ 
                Description = "Miscellaneous category covering B2C one-time password events, Identity Protection risk confirmation actions, Lifecycle Workflow task extensions, and self-service group approval notifications."
                Activity = @(
                    @{
                        DisplayName = "Generate one time password"
                        Description = ""
                        Id = "other"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Verify one time password"
                        Description = ""
                        Id = "other"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "ConfirmAccountCompromised"
                        Description = ""
                        Id = "other"
                        Type = ""
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "IdentityRiskyUser.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "ConfirmAccountSafe"
                        Description = ""
                        Id = "other"
                        Type = ""
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "IdentityRiskyUser.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "ConfirmCompromised"
                        Description = ""
                        Id = "other"
                        Type = ""
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "IdentityRiskyUser.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "ConfirmSafe"
                        Description = ""
                        Id = "other"
                        Type = ""
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "IdentityRiskyUser.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "DismissRisk"
                        Description = ""
                        Id = "other"
                        Type = ""
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "IdentityRiskyUser.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "DismissUser"
                        Description = ""
                        Id = "other"
                        Type = ""
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "IdentityRiskyUser.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "confirmServicePrincipalCompromised"
                        Description = ""
                        Id = "other"
                        Type = ""
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "ServicePrincipalRiskDetection.Read.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "DismissServicePrincipal"
                        Description = ""
                        Id = "other"
                        Type = ""
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "ServicePrincipalRiskDetection.Read.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Create custom task extension"
                        Description = ""
                        Id = "other"
                        Type = "Microsoft.LifecycleWorkflows"
                        LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                        LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete custom task extension"
                        Description = ""
                        Id = "other"
                        Type = "Microsoft.LifecycleWorkflows"
                        LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                        LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update custom task extension"
                        Description = ""
                        Id = "other"
                        Type = "Microsoft.LifecycleWorkflows"
                        LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                        LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "ApprovalNotification_Create"
                        Description = ""
                        Id = "other"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    }
                )
            }
            Agreement = @{ 
                Description = "Agreement management covers the lifecycle of Terms of Use agreements used for user acceptance policies."
                Activity = @(
                    @{
                        DisplayName = "Add agreement"
                        Description = ""
                        Id = "agreement"
                        Type = "Microsoft.AAD/agreements"
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Agreement.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete agreement"
                        Description = ""
                        Id = "agreement"
                        Type = "Microsoft.AAD/agreements"
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Agreement.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Hard delete agreement"
                        Description = ""
                        Id = "agreement"
                        Type = "Microsoft.AAD/agreements"
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Agreement.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update agreement"
                        Description = ""
                        Id = "agreement"
                        Type = "Microsoft.AAD/agreements"
                        LeastPrivilegeRBAC = "Conditional Access Administrator"
                        LeastPrivilegedMSGraph = "Agreement.ReadWrite.All"
                        Relevant = $true
                    }
                )
            }
            AuthorizationPolicy = @{ 
                Description = "Authorization policy covers tenant-wide settings controlling user abilities such as self-service group creation, application consent, and guest user permissions."
                Activity = @(
                    @{
                        DisplayName = "Update authorization policy"
                        Description = ""
                        Id = "authorizationPolicy"
                        Type = "Microsoft.Directory/policies/authorizationPolicy"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.Authorization"
                        Relevant = $true
                    }
                )
            }
            CertBasedConfiguration = @{ 
                Description = "Certificate-based authentication configuration covers setup of CBA (Certificate-Based Authentication) for the tenant."
                Activity = @(
                    @{
                        DisplayName = "Add CertBasedAuthConfiguration"
                        Description = ""
                        Id = "certBasedConfiguration"
                        Type = "Microsoft.Directory/certificateAuthorities"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Hard delete CertificationBasedAuthConfiguration"
                        Description = ""
                        Id = "certBasedConfiguration"
                        Type = "Microsoft.Directory/certificateAuthorities"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    }
                )
            }
            CertificateAuthorityEntity = @{ 
                Description = "Certificate authority entity management covers creating and managing certificate authorities used for certificate-based authentication."
                Activity = @(
                    @{
                        DisplayName = "Create CertificateAuthorityEntity"
                        Description = ""
                        Id = "certificateAuthorityEntity"
                        Type = "Microsoft.Directory/certificateAuthorities"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete CertificateAuthorityEntity"
                        Description = ""
                        Id = "certificateAuthorityEntity"
                        Type = "Microsoft.Directory/certificateAuthorities"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Hard Delete CertificateAuthorityEntity"
                        Description = ""
                        Id = "certificateAuthorityEntity"
                        Type = "Microsoft.Directory/certificateAuthorities"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore CertificateAuthorityEntity"
                        Description = ""
                        Id = "certificateAuthorityEntity"
                        Type = "Microsoft.Directory/certificateAuthorities"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update CertificateAuthorityEntity"
                        Description = ""
                        Id = "certificateAuthorityEntity"
                        Type = "Microsoft.Directory/certificateAuthorities"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    }
                )
            }
            CertificateBasedAuthConfiguration = @{ 
                Description = "Certificate-based auth configuration lifecycle operations for configuring CBA trust chains."
                Activity = @(
                    @{
                        DisplayName = "Add CertificateBasedAuthConfiguration"
                        Description = ""
                        Id = "certificateBasedAuthConfiguration"
                        Type = "Microsoft.Directory/certificateBasedAuthConfiguration"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete CertificateBasedAuthConfiguration"
                        Description = ""
                        Id = "certificateBasedAuthConfiguration"
                        Type = "Microsoft.Directory/certificateBasedAuthConfiguration"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update CertificateBasedAuthConfiguration"
                        Description = ""
                        Id = "certificateBasedAuthConfiguration"
                        Type = "Microsoft.Directory/certificateBasedAuthConfiguration"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    }
                )
            }
            CompanyBranding = @{ 
                Description = "Company branding management covers creation and modification of sign-in page branding themes."
                Activity = @(
                    @{
                        DisplayName = "Create Branding Theme"
                        Description = ""
                        Id = "companyBranding"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete Branding Theme"
                        Description = ""
                        Id = "companyBranding"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Hard Delete Branding Theme"
                        Description = ""
                        Id = "companyBranding"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update Branding Theme"
                        Description = ""
                        Id = "companyBranding"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $false
                    }
                )
            }
            CompanyBrandingLocale = @{ 
                Description = "Company branding locale management covers locale-specific sign-in page branding customization."
                Activity = @(
                    @{
                        DisplayName = "Create Branding Theme Localization"
                        Description = ""
                        Id = "companyBrandingLocale"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete Branding Theme Localization"
                        Description = ""
                        Id = "companyBrandingLocale"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Hard Delete Branding Theme Localization"
                        Description = ""
                        Id = "companyBrandingLocale"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update Branding Theme Localization"
                        Description = ""
                        Id = "companyBrandingLocale"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $false
                    }
                )
            }
            Contact = @{ 
                Description = "Contact management covers organizational contact objects synced from on-premises directories."
                Activity = @(
                    @{
                        DisplayName = "Add contact"
                        Description = ""
                        Id = "contact"
                        Type = "Microsoft.Directory/contacts"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "OrgContact.Read.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete contact"
                        Description = ""
                        Id = "contact"
                        Type = "Microsoft.Directory/contacts"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "OrgContact.Read.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Update contact"
                        Description = ""
                        Id = "contact"
                        Type = "Microsoft.Directory/contacts"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "OrgContact.Read.All"
                        Relevant = $false
                    }
                )
            }
            CrossTenantAccessSettings = @{ 
                Description = "Cross-tenant access settings management covers B2B collaboration and B2B direct connect policies with partner organizations."
                Activity = @(
                    @{
                        DisplayName = "Add a domain-based partner to cross-tenant access setting"
                        Description = ""
                        Id = "crossTenantAccessSettings"
                        Type = "Microsoft.Directory/crossTenantAccessPolicy"
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.CrossTenantAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add a partner to cross-tenant access setting"
                        Description = ""
                        Id = "crossTenantAccessSettings"
                        Type = "Microsoft.Directory/crossTenantAccessPolicy"
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.CrossTenantAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete a domain-based partner to cross-tenant access setting"
                        Description = ""
                        Id = "crossTenantAccessSettings"
                        Type = "Microsoft.Directory/crossTenantAccessPolicy"
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.CrossTenantAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete partner specific cross-tenant access setting"
                        Description = ""
                        Id = "crossTenantAccessSettings"
                        Type = "Microsoft.Directory/crossTenantAccessPolicy"
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.CrossTenantAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Migrated partner cross-tenant access settings to the scalable model"
                        Description = ""
                        Id = "crossTenantAccessSettings"
                        Type = "Microsoft.Directory/crossTenantAccessPolicy"
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.CrossTenantAccess"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Reset the cross-tenant access default setting"
                        Description = ""
                        Id = "crossTenantAccessSettings"
                        Type = "Microsoft.Directory/crossTenantAccessPolicy"
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.CrossTenantAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update a domain-based partner to cross-tenant access setting"
                        Description = ""
                        Id = "crossTenantAccessSettings"
                        Type = "Microsoft.Directory/crossTenantAccessPolicy"
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.CrossTenantAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update a partner cross-tenant access setting"
                        Description = ""
                        Id = "crossTenantAccessSettings"
                        Type = "Microsoft.Directory/crossTenantAccessPolicy"
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.CrossTenantAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update the company default cross-tenant access setting"
                        Description = ""
                        Id = "crossTenantAccessSettings"
                        Type = "Microsoft.Directory/crossTenantAccessPolicy"
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.CrossTenantAccess"
                        Relevant = $true
                    }
                )
            }
            CrossTenantIdentitySyncSettings = @{ 
                Description = "Cross-tenant identity sync settings covers configuring automatic user provisioning from partner tenants in a multi-tenant organization."
                Activity = @(
                    @{
                        DisplayName = "Create a partner cross-tenant identity sync setting"
                        Description = ""
                        Id = "crossTenantIdentitySyncSettings"
                        Type = "Microsoft.Directory/crossTenantAccessPolicy"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.CrossTenantAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete a partner cross-tenant identity sync setting"
                        Description = ""
                        Id = "crossTenantIdentitySyncSettings"
                        Type = "Microsoft.Directory/crossTenantAccessPolicy"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.CrossTenantAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update a partner cross-tenant identity sync setting"
                        Description = ""
                        Id = "crossTenantIdentitySyncSettings"
                        Type = "Microsoft.Directory/crossTenantAccessPolicy"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.CrossTenantAccess"
                        Relevant = $true
                    }
                )
            }
            DelegatedAdminServiceProviderConstraints = @{ 
                Description = "Delegated admin service provider constraints covers the assignable roles that an MSSP or partner can delegate."
                Activity = @(
                    @{
                        DisplayName = "Adding allowed assignable roles"
                        Description = ""
                        Id = "delegatedAdminServiceProviderConstraints"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Updating allowed assignable roles"
                        Description = ""
                        Id = "delegatedAdminServiceProviderConstraints"
                        Type = "Microsoft.Directory/organization"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Organization.ReadWrite.All"
                        Relevant = $true
                    }
                )
            }
            DeviceConfiguration = @{ 
                Description = "Device configuration management covers Intune/AAD device configuration profile lifecycle operations."
                Activity = @(
                    @{
                        DisplayName = "Add device configuration"
                        Description = ""
                        Id = "deviceConfiguration"
                        Type = "Microsoft.Intune/deviceConfigurations"
                        LeastPrivilegeRBAC = "Intune Administrator"
                        LeastPrivilegedMSGraph = "DeviceManagementConfiguration.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete device configuration"
                        Description = ""
                        Id = "deviceConfiguration"
                        Type = "Microsoft.Intune/deviceConfigurations"
                        LeastPrivilegeRBAC = "Intune Administrator"
                        LeastPrivilegedMSGraph = "DeviceManagementConfiguration.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update device configuration"
                        Description = ""
                        Id = "deviceConfiguration"
                        Type = "Microsoft.Intune/deviceConfigurations"
                        LeastPrivilegeRBAC = "Intune Administrator"
                        LeastPrivilegedMSGraph = "DeviceManagementConfiguration.ReadWrite.All"
                        Relevant = $true
                    }
                )
            }
            DeviceTemplate = @{ 
                Description = "Device template management covers IoT device template operations for pre-creating and managing device identities at scale."
                Activity = @(
                    @{
                        DisplayName = "Add device from DeviceTemplate"
                        Description = ""
                        Id = "deviceTemplate"
                        Type = "Microsoft.Directory/deviceTemplates"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "Device.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add DeviceTemplate"
                        Description = ""
                        Id = "deviceTemplate"
                        Type = "Microsoft.Directory/deviceTemplates"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "Device.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add owner to DeviceTemplate"
                        Description = ""
                        Id = "deviceTemplate"
                        Type = "Microsoft.Directory/deviceTemplates"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "Device.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete DeviceTemplate"
                        Description = ""
                        Id = "deviceTemplate"
                        Type = "Microsoft.Directory/deviceTemplates"
                        LeastPrivilegeRBAC = "Cloud Device Administrator"
                        LeastPrivilegedMSGraph = "Device.ReadWrite.All"
                        Relevant = $true
                    }
                )
            }
            KerberosDomain = @{ 
                Description = "Kerberos domain management covers Azure AD Kerberos server configuration for enabling Kerberos-based SSO to on-premises resources."
                Activity = @(
                    @{
                        DisplayName = "Add kerberos domain"
                        Description = ""
                        Id = "kerberosDomain"
                        Type = "Microsoft.Directory/kerberosDomain"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete kerberos domain"
                        Description = ""
                        Id = "kerberosDomain"
                        Type = "Microsoft.Directory/kerberosDomain"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore kerberos domain"
                        Description = ""
                        Id = "kerberosDomain"
                        Type = "Microsoft.Directory/kerberosDomain"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update kerberos domain"
                        Description = ""
                        Id = "kerberosDomain"
                        Type = "Microsoft.Directory/kerberosDomain"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    }
                )
            }
            Label = @{ 
                Description = "Label management covers Microsoft 365 sensitivity label assignments to directory objects."
                Activity = @(
                    @{
                        DisplayName = "Add label"
                        Description = ""
                        Id = "label"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete label"
                        Description = ""
                        Id = "label"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update label"
                        Description = ""
                        Id = "label"
                        Type = "Microsoft.Directory/groups"
                        LeastPrivilegeRBAC = "Groups Administrator"
                        LeastPrivilegedMSGraph = "Group.ReadWrite.All"
                        Relevant = $false
                    }
                )
            }
            MicrosoftSupportAccessManagement = @{ 
                Description = "Microsoft Support Access Management covers Customer Lockbox-style approval workflows for Microsoft support engineer access to the tenant."
                Activity = @(
                    @{
                        DisplayName = "Access approved"
                        Description = ""
                        Id = "microsoftSupportAccessManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Access removed"
                        Description = ""
                        Id = "microsoftSupportAccessManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Request approved"
                        Description = ""
                        Id = "microsoftSupportAccessManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Request canceled"
                        Description = ""
                        Id = "microsoftSupportAccessManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Request created"
                        Description = ""
                        Id = "microsoftSupportAccessManagement"
                        Type = ""
                        LeastPrivilegeRBAC = ""
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Request rejected"
                        Description = ""
                        Id = "microsoftSupportAccessManagement"
                        Type = ""
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    }
                )
            }
            MultiTenantOrg = @{ 
                Description = "Multi-tenant organization management covers creating and configuring the multi-tenant organization hub tenant."
                Activity = @(
                    @{
                        DisplayName = "Create a MultiTenantOrg"
                        Description = ""
                        Id = "multiTenantOrg"
                        Type = "Microsoft.Directory/tenantRelationships"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "MultiTenantOrganization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Hard Delete MultiTenantOrg"
                        Description = ""
                        Id = "multiTenantOrg"
                        Type = "Microsoft.Directory/tenantRelationships"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "MultiTenantOrganization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update a MultiTenantOrg"
                        Description = ""
                        Id = "multiTenantOrg"
                        Type = "Microsoft.Directory/tenantRelationships"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "MultiTenantOrganization.ReadWrite.All"
                        Relevant = $true
                    }
                )
            }
            MultiTenantOrgIdentitySyncPolicyUpdate = @{ 
                Description = "Multi-tenant org identity sync policy covers cross-tenant sync policy template configuration for the multi-tenant organization."
                Activity = @(
                    @{
                        DisplayName = "Reset a multi tenant org identity sync policy template"
                        Description = ""
                        Id = "multiTenantOrgIdentitySyncPolicyUpdate"
                        Type = "Microsoft.Directory/tenantRelationships"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "MultiTenantOrganization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update a multi tenant org identity sync policy template"
                        Description = ""
                        Id = "multiTenantOrgIdentitySyncPolicyUpdate"
                        Type = "Microsoft.Directory/tenantRelationships"
                        LeastPrivilegeRBAC = "Hybrid Identity Administrator"
                        LeastPrivilegedMSGraph = "MultiTenantOrganization.ReadWrite.All"
                        Relevant = $true
                    }
                )
            }
            MultiTenantOrgPartnerConfigurationTemplate = @{ 
                Description = "Multi-tenant org partner configuration template covers cross-tenant access policy template configuration for MTO member tenants."
                Activity = @(
                    @{
                        DisplayName = "Reset a multi tenant org partner configuration template"
                        Description = ""
                        Id = "multiTenantOrgPartnerConfigurationTemplate"
                        Type = "Microsoft.Directory/tenantRelationships"
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.CrossTenantAccess"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update a multi tenant org partner configuration template"
                        Description = ""
                        Id = "multiTenantOrgPartnerConfigurationTemplate"
                        Type = "Microsoft.Directory/tenantRelationships"
                        LeastPrivilegeRBAC = "Security Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.CrossTenantAccess"
                        Relevant = $true
                    }
                )
            }
            MultiTenantOrgTenant = @{ 
                Description = "Multi-tenant org tenant management covers adding and removing member tenants from a multi-tenant organization."
                Activity = @(
                    @{
                        DisplayName = "Add MultiTenantOrg tenant"
                        Description = ""
                        Id = "multiTenantOrgTenant"
                        Type = "Microsoft.Directory/tenantRelationships"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "MultiTenantOrganization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete MultiTenantOrg tenant"
                        Description = ""
                        Id = "multiTenantOrgTenant"
                        Type = "Microsoft.Directory/tenantRelationships"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "MultiTenantOrganization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Hard Delete MultiTenantOrg tenant"
                        Description = ""
                        Id = "multiTenantOrgTenant"
                        Type = "Microsoft.Directory/tenantRelationships"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "MultiTenantOrganization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Tenant joining MultiTenantOrg tenant"
                        Description = ""
                        Id = "multiTenantOrgTenant"
                        Type = "Microsoft.Directory/tenantRelationships"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "MultiTenantOrganization.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update MultiTenantOrg tenant"
                        Description = ""
                        Id = "multiTenantOrgTenant"
                        Type = "Microsoft.Directory/tenantRelationships"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "MultiTenantOrganization.ReadWrite.All"
                        Relevant = $true
                    }
                )
            }
            OrganizationalUnitContainer = @{ 
                Description = "Organizational unit container management covers creating and managing OUs for Entra Domain Services resource scoping."
                Activity = @(
                    @{
                        DisplayName = "Create OrganizationalUnit"
                        Description = ""
                        Id = "organizationalUnitContainer"
                        Type = "Microsoft.AAD/domainServices"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete OrganizationalUnit"
                        Description = ""
                        Id = "organizationalUnitContainer"
                        Type = "Microsoft.AAD/domainServices"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update OrganizationalUnit"
                        Description = ""
                        Id = "organizationalUnitContainer"
                        Type = "Microsoft.AAD/domainServices"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = ""
                        Relevant = $false
                    }
                )
            }
            PendingExternalUserProfile = @{ 
                Description = "Pending external user profile management covers the lifecycle of external user profiles awaiting invitation acceptance."
                Activity = @(
                    @{
                        DisplayName = "Create PendingExternalUserProfile"
                        Description = ""
                        Id = "pendingExternalUserProfile"
                        Type = "Microsoft.Directory/externalUserProfiles"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "ExternalUserProfile.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Delete PendingExternalUserProfile"
                        Description = ""
                        Id = "pendingExternalUserProfile"
                        Type = "Microsoft.Directory/externalUserProfiles"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "ExternalUserProfile.ReadWrite.All"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Hard Delete PendingExternalUserProfile"
                        Description = ""
                        Id = "pendingExternalUserProfile"
                        Type = "Microsoft.Directory/externalUserProfiles"
                        LeastPrivilegeRBAC = "User Administrator"
                        LeastPrivilegedMSGraph = "ExternalUserProfile.ReadWrite.All"
                        Relevant = $false
                    }
                )
            }
            PermissionGrantPolicy = @{ 
                Description = "Permission grant policy management covers creating and modifying pre-authorization policies that govern application consent."
                Activity = @(
                    @{
                        DisplayName = "Add permission grant policy"
                        Description = ""
                        Id = "permissionGrantPolicy"
                        Type = "Microsoft.Directory/permissionGrantPolicies"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.PermissionGrant"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete permission grant policy"
                        Description = ""
                        Id = "permissionGrantPolicy"
                        Type = "Microsoft.Directory/permissionGrantPolicies"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.PermissionGrant"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update permission grant policy"
                        Description = ""
                        Id = "permissionGrantPolicy"
                        Type = "Microsoft.Directory/permissionGrantPolicies"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "Policy.ReadWrite.PermissionGrant"
                        Relevant = $true
                    }
                )
            }
            PublicKeyInfrastructure = @{ 
                Description = "Public key infrastructure management covers managing PKI configurations for certificate-based authentication in Entra."
                Activity = @(
                    @{
                        DisplayName = "Create PublicKeyInfrastructure"
                        Description = ""
                        Id = "publicKeyInfrastructure"
                        Type = "Microsoft.Directory/publicKeyInfrastructure"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete PublicKeyInfrastructure"
                        Description = ""
                        Id = "publicKeyInfrastructure"
                        Type = "Microsoft.Directory/publicKeyInfrastructure"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Hard Delete PublicKeyInfrastructure"
                        Description = ""
                        Id = "publicKeyInfrastructure"
                        Type = "Microsoft.Directory/publicKeyInfrastructure"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Initiate PublicKeyInfrastructure"
                        Description = ""
                        Id = "publicKeyInfrastructure"
                        Type = "Microsoft.Directory/publicKeyInfrastructure"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore PublicKeyInfrastructure"
                        Description = ""
                        Id = "publicKeyInfrastructure"
                        Type = "Microsoft.Directory/publicKeyInfrastructure"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update PublicKeyInfrastructure"
                        Description = ""
                        Id = "publicKeyInfrastructure"
                        Type = "Microsoft.Directory/publicKeyInfrastructure"
                        LeastPrivilegeRBAC = "Global Administrator"
                        LeastPrivilegedMSGraph = "Directory.ReadWrite.All"
                        Relevant = $true
                    }
                )
            }
            RoleManagement = @{ 
                Description = "Role management covers all Entra ID role assignment lifecycle operations and PIM role-activation workflows for directory roles."
                Activity = @(
                    @{
                        DisplayName = "Add EligibleRoleAssignment to RoleDefinition"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add eligible member to role"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role scoped over Restricted Management Administrative Unit"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add role assignment to role definition"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleDefinitions"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add role definition"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleDefinitions"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add role from template"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleDefinitions"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add scoped member to role"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Delete role definition"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleDefinitions"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove EligibleRoleAssignment from RoleDefinition"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove eligible member from role"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role scoped over Restricted Management Administrative Unit"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove role assignment from role definition"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleDefinitions"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove scoped member from role"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update role"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleDefinitions"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Update role definition"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleDefinitions"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM canceled (permanent)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM canceled (renew)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM canceled (timebound)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM completed (permanent)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM completed (timebound)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM requested (permanent)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM requested (renew)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add eligible member to role in PIM requested (timebound)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role approval requested (PIM activation)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role canceled (PIM activation)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add member to role completed (PIM activation)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role in PIM canceled (renew)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add member to role in PIM canceled (timebound)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add member to role in PIM completed (permanent)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role in PIM completed (timebound)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role in PIM requested (permanent)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role in PIM requested (renew)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role in PIM requested (timebound)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role outside of PIM (permanent)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role request approved (PIM activation)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Add member to role request denied (PIM activation)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Add member to role requested (PIM activation)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Cancel request for role removal"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Cancel request for role update"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Deactivate PIM alert"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Disable PIM alert"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Enable PIM alert"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Offboarded resource from PIM"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Onboarded resource from PIM"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "PIM activation request expired"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "PIM policy removed"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Process request"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Process role removal request"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Process role update request"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Refresh PIM alert"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Remove eligible member from role in PIM completed (permanent)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove eligible member from role in PIM completed (timebound)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove eligible member from role in PIM requested (permanent)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove eligible member from role in PIM requested (timebound)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role (PIM activation expired)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Remove member from role completed (PIM deactivate)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Remove member from role in PIM completed (permanent)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role in PIM completed (timebound)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role in PIM requested (permanent)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role in PIM requested (timebound)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove member from role requested (PIM deactivate)"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Remove permanent direct role assignment"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove permanent eligible role assignment"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Remove request"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Resolve PIM alert"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $false
                    },
                    @{
                        DisplayName = "Restore eligible member from role in PIM completed"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                        LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                        Relevant = $true
                    },
                    @{
                        DisplayName = "Restore member from role"
                        Description = ""
                        Id = "roleManagement"
                        Type = "Microsoft.Directory/roleAssignments"
                        LeastPrivilegeRBAC = "Privileged Role Administrator"
                    LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                    Relevant = $true
                },
                @{
                    DisplayName = "Restore member from role in PIM completed"
                    Description = ""
                    Id = "roleManagement"
                    Type = "Microsoft.Directory/roleAssignments"
                    LeastPrivilegeRBAC = "Privileged Role Administrator"
                    LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                    Relevant = $true
                },
                @{
                    DisplayName = "Restore permanent direct role assignment"
                    Description = ""
                    Id = "roleManagement"
                    Type = "Microsoft.Directory/roleAssignments"
                    LeastPrivilegeRBAC = "Privileged Role Administrator"
                    LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                    Relevant = $true
                },
                @{
                    DisplayName = "Restore permanent eligible role assignment"
                    Description = ""
                    Id = "roleManagement"
                    Type = "Microsoft.Directory/roleAssignments"
                    LeastPrivilegeRBAC = "Privileged Role Administrator"
                    LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                    Relevant = $true
                },
                @{
                    DisplayName = "Tenant offboarded from PIM"
                    Description = ""
                    Id = "roleManagement"
                    Type = "Microsoft.Directory/roleAssignments"
                    LeastPrivilegeRBAC = "Privileged Role Administrator"
                    LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                    Relevant = $true
                },
                @{
                    DisplayName = "Triggered PIM alert"
                    Description = ""
                    Id = "roleManagement"
                    Type = "Microsoft.Directory/roleAssignments"
                    LeastPrivilegeRBAC = "Privileged Role Administrator"
                    LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                    Relevant = $true
                },
                @{
                    DisplayName = "Update PIM alert setting"
                    Description = ""
                    Id = "roleManagement"
                    Type = "Microsoft.Directory/roleAssignments"
                    LeastPrivilegeRBAC = "Privileged Role Administrator"
                    LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                    Relevant = $true
                },
                @{
                    DisplayName = "Update eligible member in PIM canceled (extend)"
                    Description = ""
                    Id = "roleManagement"
                    Type = "Microsoft.Directory/roleAssignments"
                    LeastPrivilegeRBAC = "Privileged Role Administrator"
                    LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                    Relevant = $false
                },
                @{
                    DisplayName = "Update eligible member in PIM requested (extend)"
                    Description = ""
                    Id = "roleManagement"
                    Type = "Microsoft.Directory/roleAssignments"
                    LeastPrivilegeRBAC = "Privileged Role Administrator"
                    LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                    Relevant = $true
                },
                @{
                    DisplayName = "Update member in PIM approved by admin (extend/renew)"
                    Description = ""
                    Id = "roleManagement"
                    Type = "Microsoft.Directory/roleAssignments"
                    LeastPrivilegeRBAC = "Privileged Role Administrator"
                    LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                    Relevant = $true
                },
                @{
                    DisplayName = "Update member in PIM canceled (extend)"
                    Description = ""
                    Id = "roleManagement"
                    Type = "Microsoft.Directory/roleAssignments"
                    LeastPrivilegeRBAC = "Privileged Role Administrator"
                    LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                    Relevant = $false
                },
                @{
                    DisplayName = "Update member in PIM denied by admin (extend/renew)"
                    Description = ""
                    Id = "roleManagement"
                    Type = "Microsoft.Directory/roleAssignments"
                    LeastPrivilegeRBAC = "Privileged Role Administrator"
                    LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                    Relevant = $false
                },
                @{
                    DisplayName = "Update member in PIM requested (extend)"
                    Description = ""
                    Id = "roleManagement"
                    Type = "Microsoft.Directory/roleAssignments"
                    LeastPrivilegeRBAC = "Privileged Role Administrator"
                    LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                    Relevant = $true
                },
                @{
                    DisplayName = "Update role setting in PIM"
                    Description = ""
                    Id = "roleManagement"
                    Type = "Microsoft.Directory/roleAssignments"
                    LeastPrivilegeRBAC = "Privileged Role Administrator"
                    LeastPrivilegedMSGraph = "RoleManagement.ReadWrite.Directory"
                    Relevant = $true
                }
            )
        }
        EntitlementManagement = @{ 
            Description = "Entitlement management covers access package lifecycle, assignment policies, access request workflows, and catalog management for Entra ID Governance."
            Activity = @(
                @{
                    DisplayName = "Add Entitlement Management role assignment"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Administrator directly assigns user to access package"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Administrator directly removes user access package assignment"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Approval stage completed for access package assignment request"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Approve access package assignment request"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Assign user as external sponsor"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Assign user as internal sponsor"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Auto approve access package assignment request"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Cancel access package assignment request"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Create access package"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Create access package assignment policy"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Create access package assignment user update request"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Create access package catalog"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Create connected organization"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Create custom extension"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Create incompatible access package"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Create incompatible group"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Create resource environment"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Create resource remove request"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Create resource request"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Delete access package"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Delete access package assignment policy"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Delete access package assignment request"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Delete access package assignment policy for a deleted user"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Delete access package catalog"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Delete connected organization"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Delete custom extension"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Delete incompatible access package"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Delete incompatible group"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Deny access package assignment request"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Entitlement Management creates access package assignment request for user"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Entitlement Management removes access package assignment request for user"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Execute custom extension"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Extend access package assignment"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Failed access package assignment request"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Fulfill access package assignment request"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Fulfill access package resource assignment"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Partially fulfill access package assignment request"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Ready to fulfill access package assignment request"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Remove Entitlement Management role assignment"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Remove access package resource assignment"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Remove user as external sponsor"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Remove user as internal sponsor"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Schedule a future access package assignment"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Update access package"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Update access package assignment policy"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Update access package assignment request"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Update access package catalog"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Update access package catalog resource"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Update connected organization"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Update custom extension"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Update request answers by approver"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Update tenant setting"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = "Identity Governance Administrator"
                    LeastPrivilegedMSGraph = "EntitlementManagement.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "User requests access package assignment"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "User requests an access package assignment on behalf of service principal"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "User requests to extend access package assignment"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "User requests to remove access package assignment"
                    Description = ""
                    Id = "entitlementManagement"
                    Type = "Microsoft.EntitlementManagement"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                }
            )
        }
        ObjectManagement = @{ 
            Description = "Object management covers Global Secure Access tenant onboarding/offboarding and adaptive access and enriched audit log policy configuration."
            Activity = @(
                @{
                    DisplayName = "Offboarding Process Started"
                    Description = ""
                    Id = "objectManagement"
                    Type = ""
                    LeastPrivilegeRBAC = "Global Secure Access Administrator"
                    LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Onboarding Process Started"
                    Description = ""
                    Id = "objectManagement"
                    Type = ""
                    LeastPrivilegeRBAC = "Global Secure Access Administrator"
                    LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Update Adaptive Access Policy"
                    Description = ""
                    Id = "objectManagement"
                    Type = ""
                    LeastPrivilegeRBAC = "Global Secure Access Administrator"
                    LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Update Enriched Audit Logs Settings"
                    Description = ""
                    Id = "objectManagement"
                    Type = ""
                    LeastPrivilegeRBAC = "Global Secure Access Administrator"
                    LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Update Forwarding Options Policy"
                    Description = ""
                    Id = "objectManagement"
                    Type = ""
                    LeastPrivilegeRBAC = "Global Secure Access Administrator"
                    LeastPrivilegedMSGraph = "NetworkAccessPolicy.ReadWrite.All"
                    Relevant = $true
                }
            )
        }
        TaskManagement = @{ 
            Description = "Task management covers Lifecycle Workflow task configuration within identity automation workflows for joiners, movers, and leavers."
            Activity = @(
                @{
                    DisplayName = "Add task to workflow"
                    Description = ""
                    Id = "taskManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Disable task"
                    Description = ""
                    Id = "taskManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Enable task"
                    Description = ""
                    Id = "taskManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Remove task from workflow"
                    Description = ""
                    Id = "taskManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Update task"
                    Description = ""
                    Id = "taskManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $true
                }
            )
        }
        WorkflowManagement = @{ 
            Description = "Workflow management covers Lifecycle Workflow creation, scheduling, and execution for automated joiner/mover/leaver identity processes."
            Activity = @(
                @{
                    DisplayName = "Add execution conditions"
                    Description = ""
                    Id = "workflowManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Add workflow version"
                    Description = ""
                    Id = "workflowManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Create workflow"
                    Description = ""
                    Id = "workflowManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Delete workflow"
                    Description = ""
                    Id = "workflowManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Disable workflow"
                    Description = ""
                    Id = "workflowManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Disable workflow schedule"
                    Description = ""
                    Id = "workflowManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Enable workflow"
                    Description = ""
                    Id = "workflowManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Enable workflow schedule"
                    Description = ""
                    Id = "workflowManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Hard delete workflow"
                    Description = ""
                    Id = "workflowManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "On-demand workflow execution completed"
                    Description = ""
                    Id = "workflowManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Restore workflow"
                    Description = ""
                    Id = "workflowManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Schedule workflow execution completed"
                    Description = ""
                    Id = "workflowManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Schedule workflow execution started"
                    Description = ""
                    Id = "workflowManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = ""
                    LeastPrivilegedMSGraph = ""
                    Relevant = $false
                },
                @{
                    DisplayName = "Set workflow for on-demand execution"
                    Description = ""
                    Id = "workflowManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $false
                },
                @{
                    DisplayName = "Update execution conditions"
                    Description = ""
                    Id = "workflowManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Update tenant settings"
                    Description = ""
                    Id = "workflowManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $true
                },
                @{
                    DisplayName = "Update workflow"
                    Description = ""
                    Id = "workflowManagement"
                    Type = "Microsoft.LifecycleWorkflows"
                    LeastPrivilegeRBAC = "Lifecycle Workflows Administrator"
                    LeastPrivilegedMSGraph = "LifecycleWorkflows.ReadWrite.All"
                    Relevant = $true
                }
            )
        }
    }
    }

    process {
        $matchingCategories = $activityData.Keys | Where-Object { $_ -like $Category }
        if (-not $matchingCategories) {
            Write-Error "Unknown category '$Category'. Valid categories are: $(($activityData.Keys | Sort-Object) -join ', ')"
            return
        }

        foreach ($cat in $matchingCategories) {
            $categoryData = $activityData[$cat]
            $activities = $categoryData.Activity

            if ($PSBoundParameters.ContainsKey('Name')) {
                $activities = $activities | Where-Object { $_.DisplayName -like $Name }
            }

            foreach ($activity in $activities) {
                [PSCustomObject]@{
                    Category               = $cat
                    CategoryDescription    = $categoryData.Description
                    DisplayName            = $activity.DisplayName
                    Description            = $activity.Description
                    Id                     = $activity.Id
                    Type                   = $activity.Type
                    LeastPrivilegeRBAC     = $activity.LeastPrivilegeRBAC
                    LeastPrivilegedMSGraph = $activity.LeastPrivilegedMSGraph
                    Relevant               = $activity.Relevant
                }
            }
        }
    }
}
