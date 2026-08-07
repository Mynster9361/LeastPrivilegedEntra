#Requires -Modules EntraAuth

function Invoke-LPEScan {
	<#
    .SYNOPSIS
        Runs a full least-privilege scan against a tenant: connects, gathers privileged users and their audit log
        activity, and returns a per-user role usage analysis.
    .DESCRIPTION
        Wraps the end-to-end LeastPrivilegedEntra workflow:

        1. Connects to Microsoft Graph and Log Analytics via EntraAuth (Connect-EntraService), using an app
           registration's client ID/secret, unless -SkipConnect is passed to reuse an existing connection.
        2. Get-LPEPrivilegedUser enumerates every user holding an Entra ID directory role (active or PIM-eligible).
        3. Get-LPELogActivityData queries the Log Analytics workspace for each privileged user's relevant audit log
           activity over the requested window.
        4. Get-LPEPermissionAnalysis couples the two to produce, per user, per-role usage evidence and a right-sizing
           suggestion (roles to remove/keep/add).

        Optionally writes the analysis to a JSON file via -OutFile.
    .PARAMETER TenantId
        The Entra ID tenant ID (GUID) to connect to.
    .PARAMETER ClientId
        The application (client) ID of the app registration used to authenticate.
    .PARAMETER ClientSecret
        The application's client secret, as a SecureString.
    .PARAMETER WorkspaceId
        The Log Analytics workspace ID (customer ID GUID) containing the AuditLogs table.
    .PARAMETER Days
        Number of days of audit log history to query. Default is 90.
    .PARAMETER IncludeFailures
        By default only activities that succeeded are returned. Pass this switch to also include failed attempts.
    .PARAMETER OutFile
        Optional path to write the analysis results to as JSON.
    .PARAMETER SkipConnect
        Skip calling Connect-EntraService, and reuse an already-established EntraAuth connection
        (Graph and LogAnalytics services must already be connected).
    .EXAMPLE
        $secret = "secret" | ConvertTo-SecureString -AsPlainText -Force
        Invoke-LPEScan -TenantId $tenantId -ClientId $appId -ClientSecret $secret -WorkspaceId $workspaceId

        Connects to the tenant and returns the full per-user role usage analysis.
    .EXAMPLE
        Invoke-LPEScan -TenantId $tenantId -ClientId $appId -ClientSecret $secret -WorkspaceId $workspaceId -Days 30 -OutFile ".\PrivilegedUsersAnalysis.json"

        Runs the scan over a 30-day window and writes the results to a JSON file.
    .OUTPUTS
        PSCustomObject
    #>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory = $true, ParameterSetName = 'Connect')]
		[ValidateNotNullOrEmpty()]
		[string]$TenantId,

		[Parameter(Mandatory = $true, ParameterSetName = 'Connect')]
		[ValidateNotNullOrEmpty()]
		[string]$ClientId,

		[Parameter(Mandatory = $true, ParameterSetName = 'Connect')]
		[ValidateNotNullOrEmpty()]
		[System.Security.SecureString]$ClientSecret,

		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$WorkspaceId,

		[Parameter(Mandatory = $false)]
		[ValidateRange(1, 365)]
		[int]$Days = 90,

		[Parameter(Mandatory = $false)]
		[switch]$IncludeFailures,

		[Parameter(Mandatory = $false)]
		[string]$OutFile,

		[Parameter(Mandatory = $true, ParameterSetName = 'SkipConnect')]
		[switch]$SkipConnect
	)

	$activity = 'Least-Privilege Entra Scan'

	if (-not $SkipConnect) {
		Write-Progress -Activity $activity -Status "Connecting to tenant $TenantId" -PercentComplete 0
		Write-Verbose -Message "Connecting to tenant $TenantId."
		Connect-EntraService -TenantID $TenantId -ClientID $ClientId -ClientSecret $ClientSecret -Service Graph, LogAnalytics
	}

	Write-Progress -Activity $activity -Status 'Enumerating privileged users' -PercentComplete 10
	Write-Verbose -Message "Getting privileged users."
	$privilegedUsers = Get-LPEPrivilegedUser
	if (-not $privilegedUsers) {
		Write-Progress -Activity $activity -Completed
		Write-Warning "No privileged users were found; nothing to analyze."
		return
	}

	Write-Progress -Activity $activity -Status "Found $($privilegedUsers.Count) privileged user(s); querying $Days day(s) of audit log activity" -PercentComplete 35
	Write-Verbose -Message "Getting audit log activity for the last $Days day(s)."
	$activityLogParams = @{
		WorkspaceId = $WorkspaceId
		UserId      = $privilegedUsers.Id
		Days        = $Days
	}
	if ($IncludeFailures) { $activityLogParams.IncludeFailures = $true }
	$activityLog = Get-LPELogActivityData @activityLogParams

	Write-Progress -Activity $activity -Status "Analyzing role usage for $($privilegedUsers.Count) user(s)" -PercentComplete 80
	Write-Verbose -Message "Analyzing role usage."
	$analysis = Get-LPEPermissionAnalysis -PrivilegedUser $privilegedUsers -ActivityLog $activityLog

	if ($OutFile) {
		Write-Progress -Activity $activity -Status "Writing results to $OutFile" -PercentComplete 95
		Write-Verbose -Message "Writing analysis to $OutFile."
		$analysis | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutFile
	}

	Write-Progress -Activity $activity -Completed

	$analysis
}
