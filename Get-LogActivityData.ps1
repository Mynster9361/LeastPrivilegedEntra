#Requires -Modules EntraAuth

function Get-LogActivityData {
    <#
    .SYNOPSIS
        Returns Entra ID audit log activity, grouped per user, from a Log Analytics workspace.
    .DESCRIPTION
        Queries the AuditLogs table in a Log Analytics workspace and, for each user who initiated at least one
        audit event, returns the distinct Category/DisplayName activity combinations they performed together with
        the first and last time each was seen and how many times it occurred.

        The query is restricted to the activities Get-ActivityData flags as Relevant ($true) — activities with no
        meaningful least-privilege mapping (informational/read-only events, "started (bulk)" markers, etc.) are
        excluded so the results only reflect actions that actually required a role or Microsoft Graph permission.

        The Category and DisplayName columns match the Category and Activity.DisplayName values used by
        Get-ActivityData, so the two can be cross-referenced to determine when a privileged user last performed an
        activity that required a given least-privileged role or Microsoft Graph permission.

        Requires Get-ActivityData to be loaded in the session, an existing EntraAuth connection
        (Connect-EntraService -Service LogAnalytics) with read access to the Log Analytics workspace, and that
        Entra ID audit logs are being streamed to it via diagnostic settings.
    .PARAMETER WorkspaceId
        The Log Analytics workspace ID (customer ID GUID) containing the AuditLogs table.
    .PARAMETER UserId
        One or more Entra ID user object IDs to restrict the query to (e.g. the Id values returned by
        Get-PrivilegedUsers). If omitted, activity for every user found in the window is returned.
    .PARAMETER Days
        Number of days of audit log history to query. Default is 90.
    .PARAMETER IncludeFailures
        By default only activities that succeeded are returned. Pass this switch to also include failed attempts.
    .EXAMPLE
        Get-LogActivityData -WorkspaceId $workspaceId -UserId $privilegedUsers.Id -Days 90

        Returns activity for the given privileged users over the last 90 days.
    .EXAMPLE
        $activity = Get-LogActivityData -WorkspaceId $workspaceId -Days 30
        ($activity | Where-Object Id -eq $userId).Activities | Where-Object { $_.Category -eq 'AdministrativeUnit' -and $_.DisplayName -eq 'Update administrative unit' }

        Finds the last time a specific user performed an activity that Get-ActivityData maps to a least-privileged permission.
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$WorkspaceId,

        [Parameter(Mandatory = $false)]
        [string[]]$UserId,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 365)]
        [int]$Days = 90,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeFailures
    )

    if (-not (Get-Command -Name Get-ActivityData -ErrorAction SilentlyContinue)) {
        Write-Error "Get-ActivityData must be loaded in this session to determine which activities are relevant."
        return
    }

    $relevantActivities = Get-ActivityData -Category * | Where-Object Relevant
    if (-not $relevantActivities) {
        Write-Error "Get-ActivityData returned no activities flagged as relevant; nothing to query."
        return
    }

    $relevantKeys = $relevantActivities |
        ForEach-Object { '{0}|{1}' -f $_.Category, $_.DisplayName } |
        Sort-Object -Unique
    $quotedRelevantKeys = ($relevantKeys | ForEach-Object { '"{0}"' -f ($_ -replace '"', '\"') }) -join ','

    $endDate = [datetime]::UtcNow
    $startDate = $endDate.AddDays(-$Days)
    $startDateStr = $startDate.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $endDateStr = $endDate.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

    $userFilter = ''
    if ($UserId) {
        $quotedIds = ($UserId | ForEach-Object { '"{0}"' -f $_ }) -join ','
        $userFilter = "| where UserId in ($quotedIds)"
    }

    $resultFilter = ''
    if (-not $IncludeFailures) {
        $resultFilter = '| where Result == "success"'
    }

    $kqlQuery = @"
AuditLogs
| where TimeGenerated >= datetime($startDateStr) and TimeGenerated <= datetime($endDateStr)
| extend UserId = tostring(InitiatedBy.user.id)
| extend UserDisplayName = tostring(InitiatedBy.user.displayName)
| extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| where isnotempty(UserId)
| where strcat(Category, "|", OperationName) in ($quotedRelevantKeys)
$userFilter
$resultFilter
| summarize LastActivityTime = max(TimeGenerated), FirstActivityTime = min(TimeGenerated), ActivityCount = count() by UserId, UserDisplayName, UserPrincipalName, Category, DisplayName = OperationName
| order by UserDisplayName asc, LastActivityTime desc
"@

    Write-Verbose -Message "Querying Log Analytics workspace $WorkspaceId for audit log activity from $startDateStr to $endDateStr"

    try {
        $response = Invoke-EntraRequest -Service LogAnalytics -Method POST -Path "v1/workspaces/$WorkspaceId/query" -Body @{ query = $kqlQuery } -ErrorAction Stop
    } catch {
        Write-Error "Failed to query Log Analytics workspace '$WorkspaceId': $($_.Exception.Message)"
        return
    }

    $table = $response.tables | Select-Object -First 1
    if (-not $table -or -not $table.rows -or $table.rows.Count -eq 0) {
        Write-Verbose -Message "No audit log activity found in the specified window."
        return
    }

    $columnNames = $table.columns.name
    $rows = foreach ($row in $table.rows) {
        $rowObject = [ordered]@{}
        for ($i = 0; $i -lt $columnNames.Count; $i++) {
            $rowObject[$columnNames[$i]] = $row[$i]
        }
        [PSCustomObject]$rowObject
    }

    $userActivity = @{}
    foreach ($row in $rows) {
        if (-not $userActivity.ContainsKey($row.UserId)) {
            $userActivity[$row.UserId] = [PSCustomObject]@{
                Id                = $row.UserId
                DisplayName       = $row.UserDisplayName
                UserPrincipalName = $row.UserPrincipalName
                Activities        = [System.Collections.Generic.List[object]]::new()
            }
        }

        $userActivity[$row.UserId].Activities.Add([PSCustomObject]@{
            Category          = $row.Category
            DisplayName       = $row.DisplayName
            LastActivityTime  = [datetime]$row.LastActivityTime
            FirstActivityTime = [datetime]$row.FirstActivityTime
            ActivityCount     = [int]$row.ActivityCount
        })
    }

    $userActivity.Values
}
