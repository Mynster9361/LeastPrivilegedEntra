
$tenantId = "tenantId"
$appId = "appId"
$secret = "secret" | ConvertTo-SecureString -AsPlainText -Force
$workspaceId = "workspaceId"

. ".\Get-ActivityData.ps1"
. ".\Get-PrivilegedUsers.ps1"
. ".\Get-LogActivityData.ps1"
. ".\Get-PermissionAnalysis.ps1"

Connect-EntraService -TenantId $tenantId -ClientID $appId -ClientSecret $secret -Service Graph, LogAnalytics

$privUsers = Get-PrivilegedUsers

$logs = Get-LogActivityData -WorkspaceId $workspaceId -UserId $privUsers.Id -Days 90

$analysis = Get-PermissionAnalysis -PrivilegedUser $privUsers -ActivityLog $logs

$analysis | convertto-json -depth 10 | Out-File -FilePath ".\PrivilegedUsersAnalysis.json"
$analysis |
ForEach-Object {
    $user = $_
    foreach ($role in $user.Roles) {
        [PSCustomObject]@{
            User      = $user.DisplayName
            Role      = $role.RoleName
            Type      = $role.AssignmentType
            Group     = if ($role.ViaGroup) { $role.ViaGroup } else { "-" }
            Status    = $role.Status
            LastUsed  = if ($role.LastUsed) { $role.LastUsed } else { "-" }
            Days      = $role.DaysSinceLastUse
            Count     = $role.ActivityCount
        }
    }
} |
Sort-Object User, @{E={
    switch ($_.Status) {
        'Used'              { 0 }
        'NotUsedInWindow'   { 1 }
        'NoMappedActivity'  { 2 }
        default             { 3 }
    }
}}, Role |
Format-Table -AutoSize