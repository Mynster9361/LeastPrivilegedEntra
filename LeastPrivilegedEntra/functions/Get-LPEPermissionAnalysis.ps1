function Get-LPEPermissionAnalysis {
    <#
    .SYNOPSIS
        Couples each privileged user's roles with evidence of whether they actually used them, and suggests a
        right-sized role set.
    .DESCRIPTION
        Combines the output of three functions to answer, per user, "which of these roles does this person
        actually need?":

        - Get-LPEPrivilegedUsers supplies which roles each user holds (Active or Eligible, direct or via group).
        - Get-LPELogActivityData supplies which relevant audit log activities each user actually performed, and when.
        - Get-LPEActivityData supplies the least-privileged role (and Microsoft Graph permission) required for each
          audit log activity, which is what lets a role be matched back to the activities it grants.

        Returns one object per user, containing:

        - Roles: one entry per role the user holds, with a Status ("Used" / "NotUsedInWindow" / "NoMappedActivity")
          and a RelatedActivities drill-down listing every activity Get-LPEActivityData maps to that role, whether the
          user actually performed it, and when. "NoMappedActivity" means usage can't be observed from audit logs at
          all (e.g. read-only roles), so no removal is ever suggested for it.
        - Suggestion: a right-sizing recommendation built from everything the user actually did, independent of
          which roles they currently hold:
            - RemoveRoles: held roles with no corresponding activity in the queried window.
            - KeepRoles: held roles that are either justified by observed activity or can't be evaluated at all.
            - AddRoles: roles implied by the user's activity that they do not currently hold - typically because a
              broader role (e.g. Global Administrator) is covering for a narrower one (e.g. User Administrator)
              that would have sufficed.
            - DeniedAttempts: roles the user does not hold and never successfully exercised via another role, but
              repeatedly attempted (and were denied) actions that map to. Only populated when ActivityLog was
              collected with Get-LPELogActivityData -IncludeFailures; otherwise always empty.

        Requires Get-LPEActivityData to be loaded in the session.
    .PARAMETER PrivilegedUser
        One or more user objects as returned by Get-LPEPrivilegedUsers (must have Id and a Roles collection).
    .PARAMETER ActivityLog
        Zero or more user activity objects as returned by Get-LPELogActivityData (must have Id and an Activities
        collection). Users with no corresponding entry - including when this is omitted entirely - are treated as
        having no logged activity, so every role they hold is reported as "NotUsedInWindow".
    .EXAMPLE
        $privilegedUsers = Get-LPEPrivilegedUsers
        $activityLog = Get-LPELogActivityData -WorkspaceId $workspaceId -UserId $privilegedUsers.Id -Days 90
        Get-LPEPermissionAnalysis -PrivilegedUser $privilegedUsers -ActivityLog $activityLog

        Returns one object per privileged user, with their per-role usage evidence and a right-sizing suggestion.
    .EXAMPLE
        Get-LPEPermissionAnalysis -PrivilegedUser $privilegedUsers -ActivityLog $activityLog |
            Where-Object { $_.Suggestion.RemoveRoles } |
            Select-Object DisplayName, @{N = 'RemoveRoles'; E = { $_.Suggestion.RemoveRoles -join ', ' } }

        Lists every user with at least one unused role, and which role(s) to remove.
    .EXAMPLE
        (Get-LPEPermissionAnalysis -PrivilegedUser $privilegedUsers -ActivityLog $activityLog |
            Where-Object DisplayName -eq 'Jane Doe').Roles.RelatedActivities

        Shows the full activity-by-activity breakdown behind every role a specific user holds.
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]$PrivilegedUser,

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$ActivityLog = @()
    )

    begin {
        if (-not (Get-Command -Name Get-LPEActivityData -ErrorAction SilentlyContinue)) {
            Write-Error "Get-LPEActivityData must be loaded in this session to map activities to least-privileged permissions."
            return
        }

        Write-Verbose -Message "Building role-to-activity and activity-to-role maps from Get-LPEActivityData."
        $roleActivityMap = @{}
        $activityRoleMap = @{}
        # Only Relevant activities are considered - Get-LPELogActivityData only ever logs Relevant activities, so
        # including non-relevant ones here (informational reads, "started/finished (bulk)" markers, etc.) would
        # always show up as unused noise rather than genuine evidence one way or the other.
        foreach ($activity in Get-LPEActivityData -Category * | Where-Object Relevant) {
            $activityKey = '{0}|{1}' -f $activity.Category, $activity.DisplayName
            if (-not $activityRoleMap.ContainsKey($activityKey)) {
                $activityRoleMap[$activityKey] = $activity
            }

            if (-not $activity.LeastPrivilegeRBAC) { continue }
            if (-not $roleActivityMap.ContainsKey($activity.LeastPrivilegeRBAC)) {
                $roleActivityMap[$activity.LeastPrivilegeRBAC] = [System.Collections.Generic.List[object]]::new()
            }
            $roleActivityMap[$activity.LeastPrivilegeRBAC].Add($activity)
        }

        $activityLogByUser = @{}
        foreach ($userLog in $ActivityLog) {
            $activityLogByUser[$userLog.Id] = $userLog
        }
    }

    process {
        foreach ($user in $PrivilegedUser) {
            $userLog = $activityLogByUser[$user.Id]

            $suggestedRoles = @()
            if ($userLog) {
                $suggestedRoles = @(
                    foreach ($loggedActivity in $userLog.Activities) {
                        # ActivityCount 0 rows (denied-only, only present with -IncludeFailures) are not evidence the
                        # user successfully exercised the mapped role - those feed DeniedAttempts below instead.
                        if ($loggedActivity.ActivityCount -le 0) { continue }
                        $activityKey = '{0}|{1}' -f $loggedActivity.Category, $loggedActivity.DisplayName
                        $mappedActivity = $activityRoleMap[$activityKey]
                        if ($mappedActivity -and $mappedActivity.LeastPrivilegeRBAC) { $mappedActivity.LeastPrivilegeRBAC }
                    }
                ) | Sort-Object -Unique
            }

            # Activities with ActivityCount 0 only appear when ActivityLog was collected with -IncludeFailures, and
            # mean every attempt at that activity was denied - a candidate for a role the user needs but lacks.
            $deniedRoles = @()
            if ($userLog) {
                $deniedRoles = @(
                    foreach ($loggedActivity in $userLog.Activities) {
                        if ($loggedActivity.ActivityCount -gt 0 -or $loggedActivity.FailureCount -le 0) { continue }
                        $activityKey = '{0}|{1}' -f $loggedActivity.Category, $loggedActivity.DisplayName
                        $mappedActivity = $activityRoleMap[$activityKey]
                        if ($mappedActivity -and $mappedActivity.LeastPrivilegeRBAC) { $mappedActivity.LeastPrivilegeRBAC }
                    }
                ) | Sort-Object -Unique
            }

            $roleResults = @(
                foreach ($role in $user.Roles) {
                    $mappedActivities = $roleActivityMap[$role.RoleName]

                    if (-not $mappedActivities) {
                        [PSCustomObject]@{
                            RoleName          = $role.RoleName
                            RoleId            = $role.RoleId
                            AssignmentType    = $role.AssignmentType
                            ViaGroup          = $role.ViaGroup
                            Status            = 'NoMappedActivity'
                            LastUsed          = $null
                            DaysSinceLastUse  = $null
                            ActivityCount     = 0
                            RelatedActivities = @()
                        }
                        continue
                    }

                    $activityDetails = foreach ($mappedActivity in $mappedActivities) {
                        $loggedMatch = $null
                        if ($userLog) {
                            $loggedMatch = $userLog.Activities | Where-Object {
                                $_.Category -eq $mappedActivity.Category -and $_.DisplayName -eq $mappedActivity.DisplayName
                            } | Select-Object -First 1
                        }

                        [PSCustomObject]@{
                            Category               = $mappedActivity.Category
                            DisplayName            = $mappedActivity.DisplayName
                            LeastPrivilegedMSGraph = $mappedActivity.LeastPrivilegedMSGraph
                            # loggedMatch can be a failure-only row (ActivityCount 0) when the caller collected
                            # ActivityLog with -IncludeFailures, so Used must check ActivityCount, not presence.
                            Used                   = [bool]($loggedMatch -and $loggedMatch.ActivityCount -gt 0)
                            LastActivityTime       = if ($loggedMatch) { $loggedMatch.LastActivityTime } else { $null }
                            ActivityCount          = if ($loggedMatch) { $loggedMatch.ActivityCount } else { 0 }
                            FailureCount           = if ($loggedMatch) { $loggedMatch.FailureCount } else { 0 }
                        }
                    }

                    $usedActivities = @($activityDetails | Where-Object Used)

                    if ($usedActivities.Count -gt 0) {
                        $lastUsed = $usedActivities.LastActivityTime | Sort-Object -Descending | Select-Object -First 1
                        $status = 'Used'
                        $daysSinceLastUse = [int]([datetime]::UtcNow - $lastUsed).TotalDays
                        $totalActivityCount = ($usedActivities.ActivityCount | Measure-Object -Sum).Sum
                    } else {
                        $lastUsed = $null
                        $status = 'NotUsedInWindow'
                        $daysSinceLastUse = $null
                        $totalActivityCount = 0
                    }

                    [PSCustomObject]@{
                        RoleName          = $role.RoleName
                        RoleId            = $role.RoleId
                        AssignmentType    = $role.AssignmentType
                        ViaGroup          = $role.ViaGroup
                        Status            = $status
                        LastUsed          = $lastUsed
                        DaysSinceLastUse  = $daysSinceLastUse
                        ActivityCount     = $totalActivityCount
                        RelatedActivities = $activityDetails
                    }
                }
            )

            $heldRoleNames = @($roleResults.RoleName)

            [PSCustomObject]@{
                Id                = $user.Id
                DisplayName       = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                Roles             = $roleResults
                Suggestion        = [PSCustomObject]@{
                    RemoveRoles    = @($roleResults | Where-Object Status -eq 'NotUsedInWindow' | Select-Object -ExpandProperty RoleName)
                    KeepRoles      = @($roleResults | Where-Object { $_.Status -in 'Used', 'NoMappedActivity' } | Select-Object -ExpandProperty RoleName)
                    AddRoles       = @($suggestedRoles | Where-Object { $_ -notin $heldRoleNames })
                    DeniedAttempts = @($deniedRoles | Where-Object { $_ -notin $heldRoleNames -and $_ -notin $suggestedRoles })
                }
            }
        }
    }
}
