#Requires -Modules EntraAuth

function Get-PrivilegedUsers {
    <#
    .SYNOPSIS
    Returns every user who holds any Microsoft Entra ID directory role, whether actively assigned or PIM-eligible.

    .DESCRIPTION
    Enumerates every Entra ID directory role definition, resolves its active and PIM-eligible assignments, and
    expands any role-assigned groups to their member users (Entra ID role-assignable groups do not currently
    support nested group membership, so only one level of expansion is needed). Returns one object per user,
    with a Roles property listing every role/assignment-type/via-group combination that makes them privileged.

    Falls back to the legacy roleAssignments endpoint for tenants without Entra ID P2/Governance (PIM).

    Requires an existing EntraAuth connection (Connect-EntraService -Service Graph) with at least
    RoleManagement.Read.Directory and GroupMember.Read.All.

    .EXAMPLE
    Get-PrivilegedUsers

    Returns one object per privileged user, each with a Roles list of their active/eligible role assignments.

    .OUTPUTS
    PSCustomObject

    .LINK
    https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md#highly-privileged-roles
    #>
    [CmdletBinding()]
    param()
    Write-Verbose -Message "Getting directory role definitions."
    $roles = Invoke-EntraRequest -Path 'roleManagement/directory/roleDefinitions'
    $privilegedUsers = @{}

    # PIM (roleAssignmentSchedule / roleEligibilitySchedule) requires Entra ID P2/Governance.
    # Probe once and fall back to the legacy roleAssignments endpoint if it isn't available for this tenant.
    $pimAvailable = $true
    try {
        Invoke-EntraRequest -Path 'roleManagement/directory/roleAssignmentScheduleInstances' -Query @{ '$top' = 1 } -ErrorAction Stop | Out-Null
    } catch {
        $pimAvailable = $false
        Write-Verbose -Message "PIM role schedule APIs are not available for this tenant; falling back to roleAssignments."
    }

    foreach ($role in $roles) {
        Write-Verbose -Message "Getting members for role: $($role.displayName)"
        $assignments = [System.Collections.Generic.List[object]]::new()

        if ($pimAvailable) {
            # assignmentType eq 'Assigned' filters out eligible users that have temporarily activated the role
            $activeFilter = "roleDefinitionId eq '$($role.id)' and assignmentType eq 'Assigned'"
            $active = Invoke-EntraRequest -Path 'roleManagement/directory/roleAssignmentScheduleInstances' -Query @{ '$filter' = $activeFilter; '$expand' = 'principal' }
            if ($active) {
                $active | ForEach-Object { $_ | Add-Member -NotePropertyName AssignmentType -NotePropertyValue 'Active' -Force }
                $assignments.AddRange([object[]]$active)
            }

            $eligibleFilter = "roleDefinitionId eq '$($role.id)'"
            $eligible = Invoke-EntraRequest -Path 'roleManagement/directory/roleEligibilityScheduleInstances' -Query @{ '$filter' = $eligibleFilter; '$expand' = 'principal' }
            if ($eligible) {
                $eligible | ForEach-Object { $_ | Add-Member -NotePropertyName AssignmentType -NotePropertyValue 'Eligible' -Force }
                $assignments.AddRange([object[]]$eligible)
            }
        } else {
            $activeFilter = "roleDefinitionId eq '$($role.id)'"
            $active = Invoke-EntraRequest -Path 'roleManagement/directory/roleAssignments' -Query @{ '$filter' = $activeFilter; '$expand' = 'principal' }
            if ($active) {
                $active | ForEach-Object { $_ | Add-Member -NotePropertyName AssignmentType -NotePropertyValue 'Active' -Force }
                $assignments.AddRange([object[]]$active)
            }
        }

        foreach ($assignment in $assignments) {
            $principal = $assignment.principal
            if (-not $principal) { continue }

            if ($principal.'@odata.type' -eq '#microsoft.graph.group') {
                $members = Invoke-EntraRequest -Path "groups/$($principal.id)/members"
                $viaGroup = $principal.displayName
            } else {
                $members = @($principal)
                $viaGroup = $null
            }

            foreach ($member in $members) {
                if ($member.'@odata.type' -ne '#microsoft.graph.user') { continue }

                if (-not $privilegedUsers.ContainsKey($member.id)) {
                    $privilegedUsers[$member.id] = [PSCustomObject]@{
                        DisplayName       = $member.displayName
                        UserPrincipalName = $member.userPrincipalName
                        Id                = $member.id
                        Roles             = [System.Collections.Generic.List[object]]::new()
                    }
                }

                $privilegedUsers[$member.id].Roles.Add([PSCustomObject]@{
                    RoleName       = $role.displayName
                    RoleId         = $role.id
                    AssignmentType = $assignment.AssignmentType
                    ViaGroup       = $viaGroup
                })
            }
        }
    }

    $privilegedUsers.Values
}
