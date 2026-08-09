Describe "Get-LPEPermissionAnalysis" {

    BeforeAll {
        Mock -ModuleName LeastPrivilegedEntra Get-LPEActivityData {
            [PSCustomObject]@{ Category = 'UserManagement'; DisplayName = 'Update user'; LeastPrivilegeRBAC = 'User Administrator'; LeastPrivilegedMSGraph = 'User.ReadWrite.All'; Relevant = $true }
            [PSCustomObject]@{ Category = 'GroupManagement'; DisplayName = 'Add member to group'; LeastPrivilegeRBAC = 'Groups Administrator'; LeastPrivilegedMSGraph = 'GroupMember.ReadWrite.All'; Relevant = $true }
        }

        function New-TestUser {
            param([string]$Id = 'user-1', [string]$RoleName, [string]$RoleId = 'role-1')
            [PSCustomObject]@{
                Id                = $Id
                DisplayName       = 'Test User'
                UserPrincipalName = 'testuser@contoso.com'
                Roles             = @(
                    [PSCustomObject]@{ RoleName = $RoleName; RoleId = $RoleId; AssignmentType = 'Active'; ViaGroup = $null }
                )
            }
        }

        function New-TestActivityLog {
            param(
                [string]$Id = 'user-1',
                [string]$Category,
                [string]$DisplayName,
                [int]$ActivityCount = 1,
                [int]$FailureCount = 0,
                [datetime]$LastActivityTime = (Get-Date)
            )
            [PSCustomObject]@{
                Id                = $Id
                DisplayName       = 'Test User'
                UserPrincipalName = 'testuser@contoso.com'
                Activities        = @(
                    [PSCustomObject]@{
                        Category          = $Category
                        DisplayName       = $DisplayName
                        LastActivityTime  = if ($ActivityCount -gt 0) { $LastActivityTime } else { $null }
                        FirstActivityTime = if ($ActivityCount -gt 0) { $LastActivityTime } else { $null }
                        LastAttemptTime   = $LastActivityTime
                        ActivityCount     = $ActivityCount
                        FailureCount      = $FailureCount
                    }
                )
            }
        }
    }

    Context "A held role with successful matching activity" {

        It "Is marked Used and kept" {
            $user = New-TestUser -RoleName 'User Administrator'
            $log = New-TestActivityLog -Category 'UserManagement' -DisplayName 'Update user' -ActivityCount 2

            $result = Get-LPEPermissionAnalysis -PrivilegedUser $user -ActivityLog $log

            $role = $result.Roles[0]
            $role.Status | Should -Be 'Used'
            $role.LastUsed | Should -Not -BeNullOrEmpty
            $role.ActivityCount | Should -Be 2

            $result.Suggestion.KeepRoles | Should -Contain 'User Administrator'
            $result.Suggestion.RemoveRoles | Should -Not -Contain 'User Administrator'
        }
    }

    Context "A held role with no logged activity" {

        It "Is marked NotUsedInWindow and suggested for removal" {
            $user = New-TestUser -RoleName 'User Administrator'

            $result = Get-LPEPermissionAnalysis -PrivilegedUser $user

            $result.Roles[0].Status | Should -Be 'NotUsedInWindow'
            $result.Suggestion.RemoveRoles | Should -Contain 'User Administrator'
            $result.Suggestion.KeepRoles | Should -Not -Contain 'User Administrator'
        }
    }

    Context "A held role with no mapped activity at all" {

        It "Is marked NoMappedActivity and never suggested for removal" {
            $user = New-TestUser -RoleName 'Global Reader'
            $log = New-TestActivityLog -Category 'UserManagement' -DisplayName 'Update user' -ActivityCount 1

            $result = Get-LPEPermissionAnalysis -PrivilegedUser $user -ActivityLog $log

            $result.Roles[0].Status | Should -Be 'NoMappedActivity'
            $result.Roles[0].RelatedActivities | Should -BeNullOrEmpty
            $result.Suggestion.KeepRoles | Should -Contain 'Global Reader'
            $result.Suggestion.RemoveRoles | Should -Not -Contain 'Global Reader'
        }
    }

    Context "A successful activity implying an unheld, narrower role" {

        It "Suggests adding that role, with the evidence attached" {
            $user = New-TestUser -RoleName 'Global Reader'
            $log = New-TestActivityLog -Category 'GroupManagement' -DisplayName 'Add member to group' -ActivityCount 3

            $result = Get-LPEPermissionAnalysis -PrivilegedUser $user -ActivityLog $log

            $result.Suggestion.AddRoles.RoleName | Should -Contain 'Groups Administrator'

            $suggestion = $result.Suggestion.AddRoles | Where-Object RoleName -EQ 'Groups Administrator'
            $suggestion.Activities | Should -HaveCount 1
            $suggestion.Activities[0].Category | Should -Be 'GroupManagement'
            $suggestion.Activities[0].DisplayName | Should -Be 'Add member to group'
            $suggestion.Activities[0].LeastPrivilegedMSGraph | Should -Be 'GroupMember.ReadWrite.All'
            $suggestion.Activities[0].ActivityCount | Should -Be 3
            $suggestion.Activities[0].LastActivityTime | Should -Not -BeNullOrEmpty
        }
    }

    Context "A denied-only activity (ActivityCount 0, FailureCount > 0)" {

        It "Does not mark an already-held role as Used" {
            $user = New-TestUser -RoleName 'User Administrator'
            $log = New-TestActivityLog -Category 'UserManagement' -DisplayName 'Update user' -ActivityCount 0 -FailureCount 3

            $result = Get-LPEPermissionAnalysis -PrivilegedUser $user -ActivityLog $log

            $result.Roles[0].Status | Should -Be 'NotUsedInWindow'
            $result.Suggestion.RemoveRoles | Should -Contain 'User Administrator'
        }

        It "Is not suggested via AddRoles for a role the user doesn't hold" {
            $user = New-TestUser -RoleName 'Global Reader'
            $log = New-TestActivityLog -Category 'UserManagement' -DisplayName 'Update user' -ActivityCount 0 -FailureCount 2

            $result = Get-LPEPermissionAnalysis -PrivilegedUser $user -ActivityLog $log

            $result.Suggestion.AddRoles.RoleName | Should -Not -Contain 'User Administrator'
        }

        It "Is surfaced via DeniedAttempts instead, with the denied evidence attached" {
            $user = New-TestUser -RoleName 'Global Reader'
            $log = New-TestActivityLog -Category 'UserManagement' -DisplayName 'Update user' -ActivityCount 0 -FailureCount 2

            $result = Get-LPEPermissionAnalysis -PrivilegedUser $user -ActivityLog $log

            $result.Suggestion.DeniedAttempts.RoleName | Should -Contain 'User Administrator'

            $suggestion = $result.Suggestion.DeniedAttempts | Where-Object RoleName -EQ 'User Administrator'
            $suggestion.Activities | Should -HaveCount 1
            $suggestion.Activities[0].Category | Should -Be 'UserManagement'
            $suggestion.Activities[0].DisplayName | Should -Be 'Update user'
            $suggestion.Activities[0].FailureCount | Should -Be 2
            $suggestion.Activities[0].LastAttemptTime | Should -Not -BeNullOrEmpty
        }
    }

    Context "Mixed successful and denied activity for unheld roles on the same user" {

        It "Splits them correctly between AddRoles and DeniedAttempts" {
            $user = New-TestUser -RoleName 'Global Reader'
            $log = [PSCustomObject]@{
                Id                = 'user-1'
                DisplayName       = 'Test User'
                UserPrincipalName = 'testuser@contoso.com'
                Activities        = @(
                    [PSCustomObject]@{ Category = 'GroupManagement'; DisplayName = 'Add member to group'; LastActivityTime = (Get-Date); FirstActivityTime = (Get-Date); LastAttemptTime = (Get-Date); ActivityCount = 1; FailureCount = 0 }
                    [PSCustomObject]@{ Category = 'UserManagement'; DisplayName = 'Update user'; LastActivityTime = $null; FirstActivityTime = $null; LastAttemptTime = (Get-Date); ActivityCount = 0; FailureCount = 5 }
                )
            }

            $result = Get-LPEPermissionAnalysis -PrivilegedUser $user -ActivityLog $log

            $result.Suggestion.AddRoles.RoleName | Should -Contain 'Groups Administrator'
            $result.Suggestion.AddRoles.RoleName | Should -Not -Contain 'User Administrator'
            $result.Suggestion.DeniedAttempts.RoleName | Should -Contain 'User Administrator'
            $result.Suggestion.DeniedAttempts.RoleName | Should -Not -Contain 'Groups Administrator'
        }
    }

    Context "A single unheld role with both successful and denied evidence" {

        It "Only appears in AddRoles, not DeniedAttempts, once it has any successful evidence" {
            Mock -ModuleName LeastPrivilegedEntra Get-LPEActivityData {
                [PSCustomObject]@{ Category = 'UserManagement'; DisplayName = 'Update user'; LeastPrivilegeRBAC = 'User Administrator'; LeastPrivilegedMSGraph = 'User.ReadWrite.All'; Relevant = $true }
                [PSCustomObject]@{ Category = 'UserManagement'; DisplayName = 'Reset password'; LeastPrivilegeRBAC = 'User Administrator'; LeastPrivilegedMSGraph = 'User.ReadWrite.All'; Relevant = $true }
            }

            $user = New-TestUser -RoleName 'Global Reader'
            $log = [PSCustomObject]@{
                Id                = 'user-1'
                DisplayName       = 'Test User'
                UserPrincipalName = 'testuser@contoso.com'
                Activities        = @(
                    [PSCustomObject]@{ Category = 'UserManagement'; DisplayName = 'Update user'; LastActivityTime = (Get-Date); FirstActivityTime = (Get-Date); LastAttemptTime = (Get-Date); ActivityCount = 1; FailureCount = 0 }
                    [PSCustomObject]@{ Category = 'UserManagement'; DisplayName = 'Reset password'; LastActivityTime = $null; FirstActivityTime = $null; LastAttemptTime = (Get-Date); ActivityCount = 0; FailureCount = 4 }
                )
            }

            $result = Get-LPEPermissionAnalysis -PrivilegedUser $user -ActivityLog $log

            $result.Suggestion.AddRoles.RoleName | Should -Contain 'User Administrator'
            $result.Suggestion.DeniedAttempts.RoleName | Should -Not -Contain 'User Administrator'

            $suggestion = $result.Suggestion.AddRoles | Where-Object RoleName -EQ 'User Administrator'
            $suggestion.Activities | Should -HaveCount 1
            $suggestion.Activities[0].DisplayName | Should -Be 'Update user'
        }
    }
}
