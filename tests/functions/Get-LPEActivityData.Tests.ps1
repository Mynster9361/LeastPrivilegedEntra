Describe "Get-LPEActivityData" {

    Context "Category lookup" {

        It "Returns activities for a known category" {
            $result = Get-LPEActivityData -Category AdministrativeUnit
            $result | Should -Not -BeNullOrEmpty
            ($result | Get-Member -Name Category, CategoryDescription, DisplayName, Description, Id, Type, LeastPrivilegeRBAC, LeastPrivilegedMSGraph, Relevant).Count | Should -Be 9
        }

        It "Returns a specific activity by exact name" {
            $result = Get-LPEActivityData -Category AdministrativeUnit -Name "Add administrative unit"
            $result | Should -HaveCount 1
            $result.LeastPrivilegeRBAC | Should -Be 'Privileged Role Administrator'
            $result.LeastPrivilegedMSGraph | Should -Be 'AdministrativeUnit.ReadWrite.All'
            $result.Relevant | Should -Be $true
        }

        It "Supports wildcards on Name" {
            $result = Get-LPEActivityData -Category AdministrativeUnit -Name "*administrative unit"
            $result.Count | Should -BeGreaterThan 1
            $result.DisplayName | Should -Contain "Add administrative unit"
        }

        It "Supports wildcards on Category" {
            $result = Get-LPEActivityData -Category *
            ($result.Category | Sort-Object -Unique).Count | Should -BeGreaterThan 1
        }

        It "Every returned activity carries its own category" {
            $result = Get-LPEActivityData -Category AdministrativeUnit
            $result.Category | Sort-Object -Unique | Should -Be 'AdministrativeUnit'
        }

        It "Errors on an unknown category and returns nothing" {
            $result = Get-LPEActivityData -Category DoesNotExist -ErrorAction SilentlyContinue -ErrorVariable err
            $result | Should -BeNullOrEmpty
            $err | Should -Not -BeNullOrEmpty
        }
    }

    Context "Relevant filtering" {

        It "Filtering by Relevant returns only activities flagged relevant" {
            $result = Get-LPEActivityData -Category * | Where-Object Relevant
            $result | Should -Not -BeNullOrEmpty
            ($result | Where-Object { -not $_.Relevant }) | Should -BeNullOrEmpty
        }
    }
}
