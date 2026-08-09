Describe "Export-LPEPermissionAnalysisReport" {

    BeforeAll {
        function New-TestAnalysis {
            param([string]$Id = 'user-1', [string]$DisplayName = 'Alice Admin')
            [PSCustomObject]@{
                Id                = $Id
                DisplayName       = $DisplayName
                UserPrincipalName = "$DisplayName@contoso.com" -replace ' ', ''
                Roles             = @(
                    [PSCustomObject]@{
                        RoleName          = 'Global Administrator'
                        RoleId            = 'role-1'
                        AssignmentType    = 'Active'
                        ViaGroup          = $null
                        Status            = 'Used'
                        LastUsed          = Get-Date
                        DaysSinceLastUse  = 3
                        ActivityCount     = 5
                        RelatedActivities = @()
                    }
                )
                Suggestion        = [PSCustomObject]@{
                    RemoveRoles    = @()
                    KeepRoles      = @('Global Administrator')
                    AddRoles       = @()
                    DeniedAttempts = @()
                }
            }
        }

        # No unresolved {% block xyz %}{% endblock %} tokens should ever remain in a generated report.
        function Get-LeftoverPlaceholder([string]$Html) {
            [regex]::Matches($Html, '\{%\s*block\s+\w+\s*%\}\{%\s*endblock\s*%\}')
        }
    }

    Context "Real report template" {

        It "Writes a self-contained HTML report with no unresolved placeholders" {
            $outPath = Join-Path $TestDrive 'report.html'

            $result = New-TestAnalysis | Export-LPEPermissionAnalysisReport -OutputPath $outPath -ReportTitle 'Contoso Report'

            $result | Should -Be (Resolve-Path $outPath).Path
            $outPath | Should -Exist

            $html = Get-Content -Raw $outPath
            $html | Should -Match '<html'
            $html | Should -Match '</html>'
            (Get-LeftoverPlaceholder $html) | Should -BeNullOrEmpty
        }

        It "Embeds the report title" {
            $outPath = Join-Path $TestDrive 'title.html'
            New-TestAnalysis | Export-LPEPermissionAnalysisReport -OutputPath $outPath -ReportTitle 'My Unique Title 12345' | Out-Null
            Get-Content -Raw $outPath | Should -Match 'My Unique Title 12345'
        }

        It "Embeds the analysis data for every piped-in user" {
            $outPath = Join-Path $TestDrive 'multi.html'
            @(New-TestAnalysis -Id 'user-1' -DisplayName 'Alice Admin'), (New-TestAnalysis -Id 'user-2' -DisplayName 'Bob Reader') |
                Export-LPEPermissionAnalysisReport -OutputPath $outPath | Out-Null

            $html = Get-Content -Raw $outPath
            $html | Should -Match 'Alice Admin'
            $html | Should -Match 'Bob Reader'
        }

        It "Defaults OutputPath to .\PrivilegedUsersAnalysisReport.html" {
            Push-Location $TestDrive
            try {
                New-TestAnalysis | Export-LPEPermissionAnalysisReport | Out-Null
                Join-Path $TestDrive 'PrivilegedUsersAnalysisReport.html' | Should -Exist
            } finally {
                Pop-Location
            }
        }

        It "Warns and writes nothing when the pipeline carries no analysis objects" {
            $outPath = Join-Path $TestDrive 'empty.html'
            $warnings = $null
            $result = @() | Export-LPEPermissionAnalysisReport -OutputPath $outPath -WarningVariable warnings -WarningAction SilentlyContinue
            $result | Should -BeNullOrEmpty
            $warnings | Should -Not -BeNullOrEmpty
            $outPath | Should -Not -Exist
        }
    }

    Context "Tenant info lookup" {

        It "Embeds tenant id/name when Graph resolves organization info" {
            Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
                [PSCustomObject]@{ id = 'tenant-guid-123'; displayName = 'Contoso Ltd' }
            } -ParameterFilter { $Path -eq 'organization' }

            $outPath = Join-Path $TestDrive 'tenant.html'
            New-TestAnalysis | Export-LPEPermissionAnalysisReport -OutputPath $outPath | Out-Null

            $html = Get-Content -Raw $outPath
            $html | Should -Match 'tenant-guid-123'
            $html | Should -Match 'Contoso Ltd'
        }

        It "Still generates the report when the organization lookup fails" {
            Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
                throw "not connected"
            } -ParameterFilter { $Path -eq 'organization' }

            $outPath = Join-Path $TestDrive 'no-tenant.html'
            $result = New-TestAnalysis | Export-LPEPermissionAnalysisReport -OutputPath $outPath
            $result | Should -Not -BeNullOrEmpty
            $outPath | Should -Exist
            (Get-LeftoverPlaceholder (Get-Content -Raw $outPath)) | Should -BeNullOrEmpty
        }
    }

    Context "Missing template" {

        It "Errors and writes nothing if the report template can't be found" {
            Mock -ModuleName LeastPrivilegedEntra Test-Path { $false } -ParameterFilter { $Path -like '*data*base.html' }

            $outPath = Join-Path $TestDrive 'missing-template.html'
            $result = New-TestAnalysis | Export-LPEPermissionAnalysisReport -OutputPath $outPath -ErrorAction SilentlyContinue -ErrorVariable err
            $result | Should -BeNullOrEmpty
            $err | Should -Not -BeNullOrEmpty
            $outPath | Should -Not -Exist
        }
    }
}
