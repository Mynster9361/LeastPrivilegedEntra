Describe "Get-LPELogActivityData" {

	BeforeAll {
		function New-LogAnalyticsResponse {
			param([object[]]$Rows)
			[PSCustomObject]@{
				tables = @(
					[PSCustomObject]@{
						columns = @(
							@{ name = 'UserId' }, @{ name = 'UserDisplayName' }, @{ name = 'UserPrincipalName' },
							@{ name = 'Category' }, @{ name = 'DisplayName' },
							@{ name = 'LastActivityTime' }, @{ name = 'FirstActivityTime' }, @{ name = 'LastAttemptTime' },
							@{ name = 'ActivityCount' }, @{ name = 'FailureCount' }
						)
						rows    = $Rows
					}
				)
			}
		}
	}

	Context "No relevant activities defined" {

		BeforeAll {
			Mock -ModuleName LeastPrivilegedEntra Get-LPEActivityData {
				[PSCustomObject]@{ Category = 'UserManagement'; DisplayName = 'Read user'; Relevant = $false }
			}
			# Staged only so "Should -Invoke -Times 0" below has a mock table entry to check against.
			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {}
		}

		It "Errors and returns nothing rather than querying" {
			$result = Get-LPELogActivityData -WorkspaceId 'ws-1' -ErrorAction SilentlyContinue -ErrorVariable err
			$result | Should -BeNullOrEmpty
			$err | Should -Not -BeNullOrEmpty
			Should -Invoke -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -Times 0
		}
	}

	Context "With relevant activities defined" {

		BeforeAll {
			Mock -ModuleName LeastPrivilegedEntra Get-LPEActivityData {
				[PSCustomObject]@{ Category = 'UserManagement'; DisplayName = 'Update user'; Relevant = $true }
			}
		}

		It "Parses a successful activity row into the expected shape" {
			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				New-LogAnalyticsResponse -Rows @(
					, @('user-1', 'Alice Admin', 'alice@contoso.com', 'UserManagement', 'Update user', '2026-01-01T00:00:00Z', '2025-12-01T00:00:00Z', '2026-01-01T00:00:00Z', 3, 1)
				)
			}

			$result = Get-LPELogActivityData -WorkspaceId 'ws-1'
			$result | Should -HaveCount 1
			$result.Id | Should -Be 'user-1'
			$result.DisplayName | Should -Be 'Alice Admin'
			$result.Activities | Should -HaveCount 1

			$activity = $result.Activities[0]
			$activity.Category | Should -Be 'UserManagement'
			$activity.ActivityCount | Should -Be 3
			$activity.FailureCount | Should -Be 1
			$activity.LastActivityTime | Should -BeOfType [datetime]
			$activity.LastAttemptTime | Should -BeOfType [datetime]
		}

		It "Leaves LastActivityTime/FirstActivityTime null for a denied-only activity" {
			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				New-LogAnalyticsResponse -Rows @(
					, @('user-2', 'Bob Denied', 'bob@contoso.com', 'UserManagement', 'Update user', $null, $null, '2026-01-01T00:00:00Z', 0, 4)
				)
			}

			$result = Get-LPELogActivityData -WorkspaceId 'ws-1' -IncludeFailures
			$activity = $result.Activities[0]
			$activity.ActivityCount | Should -Be 0
			$activity.FailureCount | Should -Be 4
			$activity.LastActivityTime | Should -BeNullOrEmpty
			$activity.LastAttemptTime | Should -BeOfType [datetime]
		}

		It "Returns nothing when the query yields no rows" {
			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				New-LogAnalyticsResponse -Rows @()
			}

			$result = Get-LPELogActivityData -WorkspaceId 'ws-1'
			$result | Should -BeNullOrEmpty
		}

		It "Filters out denied-only activities by default" {
			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				New-LogAnalyticsResponse -Rows @()
			}

			Get-LPELogActivityData -WorkspaceId 'ws-1' | Out-Null

			Should -Invoke -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -ParameterFilter {
				$Body.query -match '\|\s*where ActivityCount > 0'
			} -Times 1
		}

		It "Does not filter out denied-only activities when -IncludeFailures is passed" {
			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				New-LogAnalyticsResponse -Rows @()
			}

			Get-LPELogActivityData -WorkspaceId 'ws-1' -IncludeFailures | Out-Null

			Should -Invoke -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -ParameterFilter {
				$Body.query -notmatch '\|\s*where ActivityCount > 0'
			} -Times 1
		}

		It "Includes a UserId filter in the query when -UserId is passed" {
			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				New-LogAnalyticsResponse -Rows @()
			}

			Get-LPELogActivityData -WorkspaceId 'ws-1' -UserId 'user-1', 'user-2' | Out-Null

			Should -Invoke -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -ParameterFilter {
				$Body.query -match 'where UserId in \("user-1","user-2"\)'
			} -Times 1
		}

		It "Writes an error and returns nothing when the query fails" {
			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				throw "workspace unreachable"
			}

			$result = Get-LPELogActivityData -WorkspaceId 'ws-1' -ErrorAction SilentlyContinue -ErrorVariable err
			$result | Should -BeNullOrEmpty
			$err | Should -Not -BeNullOrEmpty
		}
	}
}
