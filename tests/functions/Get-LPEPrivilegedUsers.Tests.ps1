Describe "Get-LPEPrivilegedUser" {

	BeforeAll {
		$script:oneRole = [PSCustomObject]@{ id = 'role-1'; displayName = 'Global Administrator' }

		Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
			$oneRole
		} -ParameterFilter { $Path -eq 'roleManagement/directory/roleDefinitions' }
	}

	Context "Direct role assignment (PIM available)" {

		BeforeAll {
			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				# PIM probe succeeds
			} -ParameterFilter { $Path -eq 'roleManagement/directory/roleAssignmentScheduleInstances' -and $Query.ContainsKey('$top') }

			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				[PSCustomObject]@{
					principal = [PSCustomObject]@{
						'@odata.type'     = '#microsoft.graph.user'
						id                = 'user-1'
						displayName       = 'Alice Admin'
						userPrincipalName = 'alice@contoso.com'
					}
				}
			} -ParameterFilter { $Path -eq 'roleManagement/directory/roleAssignmentScheduleInstances' -and $Query.ContainsKey('$filter') }

			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				# no eligible assignments
			} -ParameterFilter { $Path -eq 'roleManagement/directory/roleEligibilityScheduleInstances' }
		}

		It "Returns the directly assigned user with no ViaGroup" {
			$result = Get-LPEPrivilegedUser
			$result | Should -HaveCount 1
			$result.DisplayName | Should -Be 'Alice Admin'
			$result.UserPrincipalName | Should -Be 'alice@contoso.com'
			$result.Roles | Should -HaveCount 1
			$result.Roles[0].RoleName | Should -Be 'Global Administrator'
			$result.Roles[0].AssignmentType | Should -Be 'Active'
			$result.Roles[0].ViaGroup | Should -BeNullOrEmpty
		}
	}

	Context "Role-assignable group expansion (PIM available)" {

		BeforeAll {
			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				# PIM probe succeeds
			} -ParameterFilter { $Path -eq 'roleManagement/directory/roleAssignmentScheduleInstances' -and $Query.ContainsKey('$top') }

			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				[PSCustomObject]@{
					principal = [PSCustomObject]@{
						'@odata.type' = '#microsoft.graph.group'
						id            = 'group-1'
						displayName   = 'Global Administrators'
					}
				}
			} -ParameterFilter { $Path -eq 'roleManagement/directory/roleAssignmentScheduleInstances' -and $Query.ContainsKey('$filter') }

			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				# no eligible assignments
			} -ParameterFilter { $Path -eq 'roleManagement/directory/roleEligibilityScheduleInstances' }

			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				@(
					[PSCustomObject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'user-2'; displayName = 'Bob Member'; userPrincipalName = 'bob@contoso.com' }
					[PSCustomObject]@{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = 'sp-1'; displayName = 'Some App' }
				)
			} -ParameterFilter { $Path -like 'groups/*/members' }
		}

		It "Expands group members, tagging them with ViaGroup, and skips non-user members" {
			$result = Get-LPEPrivilegedUser
			$result | Should -HaveCount 1
			$result.DisplayName | Should -Be 'Bob Member'
			$result.Roles[0].ViaGroup | Should -Be 'Global Administrators'
		}
	}

	Context "PIM unavailable" {

		BeforeAll {
			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				throw "PIM not available in this tenant"
			} -ParameterFilter { $Path -eq 'roleManagement/directory/roleAssignmentScheduleInstances' -and $Query.ContainsKey('$top') }

			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				[PSCustomObject]@{
					principal = [PSCustomObject]@{
						'@odata.type'     = '#microsoft.graph.user'
						id                = 'user-3'
						displayName       = 'Carol Legacy'
						userPrincipalName = 'carol@contoso.com'
					}
				}
			} -ParameterFilter { $Path -eq 'roleManagement/directory/roleAssignments' }
		}

		It "Falls back to the legacy roleAssignments endpoint" {
			$result = Get-LPEPrivilegedUser
			$result | Should -HaveCount 1
			$result.DisplayName | Should -Be 'Carol Legacy'
			Should -Invoke -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -ParameterFilter { $Path -eq 'roleManagement/directory/roleAssignments' } -Times 1
			Should -Invoke -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -ParameterFilter { $Path -eq 'roleManagement/directory/roleEligibilityScheduleInstances' } -Times 0
		}
	}

	Context "Orphaned role-assignable group" {

		BeforeAll {
			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				# PIM probe succeeds
			} -ParameterFilter { $Path -eq 'roleManagement/directory/roleAssignmentScheduleInstances' -and $Query.ContainsKey('$top') }

			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				[PSCustomObject]@{
					principal = [PSCustomObject]@{
						'@odata.type' = '#microsoft.graph.group'
						id            = 'deleted-group'
						displayName   = 'Ghost Admins'
					}
				}
			} -ParameterFilter { $Path -eq 'roleManagement/directory/roleAssignmentScheduleInstances' -and $Query.ContainsKey('$filter') }

			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				# no eligible assignments
			} -ParameterFilter { $Path -eq 'roleManagement/directory/roleEligibilityScheduleInstances' }

			Mock -ModuleName LeastPrivilegedEntra Invoke-EntraRequest -RemoveParameterValidation Service -RemoveParameterType Token {
				throw "Resource 'deleted-group' does not exist"
			} -ParameterFilter { $Path -like 'groups/*/members' }
		}

		It "Skips the assignment and warns instead of throwing" {
			$warnings = $null
			$result = Get-LPEPrivilegedUser -WarningVariable warnings -WarningAction SilentlyContinue
			$result | Should -BeNullOrEmpty
			$warnings | Should -Not -BeNullOrEmpty
			$warnings.Message | Should -Match 'Ghost Admins'
		}
	}
}
