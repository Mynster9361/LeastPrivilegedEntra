# Changelog for LeastPrivilegedEntra

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Links to documentation site
- Credits on Get-LPEPrivilegedUser
- Added `Export-LPEPermissionAnalysisReport` - renders `Get-LPEPermissionAnalysis` output into a single self-contained, offline-capable HTML report (sortable/filterable user table, per-role RelatedActivities drill-down, RemoveRoles/AddRoles/DeniedAttempts suggestions, dark mode, CSV export). The report template is built from a Vite + React + TypeScript + TanStack Table project under `report/` (see `report/README.md`); the function itself only injects data into the pre-built template and has no Node.js dependency at runtime
- `Invoke-LPEScan` gained `-OutHtml` and `-ReportTitle` parameters to generate the HTML report automatically as part of a scan, alongside the existing `-OutFile` JSON export
- Added a Pester test suite for `Export-LPEPermissionAnalysisReport`
- The HTML report's user detail view now shows the audit-log evidence (Category, DisplayName, permission, count, last seen/attempted) behind every `AddRoles`/`DeniedAttempts` suggestion, expandable per role, instead of just the bare role name

### Changed
- BREAKING CHANGE: `Get-LPEPermissionAnalysis`'s `Suggestion.AddRoles` and `Suggestion.DeniedAttempts` are no longer `string[]` of role names - each entry is now an object (`RoleName` plus an `Activities` list carrying the Category/DisplayName/LeastPrivilegedMSGraph/count/timestamp evidence behind the suggestion) so the "why" is available programmatically instead of only in the `RemoveRoles`/`KeepRoles` role-name lists

## [1.0.0] - 2026-08-07

### Added
- Added `Invoke-LPEScan` - the main entry-point cmdlet wrapping the full workflow: connect to the tenant, enumerate privileged users, pull their audit log activity, and produce the per-user role usage analysis. Supports `-SkipConnect` to reuse an existing EntraAuth connection and `-OutFile` to export the result as JSON
- `Invoke-LPEScan` reports progress via `Write-Progress` across each stage of the scan (connecting, enumerating privileged users, querying audit logs, analyzing, writing output)
- `Get-LPELogActivityData` now returns `FailureCount` and `LastAttemptTime` alongside `ActivityCount`/`LastActivityTime`/`FirstActivityTime`, splitting successful occurrences from failed/denied ones instead of merging or excluding them
- `Get-LPEPermissionAnalysis` now returns a `Suggestion.DeniedAttempts` list - roles a user doesn't hold but repeatedly attempted (and was denied) actions requiring, populated only when `ActivityLog` was collected with `Get-LPELogActivityData -IncludeFailures`
- Added a Pester test suite (`tests/functions/*.Tests.ps1`) covering `Get-LPEActivityData`, `Get-LPEPrivilegedUser`, `Get-LPELogActivityData`, `Get-LPEPermissionAnalysis`, and `Invoke-LPEScan`

### Changed
- `Get-LPEPrivilegedUser` now requests `id,displayName,userPrincipalName` via `$select` when expanding role-assignable group membership, and documents that `User.ReadBasic.All` (in addition to `RoleManagement.Read.Directory` and `GroupMember.Read.All`) is required for those fields to actually populate for group-sourced members
- `Get-LPELogActivityData`'s `-IncludeFailures` switch now means "also include activities that were attempted but never succeeded", rather than merging failed attempts into the success count

### Removed
- Removed the standalone top-level scripts (`Get-ActivityData.ps1`, `Get-PrivilegedUsers.ps1`, `Get-LogActivityData.ps1`, `Get-PermissionAnalysis.ps1`) now that their functionality lives in the `LeastPrivilegedEntra` module as `Get-LPEActivityData`, `Get-LPEPrivilegedUser`, `Get-LPELogActivityData`, and `Get-LPEPermissionAnalysis`

### Fixed
- `Get-LPEPrivilegedUser` no longer fails the entire scan when a role assignment/eligibility record references a role-assignable group that no longer exists (e.g. a deleted group); the assignment is now skipped with a warning naming the role and group instead
- `Get-LPEPermissionAnalysis` no longer marks a role as `Used`, or suggests adding it via `AddRoles`, based solely on a denied/failed activity attempt

[Unreleased]: https://github.com/Mynster9361/LeastPrivilegedEntra/commits/main