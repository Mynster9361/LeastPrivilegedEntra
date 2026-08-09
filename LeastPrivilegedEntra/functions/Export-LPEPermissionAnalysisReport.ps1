#Requires -Modules EntraAuth

function Export-LPEPermissionAnalysisReport {
    <#
    .SYNOPSIS
        Generates a self-contained interactive HTML report from Get-LPEPermissionAnalysis output.
    .DESCRIPTION
        Renders the per-user, per-role usage analysis produced by Get-LPEPermissionAnalysis into a single,
        offline-capable HTML file: a sortable/filterable user table, per-role usage detail (including the
        RelatedActivities drill-down), and the RemoveRoles/KeepRoles/AddRoles/DeniedAttempts suggestions, with a
        dark/light mode toggle and CSV export built in.

        The report itself is a static template (LeastPrivilegedEntra/data/base.html) built from the React project
        under report/ - see report/README.md for the build process. This function only injects data into it; it
        does not require Node.js or any of the report's build tooling at runtime.

        If connected to Graph (Connect-EntraService -Service Graph), tenant ID and display name are looked up and
        included in the report header; this is best-effort and the report still generates without it.
    .PARAMETER Analysis
        One or more analysis objects as returned by Get-LPEPermissionAnalysis. Accepts pipeline input.
    .PARAMETER OutputPath
        Path to write the HTML report to. Defaults to ".\PrivilegedUsersAnalysisReport.html".
    .PARAMETER ReportTitle
        Title shown in the report header and browser tab. Defaults to "Least Privileged Entra Report".
    .EXAMPLE
        $analysis = Get-LPEPermissionAnalysis -PrivilegedUser $privilegedUsers -ActivityLog $activityLog
        Export-LPEPermissionAnalysisReport -Analysis $analysis

        Writes PrivilegedUsersAnalysisReport.html in the current directory.
    .EXAMPLE
        Invoke-LPEScan -TenantId $tenantId -ClientId $appId -ClientSecret $secret -WorkspaceId $workspaceId |
            Export-LPEPermissionAnalysisReport -OutputPath ".\reports\contoso.html" -ReportTitle "Contoso - Privileged Role Review"

        Runs a full scan and pipes the result straight into a titled report.
    .OUTPUTS
        String. The full path to the generated HTML report.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]$Analysis,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\PrivilegedUsersAnalysisReport.html",

        [Parameter(Mandatory = $false)]
        [string]$ReportTitle = "Least Privileged Entra Report"
    )

    begin {
        $allAnalysis = [System.Collections.Generic.List[object]]::new()
    }

    process {
        foreach ($item in $Analysis) { $allAnalysis.Add($item) }
    }

    end {
        if ($allAnalysis.Count -eq 0) {
            Write-Warning "No analysis objects were provided; nothing to report."
            return
        }

        $templatePath = Join-Path -Path $script:ModuleRoot -ChildPath 'data/base.html'
        if (-not (Test-Path -Path $templatePath)) {
            Write-Error "Report template not found at '$templatePath'. Rebuild it from the 'report' folder (see report/README.md)."
            return
        }
        $html = Get-Content -Path $templatePath -Raw

        $tenantId = ''
        $tenantName = ''
        try {
            $organization = Invoke-EntraRequest -Path 'organization' -ErrorAction Stop | Select-Object -First 1
            if ($organization) {
                $tenantId = $organization.id
                $tenantName = $organization.displayName
            }
        } catch {
            Write-Verbose "Could not resolve tenant information for the report header: $($_.Exception.Message)"
        }

        Write-Verbose -Message "Rendering report for $($allAnalysis.Count) user(s) to $OutputPath"

        $jsonData = @($allAnalysis) | ConvertTo-Json -Depth 10 -Compress
        $jsonData = $jsonData.Replace('\', '\\').Replace('"', '\"').Replace([Environment]::NewLine, '\n')

        $html = $html.Replace('{% block app_data %}{% endblock %}', $jsonData)
        $html = $html.Replace('{% block title %}{% endblock %}', $ReportTitle)
        $html = $html.Replace('{% block tenant_id %}{% endblock %}', $tenantId)
        $html = $html.Replace('{% block tenant_name %}{% endblock %}', $tenantName)
        $html = $html.Replace('{% block generated_on %}{% endblock %}', (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

        $resolvedPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($OutputPath)
        $html | Out-File -FilePath $resolvedPath -Encoding UTF8

        $resolvedPath
    }
}
