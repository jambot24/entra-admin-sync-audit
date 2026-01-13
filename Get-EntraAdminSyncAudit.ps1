<#
.SYNOPSIS
    Enumerate all Entra ID administrator role assignments and report whether each user is synced from on-prem AD.

.DESCRIPTION
    - First checks whether the tenant uses AD Connect / directory sync (Organization.OnPremisesSyncEnabled).
      If not enabled, the script writes a small CSV noting "No AD sync detected" and exits.
    - Enumerates ALL active Entra admin roles (DirectoryRole) and their members.
    - Handles role membership granted via groups by expanding group -> transitive user members.
    - Outputs a timestamped CSV including TenantName + TestTimestamp.
    - Enhanced with error handling, progress indicators, and summary statistics.

.PARAMETER OutputDirectory
    Directory where the CSV report will be saved. Defaults to the current user's Desktop.

.PARAMETER ExportJSON
    Also export results in JSON format alongside CSV.

.EXAMPLE
    .\Get-EntraAdminSyncAudit.ps1
    Runs the audit and saves CSV to Desktop.

.EXAMPLE
    .\Get-EntraAdminSyncAudit.ps1 -OutputDirectory "C:\Reports" -Verbose
    Runs the audit with verbose output and saves to custom directory.

.EXAMPLE
    .\Get-EntraAdminSyncAudit.ps1 -ExportJSON
    Audits admins and exports both CSV and JSON formats.

.NOTES
    Author: PowerShell Admin
    Version: 2.0.0
    Requires: Microsoft.Graph PowerShell SDK
    Last Modified: 2026-01-13

.LINK
    https://github.com/yourusername/entra-admin-sync-audit
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Directory path for output files")]
    [ValidateScript({
        if (-not (Test-Path $_ -PathType Container)) {
            throw "The path '$_' does not exist or is not a directory."
        }
        return $true
    })]
    [string]$OutputDirectory = [Environment]::GetFolderPath('Desktop'),

    [Parameter(Mandatory = $false, HelpMessage = "Export JSON in addition to CSV")]
    [switch]$ExportJSON
)

$ErrorActionPreference = "Stop"

#region Helper Functions

function Write-Info {
    param([string]$Message)
    Write-Output ("[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message)
}

function Get-SafeFileNamePart {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return "UnknownTenant" }
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    foreach ($ch in $invalid) { $Value = $Value.Replace($ch, "_") }
    return ($Value -replace "\s+", "_").Trim("_")
}

function Ensure-GraphModule {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        throw "Microsoft.Graph PowerShell SDK not found. Install with: Install-Module Microsoft.Graph -Scope CurrentUser"
    }
}

function Connect-GraphWithRetry {
    param(
        [string[]]$Scopes,
        [int]$MaxRetries = 3,
        [int]$RetryDelaySeconds = 5
    )

    $attempt = 0
    $connected = $false

    while (-not $connected -and $attempt -lt $MaxRetries) {
        try {
            $attempt++
            Write-Info "Attempting to connect to Microsoft Graph (Attempt $attempt of $MaxRetries)..."

            $ctx = Get-MgContext -ErrorAction SilentlyContinue
            if (-not $ctx -or -not $ctx.Account) {
                Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop | Out-Null
            } else {
                Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop | Out-Null
            }

            $connected = $true
            Write-Info "Successfully connected to Microsoft Graph."

        } catch {
            Write-Warning "Connection attempt $attempt failed: $($_.Exception.Message)"

            if ($attempt -lt $MaxRetries) {
                Write-Info "Waiting $RetryDelaySeconds seconds before retry..."
                Start-Sleep -Seconds $RetryDelaySeconds
            } else {
                throw "Failed to connect to Microsoft Graph after $MaxRetries attempts: $($_.Exception.Message)"
            }
        }
    }
}

function Export-SecureCSV {
    param(
        [Parameter(Mandatory)]
        [object[]]$Data,

        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        # Export to CSV
        $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8

        # Set file permissions to current user only (Windows)
        if ($PSVersionTable.PSVersion.Major -le 5 -or $IsWindows) {
            try {
                $acl = Get-Acl -Path $Path
                $acl.SetAccessRuleProtection($true, $false)

                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $currentUser,
                    'FullControl',
                    'Allow'
                )
                $acl.AddAccessRule($accessRule)
                Set-Acl -Path $Path -AclObject $acl

                Write-Verbose "File permissions set to current user only: $currentUser"
            } catch {
                Write-Warning "Unable to set restrictive file permissions: $($_.Exception.Message)"
            }
        }
    } catch {
        throw "Failed to export CSV: $($_.Exception.Message)"
    }
}

function Write-AuditSummary {
    param([object[]]$Results)

    if ($Results.Count -eq 0) {
        Write-Host "`nNo results to summarize.`n" -ForegroundColor Yellow
        return @{
            TotalAdmins = 0
            SyncedFromOnPrem = 0
            CloudOnlyAdmins = 0
            DisabledAccounts = 0
            TotalRoles = 0
            TotalAssignments = 0
            AssignedViaGroups = 0
            DirectAssignments = 0
        }
    }

    $uniqueAdmins = $Results | Select-Object -Property UserId, UserDisplayName, IsSyncedFromOnPrem, AccountEnabled -Unique

    $summary = @{
        TotalAdmins           = $uniqueAdmins.Count
        SyncedFromOnPrem      = ($uniqueAdmins | Where-Object { $_.IsSyncedFromOnPrem -eq $true }).Count
        CloudOnlyAdmins       = ($uniqueAdmins | Where-Object { $_.IsSyncedFromOnPrem -eq $false }).Count
        DisabledAccounts      = ($uniqueAdmins | Where-Object { $_.AccountEnabled -eq $false }).Count
        TotalRoles            = ($Results | Select-Object -Property RoleName -Unique).Count
        TotalAssignments      = $Results.Count
        AssignedViaGroups     = ($Results | Where-Object { $_.AssignmentSource -eq 'Group' }).Count
        DirectAssignments     = ($Results | Where-Object { $_.AssignmentSource -eq 'Direct' }).Count
    }

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "   Entra ID Admin Audit Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Total Unique Administrators: " -NoNewline -ForegroundColor White
    Write-Host $summary.TotalAdmins -ForegroundColor Yellow
    Write-Host "  - Synced from On-Premises: " -NoNewline -ForegroundColor White
    Write-Host $summary.SyncedFromOnPrem -ForegroundColor Green
    Write-Host "  - Cloud-Only Admins:       " -NoNewline -ForegroundColor White
    Write-Host $summary.CloudOnlyAdmins -ForegroundColor Yellow
    Write-Host "  - Disabled Accounts:       " -NoNewline -ForegroundColor White
    Write-Host $summary.DisabledAccounts -ForegroundColor Red
    Write-Host "`nTotal Active Roles:          " -NoNewline -ForegroundColor White
    Write-Host $summary.TotalRoles -ForegroundColor Yellow
    Write-Host "Total Role Assignments:      " -NoNewline -ForegroundColor White
    Write-Host $summary.TotalAssignments -ForegroundColor Yellow
    Write-Host "  - Direct Assignments:      " -NoNewline -ForegroundColor White
    Write-Host $summary.DirectAssignments -ForegroundColor White
    Write-Host "  - Via Group Membership:    " -NoNewline -ForegroundColor White
    Write-Host $summary.AssignedViaGroups -ForegroundColor White
    Write-Host "========================================`n" -ForegroundColor Cyan

    return $summary
}

function Get-TenantInfoAndSyncState {
    try {
        $org = Get-MgOrganization -All -Property "id,displayName,onPremisesSyncEnabled,onPremisesLastSyncDateTime" -ErrorAction Stop | Select-Object -First 1
        if (-not $org) { throw "Unable to read organization information." }

        return [pscustomobject]@{
            TenantId                   = $org.Id
            TenantName                 = $org.DisplayName
            OnPremisesSyncEnabled      = [bool]$org.OnPremisesSyncEnabled
            OnPremisesLastSyncDateTime = $org.OnPremisesLastSyncDateTime
        }
    } catch {
        throw "Failed to retrieve tenant information: $($_.Exception.Message)"
    }
}

function Get-UserSyncStatus {
    param(
        [Parameter(Mandatory)][string]$UserId
    )

    try {
        $u = Get-MgUser -UserId $UserId -Property @(
            "id","displayName","userPrincipalName",
            "onPremisesSyncEnabled","onPremisesImmutableId","onPremisesSecurityIdentifier",
            "userType","accountEnabled"
        ) -ErrorAction Stop

        $immutablePresent = -not [string]::IsNullOrWhiteSpace($u.OnPremisesImmutableId)
        $sidPresent       = -not [string]::IsNullOrWhiteSpace($u.OnPremisesSecurityIdentifier)

        $synced = $false
        if ($null -ne $u.OnPremisesSyncEnabled) {
            $synced = [bool]$u.OnPremisesSyncEnabled
        } elseif ($immutablePresent -or $sidPresent) {
            $synced = $true
        }

        return [pscustomobject]@{
            UserId                               = $u.Id
            UserDisplayName                      = $u.DisplayName
            UserPrincipalName                    = $u.UserPrincipalName
            UserType                             = $u.UserType
            AccountEnabled                       = $u.AccountEnabled
            OnPremisesSyncEnabled                = $u.OnPremisesSyncEnabled
            OnPremisesImmutableIdPresent         = $immutablePresent
            OnPremisesSecurityIdentifierPresent  = $sidPresent
            IsSyncedFromOnPrem                   = $synced
        }
    } catch {
        Write-Warning "Failed to retrieve user information for $UserId : $($_.Exception.Message)"
        return $null
    }
}

function Get-DirectoryRoles {
    try {
        return Get-MgDirectoryRole -All -Property "id,displayName" -ErrorAction Stop
    } catch {
        throw "Failed to retrieve directory roles: $($_.Exception.Message)"
    }
}

function Get-RoleMembers {
    param(
        [Parameter(Mandatory)][string]$RoleId
    )
    try {
        return Get-MgDirectoryRoleMember -DirectoryRoleId $RoleId -All -ErrorAction Stop
    } catch {
        Write-Warning "Failed to retrieve members for role $RoleId : $($_.Exception.Message)"
        return @()
    }
}

function Expand-GroupToUsersTransitive {
    param(
        [Parameter(Mandatory)][string]$GroupId
    )

    try {
        $members = Get-MgGroupTransitiveMember -GroupId $GroupId -All -ErrorAction Stop
        return $members | Where-Object { $_.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.user" }
    } catch {
        Write-Warning "Failed to expand group $GroupId : $($_.Exception.Message)"
        return @()
    }
}

#endregion

#region Main Script

try {
    Write-Host "`nEntra ID Administrator Sync Audit v2.0" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Verify output directory
    if (-not (Test-Path $OutputDirectory -PathType Container)) {
        throw "Output directory does not exist: $OutputDirectory"
    }
    Write-Info "Output directory: $OutputDirectory"

    Ensure-GraphModule

    $scopes = @(
        "Organization.Read.All",
        "Directory.Read.All",
        "RoleManagement.Read.Directory",
        "User.Read.All",
        "Group.Read.All"
    )

    Connect-GraphWithRetry -Scopes $scopes

    $testTimestamp     = Get-Date
    $testTimestampIso  = $testTimestamp.ToString("yyyy-MM-ddTHH:mm:ss")
    $testTimestampFile = $testTimestamp.ToString("yyyyMMdd-HHmmss")

    Write-Info "Retrieving tenant information..."
    $tenant        = Get-TenantInfoAndSyncState
    $tenantNameSafe = Get-SafeFileNamePart -Value $tenant.TenantName

    $csvPath = Join-Path $OutputDirectory ("EntraAdminSyncReport-{0}-{1}.csv" -f $tenantNameSafe, $testTimestampFile)

    Write-Info ("Tenant: {0} ({1})" -f $tenant.TenantName, $tenant.TenantId)
    Write-Info ("OnPremisesSyncEnabled: {0}" -f $tenant.OnPremisesSyncEnabled)

    if (-not $tenant.OnPremisesSyncEnabled) {
        Write-Info "No AD sync detected for this tenant. Writing minimal CSV and exiting."

        $row = [pscustomobject]@{
            TenantName                         = $tenant.TenantName
            TenantId                           = $tenant.TenantId
            TestTimestamp                      = $testTimestampIso
            OnPremisesSyncEnabled_Tenant       = $tenant.OnPremisesSyncEnabled
            OnPremisesLastSyncDateTime         = $tenant.OnPremisesLastSyncDateTime
            Note                               = "Tenant does not appear to use Entra Connect / directory sync; admin sync test skipped."

            RoleName                           = $null
            RoleId                             = $null
            AssignmentSource                   = $null
            AssignedObjectType                 = $null
            AssignedObjectId                   = $null
            AssignedObjectDisplayName          = $null

            UserPrincipalName                  = $null
            UserId                             = $null
            IsSyncedFromOnPrem                 = $null
            OnPremisesSyncEnabled_User         = $null
            OnPremisesImmutableIdPresent       = $null
            OnPremisesSecurityIdentifierPresent = $null
            UserType                           = $null
            AccountEnabled                     = $null
        }

        Export-SecureCSV -Data @($row) -Path $csvPath
        Write-Host "`nCSV written: " -NoNewline -ForegroundColor Green
        Write-Host $csvPath -ForegroundColor White
        Write-Host ""
        return
    }

    Write-Info "Enumerating directory roles and members..."

    $roles = Get-DirectoryRoles
    if (-not $roles -or $roles.Count -eq 0) {
        Write-Info "No directory roles found (unexpected). Writing empty CSV."
        @() | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "`nCSV written: " -NoNewline -ForegroundColor Green
        Write-Host $csvPath -ForegroundColor White
        Write-Host ""
        return
    }

    $userCache = @{}
    function Get-CachedUserSyncStatus {
        param([string]$UserId)
        if (-not $userCache.ContainsKey($UserId)) {
            $userStatus = Get-UserSyncStatus -UserId $UserId
            if ($userStatus) {
                $userCache[$UserId] = $userStatus
            }
        }
        return $userCache[$UserId]
    }

    $results = New-Object System.Collections.Generic.List[object]
    $roleCount = $roles.Count
    $currentRoleNum = 0

    foreach ($role in $roles) {
        $roleName = $role.DisplayName
        $roleId   = $role.Id

        $currentRoleNum++
        $percentComplete = ($currentRoleNum / $roleCount) * 100

        Write-Progress -Activity "Processing Entra ID Admin Roles" `
                       -Status "Role: $roleName ($currentRoleNum of $roleCount)" `
                       -PercentComplete $percentComplete

        Write-Info ("Role: {0}" -f $roleName)

        $members = Get-RoleMembers -RoleId $roleId
        foreach ($m in $members) {
            $odataType = $m.AdditionalProperties.'@odata.type'

            if ($odataType -eq "#microsoft.graph.user") {
                $u = Get-CachedUserSyncStatus -UserId $m.Id
                if ($u) {
                    $results.Add([pscustomobject]@{
                        TenantName                    = $tenant.TenantName
                        TenantId                      = $tenant.TenantId
                        TestTimestamp                 = $testTimestampIso
                        OnPremisesSyncEnabled_Tenant  = $tenant.OnPremisesSyncEnabled
                        OnPremisesLastSyncDateTime    = $tenant.OnPremisesLastSyncDateTime

                        RoleName                      = $roleName
                        RoleId                        = $roleId

                        AssignmentSource              = "Direct"
                        AssignedObjectType            = "User"
                        AssignedObjectId              = $m.Id
                        AssignedObjectDisplayName     = $u.UserDisplayName

                        UserPrincipalName             = $u.UserPrincipalName
                        UserId                        = $u.UserId
                        IsSyncedFromOnPrem            = $u.IsSyncedFromOnPrem
                        OnPremisesSyncEnabled_User    = $u.OnPremisesSyncEnabled
                        OnPremisesImmutableIdPresent  = $u.OnPremisesImmutableIdPresent
                        OnPremisesSecurityIdentifierPresent = $u.OnPremisesSecurityIdentifierPresent
                        UserType                      = $u.UserType
                        AccountEnabled                = $u.AccountEnabled
                    })
                }
            }
            elseif ($odataType -eq "#microsoft.graph.group") {
                $groupId = $m.Id

                $groupDisplay = $null
                try {
                    $g = Get-MgGroup -GroupId $groupId -Property "displayName" -ErrorAction Stop
                    $groupDisplay = $g.DisplayName
                } catch {
                    $groupDisplay = $null
                }

                $groupDisplayForLog = $groupDisplay
                if ([string]::IsNullOrWhiteSpace($groupDisplayForLog)) { $groupDisplayForLog = "UnknownGroup" }

                Write-Info ("  Expanding group: {0} ({1})" -f $groupDisplayForLog, $groupId)

                $groupUsers = Expand-GroupToUsersTransitive -GroupId $groupId
                foreach ($gu in $groupUsers) {
                    $u = Get-CachedUserSyncStatus -UserId $gu.Id
                    if ($u) {
                        $results.Add([pscustomobject]@{
                            TenantName                    = $tenant.TenantName
                            TenantId                      = $tenant.TenantId
                            TestTimestamp                 = $testTimestampIso
                            OnPremisesSyncEnabled_Tenant  = $tenant.OnPremisesSyncEnabled
                            OnPremisesLastSyncDateTime    = $tenant.OnPremisesLastSyncDateTime

                            RoleName                      = $roleName
                            RoleId                        = $roleId

                            AssignmentSource              = "Group"
                            AssignedObjectType            = "Group"
                            AssignedObjectId              = $groupId
                            AssignedObjectDisplayName     = $groupDisplay

                            UserPrincipalName             = $u.UserPrincipalName
                            UserId                        = $u.UserId
                            IsSyncedFromOnPrem            = $u.IsSyncedFromOnPrem
                            OnPremisesSyncEnabled_User    = $u.OnPremisesSyncEnabled
                            OnPremisesImmutableIdPresent  = $u.OnPremisesImmutableIdPresent
                            OnPremisesSecurityIdentifierPresent = $u.OnPremisesSecurityIdentifierPresent
                            UserType                      = $u.UserType
                            AccountEnabled                = $u.AccountEnabled
                        })
                    }
                }
            }
            elseif ($odataType -eq "#microsoft.graph.servicePrincipal") {
                $spDisplay = $m.AdditionalProperties.displayName

                $results.Add([pscustomobject]@{
                    TenantName                    = $tenant.TenantName
                    TenantId                      = $tenant.TenantId
                    TestTimestamp                 = $testTimestampIso
                    OnPremisesSyncEnabled_Tenant  = $tenant.OnPremisesSyncEnabled
                    OnPremisesLastSyncDateTime    = $tenant.OnPremisesLastSyncDateTime

                    RoleName                      = $roleName
                    RoleId                        = $roleId

                    AssignmentSource              = "Direct"
                    AssignedObjectType            = "ServicePrincipal"
                    AssignedObjectId              = $m.Id
                    AssignedObjectDisplayName     = $spDisplay

                    UserPrincipalName             = $null
                    UserId                        = $null
                    IsSyncedFromOnPrem            = $null
                    OnPremisesSyncEnabled_User    = $null
                    OnPremisesImmutableIdPresent  = $null
                    OnPremisesSecurityIdentifierPresent = $null
                    UserType                      = $null
                    AccountEnabled                = $null
                })
            }
            else {
                $results.Add([pscustomobject]@{
                    TenantName                    = $tenant.TenantName
                    TenantId                      = $tenant.TenantId
                    TestTimestamp                 = $testTimestampIso
                    OnPremisesSyncEnabled_Tenant  = $tenant.OnPremisesSyncEnabled
                    OnPremisesLastSyncDateTime    = $tenant.OnPremisesLastSyncDateTime

                    RoleName                      = $roleName
                    RoleId                        = $roleId

                    AssignmentSource              = "Direct"
                    AssignedObjectType            = $odataType
                    AssignedObjectId              = $m.Id
                    AssignedObjectDisplayName     = $null

                    UserPrincipalName             = $null
                    UserId                        = $null
                    IsSyncedFromOnPrem            = $null
                    OnPremisesSyncEnabled_User    = $null
                    OnPremisesImmutableIdPresent  = $null
                    OnPremisesSecurityIdentifierPresent = $null
                    UserType                      = $null
                    AccountEnabled                = $null
                })
            }
        }
    }

    Write-Progress -Activity "Processing Entra ID Admin Roles" -Completed

    # Display summary
    $summary = Write-AuditSummary -Results $results

    Write-Info ("Writing CSV ({0} rows)..." -f $results.Count)
    Export-SecureCSV -Data $results -Path $csvPath
    Write-Host "CSV written: " -NoNewline -ForegroundColor Green
    Write-Host $csvPath -ForegroundColor White

    # Export JSON if requested
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputDirectory ("EntraAdminSyncReport-{0}-{1}.json" -f $tenantNameSafe, $testTimestampFile)
        $exportData = @{
            Metadata = @{
                TenantName = $tenant.TenantName
                TenantId = $tenant.TenantId
                TestTimestamp = $testTimestampIso
                OnPremisesSyncEnabled = $tenant.OnPremisesSyncEnabled
                OnPremisesLastSyncDateTime = $tenant.OnPremisesLastSyncDateTime
                ScriptVersion = '2.0.0'
            }
            Summary = $summary
            Results = $results
        }
        $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Host "JSON written: " -NoNewline -ForegroundColor Green
        Write-Host $jsonPath -ForegroundColor White
    }

    Write-Info ("Unique users queried: {0}" -f $userCache.Count)
    Write-Host "`nAudit completed successfully!`n" -ForegroundColor Green

} catch {
    Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red

    # Log error to file
    $errorLogPath = Join-Path $OutputDirectory "EntraAdminAudit_Error_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    $errorDetails = @"
Error occurred at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Error Message: $($_.Exception.Message)
Error Type: $($_.Exception.GetType().FullName)
Stack Trace:
$($_.ScriptStackTrace)
"@
    $errorDetails | Out-File -FilePath $errorLogPath -Encoding UTF8
    Write-Host "`nError details logged to: $errorLogPath`n" -ForegroundColor Yellow

    exit 1
} finally {
    # Cleanup - disconnect from Graph
    if (Get-MgContext -ErrorAction SilentlyContinue) {
        Write-Verbose "Disconnecting from Microsoft Graph..."
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}

#endregion
