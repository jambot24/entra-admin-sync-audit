# Usage Examples

This document provides practical examples for using the Entra ID Admin Sync Audit script.

## Table of Contents

- [Basic Usage](#basic-usage)
- [Advanced Usage](#advanced-usage)
- [Filtering and Analysis](#filtering-and-analysis)
- [Automation and Scheduling](#automation-and-scheduling)
- [Integration Examples](#integration-examples)

## Basic Usage

### Example 1: Run Basic Audit

```powershell
# Run the audit with default settings (saves to Desktop)
.\Get-EntraAdminSyncAudit.ps1
```

**Output:**
- CSV file saved to Desktop
- Console summary displayed

### Example 2: Custom Output Directory

```powershell
# Save reports to a specific directory
.\Get-EntraAdminSyncAudit.ps1 -OutputDirectory "C:\AuditReports"
```

### Example 3: Export Multiple Formats

```powershell
# Export both CSV and JSON
.\Get-EntraAdminSyncAudit.ps1 -ExportJSON
```

### Example 4: Verbose Output

```powershell
# Run with detailed logging
.\Get-EntraAdminSyncAudit.ps1 -Verbose
```

## Advanced Usage

### Example 5: Scheduled Audit

```powershell
# Create a scheduled task to run weekly audits
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Get-EntraAdminSyncAudit.ps1" -OutputDirectory "C:\AuditReports"'

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 9am

$principal = New-ScheduledTaskPrincipal -UserId "DOMAIN\AdminUser" `
    -LogonType S4U -RunLevel Highest

Register-ScheduledTask -TaskName "EntraAdminAudit" `
    -Action $action -Trigger $trigger -Principal $principal `
    -Description "Weekly Entra ID admin role audit"
```

### Example 6: Error Handling with Logging

```powershell
# Run with comprehensive error logging
try {
    .\Get-EntraAdminSyncAudit.ps1 -OutputDirectory "C:\AuditReports" -Verbose -ErrorAction Stop
    Write-Host "Audit completed successfully" -ForegroundColor Green
} catch {
    Write-Host "Audit failed: $($_.Exception.Message)" -ForegroundColor Red
    $_ | Out-File "C:\AuditReports\audit_failure_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
}
```

### Example 7: Multiple Tenants

```powershell
# Audit multiple tenants (disconnect between each)
$tenants = @("tenant1.onmicrosoft.com", "tenant2.onmicrosoft.com")

foreach ($tenant in $tenants) {
    Write-Host "Auditing tenant: $tenant" -ForegroundColor Cyan

    # Connect to specific tenant
    Connect-MgGraph -TenantId $tenant -Scopes @(
        "Organization.Read.All",
        "Directory.Read.All",
        "RoleManagement.Read.Directory",
        "User.Read.All",
        "Group.Read.All"
    )

    # Run audit
    .\Get-EntraAdminSyncAudit.ps1 -OutputDirectory "C:\AuditReports\$tenant"

    # Disconnect
    Disconnect-MgGraph
}
```

## Filtering and Analysis

### Example 8: Find Cloud-Only Admins

```powershell
# Run audit and analyze cloud-only admins
.\Get-EntraAdminSyncAudit.ps1

# Import and filter results
$report = Import-Csv "C:\Users\kevin\Desktop\EntraAdminSyncReport-*.csv" |
    Sort-Object -Property Name |
    Select-Object -First 1

$cloudOnlyAdmins = $report | Where-Object { $_.IsSyncedFromOnPrem -eq $false }

Write-Host "Cloud-Only Administrators:" -ForegroundColor Yellow
$cloudOnlyAdmins | Select-Object UserPrincipalName, RoleName, AccountEnabled | Format-Table -AutoSize
```

### Example 9: Find Disabled Admin Accounts

```powershell
# Identify disabled accounts with admin roles
.\Get-EntraAdminSyncAudit.ps1

$report = Import-Csv "C:\Users\kevin\Desktop\EntraAdminSyncReport-*.csv" |
    Sort-Object -Property Name |
    Select-Object -First 1

$disabledAdmins = $report | Where-Object { $_.AccountEnabled -eq $false }

if ($disabledAdmins.Count -gt 0) {
    Write-Host "WARNING: Found $($disabledAdmins.Count) disabled admin accounts!" -ForegroundColor Red
    $disabledAdmins | Select-Object UserPrincipalName, RoleName | Format-Table -AutoSize
}
```

### Example 10: Group-Based Role Assignments

```powershell
# Find all admins assigned via groups
.\Get-EntraAdminSyncAudit.ps1

$report = Import-Csv "C:\Users\kevin\Desktop\EntraAdminSyncReport-*.csv" |
    Sort-Object -Property Name |
    Select-Object -First 1

$groupAssignments = $report | Where-Object { $_.AssignmentSource -eq "Group" }

Write-Host "Administrators assigned via groups:" -ForegroundColor Cyan
$groupAssignments |
    Select-Object UserPrincipalName, RoleName, AssignedObjectDisplayName |
    Sort-Object AssignedObjectDisplayName |
    Format-Table -AutoSize
```

### Example 11: Role Distribution Analysis

```powershell
# Analyze role distribution
.\Get-EntraAdminSyncAudit.ps1

$report = Import-Csv "C:\Users\kevin\Desktop\EntraAdminSyncReport-*.csv" |
    Sort-Object -Property Name |
    Select-Object -First 1

$roleStats = $report |
    Group-Object RoleName |
    Select-Object Name, Count |
    Sort-Object Count -Descending

Write-Host "`nRole Assignment Distribution:" -ForegroundColor Cyan
$roleStats | Format-Table -AutoSize

# Find overprivileged users (multiple roles)
$userRoleCounts = $report |
    Group-Object UserId |
    Where-Object { $_.Count -gt 3 } |
    ForEach-Object {
        $userId = $_.Name
        $userInfo = $report | Where-Object { $_.UserId -eq $userId } | Select-Object -First 1
        [PSCustomObject]@{
            UserPrincipalName = $userInfo.UserPrincipalName
            RoleCount = $_.Count
            Roles = ($report | Where-Object { $_.UserId -eq $userId } | Select-Object -Unique RoleName).RoleName -join ", "
        }
    }

if ($userRoleCounts) {
    Write-Host "`nUsers with 4+ admin roles:" -ForegroundColor Yellow
    $userRoleCounts | Format-Table -AutoSize -Wrap
}
```

### Example 12: Sync Status Summary

```powershell
# Generate sync status summary
.\Get-EntraAdminSyncAudit.ps1

$report = Import-Csv "C:\Users\kevin\Desktop\EntraAdminSyncReport-*.csv" |
    Sort-Object -Property Name |
    Select-Object -First 1

$uniqueUsers = $report |
    Select-Object UserId, UserPrincipalName, IsSyncedFromOnPrem, AccountEnabled -Unique

$summary = [PSCustomObject]@{
    TotalAdmins = $uniqueUsers.Count
    SyncedAdmins = ($uniqueUsers | Where-Object { $_.IsSyncedFromOnPrem -eq $true }).Count
    CloudOnlyAdmins = ($uniqueUsers | Where-Object { $_.IsSyncedFromOnPrem -eq $false }).Count
    EnabledAdmins = ($uniqueUsers | Where-Object { $_.AccountEnabled -eq $true }).Count
    DisabledAdmins = ($uniqueUsers | Where-Object { $_.AccountEnabled -eq $false }).Count
    SyncPercentage = [math]::Round((($uniqueUsers | Where-Object { $_.IsSyncedFromOnPrem -eq $true }).Count / $uniqueUsers.Count) * 100, 2)
}

Write-Host "`n=== Admin Sync Status Summary ===" -ForegroundColor Cyan
$summary | Format-List
```

## Automation and Scheduling

### Example 13: Email Report After Audit

```powershell
# Run audit and email the report
.\Get-EntraAdminSyncAudit.ps1 -OutputDirectory "C:\AuditReports"

$latestReport = Get-ChildItem "C:\AuditReports\EntraAdminSyncReport-*.csv" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

$mailParams = @{
    From = "audits@contoso.com"
    To = "security-team@contoso.com"
    Subject = "Entra ID Admin Audit Report - $(Get-Date -Format 'yyyy-MM-dd')"
    Body = "Please find attached the latest Entra ID administrator audit report."
    SmtpServer = "smtp.contoso.com"
    Attachments = $latestReport.FullName
}

Send-MailMessage @mailParams
```

### Example 14: Compare with Previous Audit

```powershell
# Run audit and compare with previous run
.\Get-EntraAdminSyncAudit.ps1 -OutputDirectory "C:\AuditReports"

$reports = Get-ChildItem "C:\AuditReports\EntraAdminSyncReport-*.csv" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 2

if ($reports.Count -eq 2) {
    $current = Import-Csv $reports[0].FullName
    $previous = Import-Csv $reports[1].FullName

    $currentAdmins = $current | Select-Object -ExpandProperty UserPrincipalName -Unique
    $previousAdmins = $previous | Select-Object -ExpandProperty UserPrincipalName -Unique

    $newAdmins = $currentAdmins | Where-Object { $_ -notin $previousAdmins }
    $removedAdmins = $previousAdmins | Where-Object { $_ -notin $currentAdmins }

    if ($newAdmins) {
        Write-Host "`nNew Administrators:" -ForegroundColor Green
        $newAdmins | ForEach-Object { Write-Host "  + $_" -ForegroundColor Green }
    }

    if ($removedAdmins) {
        Write-Host "`nRemoved Administrators:" -ForegroundColor Red
        $removedAdmins | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    }

    if (-not $newAdmins -and -not $removedAdmins) {
        Write-Host "`nNo changes in admin membership" -ForegroundColor Cyan
    }
}
```

### Example 15: Archive Old Reports

```powershell
# Run audit and archive reports older than 90 days
.\Get-EntraAdminSyncAudit.ps1 -OutputDirectory "C:\AuditReports"

$archivePath = "C:\AuditReports\Archive"
if (-not (Test-Path $archivePath)) {
    New-Item -ItemType Directory -Path $archivePath | Out-Null
}

$cutoffDate = (Get-Date).AddDays(-90)
Get-ChildItem "C:\AuditReports\EntraAdminSyncReport-*.csv" |
    Where-Object { $_.LastWriteTime -lt $cutoffDate } |
    ForEach-Object {
        Move-Item $_.FullName -Destination $archivePath
        Write-Host "Archived: $($_.Name)" -ForegroundColor Yellow
    }
```

## Integration Examples

### Example 16: Export to Azure Storage

```powershell
# Run audit and upload to Azure Blob Storage
.\Get-EntraAdminSyncAudit.ps1 -OutputDirectory "C:\Temp"

# Install Azure PowerShell module if needed
# Install-Module Az.Storage -Scope CurrentUser

$latestReport = Get-ChildItem "C:\Temp\EntraAdminSyncReport-*.csv" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

$storageAccount = "yourstorageaccount"
$containerName = "audit-reports"
$resourceGroup = "YourResourceGroup"

# Upload to Azure Blob Storage
$ctx = New-AzStorageContext -StorageAccountName $storageAccount -UseConnectedAccount
Set-AzStorageBlobContent -File $latestReport.FullName `
    -Container $containerName `
    -Blob $latestReport.Name `
    -Context $ctx `
    -Force

Write-Host "Report uploaded to Azure Storage" -ForegroundColor Green
```

### Example 17: Integration with SIEM

```powershell
# Run audit and format for SIEM ingestion
.\Get-EntraAdminSyncAudit.ps1 -ExportJSON -OutputDirectory "C:\SIEM\Input"

$latestReport = Get-ChildItem "C:\SIEM\Input\EntraAdminSyncReport-*.json" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

$data = Get-Content $latestReport.FullName | ConvertFrom-Json

# Format for SIEM (example: Splunk HEC format)
foreach ($result in $data.Results) {
    $event = @{
        time = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        source = "EntraAdminAudit"
        sourcetype = "entra:admin:audit"
        event = $result
    } | ConvertTo-Json -Compress

    # Send to SIEM endpoint (example)
    # Invoke-RestMethod -Uri "https://splunk.contoso.com:8088/services/collector" `
    #     -Method Post -Body $event -Headers @{"Authorization"="Splunk your-token"}
}
```

### Example 18: Create Compliance Report

```powershell
# Generate compliance report with analysis
.\Get-EntraAdminSyncAudit.ps1 -OutputDirectory "C:\Compliance"

$report = Import-Csv (Get-ChildItem "C:\Compliance\EntraAdminSyncReport-*.csv" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1).FullName

$complianceReport = @"
ENTRA ID ADMINISTRATOR COMPLIANCE REPORT
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
========================================

SUMMARY:
Total Administrators: $(($report | Select-Object -Unique UserId).Count)
Cloud-Only Admins: $(($report | Where-Object { $_.IsSyncedFromOnPrem -eq 'False' } | Select-Object -Unique UserId).Count)
Synced Admins: $(($report | Where-Object { $_.IsSyncedFromOnPrem -eq 'True' } | Select-Object -Unique UserId).Count)
Disabled Accounts: $(($report | Where-Object { $_.AccountEnabled -eq 'False' } | Select-Object -Unique UserId).Count)

FINDINGS:
1. All admin accounts reviewed: YES
2. Disabled accounts identified: $(($report | Where-Object { $_.AccountEnabled -eq 'False' }).Count) found
3. Sync status verified: YES

RECOMMENDATIONS:
$( if (($report | Where-Object { $_.AccountEnabled -eq 'False' }).Count -gt 0) { "- Review and remove disabled admin role assignments" } )
$( if (($report | Where-Object { $_.IsSyncedFromOnPrem -eq 'False' } | Select-Object -Unique UserId).Count -gt 10) { "- High number of cloud-only admins detected" } )
"@

$complianceReport | Out-File "C:\Compliance\ComplianceReport_$(Get-Date -Format 'yyyyMMdd').txt"
Write-Host $complianceReport
```

## Tips and Best Practices

### Performance Optimization

```powershell
# For large tenants, consider running during off-peak hours
.\Get-EntraAdminSyncAudit.ps1 -Verbose
```

### Error Recovery

```powershell
# Implement retry logic for transient failures
$maxAttempts = 3
$attempt = 0
$success = $false

while (-not $success -and $attempt -lt $maxAttempts) {
    try {
        $attempt++
        Write-Host "Attempt $attempt of $maxAttempts..." -ForegroundColor Yellow
        .\Get-EntraAdminSyncAudit.ps1 -ErrorAction Stop
        $success = $true
    } catch {
        if ($attempt -eq $maxAttempts) {
            throw "Failed after $maxAttempts attempts: $_"
        }
        Write-Host "Attempt failed, retrying in 30 seconds..." -ForegroundColor Yellow
        Start-Sleep -Seconds 30
    }
}
```

### Secure Credential Management

```powershell
# Use managed identities in Azure or certificate-based auth
# Example: Using a service principal with certificate
$tenantId = "your-tenant-id"
$appId = "your-app-id"
$certThumbprint = "your-cert-thumbprint"

Connect-MgGraph -TenantId $tenantId `
    -ClientId $appId `
    -CertificateThumbprint $certThumbprint

.\Get-EntraAdminSyncAudit.ps1
```

---

For more examples and community contributions, visit the [GitHub repository](https://github.com/jambot24/entra-admin-sync-audit).
