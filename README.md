# Entra ID Admin Sync Audit

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A PowerShell script to audit Entra ID (Azure AD) administrator role assignments and identify which users are synced from on-premises Active Directory.

## Features

- ✅ Enumerates all active Entra ID administrative roles
- ✅ Expands group memberships to identify all transitive admin users
- ✅ Reports on-premises sync status for each admin
- ✅ Exports timestamped CSV reports to desktop (or custom location)
- ✅ Includes summary statistics and disabled account detection
- ✅ Secure file permissions (current user only on Windows)
- ✅ Comprehensive error handling and logging
- ✅ Progress indicators for long-running operations
- ✅ Optional JSON export format
- ✅ Retry logic for Microsoft Graph connection

## Prerequisites

### Required PowerShell Modules

The script requires the Microsoft Graph PowerShell SDK:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

### Required Microsoft Graph Permissions

The following delegated permissions are required:

- `Organization.Read.All` - Read organization information
- `Directory.Read.All` - Read directory data
- `RoleManagement.Read.Directory` - Read role assignments
- `User.Read.All` - Read user profiles
- `Group.Read.All` - Read group memberships

> **Note:** These are read-only permissions. The script does not modify any data.

### PowerShell Version

- PowerShell 5.1 or higher
- PowerShell 7+ recommended for cross-platform support

## Installation

1. Download the script:
   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yourusername/entra-admin-sync-audit/main/Get-EntraAdminSyncAudit.ps1" -OutFile "Get-EntraAdminSyncAudit.ps1"
   ```

2. Or clone the repository:
   ```powershell
   git clone https://github.com/yourusername/entra-admin-sync-audit.git
   cd entra-admin-sync-audit
   ```

## Quick Start

### Basic Usage

Run the script with default settings (saves to Desktop):

```powershell
.\Get-EntraAdminSyncAudit.ps1
```

### Custom Output Directory

Specify a different output location:

```powershell
.\Get-EntraAdminSyncAudit.ps1 -OutputDirectory "C:\Reports"
```

### Enable Verbose Logging

Get detailed progress information:

```powershell
.\Get-EntraAdminSyncAudit.ps1 -Verbose
```

### Export JSON Format

Export both CSV and JSON:

```powershell
.\Get-EntraAdminSyncAudit.ps1 -ExportJSON
```

## Output

### CSV Report

The script generates a CSV file with the following columns:

| Column | Description |
|--------|-------------|
| **TenantName** | Display name of the Entra ID tenant |
| **TenantId** | Unique tenant identifier |
| **TestTimestamp** | When the audit was performed |
| **OnPremisesSyncEnabled_Tenant** | Whether the tenant has AD sync enabled |
| **OnPremisesLastSyncDateTime** | Last sync time for the tenant |
| **RoleName** | Entra ID role name (e.g., Global Administrator) |
| **RoleId** | Unique role identifier |
| **AssignmentSource** | How the role was assigned (Direct or Group) |
| **AssignedObjectType** | Type of object assigned (User, Group, ServicePrincipal) |
| **AssignedObjectId** | ID of the assigned object |
| **AssignedObjectDisplayName** | Display name of the assigned object |
| **UserPrincipalName** | User's UPN (if applicable) |
| **UserId** | Unique user identifier (if applicable) |
| **IsSyncedFromOnPrem** | True if user is synced from on-premises AD |
| **OnPremisesSyncEnabled_User** | User's sync status |
| **OnPremisesImmutableIdPresent** | Whether user has an immutable ID |
| **OnPremisesSecurityIdentifierPresent** | Whether user has an on-prem SID |
| **UserType** | Type of user account (Member, Guest) |
| **AccountEnabled** | Whether the account is enabled |

### Console Summary

The script displays a summary after completion:

```
========================================
   Entra ID Admin Audit Summary
========================================
Total Unique Administrators: 45
  - Synced from On-Premises: 38
  - Cloud-Only Admins:       7
  - Disabled Accounts:       2

Total Active Roles:          12
Total Role Assignments:      67
  - Direct Assignments:      51
  - Via Group Membership:    16
========================================
```

### File Naming

Output files are timestamped and include the tenant name:

```
EntraAdminSyncReport-ContosoLtd-20260113-143022.csv
EntraAdminSyncReport-ContosoLtd-20260113-143022.json
```

## Use Cases

### Security Audits

Identify which administrators are managed on-premises vs. cloud-only:

```powershell
# Run audit and review cloud-only admins
.\Get-EntraAdminSyncAudit.ps1
# Import CSV and filter for cloud-only admins
Import-Csv "EntraAdminSyncReport-*.csv" | Where-Object { $_.IsSyncedFromOnPrem -eq $false }
```

### Compliance Reporting

Generate reports for regulatory requirements:

```powershell
# Export both CSV and JSON for compliance team
.\Get-EntraAdminSyncAudit.ps1 -OutputDirectory "C:\Compliance\Reports" -ExportJSON
```

### Hybrid Identity Management

Track synchronization status of privileged accounts:

```powershell
# Identify synced admins
Import-Csv "EntraAdminSyncReport-*.csv" |
    Where-Object { $_.IsSyncedFromOnPrem -eq $true } |
    Select-Object UserPrincipalName, RoleName, AccountEnabled
```

### Access Reviews

Generate reports for periodic admin access reviews:

```powershell
# Find admins assigned via groups (for review)
Import-Csv "EntraAdminSyncReport-*.csv" |
    Where-Object { $_.AssignmentSource -eq "Group" } |
    Select-Object UserPrincipalName, RoleName, AssignedObjectDisplayName
```

## Security Considerations

### Read-Only Permissions

The script only requires read-only Microsoft Graph permissions and does not modify any data in your tenant.

### File Security

On Windows, output files are automatically restricted to the current user only using NTFS ACLs.

### No Credential Storage

The script uses the Microsoft Graph SDK for authentication. No credentials are stored or logged.

### Error Logging

Errors are logged to separate files with timestamps. Review error logs for sensitive information before sharing.

## Troubleshooting

### Connection Failures

If you encounter connection issues:

```powershell
# Manually disconnect and reconnect
Disconnect-MgGraph
Connect-MgGraph -Scopes "Organization.Read.All","Directory.Read.All","RoleManagement.Read.Directory","User.Read.All","Group.Read.All"
```

### Permission Errors

If you see permission errors:

1. Ensure you have the required admin role (Global Reader or higher)
2. Verify all required Graph scopes are granted:
   ```powershell
   (Get-MgContext).Scopes
   ```
3. You may need admin consent for some permissions

### Module Not Found

Install the Microsoft Graph module:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
Import-Module Microsoft.Graph
```

### Desktop Path Not Found

If the Desktop path is not resolved:

```powershell
# Use a custom output directory
.\Get-EntraAdminSyncAudit.ps1 -OutputDirectory "C:\Temp"
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your code:
- Follows PowerShell best practices
- Includes comment-based help
- Handles errors gracefully
- Is tested in both PowerShell 5.1 and 7+

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Created by the PowerShell community

## Acknowledgments

- Built with [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)
- Inspired by enterprise security audit requirements
- Thanks to all contributors

## Support

For issues, questions, or suggestions:

1. Check the [troubleshooting section](#troubleshooting)
2. Search [existing issues](https://github.com/yourusername/entra-admin-sync-audit/issues)
3. [Open a new issue](https://github.com/yourusername/entra-admin-sync-audit/issues/new) if needed

## Changelog

### Version 2.0.0 (2026-01-13)

- Changed default output directory to user's Desktop
- Added comprehensive error handling and retry logic
- Added progress indicators for long-running operations
- Added summary statistics display
- Added secure file permissions (Windows)
- Added optional JSON export format
- Improved logging with timestamps
- Enhanced parameter validation
- Added comment-based help

### Version 1.0.0 (Initial Release)

- Basic Entra ID admin role enumeration
- Group membership expansion
- CSV export functionality
- On-premises sync detection

---

**Note:** This script is provided as-is for auditing purposes. Always test in a non-production environment first.

## Related Resources

- [Microsoft Graph PowerShell SDK Documentation](https://learn.microsoft.com/en-us/powershell/microsoftgraph/overview)
- [Entra ID Roles and Permissions](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)
- [Microsoft Entra Connect](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-azure-ad-connect)
