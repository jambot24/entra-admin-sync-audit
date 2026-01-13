# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| 1.x     | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

### How to Report

**Please DO NOT create a public GitHub issue for security vulnerabilities.**

Instead, please report security issues via one of these methods:

1. **Email**: Send details to the repository maintainer (check GitHub profile for contact)
2. **GitHub Security Advisories**: Use the [GitHub Security Advisory](https://github.com/jambot24/entra-admin-sync-audit/security/advisories/new) feature (recommended)

### What to Include

Please include the following information in your report:

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact of the vulnerability
- Any suggested fixes or mitigations (if known)
- Your contact information for follow-up

### Response Timeline

- **Initial Response**: Within 48 hours of report
- **Status Update**: Within 7 days with assessment and timeline
- **Fix Release**: Varies based on severity and complexity

We appreciate your responsible disclosure and will acknowledge your contribution in the security advisory (unless you prefer to remain anonymous).

## Security Best Practices

When using this script, please follow these security guidelines:

### 1. Permissions and Access Control

- **Minimum Permissions**: The script only requires read-only Microsoft Graph permissions
- **Delegated Access**: Never grant more permissions than necessary
- **Regular Reviews**: Periodically review and audit Graph API permissions

Required permissions (read-only):
- `Organization.Read.All`
- `Directory.Read.All`
- `RoleManagement.Read.Directory`
- `User.Read.All`
- `Group.Read.All`

### 2. Authentication

- **Use Modern Authentication**: The script uses Microsoft Graph SDK with modern auth (OAuth 2.0)
- **No Credential Storage**: Never store credentials in scripts, files, or version control
- **Session Management**: Always disconnect after use (`Disconnect-MgGraph`)
- **MFA Recommended**: Use Multi-Factor Authentication for admin accounts

### 3. Output File Security

- **Sensitive Data**: Output files contain sensitive information about admin accounts
- **File Permissions**: On Windows, files are automatically restricted to current user only
- **Secure Storage**: Store output files in encrypted locations
- **Secure Deletion**: Securely delete files when no longer needed
- **Transmission**: Use encrypted channels (HTTPS, SFTP) when sharing reports

### 4. Environment Security

- **Trusted Systems**: Only run the script on trusted, managed devices
- **Updated Software**: Keep PowerShell and Microsoft.Graph module updated
- **Antivirus**: Ensure antivirus/EDR is active and updated
- **Logging**: Monitor script execution logs for anomalies

### 5. Code Security

- **Verify Source**: Only download the script from official sources
- **Code Review**: Review the script code before execution
- **Execution Policy**: Use appropriate PowerShell execution policies
- **Digital Signatures**: Consider code signing for enterprise deployment

### 6. Data Handling

- **Data Minimization**: Only run audits as frequently as needed
- **Retention Policy**: Define and enforce data retention policies
- **PII Protection**: Treat output as Personally Identifiable Information (PII)
- **Compliance**: Ensure compliance with GDPR, CCPA, and other regulations

### 7. Operational Security

- **Audit Logging**: Log all script executions for audit trails
- **Change Management**: Use version control and change management processes
- **Testing**: Test in non-production environments first
- **Documentation**: Document when, why, and by whom audits are performed

### 8. Network Security

- **Secure Connections**: All Graph API calls use HTTPS
- **Proxy Support**: Configure proxy settings if required by your network
- **Firewall**: Ensure access to Microsoft Graph endpoints (graph.microsoft.com)

### 9. Error Handling

- **Error Logs**: Review error logs for potential security issues
- **No Sensitive Data in Logs**: Avoid logging credentials or tokens
- **Secure Error Reporting**: Redact sensitive information before sharing errors

### 10. Compliance Considerations

- **Regulatory Requirements**: Ensure compliance with industry regulations
- **Data Sovereignty**: Be aware of where data is processed and stored
- **Audit Requirements**: Maintain audit trails as required by your organization
- **Privacy Impact**: Conduct privacy impact assessments as needed

## Known Security Considerations

### Output File Contents

The CSV/JSON output contains:
- User Principal Names (email addresses)
- User IDs and display names
- Role assignments
- Account status information
- Tenant information

**Recommendation**: Treat these files as confidential and apply appropriate access controls.

### Microsoft Graph Permissions

While the script uses read-only permissions, these still provide access to sensitive directory information.

**Recommendation**: Only grant these permissions to authorized personnel and review regularly.

### Local File Storage

Output files are stored locally on the executing machine.

**Recommendation**: Ensure the local system is encrypted (BitLocker, FileVault, etc.) and secure.

## Security Updates

We regularly review and update this project for security improvements.

To stay informed:
- Watch this repository for security advisories
- Review the [CHANGELOG](README.md#changelog) for security-related updates
- Subscribe to GitHub Security Advisories for this repository

## Security-Related Configuration

### Recommended Execution Policy

For enterprise deployment, consider:

```powershell
# Set execution policy to require signed scripts
Set-ExecutionPolicy AllSigned -Scope CurrentUser

# Or, for testing environments
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Restricted Environments

If running in highly restricted environments:

1. Review and approve all code before execution
2. Consider using a dedicated service account with minimal privileges
3. Run in an isolated/sandboxed environment
4. Monitor all API calls and network traffic

## Third-Party Dependencies

This script depends on:

- **Microsoft.Graph PowerShell SDK**: Official Microsoft package
  - Source: https://github.com/microsoftgraph/msgraph-sdk-powershell
  - Security updates: Monitor Microsoft security advisories

**Recommendation**: Keep all dependencies updated to the latest stable versions.

## Questions or Concerns?

If you have security questions or concerns that are not vulnerabilities, please:

1. Check this SECURITY.md document
2. Review the [README](README.md) documentation
3. Search [existing issues](https://github.com/jambot24/entra-admin-sync-audit/issues)
4. Open a discussion or issue (for non-sensitive topics)

## Acknowledgments

We thank all security researchers and contributors who help keep this project secure.

---

**Last Updated**: 2026-01-13
**Security Policy Version**: 1.0
