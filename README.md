# Microsoft 365 Security Baseline

A CIS Benchmark-aligned Microsoft 365 security hardening guide covering Conditional Access, MFA, DLP, Microsoft Defender, Intune, and Azure AD. Includes PowerShell audit scripts for automated compliance checking.

## Table of Contents

- [Overview](#overview)
- [Identity and Access Management](#identity-and-access-management)
- [Conditional Access Policies](#conditional-access-policies)
- [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa)
- [Azure AD / Entra ID Hardening](#azure-ad--entra-id-hardening)
- [Microsoft Defender for Office 365](#microsoft-defender-for-office-365)
- [Data Loss Prevention (DLP)](#data-loss-prevention-dlp)
- [Microsoft Intune / Endpoint Management](#microsoft-intune--endpoint-management)
- [SharePoint and OneDrive Security](#sharepoint-and-onedrive-security)
- [Teams Security](#teams-security)
- [Audit and Logging](#audit-and-logging)
- [PowerShell Audit Scripts](#powershell-audit-scripts)
- [CIS Benchmark Mapping](#cis-benchmark-mapping)
- [About Petronella Technology Group](#about-petronella-technology-group)

## Overview

Microsoft 365 is the most widely deployed enterprise productivity suite, which makes it a prime target for attackers. Default configurations prioritize usability over security. This guide aligns with the CIS Microsoft 365 Foundations Benchmark to harden your tenant against common attack vectors including credential theft, business email compromise, data exfiltration, and account takeover.

**Scope:** Microsoft 365 Business Premium, E3, and E5 tenants. Some features require specific licensing noted in each section.

## Identity and Access Management

### Global Admin Hardening

- [ ] **Limit Global Administrators to 2-4 accounts** -- CIS 1.1.1. Excessive global admins increase attack surface
- [ ] **Use dedicated admin accounts** -- Admin accounts should not have mailboxes or be used for daily work
- [ ] **Enable break-glass accounts** -- 2 cloud-only emergency access accounts excluded from Conditional Access, with monitored sign-in alerts
- [ ] **Disable SSPR for admin accounts** -- Self-service password reset should be disabled for privileged roles
- [ ] **Require phishing-resistant MFA for admins** -- FIDO2 keys or Windows Hello for Business for all admin roles

### User Account Settings

- [ ] **Block legacy authentication** -- CIS 1.2. Disable POP3, IMAP4, SMTP AUTH, and legacy Exchange Web Services
- [ ] **Disable user consent to apps** -- CIS 1.3. Require admin approval for all OAuth app registrations
- [ ] **Enable user risk policy** -- Automatically block or require password change for high-risk users
- [ ] **Disable LinkedIn account connections** -- Prevent data sharing between M365 and LinkedIn
- [ ] **Configure idle session timeout** -- 1 hour for web apps, 15 minutes for admin portals

## Conditional Access Policies

### Recommended Baseline Policies

| Policy | Target | Conditions | Grant |
|--------|--------|------------|-------|
| Require MFA for all users | All users | All cloud apps | Require MFA |
| Block legacy authentication | All users | Exchange ActiveSync, Other clients | Block |
| Require compliant device | All users | All cloud apps | Require device compliance |
| Require MFA for admins | Directory roles | All cloud apps | Require phishing-resistant MFA |
| Block high-risk sign-ins | All users | High sign-in risk | Block |
| Require MFA for Azure management | All users | Azure management | Require MFA |
| Block countries | All users | Named locations (blocked countries) | Block |

### Implementation Steps

- [ ] **Create named locations** -- Define trusted networks (corporate IPs) and blocked countries
- [ ] **Deploy policies in report-only mode first** -- Monitor impact for 2 weeks before enforcement
- [ ] **Exclude break-glass accounts** -- Emergency access accounts must bypass Conditional Access
- [ ] **Require compliant or hybrid-joined devices** -- For access to sensitive data
- [ ] **Block access from unmanaged devices** -- Or limit to browser-only with no download capability
- [ ] **Configure sign-in frequency** -- Require re-authentication every 8 hours for sensitive apps

### Conditional Access PowerShell Check

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.Read.All"

# List all Conditional Access policies
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, State, CreatedDateTime | Format-Table -AutoSize

# Check for policies blocking legacy auth
Get-MgIdentityConditionalAccessPolicy | Where-Object {
    $_.Conditions.ClientAppTypes -contains "exchangeActiveSync" -or
    $_.Conditions.ClientAppTypes -contains "other"
} | Select-Object DisplayName, State
```

## Multi-Factor Authentication (MFA)

- [ ] **Enable MFA for 100% of users** -- No exceptions. Security defaults or Conditional Access
- [ ] **Disable SMS and voice call MFA** -- Allow only Microsoft Authenticator, FIDO2, or Windows Hello
- [ ] **Enable number matching** -- Prevents MFA fatigue attacks by requiring users to enter a displayed number
- [ ] **Enable additional context** -- Show application name and geographic location during MFA prompts
- [ ] **Configure MFA registration policy** -- Require MFA registration within 14 days of account creation
- [ ] **Monitor MFA registration** -- Alert on MFA method changes for admin accounts

```powershell
# Check MFA registration status for all users
Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All"

Get-MgUser -All | ForEach-Object {
    $methods = Get-MgUserAuthenticationMethod -UserId $_.Id
    [PSCustomObject]@{
        User = $_.UserPrincipalName
        MFAMethods = ($methods | Measure-Object).Count
        Methods = ($methods.AdditionalProperties.'@odata.type' -join ', ')
    }
} | Where-Object { $_.MFAMethods -le 1 } | Format-Table -AutoSize
```

## Azure AD / Entra ID Hardening

- [ ] **Enable Privileged Identity Management (PIM)** -- Just-in-time admin access with approval workflows (requires P2 license)
- [ ] **Configure access reviews** -- Quarterly review of all privileged role assignments
- [ ] **Disable guest user access to directory** -- Limit guest users to their own directory objects
- [ ] **Restrict who can invite guests** -- Only admins or specific users should invite external guests
- [ ] **Enable Identity Protection** -- Configure user risk and sign-in risk policies
- [ ] **Disable self-service group creation** -- Require admin approval for Microsoft 365 group creation
- [ ] **Configure password protection** -- Enable custom banned password list with organization-specific terms
- [ ] **Enable smart lockout** -- Lockout threshold of 10, lockout duration of 60 seconds

## Microsoft Defender for Office 365

### Safe Links Policy

- [ ] **Enable Safe Links for email** -- URL rewriting and time-of-click scanning
- [ ] **Enable Safe Links for Teams** -- Scan URLs in Teams messages
- [ ] **Enable Safe Links for Office apps** -- Scan URLs in Word, Excel, PowerPoint
- [ ] **Do not allow click-through to malicious URLs** -- Block users from bypassing warnings
- [ ] **Track user clicks** -- Enable click tracking for security investigations

### Safe Attachments Policy

- [ ] **Enable Safe Attachments with Dynamic Delivery** -- Delivers email immediately, attachments scanned in sandbox
- [ ] **Enable Safe Attachments for SharePoint, OneDrive, and Teams** -- Scan files uploaded to cloud storage
- [ ] **Configure redirect for detected malware** -- Send detected attachments to security team for review

### Anti-Phishing Policy

- [ ] **Enable mailbox intelligence** -- Uses machine learning to detect impersonation
- [ ] **Configure impersonation protection** -- Add executives and VIPs to protected users list
- [ ] **Enable first-contact safety tips** -- Warn users when receiving email from a sender for the first time
- [ ] **Configure spoofing intelligence** -- Automatically block detected spoofing attempts
- [ ] **Set action for detected impersonation** -- Quarantine impersonated messages

## Data Loss Prevention (DLP)

- [ ] **Create DLP policies for sensitive data types** -- Credit card numbers, SSNs, health records
- [ ] **Apply DLP to Exchange, SharePoint, OneDrive, and Teams** -- Cover all communication channels
- [ ] **Configure policy tips** -- Educate users when they attempt to share sensitive data
- [ ] **Block external sharing of sensitive content** -- Prevent accidental data leakage to external recipients
- [ ] **Enable endpoint DLP** -- Extend DLP controls to endpoint devices (requires E5 or compliance add-on)
- [ ] **Review DLP alerts weekly** -- Monitor false positives and tune policies

```powershell
# Check existing DLP policies
Connect-IPPSSession
Get-DlpCompliancePolicy | Select-Object Name, Mode, Enabled, Workload | Format-Table -AutoSize
```

## Microsoft Intune / Endpoint Management

- [ ] **Require device enrollment** -- All devices accessing M365 must be enrolled in Intune
- [ ] **Configure compliance policies** -- Require encryption, minimum OS version, screen lock, antivirus
- [ ] **Deploy security baselines** -- Use Microsoft security baselines for Windows, Edge, and Defender
- [ ] **Configure app protection policies** -- Prevent copy/paste from managed apps to unmanaged apps
- [ ] **Enable BitLocker enforcement** -- Require full disk encryption on Windows devices
- [ ] **Configure Windows Update for Business** -- Enforce update rings with maximum 7-day deferral for security updates
- [ ] **Disable USB storage on managed devices** -- Or require encryption for removable media
- [ ] **Enable remote wipe capability** -- For lost or stolen devices

## SharePoint and OneDrive Security

- [ ] **Restrict external sharing** -- Set to "Existing guests" or "Only people in your organization"
- [ ] **Block download from unmanaged devices** -- Browser-only access with no download, print, or sync
- [ ] **Enable sensitivity labels** -- Classify and protect documents with encryption and access controls
- [ ] **Disable anonymous sharing links** -- Require authentication for all shared links
- [ ] **Set link expiration** -- Guest access links expire after 30 days maximum
- [ ] **Enable versioning** -- Maintain 100+ versions for ransomware recovery capability
- [ ] **Audit sharing activity** -- Monitor external sharing events in the compliance portal

## Teams Security

- [ ] **Restrict external access** -- Allow communication only with specific trusted domains
- [ ] **Disable guest access** -- Or restrict to specific Teams with business justification
- [ ] **Block file sharing from unmanaged devices** -- Prevent data leakage through Teams
- [ ] **Disable third-party app installation** -- Allow only admin-approved apps
- [ ] **Configure meeting policies** -- Lobby for external participants, disable anonymous join
- [ ] **Enable meeting recording consent** -- Require consent notifications for recording

## Audit and Logging

- [ ] **Enable unified audit logging** -- CIS 3.1. Must be explicitly enabled; not on by default
- [ ] **Set audit log retention to 1 year minimum** -- Default is 90 days (E5 provides 1 year)
- [ ] **Enable mailbox auditing for all mailboxes** -- Log owner, delegate, and admin actions
- [ ] **Configure alert policies** -- Enable alerts for suspicious forwarding rules, mass downloads, impossible travel
- [ ] **Forward logs to SIEM** -- Export M365 audit logs to your SIEM via Management Activity API
- [ ] **Monitor admin activity** -- Alert on global admin sign-ins, role assignments, Conditional Access changes

```powershell
# Verify unified audit logging is enabled
Connect-ExchangeOnline
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled

# Check mailbox auditing status
Get-OrganizationConfig | Select-Object AuditDisabled
```

## PowerShell Audit Scripts

### Full M365 Security Audit Script

```powershell
# Prerequisites
# Install-Module Microsoft.Graph -Scope CurrentUser
# Install-Module ExchangeOnlineManagement -Scope CurrentUser

# Connect
Connect-MgGraph -Scopes "Directory.Read.All","Policy.Read.All","User.Read.All"
Connect-ExchangeOnline

Write-Host "=== Global Admin Count ===" -ForegroundColor Cyan
$globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'").Id
Write-Host "Global Admins: $($globalAdmins.Count)" -ForegroundColor $(if($globalAdmins.Count -gt 4){"Red"}else{"Green"})

Write-Host "`n=== Legacy Auth Check ===" -ForegroundColor Cyan
$legacyAuthPolicies = Get-MgIdentityConditionalAccessPolicy | Where-Object {
    $_.Conditions.ClientAppTypes -contains "exchangeActiveSync"
}
Write-Host "Policies blocking legacy auth: $($legacyAuthPolicies.Count)"

Write-Host "`n=== Audit Logging ===" -ForegroundColor Cyan
$auditConfig = Get-AdminAuditLogConfig
Write-Host "Unified Audit Enabled: $($auditConfig.UnifiedAuditLogIngestionEnabled)"

Write-Host "`n=== External Forwarding Rules ===" -ForegroundColor Cyan
Get-TransportRule | Where-Object {$_.RedirectMessageTo -ne $null} | Select-Object Name, State
```

## CIS Benchmark Mapping

| CIS Control | Description | Section |
|-------------|-------------|---------|
| 1.1.1 | Limit Global Administrators | Identity |
| 1.2 | Block legacy authentication | Conditional Access |
| 1.3 | Disable user consent to apps | Azure AD |
| 2.1 | Enable Safe Links | Defender |
| 2.2 | Enable Safe Attachments | Defender |
| 3.1 | Enable unified audit logging | Audit |
| 4.1 | Configure DLP policies | DLP |
| 5.1 | Enable MFA for all users | MFA |
| 6.1 | Restrict external sharing | SharePoint |

## Additional Resources

- [CIS Microsoft 365 Foundations Benchmark](https://www.cisecurity.org/benchmark/microsoft_365)
- [Microsoft Secure Score](https://security.microsoft.com/securescore)
- [Microsoft 365 Security Documentation](https://learn.microsoft.com/en-us/microsoft-365/security/)
- [CISA M365 Security Configuration Baseline](https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project)

## Contributing

Contributions are welcome. Please open an issue or submit a pull request with improvements, additional audit scripts, or corrections.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Professional IT Security Services

Need expert help securing your Microsoft 365 tenant? **Petronella Technology Group** provides:

- [Managed IT Services](https://petronellatech.com/managed-it-services/) - 24/7 monitoring and management
- [Cybersecurity Assessments](https://petronellatech.com/cybersecurity-assessment/) - Comprehensive security audits
- [Network Security](https://petronellatech.com/cybersecurity/network-security/) - Firewall, IDS/IPS, segmentation
- [AI-Powered Security](https://petronellatech.com/ai/ai-services/) - Next-gen threat detection

**Petronella Technology Group** is a CMMC-RP certified cybersecurity firm in Raleigh, NC. [Contact us](https://petronellatech.com/contact-us/) or call (919) 348-4912.

## About Petronella Technology Group

This baseline is maintained by [Petronella Technology Group, Inc.](https://www.petronellatech.com/) -- a cybersecurity and IT services firm specializing in Microsoft 365 security, compliance (CMMC, HIPAA, SOC 2, NIST), and managed IT for businesses across the United States.

- Website: [https://www.petronellatech.com](https://www.petronellatech.com/)
- Book a consultation: [https://book.petronella.ai](https://book.petronella.ai/)
- Phone: [(919) 348-4912](tel:9193484912)
- LinkedIn: [Petronella Technology Group](https://www.linkedin.com/company/petronella-computer-consultants-inc-)
