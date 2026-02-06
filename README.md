# Microsoft Sentinel Analytics Rules — Backup & Restore

PowerShell automation for backing up and restoring Microsoft Sentinel analytics rules (alert rules) from Log Analytics workspaces.

This repository contains two PowerShell scripts:

- `Export-SentinelAnalyticsRules.ps1` — Export all analytics rules to JSON backups
- `Restore-SentinelAnalyticsRules.ps1` — Restore analytics rules from JSON backups

## Overview

These scripts provide a complete solution for backing up and restoring Microsoft Sentinel analytics rules, supporting:

**Export Features:**

- Exports all analytics rules from a Sentinel workspace
- Creates timestamped backup folders automatically
- Saves each rule in its own folder with JSON file
- Preserves all rule configuration including queries, thresholds, entity mappings, and incident settings
- Handles all rule types: Scheduled, Fusion, ML Behavior Analytics, Threat Intelligence, and Microsoft Security Incident Creation
- Converts enums and complex objects to serializable JSON format

**Restore Features:**

- Restores one, multiple, or all rules from a backup
- Selective restore by rule display name(s)
- Intelligent rule kind detection (Scheduled, Fusion, etc.)
- Handles conflicts with existing rules (prefix or overwrite)
- Converts TimeSpan and enum properties correctly
- Preserves entity mappings, incident configuration, tactics, techniques, and suppression settings
- Validates and provides feedback on available rules in backup

**Use cases include:** audit trails, change management, disaster recovery, workspace migration, and environment synchronization (dev/test/prod).

---

## Prerequisites

### Software Requirements

- **PowerShell**: 7.x recommended (5.1 minimum)
- **Operating System**: Windows, macOS, or Linux
- **Network Access**: Azure Resource Manager endpoints (management.azure.com)

### Required PowerShell Modules

Install the Azure PowerShell modules:

```powershell
Install-Module Az.Accounts -Scope CurrentUser -Force
Install-Module Az.SecurityInsights -Scope CurrentUser -Force
```

Verify installation:

```powershell
Get-Module Az.Accounts, Az.SecurityInsights -ListAvailable
```

### Azure Permissions

**For Export (backup):**

- `Reader` role on the Log Analytics workspace, OR
- `Microsoft Sentinel Reader` role

**For Restore:**

- `Microsoft Sentinel Contributor` role, OR
- `Contributor` role on the subscription/resource group containing the workspace

Check your access:

```powershell
Get-AzRoleAssignment -Scope "/subscriptions/<subscription-id>/resourceGroups/<rg-name>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>"
```

### Authentication

Before running either script, authenticate to Azure and select your target subscription:

```powershell
Connect-AzAccount
Select-AzSubscription -SubscriptionId "<your-subscription-id>"
```

For automation (CI/CD, scheduled tasks), use a service principal:

```powershell
$credential = Get-Credential
Connect-AzAccount -ServicePrincipal -Credential $credential -Tenant "<tenant-id>"
```

---

## Export-SentinelAnalyticsRules.ps1

### Description

Exports all Microsoft Sentinel analytics rules from a workspace to JSON backup files. Each rule is saved in its own folder with complete configuration including queries, thresholds, entity mappings, and incident settings.

### Parameters

| Parameter           | Required | Description                                             | Default             |
| ------------------- | -------- | ------------------------------------------------------- | ------------------- |
| `SubscriptionId`    | Yes      | Azure subscription ID containing the Sentinel workspace | -                   |
| `ResourceGroupName` | Yes      | Resource group name containing the workspace            | -                   |
| `WorkspaceName`     | Yes      | Log Analytics workspace name (Sentinel workspace)       | -                   |
| `BackupPath`        | No       | Root directory for backups                              | `.\SentinelBackups` |

### Basic Usage

Export all rules from a workspace:

```powershell
.\Export-SentinelAnalyticsRules.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName "la-stnl-001"
```

### Advanced Usage

**Custom backup location:**

```powershell
.\Export-SentinelAnalyticsRules.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName "la-stnl-001" `
    -BackupPath "C:\SentinelBackups\Production"
```

**Automated daily backup (scheduled task):**

```powershell
# Schedule a daily export at 2 AM
$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' `
    -Argument '-File "C:\Scripts\Export-SentinelAnalyticsRules.ps1" -SubscriptionId "12345678-1234-1234-1234-123456789012" -ResourceGroupName "rg-sentinel" -WorkspaceName "la-stnl-001"'
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "SentinelBackup" -Description "Daily Sentinel rules backup"
```

### Output Structure

Backups are organized as follows:

```
SentinelBackups/
└── 20260206_143022/              # Timestamp folder (yyyyMMdd_HHmmss)
    ├── Advanced Multistage Attack Detection/
    │   └── Advanced Multistage Attack Detection.json
    ├── TEST_ALERT_API/
    │   └── TEST_ALERT_API.json
    └── Suspicious Login Pattern/
        └── Suspicious Login Pattern.json
```

Each JSON file contains:

- Export metadata (date, subscription, workspace)
- Rule display name and kind
- Complete rule configuration (query, frequency, severity, tactics, etc.)
- Entity mappings, incident configuration, suppression settings

### Example Output

The script provides colored console output showing export progress:

```
Checking Azure connection...
Setting subscription context to: 12345678-1234-1234-1234-123456789012
Created backup directory: .\SentinelBackups\20260206_143022

Retrieving Sentinel analytics rules...
Found 15 analytics rules
  [✓] Exported: Advanced Multistage Attack Detection
  [✓] Exported: TEST_ALERT_API
  [✓] Exported: Suspicious Login Pattern
  ...

========================================
Export Summary
========================================
Backup Location: .\SentinelBackups\20260206_143022
Successfully exported: 15 rules
========================================
```

---

## Restore-SentinelAnalyticsRules.ps1

### Description

Restores Microsoft Sentinel analytics rules from JSON backup files to a workspace. Supports selective restore by rule name(s), intelligent conflict handling, and all rule types.

### Parameters

| Parameter           | Required | Description                                                                | Default   |
| ------------------- | -------- | -------------------------------------------------------------------------- | --------- |
| `SubscriptionId`    | Yes      | Azure subscription ID containing the Sentinel workspace                    | -         |
| `ResourceGroupName` | Yes      | Resource group name containing the workspace                               | -         |
| `WorkspaceName`     | Yes      | Log Analytics workspace name (Sentinel workspace)                          | -         |
| `BackupPath`        | Yes      | Path to the backup folder containing rule JSON files                       | -         |
| `RuleNames`         | No       | Array of rule display names to restore. If omitted, all rules are restored | All rules |
| `OverwriteExisting` | No       | Switch to overwrite existing rules with same display name                  | False     |

### Basic Usage

**Restore all rules from a backup:**

```powershell
.\Restore-SentinelAnalyticsRules.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName "la-stnl-001" `
    -BackupPath ".\SentinelBackups\20260204_152051"
```

**Restore a single rule:**

```powershell
.\Restore-SentinelAnalyticsRules.ps1 `
    -SubscriptionId "58091560-03d8-46d5-a8db-efe7fa9c3175" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName "la-stnl-001" `
    -BackupPath ".\SentinelBackups\20260204_152051" `
    -RuleNames "TEST_ALERT_API"
```

**Restore multiple specific rules:**

```powershell
.\Restore-SentinelAnalyticsRules.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName "la-stnl-001" `
    -BackupPath ".\SentinelBackups\20260204_152051" `
    -RuleNames "TEST_ALERT_API", "TEST_ALERT_2", "Suspicious Login Pattern"
```

### Advanced Usage

**Overwrite existing rules:**

```powershell
.\Restore-SentinelAnalyticsRules.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName "la-stnl-001" `
    -BackupPath ".\SentinelBackups\20260204_152051" `
    -OverwriteExisting
```

**Restore to a different workspace (migration scenario):**

```powershell
# Export from production
.\Export-SentinelAnalyticsRules.ps1 `
    -SubscriptionId "prod-sub-id" `
    -ResourceGroupName "rg-sentinel-prod" `
    -WorkspaceName "la-stnl-prod"

# Restore to development
.\Restore-SentinelAnalyticsRules.ps1 `
    -SubscriptionId "dev-sub-id" `
    -ResourceGroupName "rg-sentinel-dev" `
    -WorkspaceName "la-stnl-dev" `
    -BackupPath ".\SentinelBackups\20260206_143022"
```

### Conflict Handling

When restoring a rule that already exists in the target workspace:

- **Without `-OverwriteExisting`**: The rule is created with the prefix "restore " (e.g., "restore TEST_ALERT_API")
- **With `-OverwriteExisting`**: The existing rule is updated with the backup configuration

Example:

```powershell
# Rule "TEST_ALERT_API" already exists in workspace
.\Restore-SentinelAnalyticsRules.ps1 ... -RuleNames "TEST_ALERT_API"
# Result: Creates "restore TEST_ALERT_API"

.\Restore-SentinelAnalyticsRules.ps1 ... -RuleNames "TEST_ALERT_API" -OverwriteExisting
# Result: Updates the existing "TEST_ALERT_API" rule
```

### Supported Rule Types

The script supports all Microsoft Sentinel analytics rule types:

- **Scheduled** — KQL query-based rules with custom schedules
- **Microsoft Security Incident Creation** — Rules from Microsoft security products
- **Fusion** — Advanced multistage attack detection
- **ML Behavior Analytics** — Machine learning-based anomaly detection
- **Threat Intelligence** — Threat intelligence indicator-based rules

### Example Output

```
Checking Azure connection...
Setting subscription context to: 58091560-03d8-46d5-a8db-efe7fa9c3175
Retrieving existing analytics rules...
Found 12 existing rules in workspace

Scanning backup folder...
Found 15 backup files
Filtering for specified rules: TEST_ALERT_API
Matched 1 rules to restore

Processing: TEST_ALERT_API (Type: Scheduled)
  Creating Scheduled query rule...
  [✓] Successfully restored: TEST_ALERT_API

========================================
Restore Summary
========================================
Backup Location: .\SentinelBackups\20260204_152051
Target Workspace: la-stnl-001
Successfully restored: 1 rules
========================================
```

---

## Complete Examples

### Example 1: Weekly Backup Routine

```powershell
# Weekly backup of production Sentinel workspace
Connect-AzAccount
Select-AzSubscription -SubscriptionId "prod-subscription-id"

.\Export-SentinelAnalyticsRules.ps1 `
    -SubscriptionId "prod-subscription-id" `
    -ResourceGroupName "rg-sentinel-prod" `
    -WorkspaceName "la-stnl-prod" `
    -BackupPath "\\fileserver\SentinelBackups"
```

### Example 2: Restore After Accidental Deletion

```powershell
# List available backups
Get-ChildItem ".\SentinelBackups" | Sort-Object Name -Descending | Select-Object -First 5

# Restore the deleted rule from latest backup
.\Restore-SentinelAnalyticsRules.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName "la-stnl-001" `
    -BackupPath ".\SentinelBackups\20260206_143022" `
    -RuleNames "Accidentally Deleted Rule"
```

### Example 3: Promote Rules from Dev to Production

```powershell
# Export from dev environment
.\Export-SentinelAnalyticsRules.ps1 `
    -SubscriptionId "dev-sub-id" `
    -ResourceGroupName "rg-sentinel-dev" `
    -WorkspaceName "la-stnl-dev"

# Restore specific tested rules to production
.\Restore-SentinelAnalyticsRules.ps1 `
    -SubscriptionId "prod-sub-id" `
    -ResourceGroupName "rg-sentinel-prod" `
    -WorkspaceName "la-stnl-prod" `
    -BackupPath ".\SentinelBackups\20260206_143022" `
    -RuleNames "New Brute Force Detection", "Enhanced Phishing Detection"
```

### Example 4: Audit and Compare Rules

```powershell
# Export current state
.\Export-SentinelAnalyticsRules.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName "la-stnl-001"

# Compare with previous backup
$current = Get-ChildItem ".\SentinelBackups\20260206_143022" -Recurse -Filter "*.json"
$previous = Get-ChildItem ".\SentinelBackups\20260201_143022" -Recurse -Filter "*.json"

Compare-Object $current.Name $previous.Name -IncludeEqual
```

---

## Troubleshooting

### Common Issues

**"Not connected to Azure"**

```powershell
# Solution: Connect to Azure
Connect-AzAccount
Select-AzSubscription -SubscriptionId "<your-subscription-id>"
```

**"Required modules not found"**

```powershell
# Solution: Install required modules
Install-Module Az.Accounts -Scope CurrentUser -Force
Install-Module Az.SecurityInsights -Scope CurrentUser -Force
```

**"Permission denied" during restore**

- Verify you have `Microsoft Sentinel Contributor` or `Contributor` role
- Check role assignment:

```powershell
Get-AzRoleAssignment | Where-Object {$_.Scope -like "*sentinel*"} | Format-Table DisplayName, RoleDefinitionName, Scope
```

**"No matching rules found in backup"**

The script will list available rules in the backup:

```
Available rules:
  - Advanced Multistage Attack Detection
  - TEST_ALERT_API
  - Suspicious Login Pattern
```

Check spelling and use exact display names.

**TimeSpan or enum conversion errors**

The scripts handle these automatically. If you encounter issues:

- Ensure you're using the latest version of Az.SecurityInsights module
- Check that the backup JSON is not manually edited

### Validation

**Check if rules were exported:**

```powershell
Get-ChildItem ".\SentinelBackups\20260206_143022" -Recurse -Filter "*.json" | Select-Object Name, Length
```

**Verify rule content:**

```powershell
Get-Content ".\SentinelBackups\20260206_143022\TEST_ALERT_API\TEST_ALERT_API.json" | ConvertFrom-Json | Select-Object DisplayName, Kind, @{N='Query';E={$_.Rule.Query}}
```

**List rules in workspace after restore:**

```powershell
Get-AzSentinelAlertRule -ResourceGroupName "rg-sentinel" -WorkspaceName "la-stnl-001" | Select-Object DisplayName, Kind, Enabled
```

---

## Project Structure

```
ScriptEnterpriseApps/
├── Export-SentinelAnalyticsRules.ps1    # Export script
├── Restore-SentinelAnalyticsRules.ps1   # Restore script
├── README.md                             # This file
└── SentinelBackups/                      # Default backup location
    ├── 20260204_152051/                  # Timestamped backup folder
    │   ├── TEST_ALERT_API/
    │   │   └── TEST_ALERT_API.json
    │   └── Advanced Multistage Attack Detection/
    │       └── Advanced Multistage Attack Detection.json
    └── 20260206_143022/                  # Another backup
        └── ...
```

---

## Best Practices

### Backup Strategy

- Schedule regular automated exports (daily or weekly)
- Keep multiple historical backups for change tracking
- Store backups in version control (Git) for audit trail
- Use separate backup locations for different environments

### Restore Strategy

- Always test restores in a dev/test environment first
- Use selective restore (`-RuleNames`) when possible to minimize impact
- Review the backup JSON before restoring to production
- Use `-OverwriteExisting` cautiously; consider prefixed restores first

### Security

- Backups may contain sensitive KQL queries and detection logic
- Store backups securely with appropriate access controls
- Use Azure Key Vault for storing service principal credentials in automation
- Audit who has access to backup files and restore scripts

### Change Management

- Document all restore operations
- Use Git to track changes to backup files
- Compare backups before/after major changes
- Maintain a log of rule modifications

---

## Contributing

Contributions are welcome! Please ensure:

- PowerShell best practices (approved verbs, parameter validation)
- Comment-based help in functions
- Error handling with meaningful messages
- Testing against multiple rule types

---

## License

This project is provided as-is for operational backup and restore workflows.

---

## Additional Resources

- [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [Az.SecurityInsights Module Reference](https://learn.microsoft.com/en-us/powershell/module/az.securityinsights/)
- [Analytics Rules API Reference](https://learn.microsoft.com/en-us/rest/api/securityinsights/alert-rules)

---

**Version**: 1.0  
**Last Updated**: February 6, 2026
