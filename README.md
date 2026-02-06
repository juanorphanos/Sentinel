# Sentinel

## Requisitos

- PowerShell 7
- Modulo Az


## Export Rules
```powershell
PS C:\ScriptEnterpriseApps> .\Export-SentinelAnalyticsRules.ps1 -SubscriptionId "XXXXXXXXXXXXXXXXXXXXXXXXXX" -ResourceGroupName "rg-sentinel" -WorkspaceName "la-stnl-001"
Checking Azure connection...
Setting subscription context to: XXXXXXXXXXXXXXXXXXXXXXXXXX
Created backup directory: .\SentinelBackups\20260206_111512

Retrieving Sentinel analytics rules...
Found 10 analytics rules
  [✓] Exported: Advanced Multistage Attack Detection
  [✓] Exported: AD FS Remote Auth Sync Connection
  [✓] Exported: TEST_ALERT_API
  [✓] Exported: TEST_ALERT_2
  [✓] Exported: Conditional Access - Dynamic Group Exclusion Changes
  [✓] Exported: PRUEBA  - Attempts to sign in to disabled accounts
  [✓] Exported: restore AD FS Remote Auth Sync Connection
  [✓] Exported: restore TEST_ALERT_2
  [✓] Exported: restore TEST_ALERT_API
  [✓] Exported: restore TEST_ALERT_API


Export Summary

Backup Location: .\SentinelBackups\20260206_111512
Successfully exported: 10 rules
```


---

## Import a Rule

```powershell
.\Restore-SentinelAnalyticsRules.ps1 -SubscriptionId "XXXXXXXXX" -ResourceGroupName "rg-sentinel" -WorkspaceName "la-stnl-001" -BackupPath .\SentinelBackups\20260204_152051\ -RuleNames "TEST_ALERT_API"
Checking Azure connection...
Setting subscription context to:XXXXXXXXXX
Retrieving existing analytics rules...
Found 10 existing rules in workspace

Scanning backup folder...
Found 6 backup files
Filtering for specified rules: TEST_ALERT_API
Matched 1 rules to restore

Processing: TEST_ALERT_API (Type: Scheduled)
  [!] Rule already exists. Creating with prefix: restore TEST_ALERT_API
  Creating Scheduled query rule...

  [✓] Successfully restored: restore TEST_ALERT_API


Restore Summary

Backup Location: .\SentinelBackups\20260204_152051\
Target Workspace: la-stnl-001
Successfully restored: 1 rules

Etag                                   Kind      Name                                 SystemDataCreatedAt SystemDataCreatedBy SystemDataCreatedByType Syst 
                                                                                                                                                      emDa 
                                                                                                                                                      taLa 
                                                                                                                                                      stMo 
                                                                                                                                                      difi 
                                                                                                                                                      edAt 

"100162ba-0000-0100-0000-6985f8c90000" Scheduled d640c9e1-f2c4-4f62-b5bc-42829e539b83

PS C:\ScriptEnterpriseApps> 
```
