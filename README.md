# Sentinel

## Export Rules
´´´powershell
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
´´´
