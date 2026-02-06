<#
.SYNOPSIS
    Restores Microsoft Sentinel analytics rules from backup files.

.DESCRIPTION
    This script restores analytics rules to a Microsoft Sentinel workspace from JSON backup files.
    It reads the backup folder structure and creates or updates rules accordingly.
    
.PARAMETER SubscriptionId
    The Azure subscription ID containing the Sentinel workspace.

.PARAMETER ResourceGroupName
    The resource group name containing the Sentinel workspace.

.PARAMETER WorkspaceName
    The name of the Log Analytics workspace (Sentinel workspace).

.PARAMETER BackupPath
    The path to the backup folder containing rule backups.

.PARAMETER RuleNames
    Optional array of rule display names to restore. If not specified, all rules will be restored.
    Rule names should match the DisplayName property from the backup files.

.PARAMETER OverwriteExisting
    If specified, existing rules with the same display name will be updated.

.EXAMPLE
    .\Restore-SentinelAnalyticsRules.ps1 -SubscriptionId "your-sub-id" -ResourceGroupName "rg-sentinel" -WorkspaceName "workspace-sentinel" -BackupPath ".\SentinelBackups\20260204_120000"

.EXAMPLE
    .\Restore-SentinelAnalyticsRules.ps1 -SubscriptionId "your-sub-id" -ResourceGroupName "rg-sentinel" -WorkspaceName "workspace-sentinel" -BackupPath ".\SentinelBackups\20260204_120000" -OverwriteExisting

.EXAMPLE
    .\Restore-SentinelAnalyticsRules.ps1 -SubscriptionId "your-sub-id" -ResourceGroupName "rg-sentinel" -WorkspaceName "workspace-sentinel" -BackupPath ".\SentinelBackups\20260204_120000" -RuleNames "Suspicious Login Pattern", "Malware Detection"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceName,
    
    [Parameter(Mandatory = $true)]
    [string]$BackupPath,
    
    [Parameter(Mandatory = $false)]
    [string[]]$RuleNames,
    
    [Parameter(Mandatory = $false)]
    [switch]$OverwriteExisting
)

# Import required modules
try {
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Az.SecurityInsights -ErrorAction Stop
}
catch {
    Write-Error "Required modules not found. Please install: Install-Module Az.Accounts, Az.SecurityInsights"
    exit 1
}

# Validate backup path
if (-not (Test-Path $BackupPath)) {
    Write-Error "Backup path does not exist: $BackupPath"
    exit 1
}

# Connect to Azure if not already connected
Write-Host "Checking Azure connection..." -ForegroundColor Cyan
$context = Get-AzContext
if (-not $context) {
    Write-Host "Not connected to Azure. Initiating login..." -ForegroundColor Yellow
    Connect-AzAccount
}

# Set the subscription context
Write-Host "Setting subscription context to: $SubscriptionId" -ForegroundColor Cyan
Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

# Get existing rules for comparison
Write-Host "Retrieving existing analytics rules..." -ForegroundColor Cyan
try {
    $existingRules = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName
    Write-Host "Found $($existingRules.Count) existing rules in workspace" -ForegroundColor Green
}
catch {
    Write-Warning "Could not retrieve existing rules: $_"
    $existingRules = @()
}

# Get all JSON files from backup
Write-Host "`nScanning backup folder..." -ForegroundColor Cyan
$backupFiles = Get-ChildItem -Path $BackupPath -Filter "*.json" -Recurse
Write-Host "Found $($backupFiles.Count) backup files" -ForegroundColor Green

# Filter by specified rule names if provided
if ($RuleNames) {
    Write-Host "Filtering for specified rules: $($RuleNames -join ', ')" -ForegroundColor Cyan
    $filteredFiles = @()
    foreach ($file in $backupFiles) {
        $content = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        if ($RuleNames -contains $content.DisplayName) {
            $filteredFiles += $file
        }
    }
    $backupFiles = $filteredFiles
    Write-Host "Matched $($backupFiles.Count) rules to restore" -ForegroundColor Green
    
    if ($backupFiles.Count -eq 0) {
        Write-Warning "No matching rules found in backup. Available rules:"
        Get-ChildItem -Path $BackupPath -Filter "*.json" -Recurse | ForEach-Object {
            $content = Get-Content -Path $_.FullName -Raw | ConvertFrom-Json
            Write-Host "  - $($content.DisplayName)" -ForegroundColor Yellow
        }
        exit 0
    }
}

# Restore each rule
$successCount = 0
$failureCount = 0

foreach ($backupFile in $backupFiles) {
    try {
        # Read backup file
        $backupContent = Get-Content -Path $backupFile.FullName -Raw | ConvertFrom-Json
        $rule = $backupContent.Rule
        $displayName = $backupContent.DisplayName
        
        # Get rule kind - detect from properties if Kind is not properly set
        $ruleKind = if ($backupContent.Kind -is [string] -and $backupContent.Kind -ne '') { 
            $backupContent.Kind 
        }
        elseif ($rule.Kind -is [string] -and $rule.Kind -ne '') {
            $rule.Kind
        }
        elseif ($null -ne $rule.Kind -and $rule.Kind.ToString() -match '^\w+$') {
            $rule.Kind.ToString()
        }
        else {
            # Detect rule type based on properties present
            if ($null -ne $rule.Query -and $null -ne $rule.QueryFrequency) {
                'Scheduled'
            }
            elseif ($null -ne $rule.ProductFilter) {
                'MicrosoftSecurityIncidentCreation'
            }
            elseif ($rule.AlertRuleTemplateName -and $rule.Type -like '*Fusion*') {
                'Fusion'
            }
            elseif ($rule.AlertRuleTemplateName -and $rule.Type -like '*MLBehaviorAnalytics*') {
                'MLBehaviorAnalytics'
            }
            elseif ($rule.AlertRuleTemplateName -and $rule.Type -like '*ThreatIntelligence*') {
                'ThreatIntelligence'
            }
            else {
                'Unknown'
            }
        }
        
        Write-Host "`nProcessing: $displayName (Type: $ruleKind)" -ForegroundColor Cyan
        
        # Check if rule already exists
        $existingRule = $existingRules | Where-Object { $_.DisplayName -eq $displayName }
        
        # If rule exists and OverwriteExisting is not set, create with "restore" prefix
        $actualDisplayName = $displayName
        if ($existingRule -and -not $OverwriteExisting) {
            $actualDisplayName = "restore $displayName"
            Write-Host "  [!] Rule already exists. Creating with prefix: $actualDisplayName" -ForegroundColor Yellow
        }
        
        # Prepare parameters based on rule kind
        $commonParams = @{
            ResourceGroupName = $ResourceGroupName
            WorkspaceName     = $WorkspaceName
            Enabled           = $rule.Enabled
        }
        
        # Handle different rule types
        switch ($ruleKind) {
            "Scheduled" {
                Write-Host "  Creating Scheduled query rule..." -ForegroundColor Gray
                
                # Convert TimeSpan objects from JSON (they have Ticks property)
                $queryFrequency = if ($rule.QueryFrequency.Ticks) { 
                    [TimeSpan]::FromTicks($rule.QueryFrequency.Ticks) 
                }
                else { 
                    $rule.QueryFrequency 
                }
                
                $queryPeriod = if ($rule.QueryPeriod.Ticks) { 
                    [TimeSpan]::FromTicks($rule.QueryPeriod.Ticks) 
                }
                else { 
                    $rule.QueryPeriod 
                }
                
                $suppressionDuration = if ($rule.SuppressionDuration.Ticks) { 
                    [TimeSpan]::FromTicks($rule.SuppressionDuration.Ticks) 
                }
                else { 
                    $rule.SuppressionDuration 
                }
                
                # Handle enum values that might be empty strings or objects
                $severity = if ([string]::IsNullOrEmpty($rule.Severity) -or $rule.Severity -is [PSCustomObject]) {
                    'Medium'  # Default severity
                }
                else {
                    $rule.Severity
                }
                
                $triggerOperator = if ([string]::IsNullOrEmpty($rule.TriggerOperator) -or $rule.TriggerOperator -is [PSCustomObject]) {
                    'GreaterThan'  # Default trigger operator
                }
                else {
                    $rule.TriggerOperator
                }
                
                $params = $commonParams + @{
                    Kind                = 'Scheduled'
                    DisplayName         = $actualDisplayName
                    Severity            = $severity
                    Query               = $rule.Query
                    QueryFrequency      = $queryFrequency
                    QueryPeriod         = $queryPeriod
                    TriggerOperator     = $triggerOperator
                    TriggerThreshold    = $rule.TriggerThreshold
                    SuppressionDuration = $suppressionDuration
                }
                
                # Add Description only if it has a value
                if (-not [string]::IsNullOrWhiteSpace($rule.Description)) {
                    $params.Description = $rule.Description
                }
                
                # Add SuppressionEnabled as switch parameter only if true
                if ($rule.SuppressionEnabled -eq $true) {
                    $params.SuppressionEnabled = $true
                }
                
                # Add optional parameters if present
                if ($rule.Tactics) { $params.Tactics = $rule.Tactics }
                if ($rule.Techniques) { $params.Techniques = $rule.Techniques }
                if ($rule.AlertRuleTemplateName) { $params.AlertRuleTemplateName = $rule.AlertRuleTemplateName }
                if ($rule.EntityMappings) { $params.EntityMapping = $rule.EntityMappings }
                if ($rule.IncidentConfiguration) { 
                    $params.CreateIncident = $rule.IncidentConfiguration.CreateIncident 
                    if ($rule.IncidentConfiguration.GroupingConfiguration) {
                        # Convert GroupingConfigurationLookbackDuration TimeSpan
                        $lookbackDuration = if ($rule.IncidentConfiguration.GroupingConfiguration.LookbackDuration.Ticks) {
                            [TimeSpan]::FromTicks($rule.IncidentConfiguration.GroupingConfiguration.LookbackDuration.Ticks)
                        }
                        else {
                            $rule.IncidentConfiguration.GroupingConfiguration.LookbackDuration
                        }
                        
                        $params.GroupingConfigurationEnabled = $rule.IncidentConfiguration.GroupingConfiguration.Enabled
                        $params.GroupingConfigurationReopenClosedIncident = $rule.IncidentConfiguration.GroupingConfiguration.ReopenClosedIncident
                        $params.GroupingConfigurationLookbackDuration = $lookbackDuration
                        $params.GroupingConfigurationMatchingMethod = $rule.IncidentConfiguration.GroupingConfiguration.MatchingMethod
                    }
                }
                
                if ($existingRule -and $OverwriteExisting) {
                    Write-Host "  Updating existing rule..." -ForegroundColor Gray
                    Update-AzSentinelAlertRule @params -RuleId $existingRule.Name
                }
                else {
                    New-AzSentinelAlertRule @params
                }
            }
            
            "MicrosoftSecurityIncidentCreation" {
                Write-Host "  Creating Microsoft Security Incident Creation rule..." -ForegroundColor Gray
                
                $params = $commonParams + @{
                    Kind          = 'MicrosoftSecurityIncidentCreation'
                    DisplayName   = $actualDisplayName
                    ProductFilter = $rule.ProductFilter
                }
                
                # Add Description only if it has a value
                if (-not [string]::IsNullOrWhiteSpace($rule.Description)) {
                    $params.Description = $rule.Description
                }
                
                if ($rule.DisplayNamesFilter) { $params.DisplayNamesFilter = $rule.DisplayNamesFilter }
                if ($rule.SeveritiesFilter) { $params.SeveritiesFilter = $rule.SeveritiesFilter }
                
                if ($existingRule -and $OverwriteExisting) {
                    Write-Host "  Updating existing rule..." -ForegroundColor Gray
                    Update-AzSentinelAlertRule @params -RuleId $existingRule.Name
                }
                else {
                    New-AzSentinelAlertRule @params
                }
            }
            
            "Fusion" {
                Write-Host "  Creating Fusion rule..." -ForegroundColor Gray
                
                $params = $commonParams + @{
                    Kind              = 'Fusion'
                    AlertRuleTemplate = $rule.AlertRuleTemplateName
                }
                
                if ($existingRule -and $OverwriteExisting) {
                    Write-Host "  Updating existing rule..." -ForegroundColor Gray
                    Update-AzSentinelAlertRule @params -RuleId $existingRule.Name
                }
                else {
                    New-AzSentinelAlertRule @params
                }
            }
            
            "MLBehaviorAnalytics" {
                Write-Host "  Creating ML Behavior Analytics rule..." -ForegroundColor Gray
                
                $params = $commonParams + @{
                    Kind              = 'MLBehaviorAnalytics'
                    AlertRuleTemplate = $rule.AlertRuleTemplateName
                }
                
                if ($existingRule -and $OverwriteExisting) {
                    Write-Host "  Updating existing rule..." -ForegroundColor Gray
                    Update-AzSentinelAlertRule @params -RuleId $existingRule.Name
                }
                else {
                    New-AzSentinelAlertRule @params
                }
            }
            
            "ThreatIntelligence" {
                Write-Host "  Creating Threat Intelligence rule..." -ForegroundColor Gray
                
                $params = $commonParams + @{
                    Kind              = 'ThreatIntelligence'
                    AlertRuleTemplate = $rule.AlertRuleTemplateName
                }
                
                if ($existingRule -and $OverwriteExisting) {
                    Write-Host "  Updating existing rule..." -ForegroundColor Gray
                    Update-AzSentinelAlertRule @params -RuleId $existingRule.Name
                }
                else {
                    New-AzSentinelAlertRule @params
                }
            }
            
            default {
                Write-Warning "  [!] Unsupported rule kind: '$ruleKind'"
                Write-Warning "      Full rule type: $($rule.Type)"
                $failureCount++
                continue
            }
        }
        
        Write-Host "  [✓] Successfully restored: $actualDisplayName" -ForegroundColor Green
        $successCount++
    }
    catch {
        Write-Warning "  [✗] Failed to restore rule from '$($backupFile.Name)': $_"
        $failureCount++
    }
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Restore Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Backup Location: $BackupPath" -ForegroundColor White
Write-Host "Target Workspace: $WorkspaceName" -ForegroundColor White
Write-Host "Successfully restored: $successCount rules" -ForegroundColor Green
if ($failureCount -gt 0) {
    Write-Host "Failed to restore: $failureCount rules" -ForegroundColor Red
}
Write-Host "========================================" -ForegroundColor Cyan
