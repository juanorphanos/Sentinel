<#
.SYNOPSIS
    Exports Microsoft Sentinel analytics rules to backup files.

.DESCRIPTION
    This script exports all analytics rules from a Microsoft Sentinel workspace.
    Each rule is saved in its own folder as a JSON file for backup purposes.
    
.PARAMETER SubscriptionId
    The Azure subscription ID containing the Sentinel workspace.

.PARAMETER ResourceGroupName
    The resource group name containing the Sentinel workspace.

.PARAMETER WorkspaceName
    The name of the Log Analytics workspace (Sentinel workspace).

.PARAMETER BackupPath
    The path where backup folders will be created. Defaults to .\SentinelBackups

.EXAMPLE
    .\Export-SentinelAnalyticsRules.ps1 -SubscriptionId "your-sub-id" -ResourceGroupName "rg-sentinel" -WorkspaceName "workspace-sentinel"

.EXAMPLE
    .\Export-SentinelAnalyticsRules.ps1 -SubscriptionId "your-sub-id" -ResourceGroupName "rg-sentinel" -WorkspaceName "workspace-sentinel" -BackupPath "C:\Backups\Sentinel"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceName,
    
    [Parameter(Mandatory = $false)]
    [string]$BackupPath = ".\SentinelBackups"
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

# Create backup directory with timestamp
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupRoot = Join-Path $BackupPath $timestamp
if (-not (Test-Path $backupRoot)) {
    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    Write-Host "Created backup directory: $backupRoot" -ForegroundColor Green
}

# Get all analytics rules
Write-Host "`nRetrieving Sentinel analytics rules..." -ForegroundColor Cyan
try {
    $rules = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName
    Write-Host "Found $($rules.Count) analytics rules" -ForegroundColor Green
}
catch {
    Write-Error "Failed to retrieve analytics rules: $_"
    exit 1
}

# Export each rule
$successCount = 0
$failureCount = 0

# Helper function to convert enum properties to strings for proper JSON serialization
function ConvertTo-SerializableObject {
    param($Object)
    
    if ($null -eq $Object) { return $null }
    
    $result = @{}
    foreach ($prop in $Object.PSObject.Properties) {
        $value = $prop.Value
        
        # Convert enums to strings
        if ($null -ne $value -and $value.GetType().IsEnum) {
            $result[$prop.Name] = $value.ToString()
        }
        # Handle nested objects but avoid circular references
        elseif ($null -ne $value -and $value -is [PSCustomObject] -and $prop.Name -notin @('SystemData')) {
            $result[$prop.Name] = ConvertTo-SerializableObject $value
        }
        # Handle arrays
        elseif ($null -ne $value -and $value -is [Array]) {
            $result[$prop.Name] = @($value | ForEach-Object { 
                    if ($_ -is [PSCustomObject]) { ConvertTo-SerializableObject $_ } else { $_ }
                })
        }
        else {
            $result[$prop.Name] = $value
        }
    }
    
    return [PSCustomObject]$result
}

foreach ($rule in $rules) {
    try {
        # Sanitize rule name for folder creation
        $ruleName = $rule.Name
        $displayName = $rule.DisplayName -replace '[\\/:*?"<>|]', '_'
        
        # Create folder for this rule
        $ruleFolderPath = Join-Path $backupRoot $displayName
        if (-not (Test-Path $ruleFolderPath)) {
            New-Item -ItemType Directory -Path $ruleFolderPath -Force | Out-Null
        }
        
        # Export rule to JSON
        $jsonPath = Join-Path $ruleFolderPath "$displayName.json"
        
        # Convert rule to serializable object (enums to strings)
        $serializableRule = ConvertTo-SerializableObject $rule
        
        # Create a backup object with metadata
        $backupObject = @{
            ExportDate        = Get-Date -Format "o"
            SubscriptionId    = $SubscriptionId
            ResourceGroupName = $ResourceGroupName
            WorkspaceName     = $WorkspaceName
            RuleName          = $ruleName
            DisplayName       = $rule.DisplayName
            Kind              = $rule.Kind.ToString()
            Rule              = $serializableRule
        }
        
        $backupObject | ConvertTo-Json -Depth 100 | Out-File -FilePath $jsonPath -Encoding UTF8
        
        Write-Host "  [✓] Exported: $displayName" -ForegroundColor Green
        $successCount++
    }
    catch {
        Write-Warning "  [✗] Failed to export rule '$($rule.DisplayName)': $_"
        $failureCount++
    }
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Export Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Backup Location: $backupRoot" -ForegroundColor White
Write-Host "Successfully exported: $successCount rules" -ForegroundColor Green
if ($failureCount -gt 0) {
    Write-Host "Failed to export: $failureCount rules" -ForegroundColor Red
}
Write-Host "========================================" -ForegroundColor Cyan
