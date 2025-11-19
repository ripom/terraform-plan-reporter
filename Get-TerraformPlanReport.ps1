<#
.SYNOPSIS
    Parses Terraform plan output and generates a human-readable report with categorized resource changes.

.DESCRIPTION
    This script analyzes Terraform plan log files and displays resources grouped by action type (Create, Update, Destroy, Replace).
    It provides color-coded output for easy visual scanning and optional detailed attribute change display.
    Works with direct Terraform plan output using 'terraform plan -no-color > file.log'.

.PARAMETER LogFile
    Path to the Terraform plan output file to analyze.

.PARAMETER ShowChanges
    Optional switch to display detailed attribute changes for each resource.

.PARAMETER ListCreated
    Optional switch to show only resources that will be created.

.PARAMETER ListChanged
    Optional switch to show only resources that will be updated or replaced.

.PARAMETER ListDestroyed
    Optional switch to show only resources that will be destroyed.

.EXAMPLE
    .\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out
    Displays a summary of all resource changes.

.EXAMPLE
    .\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ShowChanges
    Displays resource changes with detailed attribute modifications.

.EXAMPLE
    .\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ListDestroyed
    Shows only resources that will be destroyed.

.NOTES
    Version: 1.0
    Compatible with PowerShell 5.1 and higher.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$LogFile,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowChanges,
    
    [Parameter(Mandatory=$false)]
    [switch]$ListCreated,
    
    [Parameter(Mandatory=$false)]
    [switch]$ListChanged,
    
    [Parameter(Mandatory=$false)]
    [switch]$ListDestroyed
)

# Read all lines from the file
$lines = Get-Content -Path $LogFile

# Collect results
$results = @()
$currentResource = $null
$captureChanges = $false
$changes = @()

foreach ($line in $lines) {
    # Remove ANSI color codes (both \x1b[...m and [..m formats) and timestamps
    # Note: Timestamps are only present in manually copied Azure DevOps raw logs
    # Direct 'terraform plan -no-color' output doesn't have timestamps
    $cleanLine = $line -replace '\x1b\[[0-9;]*m', '' -replace '\[[0-9;]*m', '' -replace '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s+', ''
    
    # Match resource declaration lines like:
    # "  # azurerm_resource.name will be created"
    # "  # azurerm_resource.name will be destroyed"
    # "  # azurerm_resource.name will be updated"
    # "  # azurerm_resource.name must be replaced"
    if ($cleanLine -match '^\s*#\s+(.+?)\s+(will be|must be)\s+(created|destroyed|updated|replaced)') {
        # Save previous resource if exists
        if ($currentResource) {
            $results += [PSCustomObject]@{
                Resource = $currentResource.Resource
                Action   = $currentResource.Action
                Changes  = $changes
            }
        }
        
        $resourceName = $matches[1]
        $action = $matches[3]  # The action is now in match group 3
        
        # Map action to shorter form
        $actionType = switch ($action) {
            "created" { "Create" }
            "destroyed" { "Destroy" }
            "updated" { "Update" }
            "replaced" { "Replace" }
            default { $action }
        }
        
        $currentResource = @{
            Resource = $resourceName
            Action   = $actionType
        }
        $changes = @()
        $captureChanges = $true
    }
    # Capture attribute changes if we're tracking a resource
    elseif ($ShowChanges -and $captureChanges -and $cleanLine -match '^\s+([+~-])\s+(.+)') {
        $changeType = $matches[1]
        $changeDetail = $matches[2].Trim()
        
        # Skip unwanted lines
        if ($changeDetail -match '^(resource|data)\s+"' -or
            $changeDetail -match '^\(known after apply\)' -or
            $changeDetail -match '^#' -or
            $changeDetail -match '^[\{\}]$' -or
            $changeDetail -match '^\[$' -or
            $changeDetail -match '^\]$' -or
            $changeDetail -eq '') {
            continue
        }
        
        # Parse the attribute change
        if ($changeDetail -match '^(.+?)\s*=\s*(.+)$') {
            $attribute = $matches[1].Trim()
            $value = $matches[2].Trim()
            
            # Skip complex nested structures
            if ($value -match '^\{' -or $value -match '^\[') {
                continue
            }
            
            # Handle value changes (old -> new)
            if ($value -match '^"?([^"]+)"?\s*->\s*"?([^"]+)"?$') {
                $oldVal = $matches[1]
                $newVal = $matches[2]
                $changes += "      ${attribute}: $oldVal → $newVal"
            }
            else {
                $changes += "      + ${attribute} = $value"
            }
        }
        elseif ($changeDetail -match '^"([^"]+)"') {
            # Array/list element
            $val = $matches[1]
            $symbol = if ($changeType -eq '+') { '+' } elseif ($changeType -eq '-') { '-' } else { '~' }
            $changes += "      $symbol $val"
        }
    }
}

# Save last resource
if ($currentResource) {
    $results += [PSCustomObject]@{
        Resource = $currentResource.Resource
        Action   = $currentResource.Action
        Changes  = $changes
    }
}

if ($results.Count -eq 0) {
    Write-Host "No resources found in plan file: $LogFile" -ForegroundColor Yellow
} else {
    # Group by action
    $grouped = $results | Group-Object -Property Action
    
    # Determine which actions to display based on switches
    $actionsToShow = @()
    if ($ListCreated -or $ListChanged -or $ListDestroyed) {
        if ($ListCreated) { $actionsToShow += "Create" }
        if ($ListChanged) { $actionsToShow += "Update", "Replace" }
        if ($ListDestroyed) { $actionsToShow += "Destroy" }
    } else {
        # Show all if no filter switches are specified
        $actionsToShow = @("Create", "Update", "Destroy", "Replace")
    }
    
    Write-Host "`n================================================================================`n" -ForegroundColor Cyan
    
    foreach ($group in $grouped) {
        # Skip this group if it's not in the actions to show
        if ($actionsToShow -notcontains $group.Name) {
            continue
        }
        
        $color = switch ($group.Name) {
            "Create" { "Green" }
            "Update" { "Yellow" }
            "Destroy" { "Red" }
            "Replace" { "Magenta" }
            default { "White" }
        }
        
        $icon = switch ($group.Name) {
            "Create" { "✓" }
            "Update" { "≈" }
            "Destroy" { "✗" }
            "Replace" { "⟳" }
            default { "•" }
        }
        
        Write-Host "$icon $($group.Name.ToUpper()): $($group.Count)" -ForegroundColor $color
        
        foreach ($item in $group.Group) {
            Write-Host "  • $($item.Resource)" -ForegroundColor $color
            if ($ShowChanges -and $item.Changes.Count -gt 0) {
                foreach ($change in $item.Changes) {
                    Write-Host $change -ForegroundColor DarkGray
                }
            }
        }
        Write-Host ""
    }
    
    if (-not $ShowChanges) {
        Write-Host "Use -ShowChanges to see attribute changes`n" -ForegroundColor DarkGray
    }
    
    Write-Host "================================================================================`n" -ForegroundColor Cyan
    
    # Display summary
    $createCount = ($grouped | Where-Object { $_.Name -eq "Create" }).Count
    $updateCount = ($grouped | Where-Object { $_.Name -eq "Update" }).Count
    $destroyCount = ($grouped | Where-Object { $_.Name -eq "Destroy" }).Count
    $replaceCount = ($grouped | Where-Object { $_.Name -eq "Replace" }).Count
    
    if ($createCount -eq $null) { $createCount = 0 }
    if ($updateCount -eq $null) { $updateCount = 0 }
    if ($destroyCount -eq $null) { $destroyCount = 0 }
    if ($replaceCount -eq $null) { $replaceCount = 0 }
    
    Write-Host "Plan: " -ForegroundColor White
    Write-Host "$createCount to add" -NoNewline -ForegroundColor Green
    Write-Host ", "
    Write-Host "$updateCount to change" -NoNewline -ForegroundColor Yellow
    Write-Host ", "
    Write-Host "$destroyCount to destroy" -NoNewline -ForegroundColor Red
    if ($replaceCount -gt 0) {
        Write-Host ", "
        Write-Host "$replaceCount to replace" -NoNewline -ForegroundColor Magenta
    }
    Write-Host ".`n"
}
