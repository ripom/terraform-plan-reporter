<#
.SYNOPSIS
    Converts manually copied Azure DevOps "View Raw Log" output to a clean format.

.DESCRIPTION
    This script removes Azure DevOps timestamps and ANSI color codes from manually copied raw logs.
    
    IMPORTANT: This script is only needed when you manually copy/paste logs from Azure DevOps "View Raw Log" view.
    If you capture Terraform output directly in your pipeline using 'terraform plan -no-color > file.log',
    the output is already in the correct format and this conversion is NOT required.

.PARAMETER InputFile
    Path to the raw Azure DevOps log file (manually copied from "View Raw Log").

.PARAMETER OutputFile
    Path where the cleaned output will be saved.

.EXAMPLE
    .\Convert-AzDevOpsLog.ps1 -InputFile .\raw_log.txt -OutputFile .\clean_log.txt
    Converts a manually copied Azure DevOps raw log to a clean format.

.NOTES
    Version: 1.0
    Compatible with PowerShell 5.1 and higher.
    Only use this when manually copying logs from Azure DevOps UI.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$InputFile,
    
    [Parameter(Mandatory=$true)]
    [string]$OutputFile
)

# Check if input file exists
if (-not (Test-Path $InputFile)) {
    Write-Host "Error: Input file not found: $InputFile" -ForegroundColor Red
    exit 1
}

Write-Host "Converting $InputFile to $OutputFile..." -ForegroundColor Cyan

# Read all lines from the input file
$lines = Get-Content -Path $InputFile

# Process each line: remove timestamps and ANSI codes
$cleanedLines = $lines | ForEach-Object {
    # Remove timestamp at the beginning (format: 2025-11-18T16:49:18.9245450Z )
    # Only remove ONE space after timestamp to preserve indentation
    $line = $_ -replace '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s', ''
    
    # Remove ANSI color codes (both \x1b[...m and [...m formats)
    $line = $line -replace '\x1b\[[0-9;]*m', '' -replace '\[(?=[0-9;]*m)[0-9;]*m', ''
    
    $line
}

# Write to output file
$cleanedLines | Set-Content -Path $OutputFile -Encoding UTF8

Write-Host "Conversion complete!" -ForegroundColor Green
Write-Host "  Input:  $InputFile ($($lines.Count) lines)" -ForegroundColor Gray
Write-Host "  Output: $OutputFile ($($cleanedLines.Count) lines)" -ForegroundColor Gray
