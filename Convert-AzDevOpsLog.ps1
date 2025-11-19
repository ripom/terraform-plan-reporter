# Convert plan.mine format to plan1.mine format by removing timestamps and ANSI codes
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
