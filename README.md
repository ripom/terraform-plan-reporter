# Terraform Plan Parser

A PowerShell-based tool to parse and humanize Terraform plan output, making it easier to identify which resources will be impacted by infrastructure changes.

## Overview

When running Terraform plans, especially in CI/CD pipelines like Azure DevOps, the output can be verbose and difficult to parse quickly. This project provides tools to:

1. **Parse Terraform plan output** into a clean, human-readable format
2. **Convert Azure DevOps log format** into a format compatible with the parser
3. **Filter and highlight** resources by action (create, update, destroy, replace)
4. **Display detailed attribute changes** for deeper analysis

## Scripts

### `Get-TerraformPlanReport.ps1`

Main script that parses Terraform plan output and generates a human-readable report with categorized resource changes.

#### Features

- ✓ Categorizes resources by action type (Create, Update, Destroy, Replace)
- ✓ Color-coded output for easy visual scanning
- ✓ Optional detailed attribute change display
- ✓ Filtering by specific action types
- ✓ Automatic ANSI color code and timestamp removal
- ✓ Summary statistics at the end

#### Usage

```powershell
# Basic usage - show all resource changes
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out

# Show detailed attribute changes
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ShowChanges

# Filter to show only resources being created
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ListCreated

# Filter to show only resources being changed (updated or replaced)
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ListChanged

# Filter to show only resources being destroyed
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ListDestroyed

# Combine filters (show created and destroyed resources)
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ListCreated -ListDestroyed
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `LogFile` | String | Yes | Path to the Terraform plan output file |
| `ShowChanges` | Switch | No | Display detailed attribute changes for each resource |
| `ListCreated` | Switch | No | Show only resources that will be created |
| `ListChanged` | Switch | No | Show only resources that will be updated or replaced |
| `ListDestroyed` | Switch | No | Show only resources that will be destroyed |

#### Output Example

```
================================================================================

✓ CREATE: 5
  • azurerm_resource_group.rg_example
  • azurerm_virtual_network.vnet_example
  • azurerm_subnet.subnet_example
  • azurerm_network_security_group.nsg_example
  • azurerm_subnet_network_security_group_association.nsg_assoc

≈ UPDATE: 2
  • azurerm_storage_account.storage
  • azurerm_key_vault.kv

✗ DESTROY: 1
  • azurerm_public_ip.old_pip

================================================================================

Plan: 
5 to add, 
2 to change, 
1 to destroy.
```

### `Convert-AzDevOpsLog.ps1`

Utility script that converts Azure DevOps pipeline log format into a clean format compatible with the parser.

#### Features

- ✓ Removes Azure DevOps timestamps (format: `2025-11-18T16:49:18.9245450Z`)
- ✓ Strips ANSI color codes
- ✓ Preserves original log line indentation
- ✓ UTF-8 output encoding

#### Usage

```powershell
# Convert Azure DevOps log to clean format
.\Convert-AzDevOpsLog.ps1 -InputFile .\tfplan.out -OutputFile .\tfplan_clean.out
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `InputFile` | String | Yes | Path to the raw Azure DevOps log file |
| `OutputFile` | String | Yes | Path where the cleaned output will be saved |

## Workflow

### Typical Use Case in Azure DevOps Pipeline

1. **Capture Terraform Plan Output**
   ```yaml
   - task: PowerShell@2
     displayName: 'Run Terraform Plan'
     inputs:
       targetType: 'inline'
       script: |
         terraform plan -no-color > terraform_plan.log
   ```

2. **Convert Log Format** (if using Azure DevOps timestamps)
   ```yaml
   - task: PowerShell@2
     displayName: 'Convert Log Format'
     inputs:
       filePath: 'scripts/Convert-AzDevOpsLog.ps1'
       arguments: '-InputFile terraform_plan.log -OutputFile terraform_plan_clean.log'
   ```

3. **Parse and Display Summary**
   ```yaml
   - task: PowerShell@2
     displayName: 'Display Plan Summary'
     inputs:
       filePath: 'scripts/Get-TerraformPlanReport.ps1'
       arguments: '-LogFile terraform_plan_clean.log -ShowChanges'
   ```

### Local Development

```powershell
# If you have a local Terraform plan output
terraform plan -no-color > tfplan.out
.\Get-TerraformPlanReport.ps1 -LogFile tfplan.out -ShowChanges

# If you captured logs from Azure DevOps
.\Convert-AzDevOpsLog.ps1 -InputFile .\azdo_tfplan.log -OutputFile .\tfplan_clean.out
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan_clean.out
```

## Sample Files

The repository includes sample files for testing:

- `tfplan.out` - Raw Azure DevOps log with timestamps and ANSI codes
- `tfplan_clean.out` - Cleaned version suitable for parsing

## Requirements

- PowerShell 5.1 or higher
- No external dependencies

## How It Works

### Parsing Logic

The parser:
1. Reads the log file line by line
2. Strips ANSI color codes and timestamps using regex patterns
3. Identifies resource action lines matching pattern: `# <resource_name> will be <action>`
4. Captures attribute changes for each resource when `-ShowChanges` is enabled
5. Groups resources by action type
6. Displays formatted output with color coding and icons

### Color Coding

- **Green (✓)**: Resources being created
- **Yellow (≈)**: Resources being updated
- **Red (✗)**: Resources being destroyed
- **Magenta (⟳)**: Resources being replaced

## Benefits

- **Quick Visual Scanning**: Instantly identify the scope of infrastructure changes
- **Better Code Reviews**: Easily spot unintended resource deletions or modifications
- **Pipeline Integration**: Integrate into CI/CD pipelines for automated change reporting
- **Reduced Errors**: Clear visibility reduces the risk of approving destructive changes
- **Time Savings**: No need to scroll through hundreds of lines of raw Terraform output

## Contributing

Feel free to submit issues or pull requests to improve the scripts.

## License

This project is provided as-is for use in Terraform workflows.
