# Terraform Plan Parser

A PowerShell-based tool to parse and humanize Terraform plan output, making it easier to identify which resources will be impacted by infrastructure changes.

## Overview

When running Terraform plans, especially in CI/CD pipelines like Azure DevOps, the output can be verbose and difficult to parse quickly. This project provides tools to:

1. **Parse Terraform plan output** into a clean, human-readable format
2. **Convert manually copied Azure DevOps raw logs** (only needed when copy/pasting from "View Raw Log")
3. **Filter and highlight** resources by action (create, update, destroy, replace)
4. **Display detailed attribute changes** for deeper analysis

## Scripts

### `Get-TerraformPlanReport.ps1`

Main script that parses Terraform plan output and generates a human-readable report with categorized resource changes.

#### Features

- ✓ Categorizes resources by action type (Create, Update, Destroy, Replace)
- ✓ Color-coded output for easy visual scanning
- ✓ Optional detailed attribute change display with color-coded diff
- ✓ Filtering by specific action types
- ✓ Filtering by resource category (Compute, Storage, Network, Database, Security, Monitoring)
- ✓ Filtering by resource name pattern (supports wildcards)
- ✓ Filtering by resource type (supports wildcards)
- ✓ Table view for listing all resources
- ✓ Intelligent insights: cost estimation, security impact, governance analysis
  - Cost Impact: Categorizes resources as High/Medium/Low cost with monthly estimates
  - Security Analysis: Detects security-sensitive changes and trends
  - Governance: Analyzes tags, naming conventions, policies, backup, RBAC, network isolation, and more
  - Naming Convention Detection: Validates Azure CAF, AWS, and GCP naming standards
- ✓ Automatic ANSI color code and timestamp removal
- ✓ Summary statistics at the end

#### Usage

```powershell
# Basic usage - show all resource changes
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out

# Show detailed attribute changes with color-coded diff
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ShowChanges

# Show intelligent insights (cost, security, governance)
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ShowInsights

# Display all resources in a table format
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -TableAll

# Filter to show only resources being created
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ListCreated

# Filter to show only resources being changed (updated or replaced)
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ListChanged

# Filter to show only resources being destroyed
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ListDestroyed

# Filter to show only resources being replaced
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ListReplaced

# Filter by resource category
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -Category Compute -ShowInsights

# Filter by resource name pattern (supports wildcards)
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ResourceName "*prod*" -ListCreated

# Filter by resource type (supports wildcards)
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ResourceType "azurerm_virtual_machine" -ShowInsights

# Combine multiple filters
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -Category Storage -ResourceType "*storage_account*" -ListCreated -TableAll

# Advanced: Show created compute resources in production with cost insights
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -Category Compute -ResourceName "*prod*" -ListCreated -ShowInsights

# View governance compliance for all resources
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ShowInsights

# Analyze naming conventions for specific resource types
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ResourceType "azurerm_resource_group" -ShowInsights
```

#### Intelligent Insights Features

When using the `-ShowInsights` switch, the script provides comprehensive analysis:

**Cost Impact Analysis**
- Categorizes resources as High/Medium/Low cost impact
- Provides approximate monthly cost estimates in USD
- Shows overall cost trend (increase/decrease)
- Example output:
  ```
  💰 COST IMPACT ANALYSIS
     Overall Impact: Moderate Increase 💰💰 (+$450/mo)
     High Cost Resources (3):
     • azurerm_virtual_machine.vm_prod [+High] Standard_D4s_v3 ≈ $140/mo
  ```

**Security Impact Analysis**
- Detects security-sensitive attribute changes
- Identifies improvements vs. risks
- Tracks changes to encryption, access controls, network security
- Example output:
  ```
  🔒 SECURITY IMPACT ANALYSIS
     Security Trend: Improved ✓
     ✓ Security Improvements (2):
     • azurerm_storage_account.storage - Improved: enable_https_traffic_only
  ```

**Governance & Compliance Analysis**
- **Tags**: Detects resources with tags configured
- **Naming Conventions**: Validates against best practices
  - Azure CAF prefixes (rg-, vnet-, vm-, kv-, etc.)
  - AWS prefixes (vpc-, ec2-, s3-, lambda-, etc.)
  - GCP prefixes (vpc-, vm-, gke-, bucket-, etc.)
  - Environment indicators (-prod, -dev, -test, -staging, etc.)
  - Region indicators (-eastus, -us-west-2, -eu-west-1, etc.)
  - Numbered instances (-01, -02, -v1, etc.)
  - Multi-segment structure (4+ parts)
- **Policies & Monitoring**: Azure Policy, AWS Config, monitoring resources
- **Backup & Retention**: Backup configurations, retention policies
- **Resource Locks**: Management locks for production resources
- **RBAC/IAM**: Role assignments and identity configurations
- **Network Isolation**: Private endpoints, VNet integration
- **Audit Logging**: Diagnostic settings, log analytics
- **Compliance Frameworks**: Security center, compliance policies
- **Cost Management**: Budgets, cost exports

Example output:
```
📋 GOVERNANCE & COMPLIANCE ANALYSIS
   Governance Score: 8/12
   Breakdown:
   • Tags: ✓ +1
   • Naming: ✓ +1
   • Policies/Monitoring: ✓ +1
   • Network Isolation: ✓ +2

   🏷️  Tags (144):
   • azurerm_resource_group.rg_prod - Tags configured
   
   📝 Naming Conventions (87):
   • azurerm_resource_group.rg-myapp-prod-eastus - Follows naming convention: Azure CAF prefix (rg-), environment indicator (prod), region indicator (eastus), multi-segment structure (5 parts)
   • azurerm_virtual_network.vnet-hub-prod - Follows naming convention: Azure CAF prefix (vnet-), environment indicator (prod)
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `LogFile` | String | Yes | Path to the Terraform plan output file |
| `ShowChanges` | Switch | No | Display detailed attribute changes for each resource with color-coded diff |
| `ShowInsights` | Switch | No | Display intelligent analysis of cost, security, and governance impacts |
| `TableAll` | Switch | No | Display all resources in a table format with Action, ResourceType, and ResourceName |
| `ListCreated` | Switch | No | Show only resources that will be created |
| `ListChanged` | Switch | No | Show only resources that will be updated |
| `ListDestroyed` | Switch | No | Show only resources that will be destroyed |
| `ListReplaced` | Switch | No | Show only resources that will be replaced |
| `Category` | String | No | Filter by category: Compute, Storage, Network, Database, Security, Monitoring, All |
| `ResourceName` | String | No | Filter by resource name pattern (supports wildcards, e.g., "*prod*") |
| `ResourceType` | String | No | Filter by resource type (supports wildcards, e.g., "azurerm_virtual_machine") |

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

⟳ REPLACE: 3
  • azurerm_network_interface.nic_old
  • azurerm_virtual_machine.vm_resize
  • azurerm_subnet.subnet_config_change

================================================================================

Plan: 
5 to add, 
2 to change, 
1 to destroy, 
3 to replace.
```

### `Convert-AzDevOpsLog.ps1`

Utility script that converts manually copied Azure DevOps "View Raw Log" output into a clean format compatible with the parser.

**Note**: This script is only needed when you manually copy/paste logs from Azure DevOps "View Raw Log" view. If you capture Terraform output directly in your pipeline using `terraform plan -no-color > file.log`, the output is already in the correct format and this conversion step is not required.

#### Features

- ✓ Removes Azure DevOps timestamps (format: `2025-11-18T16:49:18.9245450Z`)
- ✓ Strips ANSI color codes
- ✓ Preserves original log line indentation
- ✓ UTF-8 output encoding

#### Usage

```powershell
# Convert manually copied Azure DevOps raw log to clean format
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

2. **Parse and Display Summary**
   ```yaml
   - task: PowerShell@2
     displayName: 'Display Plan Summary'
     inputs:
       filePath: 'scripts/Get-TerraformPlanReport.ps1'
       arguments: '-LogFile terraform_plan.log -ShowChanges'
   ```

**Note**: The output from `terraform plan -no-color` is already compatible with the parser. You only need `Convert-AzDevOpsLog.ps1` if you manually copy/paste logs from Azure DevOps "View Raw Log" interface.

### Local Development

```powershell
# Direct Terraform plan output (no conversion needed)
terraform plan -no-color > tfplan.out
.\Get-TerraformPlanReport.ps1 -LogFile tfplan.out -ShowChanges

# If you manually copied logs from Azure DevOps "View Raw Log"
.\Convert-AzDevOpsLog.ps1 -InputFile .\azdo_raw_log.txt -OutputFile .\tfplan_clean.out
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan_clean.out
```

## Sample Files

The repository includes sample files for testing:

- `plan.mine` - Sample manually copied Azure DevOps raw log with timestamps and ANSI codes
- `plan1.mine` - Cleaned version suitable for parsing (after running Convert-AzDevOpsLog.ps1)

## Requirements

- PowerShell 5.1 or higher
- No external dependencies

## How It Works

### Parsing Logic

The parser:
1. Reads the log file line by line
2. Strips ANSI color codes and timestamps using regex patterns
3. Identifies resource action lines matching patterns:
   - `# <resource_name> will be <action>` (created, destroyed, updated, replaced)
   - `# <resource_name> must be replaced`
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
