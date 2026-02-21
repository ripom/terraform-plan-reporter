# Terraform Plan Parser

![Version](https://img.shields.io/badge/version-1.7.0-blue)

A PowerShell-based tool to parse and humanize Terraform plan output, making it easier to identify which resources will be impacted by infrastructure changes.

> **Current Version:** 1.7.0 — See [version.json](version.json) for full release history.

## Prerequisites

- **PowerShell 7.0** or later is required. You can download it from [https://github.com/PowerShell/PowerShell](https://github.com/PowerShell/PowerShell).

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

- ✓ Categorizes resources by action type (Import, Create, Update, Destroy, Replace)
- ✓ Color-coded output for easy visual scanning
- ✓ Attribute change display for Update/Replace resources with color-coded diff
- ✓ Filtering by specific action types
- ✓ Filtering by resource category (Compute, Storage, Network, Database, Security, Monitoring)
- ✓ Filtering by resource name pattern (supports wildcards)
- ✓ Filtering by resource type (supports wildcards)
- ✓ Table view for listing all resources with Azure Name, Resource Group, and Subscription columns
- ✓ Intelligent insights: cost estimation, security impact, governance analysis
  - Cost Impact: Categorizes resources as High/Medium/Low cost with monthly estimates
  - Security Analysis: Detects security-sensitive changes and trends
  - Governance: Analyzes tags, naming conventions, policies, backup, RBAC, network isolation, and more
  - Naming Convention Detection: Validates Azure CAF naming standards against **actual Azure resource names** (not Terraform addresses)
  - **Carbon Emission Analysis**: Estimates CO2 emissions with regional carbon intensity and sustainability recommendations
- ✓ Automatic ANSI color code and timestamp removal
- ✓ Summary statistics at the end
- ✓ Self-update from GitHub with cumulative changelog display
- ✓ HTML report generation with embedded insights, executive summary, and comprehensive **legend/methodology** section
  - Collapsible sections for all report areas (Resources, Attribute Changes, Cost, Security, Carbon, Governance, Executive Summary, Legend)
  - Contextual info (&#x24D8;) icons on each section header with hover tooltips explaining colors, symbols, and methodology
  - Each section header includes an item count for at-a-glance overview
  - Executive Summary expanded by default; all other sections collapsed
  - Disclaimer noting that all insights are heuristic-based approximations, not exact billing/emission/audit data

#### Documentation

- How `-ShowInsights` works (heuristics, interpretation, false positives): `SHOW_INSIGHTS.md`

#### Usage

```powershell
# Basic usage - show all resource changes
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out

# Show detailed attribute changes with color-coded diff
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ShowChanges

# Show intelligent insights (cost, security, governance)
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ShowInsights

# Show insights and return a structured object (useful for automation)
$report = .\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ShowInsights -PassThru
$report.Insights.Security.Negative.Count

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

# Check for updates and self-update from GitHub
.\Get-TerraformPlanReport.ps1 -Update

# Generate a self-contained HTML report with auto-generated timestamped name
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -OutputHtml

# Generate HTML report with a custom filename
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -OutputHtml -OutputHtmlPath .\report.html

# Combine with filters for a targeted HTML report
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -Category Compute -OutputHtml
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
- **Naming Conventions**: Validates the **actual Azure resource name** (extracted from the plan's `name` attribute) rather than the Terraform address
  - Azure CAF prefixes (rg-, vnet-, vm-, kv-, etc.)
  - Environment indicators (-prod, -dev, -test, -staging, etc.)
  - Region indicators (-eastus, -westeurope, -northeurope, etc.)
  - Numbered instances (-01, -02, -v1, etc.)
  - Multi-segment structure (3+ hyphenated parts)
  - Excludes: policy/RBAC/management-group resources (governance objects), auto-generated names (UUIDs, timestamps)
- **Policies & Monitoring**: Azure Policy, monitoring resources
- **Backup & Retention**: Backup configurations, retention policies
- **Resource Locks**: Management locks for production resources
- **RBAC/IAM**: Role assignments and identity configurations
- **Network Isolation**: Private endpoints, VNet integration
- **Audit Logging**: Diagnostic settings, log analytics
- **Compliance Frameworks**: Security center, compliance policies (bulk `azapi_resource` matches are summarized with counts)
- **Cost Management**: Budgets, cost exports

> **Note:** All governance checks use type-aware matching against the Terraform resource type (not substring matching on the full address). For `azapi_resource`, the instance name part (e.g., `policy_assignments`, `role_definitions`) is checked against the pattern. Bulk matches from Azure Landing Zone plans are automatically grouped into summary entries (e.g., "132 azapi_resource.policy_role_assignments detected") to reduce noise.

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

**Carbon Emission Analysis**
- Estimates monthly CO2 emissions (kg CO2e) per resource
- Considers regional carbon intensity factors
  - Low carbon regions: Norway (~8 gCO2e/kWh), Sweden (~9), France (~56), Canada (~25)
  - High carbon regions: Australia (~640), South Africa (~890), India (~700)
- Provides sustainability recommendations
- Categorizes resources by carbon impact (High/Medium/Low)
- Tracks overall carbon footprint changes with color-coded direction indicators:
  - **Red (+)**: Increase in emissions (creating resources adds CO2)
  - **Green (-)**: Decrease in emissions (destroying resources reduces CO2)
  - **Gray (0)**: No change in emissions

Example output:
```
🌍 CARBON IMPACT ANALYSIS
   Monthly Carbon Footprint: Moderate Impact 🌡️🌡️ (+45.3 kg CO2e/mo)
   ⚠️  Estimates based on regional carbon intensity and resource utilization
   
   High Carbon Resources (2):
   • azurerm_virtual_machine.vm_prod [+High] Standard_D8s_v3 ≈ 34.0 kg CO2e/mo (eastus)
   • azurerm_kubernetes_cluster.aks [+High] ≈ 25.0 kg CO2e/mo (eastus)
   
   💡 Sustainability Recommendations:
   • Consider migrating to low-carbon regions (Norway, Sweden, France, Canada, Brazil)
   • Evaluate B-series burstable VMs for non-production workloads (up to 60% carbon reduction)
   • Enable auto-shutdown for dev/test VMs during non-business hours

📊 EXECUTIVE SUMMARY
   🌍 Carbon Footprint:
      Monthly Emissions Change: +51.5 kg CO2e/month (Red indicates increased environmental impact)
      Carbon-Emitting Resources: 40 (0 High, 2 Medium, 38 Low)
```

**Understanding Carbon Footprint Colors**:
The color coding reflects the **direction of environmental impact**, not severity:
- When deploying new infrastructure, you'll see red (+X kg CO2e/month) indicating additional carbon emissions
- When decommissioning infrastructure, you'll see green (-X kg CO2e/month) indicating carbon reduction
- This helps teams understand the environmental cost of infrastructure changes and make informed decisions

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `LogFile` | String | Yes | Path to the Terraform plan output file |
| `ShowChanges` | Switch | No | Display attribute changes in console output (changes are always captured; this controls console display only; HTML reports always include them; only Update/Replace diffs are shown) |
| `ShowInsights` | Switch | No | Display intelligent analysis of cost, security, and governance impacts |
| `TableAll` | Switch | No | Display all resources in a table format with Action, ResourceType, ResourceName, AzureName, ResourceGroup, and Subscription |
| `ListCreated` | Switch | No | Show only resources that will be created |
| `ListChanged` | Switch | No | Show only resources that will be updated |
| `ListDestroyed` | Switch | No | Show only resources that will be destroyed |
| `ListReplaced` | Switch | No | Show only resources that will be replaced |
| `Category` | String | No | Filter by category: Compute, Storage, Network, Database, Security, Monitoring, All |
| `ResourceName` | String | No | Filter by resource name pattern (supports wildcards, e.g., "*prod*") |
| `ResourceType` | String | No | Filter by resource type (supports wildcards, e.g., "azurerm_virtual_machine") |
| `PassThru` | Switch | No | Output a structured object with summary counts (and Insights when -ShowInsights is used) |
| `OutputHtml` | Switch | No | Generate a self-contained HTML report (default: timestamped filename, insights always included, auto-opens in browser) |
| `OutputHtmlPath` | String | No | Custom path for the HTML report file (only used with -OutputHtml) |
| `Update` | Switch | No | Check for updates from GitHub, show cumulative changes, and self-update |

#### Output Example

```
================================================================================

⇪ IMPORT: 1
  • azurerm_log_analytics_workspace.securitylaw

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
1 to import,
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

## Supported Resources

The script includes comprehensive coverage of **90+ Azure resources** across multiple categories with cost estimation, carbon footprint calculation, and security analysis.

### Azure Resources by Category

#### **Compute (16 resources)**
- Virtual Machines: `azurerm_virtual_machine`, `azurerm_windows_virtual_machine`, `azurerm_linux_virtual_machine`
- Container Services: `azurerm_kubernetes_cluster`, `azurerm_container_group`, `azurerm_container_registry`, `azurerm_container_app`, `azurerm_container_app_environment`
- App Services: `azurerm_app_service`, `azurerm_function_app`, `azurerm_linux_web_app`, `azurerm_windows_web_app`
- Scale & Batch: `azurerm_virtual_machine_scale_set`, `azurerm_batch_account`
- Integration: `azurerm_logic_app_workflow`
- Hosting: `azurerm_bastion_host`

#### **Database (12 resources)**
- SQL: `azurerm_sql_database`, `azurerm_mssql_database`, `azurerm_sql_managed_instance`
- PostgreSQL: `azurerm_postgresql_server`, `azurerm_postgresql_flexible_server`
- MySQL: `azurerm_mysql_server`, `azurerm_mysql_flexible_server`
- Other: `azurerm_mariadb_server`, `azurerm_cosmosdb_account`, `azurerm_redis_cache`, `azurerm_synapse_workspace`, `azurerm_databricks_workspace`

#### **Networking (23 resources)**
- Core: `azurerm_virtual_network`, `azurerm_subnet`, `azurerm_network_security_group`, `azurerm_network_interface`
- Load Balancing: `azurerm_lb`, `azurerm_application_gateway`, `azurerm_traffic_manager_profile`, `azurerm_traffic_manager_endpoint`
- Security: `azurerm_firewall`, `azurerm_firewall_policy`, `azurerm_web_application_firewall_policy`
- Gateways: `azurerm_vpn_gateway`, `azurerm_virtual_network_gateway`, `azurerm_local_network_gateway`, `azurerm_point_to_site_vpn_gateway`, `azurerm_nat_gateway`
- Front Door: `azurerm_front_door`, `azurerm_frontdoor_firewall_policy`
- DNS: `azurerm_dns_zone`, `azurerm_private_dns_zone`
- Virtual WAN: `azurerm_virtual_wan`, `azurerm_virtual_hub`
- Other: `azurerm_public_ip`, `azurerm_express_route_circuit`, `azurerm_route_table`, `azurerm_network_watcher`, `azurerm_private_endpoint`

#### **Storage (9 resources)**
- Accounts: `azurerm_storage_account`, `azurerm_data_lake_store`
- Sub-resources: `azurerm_storage_blob`, `azurerm_storage_container`, `azurerm_storage_queue`, `azurerm_storage_table`
- CDN: `azurerm_cdn_profile`, `azurerm_app_service_plan`

#### **Security & Identity (6 resources)**
- Key Vault: `azurerm_key_vault`, `azurerm_key_vault_secret`, `azurerm_key_vault_key`, `azurerm_key_vault_certificate`
- Policies: `azurerm_policy_assignment`, `azurerm_policy_definition`

#### **Monitoring & Logging (6 resources)**
- Insights: `azurerm_application_insights`, `azurerm_log_analytics_workspace`
- Monitoring: `azurerm_monitor_diagnostic_setting`, `azurerm_monitor_action_group`, `azurerm_monitor_metric_alert`, `azurerm_monitor_autoscale_setting`, `azurerm_monitor_scheduled_query_rules_alert`

#### **Backup & Recovery (6 resources)**
- Recovery Services: `azurerm_recovery_services_vault`, `azurerm_backup_policy_vm`, `azurerm_backup_protected_vm`
- Site Recovery: `azurerm_site_recovery_fabric`, `azurerm_site_recovery_replication_policy`, `azurerm_site_recovery_protection_container`

#### **Integration & Messaging (4 resources)**
- Messaging: `azurerm_service_bus_namespace`, `azurerm_eventhub_namespace`, `azurerm_eventgrid_topic`
- API: `azurerm_api_management`

#### **AI & Machine Learning (2 resources)**
- `azurerm_cognitive_account`
- `azurerm_machine_learning_workspace`

#### **Management (2 resources)**
- `azurerm_resource_group`
- `azurerm_management_lock`

### Azure Landing Zone (ALZ) Compliance
When the plan contains Azure Policy assignments from an ALZ/Enterprise-Scale deployment, the report categorizes them against well-known ALZ policy categories:
- **Security**: Deny-MgmtPorts-Internet, Deny-Public-IP, Deploy-MDFC, Enforce-TLS-SSL
- **Identity**: Deny-Public-IP, Deny-Subnet-Without-Nsg
- **Networking**: Deploy-Private-DNS-Zones, Enforce-Subnet-Private, Deploy-Nsg-FlowLogs
- **Logging**: Deploy-AzActivity-Log, Enable-AllLogs-to-law, Deploy-Diag-LogsCat
- **Monitoring**: Deploy-VM-Monitoring, Deploy-VM-ChangeTrack, Enable-AUM-CheckUpdates
- **DataProtection**: Deploy-VM-Backup, Deploy-SQL-TDE, Deploy-SQL-Threat, Deploy-MDFC-SqlAtp
- **Compliance**: allowed_locations, Deny-Classic-Resources, Audit-ZoneResiliency
- **KeyManagement**: Enforce-GR-KeyVault
- **Storage**: Deny-Storage-http

The script provides:
- ✅ **Cost estimation** with monthly USD approximations
- ✅ **Carbon footprint** calculation with regional intensity factors
- ✅ **Security analysis** for sensitive attributes
- ✅ **Governance scoring** with ALZ compliance validation

**Note:** If you need support for additional resources, please open an issue or submit a pull request!

## How It Works

### Parsing Logic

The parser:
1. Reads the log file line by line
2. Strips ANSI color codes and timestamps using regex patterns
3. Identifies resource action lines matching patterns:
   - `# <resource_name> will be <action>` (created, destroyed, updated, replaced)
   - `# <resource_name> must be replaced`
4. Always captures attribute changes for each resource (only Update/Replace diffs are displayed; Create/Destroy show full attribute dumps and are excluded)
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

## Version History

See [version.json](version.json) for the complete version history with detailed changelogs.

| Version | Date       | Description                                     |
|---------|------------|-------------------------------------------------|
| 1.7.0   | 2026-02-19 | Self-update, HTML report with info tooltips & disclaimer, module resource type fix |
| 1.6.0   | 2026-01-23 | Import parsing support                          |
| 1.5.0   | 2025-11-23 | Extended resource support                       |
| 1.4.0   | 2025-11-22 | Carbon footprint analysis and destroy logic fix |
| 1.3.0   | 2025-11-21 | Insights, filters, and governance analysis      |
| 1.1.0   | 2025-11-19 | Replace scenario and documentation improvements|
| 1.0.0   | 2025-11-19 | Initial release                                 |

## License

This project is provided as-is for use in Terraform workflows.
