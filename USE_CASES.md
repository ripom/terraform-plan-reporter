# Terraform Plan Reporter - Use Cases & Examples

This document provides practical scenarios and examples for using the Terraform Plan Reporter in real-world situations.

---

## Table of Contents

1. [Basic Reporting](#basic-reporting)
2. [Cost Analysis](#cost-analysis)
3. [Security Review](#security-review)
4. [Governance & Compliance](#governance--compliance)
5. [Team Collaboration](#team-collaboration)
6. [CI/CD Pipeline Integration](#cicd-pipeline-integration)
7. [Troubleshooting & Debugging](#troubleshooting--debugging)
8. [Advanced Filtering](#advanced-filtering)

---

## Basic Reporting

### Scenario 1: Quick Overview of All Changes

**Situation**: You need a quick summary of what will change in your infrastructure.

```powershell
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out
```

**Output**:
```
✓ CREATE: 5
  • azurerm_resource_group.rg_example
  • azurerm_virtual_network.vnet_example
  ...

≈ UPDATE: 2
  • azurerm_storage_account.storage
  ...

Plan: 5 to add, 2 to change, 0 to destroy.
```

**Use When**: 
- Initial plan review
- Daily development work
- Quick status checks

---

### Scenario 2: Detailed Change Analysis

**Situation**: You need to see exactly what attributes are changing in each resource.

```powershell
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ShowChanges
```

**Output**: Shows color-coded attribute changes:
- `+` (Green): Additions
- `-` (Red): Deletions
- `~` (Yellow): Modifications

**Use When**:
- Code reviews
- Debugging unexpected changes
- Compliance audits

---

### Scenario 3: List All Resources in Table Format

**Situation**: You need a spreadsheet-like view of all resources.

```powershell
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -TableAll
```

**Output**:
```
Action     ResourceType                    ResourceName
------     ------------                    ------------
Create     azurerm_virtual_machine         web_vm[0]
Update     azurerm_storage_account         storage_prod
Destroy    azurerm_public_ip              old_ip
```

**Use When**:
- Generating documentation
- Creating change tickets
- Team status reports

---

## Cost Analysis

### Scenario 4: Estimate Infrastructure Costs

**Situation**: Finance needs to understand the cost impact of changes.

```powershell
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ShowInsights
```

**Output**:
```
💰 COST IMPACT ANALYSIS
   Overall Impact: Moderate Increase 💰💰 (+$420/mo)
   
   High Cost Resources (3):
   • azurerm_windows_virtual_machine.app_vm [+High] Standard_D4s_v3 ≈ $140/mo
   • azurerm_kubernetes_cluster.aks [+High] ≈ $73/mo
   ...
```

**Use When**:
- Budget planning
- Cost optimization reviews
- Monthly forecasting
- Approval workflows

---

### Scenario 5: Review Only High-Cost Resources

**Situation**: Focus on resources that significantly impact the budget.

```powershell
# Show only VMs and databases being created
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -Category Compute -ListCreated -ShowInsights
```

**Use When**:
- Cost approval process
- Resource optimization
- Capacity planning

---

## Security Review

### Scenario 6: Security Impact Analysis

**Situation**: Security team needs to review security-related changes.

```powershell
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ShowInsights
```

**Output**:
```
🔒 SECURITY IMPACT ANALYSIS
   Security Trend: Improved ✓
   
   ✓ Security Improvements (2):
   • azurerm_storage_account.data - Improved: enable_https_traffic_only
   • azurerm_key_vault.secrets - Improved: encryption
   
   ⚠ Security Concerns (1):
   • azurerm_network_security_group.frontend - Risk: source_address_prefix = "0.0.0.0/0"
```

**Use When**:
- Security audits
- Compliance reviews
- Change approval process
- Incident prevention

---

### Scenario 7: Review Security Resources

**Situation**: Audit all security-related infrastructure changes.

```powershell
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -Category Security -ShowChanges -ShowInsights
```

**Shows**: Key vaults, NSGs, firewalls, policies, identities

**Use When**:
- Security hardening projects
- Penetration test remediation
- SOC2/ISO27001 audits

---

## Governance & Compliance

### Scenario 8: Governance Score Analysis

**Situation**: Compliance team needs to track governance posture.

```powershell
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ShowInsights
```

**Output**:
```
📋 GOVERNANCE & COMPLIANCE ANALYSIS
   Governance Score: 7/12
   Breakdown:
   • Tags: ✓ +1
   • Naming: ✓ +1
   • Policies/Monitoring: ✓ +1
   • Backup/Retention: ✓ +1
   • Resource Locks: ✗ +0
   • RBAC/IAM: ✓ +1
   • Network Isolation: ✓ +2
   • Audit Logging: ✗ +0
   • Compliance Frameworks: ✗ +0
   • Cost Management: ✗ +0
```

**Use When**:
- Compliance audits
- Governance maturity assessments
- Policy enforcement
- Risk management

---

### Scenario 9: Ensure Proper Tagging

**Situation**: Verify all production resources have proper tags.

```powershell
# Check for tagged resources in production
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ResourceName "*prod*" -ShowInsights
```

**Use When**:
- Tag policy enforcement
- Cost allocation tracking
- Resource ownership verification

---

## Team Collaboration

### Scenario 10: Code Review - Focus on Destroyed Resources

**Situation**: Reviewer wants to ensure no critical resources are being deleted.

```powershell
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ListDestroyed -ShowChanges
```

**Use When**:
- Pull request reviews
- Production deployments
- Disaster prevention

---

### Scenario 11: Track Database Changes

**Situation**: DBA needs to review all database-related changes before deployment.

```powershell
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -Category Database -ShowChanges -ShowInsights
```

**Shows**: SQL databases, Cosmos DB, Redis, PostgreSQL, MySQL

**Use When**:
- Database change approval
- Data integrity reviews
- Performance impact analysis

---

### Scenario 12: Network Team Review

**Situation**: Network team needs to approve firewall and connectivity changes.

```powershell
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -Category Network -ListCreated -ListDestroyed -ShowChanges
```

**Shows**: VNets, subnets, NSGs, firewalls, load balancers, gateways

**Use When**:
- Network change requests
- Security rule reviews
- Connectivity planning

---

## CI/CD Pipeline Integration

### Scenario 13: Azure DevOps Pipeline - Basic Report

**Situation**: Display plan summary in pipeline logs.

**Pipeline YAML**:
```yaml
- task: PowerShell@2
  displayName: 'Terraform Plan'
  inputs:
    targetType: 'inline'
    script: |
      terraform plan -no-color | Tee-Object -FilePath terraform_plan.log

- task: PowerShell@2
  displayName: 'Display Plan Summary'
  inputs:
    targetType: 'filePath'
    filePath: '$(System.DefaultWorkingDirectory)/scripts/Get-TerraformPlanReport.ps1'
    arguments: '-LogFile $(System.DefaultWorkingDirectory)/terraform_plan.log'
```

**Note**: Adjust `scripts/` path to match where you store the script in your repository.

---

### Scenario 14: Azure DevOps Pipeline - With Insights

**Situation**: Generate comprehensive report with cost and security analysis.

**Pipeline YAML**:
```yaml
- task: PowerShell@2
  displayName: 'Generate Plan Report with Insights'
  inputs:
    targetType: 'filePath'
    filePath: '$(System.DefaultWorkingDirectory)/scripts/Get-TerraformPlanReport.ps1'
    arguments: '-LogFile $(System.DefaultWorkingDirectory)/terraform_plan.log -ShowInsights'
```

---

### Scenario 15: Pipeline - Fail on Destructive Changes

**Situation**: Automatically fail pipeline if resources will be destroyed.

**Pipeline YAML**:
```yaml
- task: PowerShell@2
  displayName: 'Check for Destructive Changes'
  inputs:
    targetType: 'inline'
    script: |
      # Run report and capture output
      $report = & "$(System.DefaultWorkingDirectory)/scripts/Get-TerraformPlanReport.ps1" `
        -LogFile "$(System.DefaultWorkingDirectory)/terraform_plan.log" `
        -ListDestroyed
      
      # Check if any resources will be destroyed
      if ($report -match "DESTROY:") {
          Write-Host "##vso[task.logissue type=error]Resources will be destroyed!"
          Write-Host "##vso[task.complete result=Failed;]STOPPED: Destructive changes detected"
          exit 1
      } else {
          Write-Host "✓ No destructive changes detected"
      }
```

---

### Scenario 16: Pipeline - Cost Gate

**Situation**: Fail pipeline if monthly cost increase exceeds threshold.

**Pipeline YAML**:
```yaml
- task: PowerShell@2
  displayName: 'Cost Impact Gate'
  inputs:
    targetType: 'inline'
    script: |
      # Generate insights report
      $report = & "$(System.DefaultWorkingDirectory)/scripts/Get-TerraformPlanReport.ps1" `
        -LogFile "$(System.DefaultWorkingDirectory)/terraform_plan.log" `
        -ShowInsights | Out-String
      
      # Extract cost increase
      if ($report -match '\+\$(\d+)/mo') {
          $increase = [int]$Matches[1]
          Write-Host "Estimated monthly cost increase: +`$$increase"
          
          if ($increase -gt 500) {
              Write-Host "##vso[task.logissue type=warning]High cost increase detected: +`$$increase/month"
              Write-Host "##vso[task.logissue type=warning]Manual approval required for increases over `$500/month"
              # Optionally fail the pipeline
              # exit 1
          }
      }
```

---

### Scenario 17: GitHub Actions Pipeline

**Situation**: Use the script in GitHub Actions workflow.

**Workflow YAML** (`.github/workflows/terraform.yml`):
```yaml
name: Terraform Plan Review

on: [pull_request]

jobs:
  terraform-plan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Terraform
      uses: hashicorp/setup-terraform@v2
    
    - name: Terraform Plan
      run: |
        terraform init
        terraform plan -no-color | tee terraform_plan.log
    
    - name: Generate Plan Report
      shell: pwsh
      run: |
        ./scripts/Get-TerraformPlanReport.ps1 -LogFile terraform_plan.log -ShowInsights
    
    - name: Upload Plan Report
      uses: actions/upload-artifact@v3
      with:
        name: terraform-plan-report
        path: terraform_plan.log
```

---

## Troubleshooting & Debugging

### Scenario 17: Find Why Resource is Being Replaced

**Situation**: Unexpected resource replacement needs investigation.

```powershell
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ListReplaced -ShowChanges
```

**Output**: Shows exactly which attributes are forcing replacement

**Use When**:
- Debugging Terraform behavior
- Understanding resource lifecycles
- Avoiding downtime

---

### Scenario 18: Track Specific Resource

**Situation**: Monitor a specific resource across multiple plan runs.

```powershell
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ResourceName "azurerm_virtual_machine.critical_vm" -ShowChanges
```

**Use When**:
- Troubleshooting specific resource issues
- Monitoring critical infrastructure
- Change tracking

---

## Advanced Filtering

### Scenario 19: Production Storage Changes Only

**Situation**: Review only storage resources in production environment.

```powershell
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -Category Storage -ResourceName "*prod*" -ShowInsights
```

---

### Scenario 20: All VMs Being Created or Destroyed

**Situation**: Capacity planning needs to track VM lifecycle.

```powershell
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ResourceType "*virtual_machine*" -ListCreated -ListDestroyed -TableAll
```

---

### Scenario 21: Security Resources with Changes

**Situation**: Audit all security-related updates.

```powershell
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -Category Security -ListChanged -ShowChanges
```

---

### Scenario 22: Network Resources by Type

**Situation**: Review specific network resource types.

```powershell
# Show only Network Security Groups
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ResourceType "azurerm_network_security_group" -TableAll

# Show all private endpoints
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ResourceType "*private_endpoint*" -ShowChanges
```

---

### Scenario 23: Multi-Filter Complex Query

**Situation**: Very specific filtering for precise analysis.

```powershell
# Show created compute resources in production with insights
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out `
    -Category Compute `
    -ResourceName "*prod*" `
    -ListCreated `
    -ShowInsights `
    -ShowChanges
```

---

## Quick Reference Commands

### Daily Development
```powershell
# Quick overview
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out

# Detailed review
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ShowChanges
```

### Code Reviews
```powershell
# Full analysis
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ShowChanges -ShowInsights

# Check for deletions
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ListDestroyed -ShowChanges
```

### Financial Reviews
```powershell
# Cost analysis
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ShowInsights

# High-cost resources only
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -Category Compute -ShowInsights
```

### Security Audits
```powershell
# Security review
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -Category Security -ShowInsights -ShowChanges

# Governance check
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ShowInsights
```

### Documentation
```powershell
# Export table to file
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -TableAll > changes.txt

# Specific category report
.\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -Category Database -TableAll
```

---

## Tips & Best Practices

1. **Always use `-ShowInsights`** for production deployments
2. **Use `-TableAll`** when generating documentation or tickets
3. **Combine filters** for targeted analysis
4. **Review with `-ListDestroyed`** before approving destructive changes
5. **Track costs** with regular `-ShowInsights` reports
6. **Use wildcards** for flexible filtering (`*prod*`, `*vm*`)
7. **Integrate into CI/CD** for automated change validation
8. **Share reports** with stakeholders using `-TableAll > report.txt`
9. **Monitor governance scores** to improve infrastructure maturity
10. **Document patterns** that work for your team's workflow

---

## Support

For issues or feature requests, please open an issue in the repository.
