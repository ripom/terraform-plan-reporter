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

.PARAMETER ListReplaced
    Optional switch to show only resources that will be replaced.

.PARAMETER ShowInsights
    Optional switch to display intelligent analysis of cost, security, and governance impacts.

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
    [switch]$ListDestroyed,
    
    [Parameter(Mandatory=$false)]
    [switch]$ListReplaced,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowInsights
)

# Knowledge base for intelligent insights
$knowledgeBase = @{
    # Cost-impacting resources (High/Medium/Low) with approximate monthly costs in USD
    CostResources = @{
        High = @(
            'azurerm_virtual_machine', 'azurerm_windows_virtual_machine', 'azurerm_linux_virtual_machine',
            'azurerm_kubernetes_cluster', 'azurerm_app_service', 'azurerm_function_app',
            'azurerm_sql_database', 'azurerm_mssql_database', 'azurerm_cosmosdb_account',
            'azurerm_synapse_workspace', 'azurerm_databricks_workspace',
            'azurerm_application_gateway', 'azurerm_firewall', 'azurerm_vpn_gateway',
            'aws_instance', 'aws_rds_instance', 'aws_eks_cluster', 'aws_ecs_cluster',
            'google_compute_instance', 'google_container_cluster', 'google_sql_database_instance'
        )
        Medium = @(
            'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_lb', 'azurerm_nat_gateway',
            'azurerm_redis_cache', 'azurerm_app_service_plan', 'azurerm_cdn_profile',
            'azurerm_virtual_network_gateway', 'azurerm_express_route_circuit',
            'aws_s3_bucket', 'aws_ebs_volume', 'aws_elasticache_cluster', 'aws_elb',
            'google_storage_bucket', 'google_compute_disk'
        )
        Low = @(
            'azurerm_resource_group', 'azurerm_virtual_network', 'azurerm_subnet',
            'azurerm_network_security_group', 'azurerm_key_vault', 'azurerm_log_analytics_workspace',
            'aws_vpc', 'aws_subnet', 'aws_security_group', 'aws_iam_role',
            'google_compute_network', 'google_compute_subnetwork'
        )
    }
    
    # Cost estimation patterns (approximate monthly USD)
    CostEstimation = @{
        # Azure VM sizes
        VMSizes = @{
            'Standard_B1s' = 8; 'Standard_B2s' = 30; 'Standard_B4ms' = 120
            'Standard_D2s_v3' = 70; 'Standard_D4s_v3' = 140; 'Standard_D8s_v3' = 280
            'Standard_D16s_v3' = 560; 'Standard_D32s_v3' = 1120
            'Standard_E2s_v3' = 110; 'Standard_E4s_v3' = 220; 'Standard_E8s_v3' = 440
            'Standard_F2s_v2' = 68; 'Standard_F4s_v2' = 136; 'Standard_F8s_v2' = 272
            't2.micro' = 8; 't2.small' = 17; 't2.medium' = 33; 't2.large' = 67
            't3.micro' = 7; 't3.small' = 15; 't3.medium' = 30; 't3.large' = 60
            'm5.large' = 70; 'm5.xlarge' = 140; 'm5.2xlarge' = 280
            'e2-micro' = 6; 'e2-small' = 12; 'e2-medium' = 24; 'e2-standard-2' = 49
        }
        # Storage accounts
        Storage = @{
            'Standard_LRS' = 20; 'Standard_GRS' = 40; 'Premium_LRS' = 135
        }
        # Other services (base costs)
        Services = @{
            'azurerm_kubernetes_cluster' = 73        # Control plane
            'azurerm_application_gateway' = 125      # Gateway hours + capacity
            'azurerm_firewall' = 1000                # Premium tier
            'azurerm_vpn_gateway' = 140              # VpnGw1
            'azurerm_bastion_host' = 140             # Basic SKU
            'azurerm_public_ip' = 3                  # Static IP
            'azurerm_sql_database' = 15              # Basic tier minimum
            'azurerm_mssql_database' = 15            # Basic tier minimum
            'azurerm_redis_cache' = 15               # Basic C0
            'azurerm_cosmosdb_account' = 25          # 400 RU/s minimum
            'aws_eks_cluster' = 73
            'aws_rds_instance' = 15                  # db.t3.micro
            'aws_elasticache_cluster' = 12
            'google_container_cluster' = 73
            'google_sql_database_instance' = 10
        }
    }
    
    # Security-sensitive attributes and resources
    SecurityIndicators = @{
        Critical = @(
            'public_network_access_enabled', 'public_access', 'publicly_accessible',
            'enable_ip_forwarding', 'source_address_prefix = "0.0.0.0/0"', 'source_address_prefix = "*"',
            'min_tls_version', 'enable_https_traffic_only', 'encryption', 'encrypted',
            'firewall_', 'security_rule', 'network_security_group', 'access_policy',
            'enable_rbac', 'identity', 'key_vault', 'certificate', 'secret',
            'password', 'ssh_key', 'admin_', 'administrator_login'
        )
        PositiveKeywords = @('enabled', 'enforce', 'required', 'true', '1.2', 'AES256', 'encrypted')
        NegativeKeywords = @('disabled', 'false', 'none', '0.0.0.0/0', '*', 'public', 'allow_all')
    }
    
    # Governance and compliance indicators
    GovernanceIndicators = @{
        Tags = @('tags', 'tag =', 'cost_center', 'environment', 'owner', 'project', 'compliance')
        Naming = @('name =', 'naming_convention', 'prefix', 'suffix')
        Policies = @('policy', 'compliance', 'audit', 'diagnostic_setting', 'log_analytics', 'monitoring')
        Backup = @('backup', 'retention', 'geo_redundant', 'replication')
        Locks = @('azurerm_management_lock', 'aws_resourcegroups_resource', 'can_not_delete', 'read_only_lock', 'delete_lock')
        RBAC = @('role_assignment', 'role_definition', 'iam_policy', 'iam_role', 'principal_id', 'scope_id')
        NetworkIsolation = @('private_endpoint', 'service_endpoint', 'private_link_service', 'network_acl', 'private_dns_zone_group')
        AuditLogging = @('log_analytics_workspace', 'diagnostic_setting', 'activity_log_alert', 'log_retention_days')
        ComplianceFrameworks = @('policy_assignment', 'policy_definition', 'aws_config_rule', 'security_center_subscription', 'defender_for_cloud')
        CostManagement = @('consumption_budget', 'cost_management_export', 'aws_budgets_budget', 'spending_limit')
    }
}

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
    # Capture all content within the resource block when ShowChanges is enabled
    elseif ($ShowChanges -and $captureChanges) {
        # Stop capturing when we hit another resource or end of resource block
        if ($cleanLine -match '^\s*#\s+' -or $cleanLine -match '^\s*$') {
            # Don't stop on comment lines within the resource
            if ($cleanLine -match '^\s*#\s+\(.*\)') {
                continue
            }
            # Empty line might signal end of resource block in some cases
            # but we'll continue to be safe
        }
        
        # Capture the entire line with its change indicator
        if ($cleanLine -match '^\s+([+~-])\s+(.+)') {
            $changeType = $matches[1]
            $changeDetail = $matches[2]
            
            # Skip lines that start with "resource", "data", or "body"
            if ($changeDetail -match '^(resource|data)\s+"' -or $changeDetail -match '^body\s+') {
                continue
            }
            
            # Store the change with its type for color coding later
            $changes += [PSCustomObject]@{
                Type = $changeType
                Line = "`e[3m    $changeType $changeDetail`e[23m"  # ANSI escape codes for italic
            }
        }
        # Also capture lines without change indicators (context lines)
        elseif ($cleanLine -match '^\s{2,}(.+)' -and $cleanLine -notmatch '^\s*#' -and $cleanLine.Trim() -ne '') {
            $content = $matches[1]
            # Skip "body" and resource declaration lines
            if ($content -notmatch '^(resource|data|body)\s+') {
                $changes += [PSCustomObject]@{
                    Type = ' '
                    Line = "`e[3m      $content`e[23m"  # ANSI escape codes for italic
                }
            }
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
    if ($ListCreated -or $ListChanged -or $ListDestroyed -or $ListReplaced) {
        if ($ListCreated) { $actionsToShow += "Create" }
        if ($ListChanged) { $actionsToShow += "Update" }
        if ($ListDestroyed) { $actionsToShow += "Destroy" }
        if ($ListReplaced) { $actionsToShow += "Replace" }
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
                    # Color code based on change type
                    $changeColor = switch ($change.Type) {
                        '+' { "DarkGreen" }   # Additions in dark green
                        '-' { "DarkRed" }     # Deletions in dark red
                        '~' { "DarkYellow" }  # Changes in dark yellow
                        default { "Gray" }    # Context lines in gray
                    }
                    Write-Host $change.Line -ForegroundColor $changeColor
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
    
    # Generate insights if requested
    if ($ShowInsights) {
        Write-Host "================================================================================`n" -ForegroundColor Cyan
        Write-Host "📊 INTELLIGENT INSIGHTS" -ForegroundColor Cyan
        Write-Host "================================================================================`n" -ForegroundColor Cyan
        
        $insights = @{
            Cost = @{
                High = @()
                Medium = @()
                Low = @()
                EstimatedImpact = "Unknown"
                MonthlyEstimate = 0
                Details = @()
            }
            Security = @{
                Positive = @()
                Negative = @()
                Neutral = @()
                OverallTrend = "Neutral"
            }
            Governance = @{
                Tags = @()
                Naming = @()
                Policies = @()
                Backup = @()
                Locks = @()
                RBAC = @()
                NetworkIsolation = @()
                AuditLogging = @()
                ComplianceFrameworks = @()
                CostManagement = @()
            }
        }
        
        # Analyze each resource
        foreach ($item in $results) {
            $resourceType = ($item.Resource -split '\.')[0]
            $changesText = ($item.Changes | ForEach-Object { $_.Line }) -join ' '
            
            # === COST ANALYSIS ===
            if ($knowledgeBase.CostResources.High -contains $resourceType) {
                $impact = switch ($item.Action) {
                    "Create" { "+High" }
                    "Destroy" { "-High" }
                    "Replace" { "~High" }
                    "Update" { "≈High" }
                    default { "High" }
                }
                
                # Try to estimate cost
                $estimatedCost = 0
                $costDetail = ""
                
                # Check for VM size
                if ($resourceType -match 'virtual_machine|instance') {
                    foreach ($sizePattern in $knowledgeBase.CostEstimation.VMSizes.Keys) {
                        if ($changesText -match [regex]::Escape($sizePattern)) {
                            $estimatedCost = $knowledgeBase.CostEstimation.VMSizes[$sizePattern]
                            $costDetail = "$sizePattern ≈ `$$estimatedCost/mo"
                            break
                        }
                    }
                    if ($estimatedCost -eq 0) {
                        $estimatedCost = 70  # Default medium VM
                        $costDetail = "≈ `$70-200/mo"
                    }
                }
                # Check for known services
                elseif ($knowledgeBase.CostEstimation.Services.ContainsKey($resourceType)) {
                    $estimatedCost = $knowledgeBase.CostEstimation.Services[$resourceType]
                    $costDetail = "≈ `$$estimatedCost/mo"
                }
                else {
                    $estimatedCost = 100  # Default high-cost estimate
                    $costDetail = "≈ `$100-500/mo"
                }
                
                # Adjust for action type
                $costImpact = switch ($item.Action) {
                    "Create" { $estimatedCost }
                    "Destroy" { -$estimatedCost }
                    "Replace" { 0 }  # Replacement doesn't change monthly cost
                    "Update" { 0 }   # Update in-place doesn't change monthly cost
                    default { 0 }
                }
                
                $insights.Cost.MonthlyEstimate += $costImpact
                $insights.Cost.High += "$($item.Resource) [$impact] $costDetail"
                $insights.Cost.Details += [PSCustomObject]@{
                    Resource = $item.Resource
                    Action = $item.Action
                    MonthlyCost = $estimatedCost
                    Impact = $costImpact
                }
            }
            elseif ($knowledgeBase.CostResources.Medium -contains $resourceType) {
                $impact = switch ($item.Action) {
                    "Create" { "+Medium" }
                    "Destroy" { "-Medium" }
                    "Replace" { "~Medium" }
                    "Update" { "≈Medium" }
                    default { "Medium" }
                }
                
                $estimatedCost = 0
                $costDetail = ""
                
                # Check for storage account SKU
                if ($resourceType -match 'storage') {
                    foreach ($sku in $knowledgeBase.CostEstimation.Storage.Keys) {
                        if ($changesText -match [regex]::Escape($sku)) {
                            $estimatedCost = $knowledgeBase.CostEstimation.Storage[$sku]
                            $costDetail = "$sku ≈ `$$estimatedCost/mo"
                            break
                        }
                    }
                    if ($estimatedCost -eq 0) {
                        $estimatedCost = 20
                        $costDetail = "≈ `$20-100/mo"
                    }
                }
                # Check for known services
                elseif ($knowledgeBase.CostEstimation.Services.ContainsKey($resourceType)) {
                    $estimatedCost = $knowledgeBase.CostEstimation.Services[$resourceType]
                    $costDetail = "≈ `$$estimatedCost/mo"
                }
                else {
                    $estimatedCost = 30
                    $costDetail = "≈ `$20-100/mo"
                }
                
                $costImpact = switch ($item.Action) {
                    "Create" { $estimatedCost }
                    "Destroy" { -$estimatedCost }
                    "Replace" { 0 }
                    "Update" { 0 }   # Update in-place doesn't change monthly cost
                    default { 0 }
                }
                
                $insights.Cost.MonthlyEstimate += $costImpact
                $insights.Cost.Medium += "$($item.Resource) [$impact] $costDetail"
                $insights.Cost.Details += [PSCustomObject]@{
                    Resource = $item.Resource
                    Action = $item.Action
                    MonthlyCost = $estimatedCost
                    Impact = $costImpact
                }
            }
            elseif ($knowledgeBase.CostResources.Low -contains $resourceType) {
                $impact = switch ($item.Action) {
                    "Create" { "+Low" }
                    "Destroy" { "-Low" }
                    "Replace" { "~Low" }
                    "Update" { "≈Low" }
                    default { "Low" }
                }
                
                $estimatedCost = 5
                $costDetail = "≈ `$0-20/mo"
                
                $costImpact = switch ($item.Action) {
                    "Create" { $estimatedCost }
                    "Destroy" { -$estimatedCost }
                    "Replace" { 0 }
                    "Update" { 0 }   # Update in-place doesn't change monthly cost
                    default { 0 }
                }
                
                $insights.Cost.MonthlyEstimate += $costImpact
                $insights.Cost.Low += "$($item.Resource) [$impact] $costDetail"
                $insights.Cost.Details += [PSCustomObject]@{
                    Resource = $item.Resource
                    Action = $item.Action
                    MonthlyCost = $estimatedCost
                    Impact = $costImpact
                }
            }
            
            # === SECURITY ANALYSIS ===
            $securityRelevant = $false
            $securityImprovement = 0
            
            foreach ($indicator in $knowledgeBase.SecurityIndicators.Critical) {
                if ($changesText -match [regex]::Escape($indicator) -or $item.Resource -match $indicator) {
                    $securityRelevant = $true
                    
                    # Check if it's a positive or negative change
                    $positiveMatch = $false
                    $negativeMatch = $false
                    
                    foreach ($positive in $knowledgeBase.SecurityIndicators.PositiveKeywords) {
                        if ($changesText -match [regex]::Escape($positive)) {
                            $positiveMatch = $true
                            break
                        }
                    }
                    
                    foreach ($negative in $knowledgeBase.SecurityIndicators.NegativeKeywords) {
                        if ($changesText -match [regex]::Escape($negative)) {
                            $negativeMatch = $true
                            break
                        }
                    }
                    
                    if ($positiveMatch -and -not $negativeMatch) {
                        $insights.Security.Positive += "$($item.Resource) - Improved: $indicator"
                        $securityImprovement += 1
                    }
                    elseif ($negativeMatch) {
                        $insights.Security.Negative += "$($item.Resource) - Risk: $indicator"
                        $securityImprovement -= 1
                    }
                    else {
                        $insights.Security.Neutral += "$($item.Resource) - Modified: $indicator"
                    }
                    break
                }
            }
            
            # === GOVERNANCE ANALYSIS ===
            $tagMatch = $false
            foreach ($tag in $knowledgeBase.GovernanceIndicators.Tags) {
                if ($changesText -match [regex]::Escape($tag) -or $item.Resource -match $tag) {
                    if (-not $tagMatch) {
                        $insights.Governance.Tags += "$($item.Resource) - Tags modified"
                        $tagMatch = $true
                    }
                    break
                }
            }
            
            $namingMatch = $false
            foreach ($naming in $knowledgeBase.GovernanceIndicators.Naming) {
                if ($changesText -match [regex]::Escape($naming)) {
                    if (-not $namingMatch) {
                        $insights.Governance.Naming += "$($item.Resource) - Naming convention applied"
                        $namingMatch = $true
                    }
                    break
                }
            }
            
            $policyMatch = $false
            foreach ($policy in $knowledgeBase.GovernanceIndicators.Policies) {
                if ($changesText -match [regex]::Escape($policy) -or $item.Resource -match $policy) {
                    if (-not $policyMatch) {
                        $insights.Governance.Policies += "$($item.Resource) - Policy/Compliance related"
                        $policyMatch = $true
                    }
                    break
                }
            }
            
            $backupMatch = $false
            foreach ($backup in $knowledgeBase.GovernanceIndicators.Backup) {
                if ($changesText -match [regex]::Escape($backup)) {
                    if (-not $backupMatch) {
                        $insights.Governance.Backup += "$($item.Resource) - Backup/Retention configured"
                        $backupMatch = $true
                    }
                    break
                }
            }
            
            $lockMatch = $false
            foreach ($lock in $knowledgeBase.GovernanceIndicators.Locks) {
                if ($changesText -match [regex]::Escape($lock) -or $item.Resource -match $lock) {
                    if (-not $lockMatch) {
                        $insights.Governance.Locks += "$($item.Resource) - Resource lock configured"
                        $lockMatch = $true
                    }
                    break
                }
            }
            
            $rbacMatch = $false
            foreach ($rbac in $knowledgeBase.GovernanceIndicators.RBAC) {
                if ($changesText -match [regex]::Escape($rbac) -or $item.Resource -match $rbac) {
                    if (-not $rbacMatch) {
                        $insights.Governance.RBAC += "$($item.Resource) - RBAC/IAM configured"
                        $rbacMatch = $true
                    }
                    break
                }
            }
            
            $networkMatch = $false
            foreach ($network in $knowledgeBase.GovernanceIndicators.NetworkIsolation) {
                if ($changesText -match [regex]::Escape($network) -or $item.Resource -match $network) {
                    if (-not $networkMatch) {
                        $insights.Governance.NetworkIsolation += "$($item.Resource) - Network isolation applied"
                        $networkMatch = $true
                    }
                    break
                }
            }
            
            $auditMatch = $false
            foreach ($audit in $knowledgeBase.GovernanceIndicators.AuditLogging) {
                if ($changesText -match [regex]::Escape($audit) -or $item.Resource -match $audit) {
                    if (-not $auditMatch) {
                        $insights.Governance.AuditLogging += "$($item.Resource) - Audit logging enabled"
                        $auditMatch = $true
                    }
                    break
                }
            }
            
            $complianceMatch = $false
            foreach ($compliance in $knowledgeBase.GovernanceIndicators.ComplianceFrameworks) {
                if ($changesText -match [regex]::Escape($compliance) -or $item.Resource -match $compliance) {
                    if (-not $complianceMatch) {
                        $insights.Governance.ComplianceFrameworks += "$($item.Resource) - Compliance framework applied"
                        $complianceMatch = $true
                    }
                    break
                }
            }
            
            $costMgmtMatch = $false
            foreach ($costMgmt in $knowledgeBase.GovernanceIndicators.CostManagement) {
                if ($changesText -match [regex]::Escape($costMgmt) -or $item.Resource -match $costMgmt) {
                    if (-not $costMgmtMatch) {
                        $insights.Governance.CostManagement += "$($item.Resource) - Cost management configured"
                        $costMgmtMatch = $true
                    }
                    break
                }
            }
        }
        
        # Calculate overall security trend
        $securityScore = $insights.Security.Positive.Count - $insights.Security.Negative.Count
        $insights.Security.OverallTrend = if ($securityScore -gt 0) { "Improved ✓" } 
                                          elseif ($securityScore -lt 0) { "Degraded ⚠" } 
                                          else { "Neutral ≈" }
        
        # Calculate estimated cost impact with monthly estimate
        $monthlyChange = $insights.Cost.MonthlyEstimate
        $insights.Cost.EstimatedImpact = if ($monthlyChange -gt 200) { "Significant Increase 💰💰💰 (+`$$([Math]::Round($monthlyChange, 0))/mo)" }
                                        elseif ($monthlyChange -gt 50) { "Moderate Increase 💰💰 (+`$$([Math]::Round($monthlyChange, 0))/mo)" }
                                        elseif ($monthlyChange -gt 0) { "Minor Increase 💰 (+`$$([Math]::Round($monthlyChange, 0))/mo)" }
                                        elseif ($monthlyChange -eq 0) { "No Change ≈" }
                                        elseif ($monthlyChange -gt -100) { "Minor Decrease ✓ (`$$([Math]::Round($monthlyChange, 0))/mo)" }
                                        elseif ($monthlyChange -gt -300) { "Moderate Decrease ✓✓ (`$$([Math]::Round($monthlyChange, 0))/mo)" }
                                        else { "Significant Decrease ✓✓✓ (`$$([Math]::Round($monthlyChange, 0))/mo)" }
        
        # Display insights
        Write-Host "💰 COST IMPACT ANALYSIS" -ForegroundColor Yellow
        Write-Host "   Overall Impact: " -NoNewline
        $costColor = if ($insights.Cost.EstimatedImpact -match "Increase") { "Red" } 
                    elseif ($insights.Cost.EstimatedImpact -match "Decrease") { "Green" } 
                    else { "Gray" }
        Write-Host $insights.Cost.EstimatedImpact -ForegroundColor $costColor
        Write-Host "   ⚠️  Estimates are approximate - actual costs may vary by region, commitment, and usage" -ForegroundColor DarkGray
        Write-Host ""
        
        if ($insights.Cost.High.Count -gt 0) {
            Write-Host "   High Cost Resources ($($insights.Cost.High.Count)):" -ForegroundColor Red
            $insights.Cost.High | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkRed }
            Write-Host ""
        }
        if ($insights.Cost.Medium.Count -gt 0) {
            Write-Host "   Medium Cost Resources ($($insights.Cost.Medium.Count)):" -ForegroundColor Yellow
            $insights.Cost.Medium | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkYellow }
            Write-Host ""
        }
        if ($insights.Cost.Low.Count -gt 0) {
            Write-Host "   Low Cost Resources ($($insights.Cost.Low.Count)):" -ForegroundColor Green
            $insights.Cost.Low | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkGreen }
            Write-Host ""
        }
        
        Write-Host "🔒 SECURITY IMPACT ANALYSIS" -ForegroundColor Cyan
        Write-Host "   Security Trend: " -NoNewline
        $secColor = if ($insights.Security.OverallTrend -match "Improved") { "Green" } 
                   elseif ($insights.Security.OverallTrend -match "Degraded") { "Red" } 
                   else { "Gray" }
        Write-Host $insights.Security.OverallTrend -ForegroundColor $secColor
        Write-Host ""
        
        if ($insights.Security.Positive.Count -gt 0) {
            Write-Host "   ✓ Security Improvements ($($insights.Security.Positive.Count)):" -ForegroundColor Green
            $insights.Security.Positive | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkGreen }
            Write-Host ""
        }
        if ($insights.Security.Negative.Count -gt 0) {
            Write-Host "   ⚠ Security Concerns ($($insights.Security.Negative.Count)):" -ForegroundColor Red
            $insights.Security.Negative | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkRed }
            Write-Host ""
        }
        if ($insights.Security.Neutral.Count -gt 0) {
            Write-Host "   ≈ Security Modifications ($($insights.Security.Neutral.Count)):" -ForegroundColor Gray
            $insights.Security.Neutral | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkGray }
            Write-Host ""
        }
        if ($insights.Security.Positive.Count -eq 0 -and $insights.Security.Negative.Count -eq 0 -and $insights.Security.Neutral.Count -eq 0) {
            Write-Host "   No security-related changes detected.`n" -ForegroundColor Gray
        }
        
        # Calculate governance score (0-10 scale)
        $govScore = 0
        if ($insights.Governance.Tags.Count -gt 0) { $govScore += 1 }
        if ($insights.Governance.Naming.Count -gt 0) { $govScore += 1 }
        if ($insights.Governance.Policies.Count -gt 0) { $govScore += 1 }
        if ($insights.Governance.Backup.Count -gt 0) { $govScore += 1 }
        if ($insights.Governance.Locks.Count -gt 0) { $govScore += 1 }
        if ($insights.Governance.RBAC.Count -gt 0) { $govScore += 1 }
        if ($insights.Governance.NetworkIsolation.Count -gt 0) { $govScore += 2 }
        if ($insights.Governance.AuditLogging.Count -gt 0) { $govScore += 1 }
        if ($insights.Governance.ComplianceFrameworks.Count -gt 0) { $govScore += 2 }
        if ($insights.Governance.CostManagement.Count -gt 0) { $govScore += 1 }
        
        Write-Host "📋 GOVERNANCE & COMPLIANCE ANALYSIS" -ForegroundColor Magenta
        Write-Host "   Governance Score: " -NoNewline
        $govColor = if ($govScore -ge 8) { "Green" } 
                   elseif ($govScore -ge 5) { "Yellow" } 
                   else { "Red" }
        Write-Host "$govScore/12" -ForegroundColor $govColor
        
        # Show comprehensive score breakdown
        Write-Host "   Breakdown:" -ForegroundColor Gray
        Write-Host "   • Tags: " -NoNewline -ForegroundColor Gray
        Write-Host $(if ($insights.Governance.Tags.Count -gt 0) { "✓ +1" } else { "✗ +0" }) -ForegroundColor $(if ($insights.Governance.Tags.Count -gt 0) { "Green" } else { "DarkGray" })
        Write-Host "   • Naming: " -NoNewline -ForegroundColor Gray
        Write-Host $(if ($insights.Governance.Naming.Count -gt 0) { "✓ +1" } else { "✗ +0" }) -ForegroundColor $(if ($insights.Governance.Naming.Count -gt 0) { "Green" } else { "DarkGray" })
        Write-Host "   • Policies/Monitoring: " -NoNewline -ForegroundColor Gray
        Write-Host $(if ($insights.Governance.Policies.Count -gt 0) { "✓ +1" } else { "✗ +0" }) -ForegroundColor $(if ($insights.Governance.Policies.Count -gt 0) { "Green" } else { "DarkGray" })
        Write-Host "   • Backup/Retention: " -NoNewline -ForegroundColor Gray
        Write-Host $(if ($insights.Governance.Backup.Count -gt 0) { "✓ +1" } else { "✗ +0" }) -ForegroundColor $(if ($insights.Governance.Backup.Count -gt 0) { "Green" } else { "DarkGray" })
        Write-Host "   • Resource Locks: " -NoNewline -ForegroundColor Gray
        Write-Host $(if ($insights.Governance.Locks.Count -gt 0) { "✓ +1" } else { "✗ +0" }) -ForegroundColor $(if ($insights.Governance.Locks.Count -gt 0) { "Green" } else { "DarkGray" })
        Write-Host "   • RBAC/IAM: " -NoNewline -ForegroundColor Gray
        Write-Host $(if ($insights.Governance.RBAC.Count -gt 0) { "✓ +1" } else { "✗ +0" }) -ForegroundColor $(if ($insights.Governance.RBAC.Count -gt 0) { "Green" } else { "DarkGray" })
        Write-Host "   • Network Isolation: " -NoNewline -ForegroundColor Gray
        Write-Host $(if ($insights.Governance.NetworkIsolation.Count -gt 0) { "✓ +2" } else { "✗ +0" }) -ForegroundColor $(if ($insights.Governance.NetworkIsolation.Count -gt 0) { "Green" } else { "DarkGray" })
        Write-Host "   • Audit Logging: " -NoNewline -ForegroundColor Gray
        Write-Host $(if ($insights.Governance.AuditLogging.Count -gt 0) { "✓ +1" } else { "✗ +0" }) -ForegroundColor $(if ($insights.Governance.AuditLogging.Count -gt 0) { "Green" } else { "DarkGray" })
        Write-Host "   • Compliance Frameworks: " -NoNewline -ForegroundColor Gray
        Write-Host $(if ($insights.Governance.ComplianceFrameworks.Count -gt 0) { "✓ +2" } else { "✗ +0" }) -ForegroundColor $(if ($insights.Governance.ComplianceFrameworks.Count -gt 0) { "Green" } else { "DarkGray" })
        Write-Host "   • Cost Management: " -NoNewline -ForegroundColor Gray
        Write-Host $(if ($insights.Governance.CostManagement.Count -gt 0) { "✓ +1" } else { "✗ +0" }) -ForegroundColor $(if ($insights.Governance.CostManagement.Count -gt 0) { "Green" } else { "DarkGray" })
        Write-Host ""
        
        $totalGovItems = $insights.Governance.Tags.Count + $insights.Governance.Naming.Count + 
                        $insights.Governance.Policies.Count + $insights.Governance.Backup.Count +
                        $insights.Governance.Locks.Count + $insights.Governance.RBAC.Count +
                        $insights.Governance.NetworkIsolation.Count + $insights.Governance.AuditLogging.Count +
                        $insights.Governance.ComplianceFrameworks.Count + $insights.Governance.CostManagement.Count
        
        if ($totalGovItems -gt 0) {
            if ($insights.Governance.Tags.Count -gt 0) {
                Write-Host "   🏷️  Tags ($($insights.Governance.Tags.Count)):" -ForegroundColor Blue
                $insights.Governance.Tags | Select-Object -First 3 | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkCyan }
                if ($insights.Governance.Tags.Count -gt 3) { Write-Host "   • ... and $($insights.Governance.Tags.Count - 3) more" -ForegroundColor DarkGray }
                Write-Host ""
            }
            if ($insights.Governance.Policies.Count -gt 0) {
                Write-Host "   📜 Policies & Monitoring ($($insights.Governance.Policies.Count)):" -ForegroundColor Magenta
                $insights.Governance.Policies | Select-Object -First 3 | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkMagenta }
                if ($insights.Governance.Policies.Count -gt 3) { Write-Host "   • ... and $($insights.Governance.Policies.Count - 3) more" -ForegroundColor DarkGray }
                Write-Host ""
            }
            if ($insights.Governance.Backup.Count -gt 0) {
                Write-Host "   💾 Backup & Retention ($($insights.Governance.Backup.Count)):" -ForegroundColor Green
                $insights.Governance.Backup | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkGreen }
                Write-Host ""
            }
            if ($insights.Governance.Locks.Count -gt 0) {
                Write-Host "   🔒 Resource Locks ($($insights.Governance.Locks.Count)):" -ForegroundColor Yellow
                $insights.Governance.Locks | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkYellow }
                Write-Host ""
            }
            if ($insights.Governance.RBAC.Count -gt 0) {
                Write-Host "   👤 RBAC/IAM ($($insights.Governance.RBAC.Count)):" -ForegroundColor Cyan
                $insights.Governance.RBAC | Select-Object -First 3 | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkCyan }
                if ($insights.Governance.RBAC.Count -gt 3) { Write-Host "   • ... and $($insights.Governance.RBAC.Count - 3) more" -ForegroundColor DarkGray }
                Write-Host ""
            }
            if ($insights.Governance.NetworkIsolation.Count -gt 0) {
                Write-Host "   🌐 Network Isolation ($($insights.Governance.NetworkIsolation.Count)):" -ForegroundColor Blue
                $insights.Governance.NetworkIsolation | Select-Object -First 3 | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkBlue }
                if ($insights.Governance.NetworkIsolation.Count -gt 3) { Write-Host "   • ... and $($insights.Governance.NetworkIsolation.Count - 3) more" -ForegroundColor DarkGray }
                Write-Host ""
            }
            if ($insights.Governance.AuditLogging.Count -gt 0) {
                Write-Host "   📊 Audit Logging ($($insights.Governance.AuditLogging.Count)):" -ForegroundColor Magenta
                $insights.Governance.AuditLogging | Select-Object -First 3 | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkMagenta }
                if ($insights.Governance.AuditLogging.Count -gt 3) { Write-Host "   • ... and $($insights.Governance.AuditLogging.Count - 3) more" -ForegroundColor DarkGray }
                Write-Host ""
            }
            if ($insights.Governance.ComplianceFrameworks.Count -gt 0) {
                Write-Host "   ✅ Compliance Frameworks ($($insights.Governance.ComplianceFrameworks.Count)):" -ForegroundColor Green
                $insights.Governance.ComplianceFrameworks | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkGreen }
                Write-Host ""
            }
            if ($insights.Governance.CostManagement.Count -gt 0) {
                Write-Host "   💵 Cost Management ($($insights.Governance.CostManagement.Count)):" -ForegroundColor Yellow
                $insights.Governance.CostManagement | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkYellow }
                Write-Host ""
            }
        } else {
            Write-Host "   No governance-related changes detected.`n" -ForegroundColor Gray
        }
        
        Write-Host "================================================================================`n" -ForegroundColor Cyan
    }
}

