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

.PARAMETER TableAll
    Optional switch to display all resources in a table format with ResourceName, ResourceType, and Action.

.PARAMETER ShowInsights
    Optional switch to display intelligent analysis of cost, security, and governance impacts.

.PARAMETER PassThru
    Optional switch to output a structured object with summary counts (and Insights when -ShowInsights is used).

.PARAMETER Category
    Optional filter to show only resources in specific categories (Compute, Storage, Network, Database, Security, Monitoring).

.PARAMETER ResourceName
    Optional filter to show only resources matching a name pattern (supports wildcards).

.PARAMETER ResourceType
    Optional filter to show only resources of specific type (e.g., azurerm_virtual_machine, supports wildcards).

.EXAMPLE
    .\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out
    Displays a summary of all resource changes.

.EXAMPLE
    .\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ShowChanges
    Displays resource changes with detailed attribute modifications.

.EXAMPLE
    .\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ListDestroyed
    Shows only resources that will be destroyed.

.EXAMPLE
    .\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -Category Compute -ShowInsights
    Shows only compute resources with cost and security insights.

.EXAMPLE
    .\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ResourceName "*prod*" -ListCreated
    Shows only resources with 'prod' in the name that will be created.

.EXAMPLE
    .\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ResourceType "azurerm_virtual_machine" -ShowInsights
    Shows only virtual machine resources with insights.

.EXAMPLE
    .\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -ResourceType "*storage*" -Category Storage
    Shows only storage-related resource types.

.PARAMETER Update
    Optional switch to check for updates from the GitHub repository, display cumulative changes,
    and update the script to the latest version.

.PARAMETER OutputHtml
    Optional switch to generate a self-contained HTML report file. When used without
    -OutputHtmlPath, generates a file named TerraformPlanReport_yyyyMMdd_HHmmss.html in the
    current directory. The report includes summary cards, resource table, attribute changes,
    cost/security/carbon/governance insights, and executive summary. Insights are always
    computed for the HTML report regardless of -ShowInsights.
    The file auto-opens in the default browser after generation.

.PARAMETER OutputHtmlPath
    Optional path for the HTML report file. If omitted, a default timestamped filename is used.
    Only effective when -OutputHtml is also specified.

    The HTML report features:
    - Summary cards with resource action counts
    - Contextual info (i) icons on each section header with hover tooltips explaining that section
    - Collapsible sections for Resources, Attribute Changes, Cost, Security, Carbon, Governance, and Executive Summary
    - Each section header shows an item count for at-a-glance overview
    - Executive Summary section is expanded by default; all others are collapsed
    - Disclaimer noting that all insights are heuristic-based estimates, not exact calculations

.EXAMPLE
    .\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -TableAll
    Displays all resources in a table with ResourceName, ResourceType, and Action columns.

.EXAMPLE
    .\Get-TerraformPlanReport.ps1 -Update
    Checks for a new version on GitHub, shows all changes since the current version, and updates the scripts.

.EXAMPLE
    .\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -OutputHtml
    Generates an HTML report with a default timestamped name (e.g., TerraformPlanReport_20260219_143000.html).

.EXAMPLE
    .\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -OutputHtml -OutputHtmlPath .\report.html
    Generates a full HTML report at the specified path and opens it in the default browser.

.NOTES
    Version: 1.7.1
    Requires PowerShell 7.0 or later.
#>

[CmdletBinding(DefaultParameterSetName='Report')]
param(
    [Parameter(Mandatory=$true, ParameterSetName='Report')]
    [string]$LogFile,
    
    [Parameter(Mandatory=$false, ParameterSetName='Report')]
    [switch]$ShowChanges,
    
    [Parameter(Mandatory=$false, ParameterSetName='Report')]
    [switch]$ListCreated,
    
    [Parameter(Mandatory=$false, ParameterSetName='Report')]
    [switch]$ListChanged,
    
    [Parameter(Mandatory=$false, ParameterSetName='Report')]
    [switch]$ListDestroyed,
    
    [Parameter(Mandatory=$false, ParameterSetName='Report')]
    [switch]$ListReplaced,
    
    [Parameter(Mandatory=$false, ParameterSetName='Report')]
    [switch]$TableAll,
    
    [Parameter(Mandatory=$false, ParameterSetName='Report')]
    [switch]$ShowInsights,
    
    [Parameter(Mandatory=$false, ParameterSetName='Report')]
    [ValidateSet('Compute', 'Storage', 'Network', 'Database', 'Security', 'Monitoring', 'All')]
    [string]$Category,
    
    [Parameter(Mandatory=$false, ParameterSetName='Report')]
    [string]$ResourceName,
    
    [Parameter(Mandatory=$false, ParameterSetName='Report')]
    [string]$ResourceType,
    
    [Parameter(Mandatory=$false, ParameterSetName='Report')]
    [switch]$PassThru,

    [Parameter(Mandatory=$false, ParameterSetName='Report')]
    [switch]$OutputHtml,

    [Parameter(Mandatory=$false, ParameterSetName='Report')]
    [string]$OutputHtmlPath,

    [Parameter(Mandatory=$true, ParameterSetName='Update')]
    [switch]$Update
)

# ─── Self-Update Logic ──────────────────────────────────────────────────────────
if ($Update) {
    $gitHubOwner = 'ripom'
    $gitHubRepo  = 'terraform-plan-reporter'
    $branch      = 'main'
    $rawBase     = "https://raw.githubusercontent.com/$gitHubOwner/$gitHubRepo/$branch"
    $scriptDir   = $PSScriptRoot
    if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }

    # ── Helper: compare semantic versions (returns -1, 0, or 1) ──
    function Compare-SemVer {
        param([string]$A, [string]$B)
        $pa = $A -split '\.' | ForEach-Object { [int]$_ }
        $pb = $B -split '\.' | ForEach-Object { [int]$_ }
        for ($i = 0; $i -lt [Math]::Max($pa.Count, $pb.Count); $i++) {
            $va = if ($i -lt $pa.Count) { $pa[$i] } else { 0 }
            $vb = if ($i -lt $pb.Count) { $pb[$i] } else { 0 }
            if ($va -lt $vb) { return -1 }
            if ($va -gt $vb) { return  1 }
        }
        return 0
    }

    # ── Read local version.json ──
    $localVersionFile = Join-Path $scriptDir 'version.json'
    if (-not (Test-Path $localVersionFile)) {
        Write-Host "Error: version.json not found in $scriptDir" -ForegroundColor Red
        exit 1
    }
    $localVersion = Get-Content $localVersionFile -Raw | ConvertFrom-Json
    $currentVersion = $localVersion.version
    Write-Host "`n  Terraform Plan Reporter - Update Check" -ForegroundColor Cyan
    Write-Host "  ========================================" -ForegroundColor Cyan
    Write-Host "  Local version:  " -NoNewline -ForegroundColor Gray
    Write-Host "v$currentVersion" -ForegroundColor Yellow

    # ── Fetch remote version.json from GitHub ──
    Write-Host "  Checking GitHub..." -NoNewline -ForegroundColor Gray
    try {
        $remoteVersionJson = Invoke-RestMethod -Uri "$rawBase/version.json" -UseBasicParsing -ErrorAction Stop
        # Invoke-RestMethod auto-parses JSON on PS 5.1+; handle string fallback
        if ($remoteVersionJson -is [string]) {
            $remoteVersion = $remoteVersionJson | ConvertFrom-Json
        } else {
            $remoteVersion = $remoteVersionJson
        }
        Write-Host " done" -ForegroundColor Green
    } catch {
        Write-Host " failed" -ForegroundColor Red
        Write-Host "  Could not reach GitHub: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }

    $latestVersion = $remoteVersion.version
    Write-Host "  Remote version: " -NoNewline -ForegroundColor Gray
    Write-Host "v$latestVersion" -ForegroundColor Cyan

    $cmp = Compare-SemVer $currentVersion $latestVersion
    if ($cmp -ge 0) {
        Write-Host "`n  You are already running the latest version (v$currentVersion).`n" -ForegroundColor Green
        exit 0
    }

    # ── Collect cumulative changes between current and latest ──
    Write-Host "`n  Changes from v$currentVersion -> v$latestVersion :" -ForegroundColor White
    Write-Host "  ----------------------------------------" -ForegroundColor DarkGray

    $applicableVersions = $remoteVersion.history | Where-Object {
        (Compare-SemVer $_.version $currentVersion) -gt 0
    } | Sort-Object { $v = $_.version -split '\.'; [int]$v[0] * 10000 + [int]$v[1] * 100 + [int]$v[2] }

    foreach ($entry in $applicableVersions) {
        Write-Host "`n  v$($entry.version)" -NoNewline -ForegroundColor Cyan
        Write-Host " ($($entry.date))" -NoNewline -ForegroundColor DarkGray
        Write-Host " - $($entry.description)" -ForegroundColor White
        foreach ($change in $entry.changes) {
            Write-Host "    • $change" -ForegroundColor Gray
        }
    }

    # ── Prompt for confirmation ──
    Write-Host "`n  ----------------------------------------" -ForegroundColor DarkGray
    $totalChanges = ($applicableVersions | ForEach-Object { $_.changes.Count } | Measure-Object -Sum).Sum
    Write-Host "  Total: $($applicableVersions.Count) version(s), $totalChanges change(s)`n" -ForegroundColor Yellow

    $confirm = Read-Host "  Do you want to update to v$latestVersion? (y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "  Update cancelled.`n" -ForegroundColor Yellow
        exit 0
    }

    # ── Download and replace files ──
    $filesToUpdate = @(
        'Get-TerraformPlanReport.ps1',
        'Convert-AzDevOpsLog.ps1',
        'version.json'
    )

    Write-Host ""
    foreach ($file in $filesToUpdate) {
        $targetPath = Join-Path $scriptDir $file
        $downloadUrl = "$rawBase/$file"
        Write-Host "  Downloading $file..." -NoNewline -ForegroundColor Gray
        try {
            $content = Invoke-WebRequest -Uri $downloadUrl -UseBasicParsing -ErrorAction Stop
            # Write with UTF-8 no BOM
            [System.IO.File]::WriteAllText($targetPath, $content.Content, [System.Text.UTF8Encoding]::new($false))
            Write-Host " updated" -ForegroundColor Green
        } catch {
            Write-Host " failed" -ForegroundColor Red
            Write-Host "    $($_.Exception.Message)" -ForegroundColor DarkRed
        }
    }

    Write-Host "`n  Update complete: v$currentVersion -> v$latestVersion`n" -ForegroundColor Green
    exit 0
}

# Knowledge base for intelligent insights
$knowledgeBase = @{
    # ==================================================================================
    # COST ESTIMATION — METHODOLOGY & DISCLAIMER
    # ==================================================================================
    #
    # ⚠️  IMPORTANT: These values are INFERENCE-BASED ESTIMATES, NOT actual Azure pricing.
    #     They are NOT sourced from the Azure Pricing API, Azure Cost Management, or the
    #     Azure Pricing Calculator at runtime. Real costs depend on SKU tier, region,
    #     reserved instances, dev/test pricing, enterprise agreements, consumption patterns,
    #     and many other factors invisible in a Terraform plan.
    #     Use these figures for DIRECTIONAL AWARENESS only — not for budgeting, procurement,
    #     or financial reporting.
    #
    # For actual pricing, use:
    #   - Azure Pricing Calculator: https://azure.microsoft.com/en-us/pricing/calculator/
    #   - Azure Cost Management: https://learn.microsoft.com/en-us/azure/cost-management-billing/
    #   - az cli: az vm list-sizes / az vm list-skus (for VM pricing by region)
    #
    # --- CALCULATION METHODOLOGY ---
    #
    # VM costs: Based on the AUTHOR'S APPROXIMATE KNOWLEDGE of Azure Pay-As-You-Go (PAYG)
    # pricing for the East US region (Linux, no reservations, no hybrid benefit).
    # These are rough midpoint estimates — Azure prices frequently change and vary ±30%
    # across regions. Reserved instances can reduce costs by 40-72%.
    #
    # Service costs: Based on the author's approximate knowledge of minimum/entry-level tier
    # pricing (e.g., Basic, Standard, Consumption). Real costs depend heavily on the tier,
    # capacity, throughput, and data volume configured.
    #
    # The script does NOT adjust costs by region — all estimates use a single baseline
    # (approximately East US PAYG). Unlike carbon, there is no regional multiplier.
    #
    # --- WORKED EXAMPLE ---
    #
    #   Resource: azurerm_linux_virtual_machine with Standard_D4s_v3 in Terraform plan
    #   Step 1 — Match VM size string "Standard_D4s_v3" in plan attribute text
    #   Step 2 — Look up in VMSizes table → $140/mo (PAYG Linux East US approximate)
    #   Step 3 — Action is "Create" → cost impact = +$140/mo
    #
    #   Resource: azurerm_storage_account (no size string detected)
    #   Step 1 — Look up in Services table → $20/mo (Standard LRS~1TB approximate)
    #   Step 2 — Action is "Update" → cost impact = $0 (no new cost for in-place update)
    #
    # --- LEGEND ---
    #
    #   CostResources.High    : Resources typically costing >$50/mo (VMs, databases, firewalls)
    #   CostResources.Medium  : Resources typically costing $5-100/mo (storage, caches, gateways)
    #   CostResources.Low     : Resources typically costing $0-20/mo (NSGs, DNS, NICs, subnets)
    #
    #   CostEstimation.VMSizes   : Approximate PAYG Linux monthly cost per VM SKU (East US)
    #   CostEstimation.Storage   : Approximate monthly cost per storage redundancy tier (~1TB)
    #   CostEstimation.Services  : Approximate monthly cost per service resource type (base tier)
    #
    #   Fallback values:
    #     Unknown VM         → $70/mo (assumes medium general-purpose VM)
    #     Unknown High       → $100/mo
    #     Unknown Medium     → $30/mo
    #     Unknown Low        → $5/mo
    #     Unknown Storage    → $20/mo
    #
    # --- REFERENCES & RECOMMENDED READING ---
    #
    # The following resources are recommended for obtaining accurate, up-to-date pricing.
    # The values in this script are the author's approximations and were NOT fetched from
    # these sources at runtime.
    #
    #   [1] Azure Pricing Calculator
    #       https://azure.microsoft.com/en-us/pricing/calculator/
    #   [2] Azure Cost Management + Billing
    #       https://learn.microsoft.com/en-us/azure/cost-management-billing/
    #   [3] Azure VM pricing page (Linux, PAYG)
    #       https://azure.microsoft.com/en-us/pricing/details/virtual-machines/linux/
    #   [4] Azure pricing overview (all services)
    #       https://azure.microsoft.com/en-us/pricing/
    #
    # ==================================================================================

    # Cost-impacting resources (High/Medium/Low)
    # Aligned with the same resource types covered by the CarbonFootprint.Services table
    CostResources = @{
        High = @(
            # Compute
            'azurerm_virtual_machine', 'azurerm_windows_virtual_machine', 'azurerm_linux_virtual_machine',
            'azurerm_kubernetes_cluster', 'azurerm_virtual_machine_scale_set',
            'azurerm_orchestrated_virtual_machine_scale_set',
            'azurerm_dedicated_host', 'azurerm_vmware_private_cloud',
            'azurerm_redhat_openshift_cluster',
            'azurerm_hdinsight_hadoop_cluster', 'azurerm_hdinsight_spark_cluster',
            'azurerm_hdinsight_hbase_cluster', 'azurerm_hdinsight_interactive_query_cluster',
            'azurerm_hdinsight_kafka_cluster',
            'azurerm_api_management', 'azurerm_spring_cloud_service',
            'azurerm_machine_learning_compute_cluster',
            'azurerm_batch_pool',
            # Databases
            'azurerm_sql_database', 'azurerm_mssql_database', 'azurerm_mssql_elasticpool',
            'azurerm_sql_managed_instance',
            'azurerm_postgresql_server', 'azurerm_postgresql_flexible_server',
            'azurerm_mysql_server', 'azurerm_mysql_flexible_server',
            'azurerm_mariadb_server', 'azurerm_cosmosdb_account',
            'azurerm_redis_enterprise_cluster',
            'azurerm_synapse_sql_pool', 'azurerm_synapse_spark_pool',
            'azurerm_kusto_cluster',
            # Networking
            'azurerm_application_gateway', 'azurerm_firewall',
            'azurerm_vpn_gateway', 'azurerm_virtual_network_gateway',
            'azurerm_express_route_circuit', 'azurerm_express_route_gateway',
            'azurerm_front_door'
        )
        Medium = @(
            # Compute
            'azurerm_app_service', 'azurerm_function_app',
            'azurerm_linux_function_app', 'azurerm_windows_function_app',
            'azurerm_linux_web_app', 'azurerm_windows_web_app',
            'azurerm_app_service_plan', 'azurerm_service_plan',
            'azurerm_container_app', 'azurerm_container_group',
            'azurerm_container_registry',
            'azurerm_cognitive_account', 'azurerm_machine_learning_workspace',
            'azurerm_machine_learning_compute_instance',
            'azurerm_logic_app_workflow', 'azurerm_powerbi_embedded',
            'azurerm_signalr_service', 'azurerm_web_pubsub',
            'azurerm_batch_account',
            # Databases & Data
            'azurerm_redis_cache', 'azurerm_search_service',
            'azurerm_data_factory', 'azurerm_synapse_workspace', 'azurerm_databricks_workspace',
            'azurerm_stream_analytics_job', 'azurerm_kusto_cluster',
            'azurerm_eventhub_namespace', 'azurerm_service_bus_namespace',
            'azurerm_iothub', 'azurerm_digital_twins_instance',
            'azurerm_data_lake_store', 'azurerm_data_lake_analytics_account',
            'azurerm_purview_account',
            # Storage
            'azurerm_storage_account', 'azurerm_hpc_cache',
            'azurerm_netapp_pool', 'azurerm_netapp_volume',
            'azurerm_recovery_services_vault', 'azurerm_backup_protected_vm',
            # Networking
            'azurerm_bastion_host', 'azurerm_public_ip', 'azurerm_lb', 'azurerm_nat_gateway',
            'azurerm_cdn_profile', 'azurerm_point_to_site_vpn_gateway',
            'azurerm_virtual_wan', 'azurerm_virtual_hub',
            'azurerm_network_ddos_protection_plan',
            'azurerm_frontdoor_firewall_policy',
            # Monitoring
            'azurerm_log_analytics_workspace', 'azurerm_dashboard_grafana',
            'azurerm_monitor_workspace', 'azurerm_application_insights'
        )
        Low = @(
            # Compute (minimal cost)
            'azurerm_container_app_environment', 'azurerm_dedicated_host_group',
            'azurerm_static_site',
            # Databases (child resources with no independent cost)
            'azurerm_mssql_server', 'azurerm_postgresql_database', 'azurerm_mysql_database',
            'azurerm_cosmosdb_sql_database', 'azurerm_cosmosdb_sql_container',
            'azurerm_cosmosdb_mongo_database', 'azurerm_cosmosdb_mongo_collection',
            'azurerm_cosmosdb_table', 'azurerm_cosmosdb_cassandra_keyspace',
            'azurerm_cosmosdb_gremlin_database',
            'azurerm_data_factory_pipeline',
            'azurerm_eventhub', 'azurerm_service_bus_queue', 'azurerm_service_bus_topic',
            'azurerm_eventgrid_topic', 'azurerm_eventgrid_domain',
            'azurerm_notification_hub_namespace',
            # Storage (child/config resources)
            'azurerm_storage_share', 'azurerm_storage_container', 'azurerm_storage_queue',
            'azurerm_storage_table', 'azurerm_storage_blob',
            'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_storage_management_policy',
            'azurerm_managed_disk', 'azurerm_netapp_account',
            'azurerm_backup_container_storage_account', 'azurerm_data_protection_backup_vault',
            # Networking (SDN/config — near-zero cost)
            'azurerm_virtual_network', 'azurerm_subnet',
            'azurerm_network_security_group', 'azurerm_route_table',
            'azurerm_network_interface', 'azurerm_network_watcher',
            'azurerm_network_watcher_flow_log',
            'azurerm_traffic_manager_profile', 'azurerm_traffic_manager_endpoint',
            'azurerm_dns_zone', 'azurerm_private_dns_zone',
            'azurerm_cdn_endpoint', 'azurerm_public_ip_prefix',
            'azurerm_lb_rule', 'azurerm_local_network_gateway',
            'azurerm_virtual_network_peering', 'azurerm_private_endpoint',
            'azurerm_private_link_service', 'azurerm_ip_group',
            'azurerm_firewall_policy', 'azurerm_web_application_firewall_policy'
        )
    }
    
    # Cost estimation patterns (approximate monthly USD, PAYG Linux East US baseline)
    # See methodology documentation above for how these values were derived.
    CostEstimation = @{
        # Azure VM sizes — approximate PAYG monthly cost (Linux, East US, no reservations)
        # These are the AUTHOR'S APPROXIMATE estimates. For current pricing, consult:
        #   https://azure.microsoft.com/en-us/pricing/details/virtual-machines/linux/
        VMSizes = @{
            # B-series (burstable) — pricing reflects burstable discount
            'Standard_B1s' = 8; 'Standard_B1ms' = 15; 'Standard_B2s' = 30
            'Standard_B2ms' = 60; 'Standard_B4ms' = 120; 'Standard_B8ms' = 240
            'Standard_B12ms' = 360; 'Standard_B16ms' = 480; 'Standard_B20ms' = 600
            # D-series v3 (general purpose)
            'Standard_D2s_v3' = 70; 'Standard_D4s_v3' = 140; 'Standard_D8s_v3' = 280
            'Standard_D16s_v3' = 560; 'Standard_D32s_v3' = 1120; 'Standard_D48s_v3' = 1680; 'Standard_D64s_v3' = 2240
            # D-series v4
            'Standard_D2s_v4' = 70; 'Standard_D4s_v4' = 140; 'Standard_D8s_v4' = 280
            'Standard_D16s_v4' = 560; 'Standard_D32s_v4' = 1120; 'Standard_D48s_v4' = 1680; 'Standard_D64s_v4' = 2240
            # D-series v5 (slightly cheaper per vCPU vs v3/v4)
            'Standard_D2s_v5' = 63; 'Standard_D4s_v5' = 126; 'Standard_D8s_v5' = 252
            'Standard_D16s_v5' = 504; 'Standard_D32s_v5' = 1008; 'Standard_D48s_v5' = 1512; 'Standard_D64s_v5' = 2016
            # D-series v5 AMD
            'Standard_D2as_v5' = 56; 'Standard_D4as_v5' = 112; 'Standard_D8as_v5' = 224
            'Standard_D16as_v5' = 448; 'Standard_D32as_v5' = 896; 'Standard_D48as_v5' = 1344; 'Standard_D64as_v5' = 1792
            # E-series v3 (memory optimized — higher $/vCPU due to RAM)
            'Standard_E2s_v3' = 91; 'Standard_E4s_v3' = 182; 'Standard_E8s_v3' = 365
            'Standard_E16s_v3' = 730; 'Standard_E32s_v3' = 1460; 'Standard_E48s_v3' = 2190; 'Standard_E64s_v3' = 2920
            # E-series v4
            'Standard_E2s_v4' = 91; 'Standard_E4s_v4' = 182; 'Standard_E8s_v4' = 365
            'Standard_E16s_v4' = 730; 'Standard_E32s_v4' = 1460; 'Standard_E48s_v4' = 2190; 'Standard_E64s_v4' = 2920
            # E-series v5
            'Standard_E2s_v5' = 84; 'Standard_E4s_v5' = 167; 'Standard_E8s_v5' = 334
            'Standard_E16s_v5' = 668; 'Standard_E32s_v5' = 1336; 'Standard_E48s_v5' = 2004; 'Standard_E64s_v5' = 2672
            # E-series v5 AMD
            'Standard_E2as_v5' = 73; 'Standard_E4as_v5' = 146; 'Standard_E8as_v5' = 292
            'Standard_E16as_v5' = 584; 'Standard_E32as_v5' = 1168; 'Standard_E48as_v5' = 1752; 'Standard_E64as_v5' = 2336
            # F-series v2 (compute optimized)
            'Standard_F2s_v2' = 62; 'Standard_F4s_v2' = 124; 'Standard_F8s_v2' = 248
            'Standard_F16s_v2' = 496; 'Standard_F32s_v2' = 992; 'Standard_F48s_v2' = 1488; 'Standard_F64s_v2' = 1984; 'Standard_F72s_v2' = 2232
            # L-series v2 (storage optimized)
            'Standard_L8s_v2' = 450; 'Standard_L16s_v2' = 900; 'Standard_L32s_v2' = 1800
            'Standard_L48s_v2' = 2700; 'Standard_L64s_v2' = 3600; 'Standard_L80s_v2' = 4500
            # L-series v3
            'Standard_L8s_v3' = 500; 'Standard_L16s_v3' = 1000; 'Standard_L32s_v3' = 2000
            'Standard_L48s_v3' = 3000; 'Standard_L64s_v3' = 4000; 'Standard_L80s_v3' = 5000
            # M-series (memory intensive — very expensive)
            'Standard_M8ms' = 1100; 'Standard_M16ms' = 2200; 'Standard_M32ms' = 4400
            'Standard_M64ms' = 8800; 'Standard_M128ms' = 17600
            # N-series (GPU — pricing reflects GPU premium)
            'Standard_NC6' = 660; 'Standard_NC12' = 1320; 'Standard_NC24' = 2640
            'Standard_NC6s_v3' = 2200; 'Standard_NC12s_v3' = 4400; 'Standard_NC24s_v3' = 8800
            'Standard_NC24ads_A100_v4' = 2700; 'Standard_NC48ads_A100_v4' = 5400; 'Standard_NC96ads_A100_v4' = 10800
            'Standard_ND96asr_v4' = 22000; 'Standard_ND96amsr_A100_v4' = 22000
            'Standard_NV6' = 780; 'Standard_NV12' = 1560; 'Standard_NV24' = 3120
            'Standard_NV12s_v3' = 840; 'Standard_NV24s_v3' = 1680; 'Standard_NV48s_v3' = 3360
            # A-series v2 (basic/legacy — cheapest)
            'Standard_A1_v2' = 25; 'Standard_A2_v2' = 50; 'Standard_A4_v2' = 100; 'Standard_A8_v2' = 200
            'Standard_A2m_v2' = 75; 'Standard_A4m_v2' = 150; 'Standard_A8m_v2' = 300
        }
        # Storage accounts — approximate monthly cost per redundancy tier (~1TB stored)
        Storage = @{
            'Standard_LRS' = 20; 'Standard_ZRS' = 25; 'Standard_GRS' = 40
            'Standard_RAGRS' = 45; 'Standard_GZRS' = 50; 'Standard_RAGZRS' = 55
            'Premium_LRS' = 135; 'Premium_ZRS' = 170
        }
        # Service costs (approximate monthly USD, base/entry-level tier, PAYG)
        # Aligned with CarbonFootprint.Services resource types
        Services = @{
            # --- Compute ---
            'azurerm_kubernetes_cluster' = 73        # AKS free tier (control plane), nodes separate
            'azurerm_virtual_machine_scale_set' = 140 # 2-node D2s avg
            'azurerm_orchestrated_virtual_machine_scale_set' = 140 # Same as VMSS
            'azurerm_container_group' = 30           # 1 vCPU, 1.5GB RAM
            'azurerm_container_registry' = 5         # Basic tier ($0.167/day)
            'azurerm_container_app' = 20             # Consumption + requests
            'azurerm_container_app_environment' = 0  # Included in container app cost
            'azurerm_linux_web_app' = 13             # Basic B1 plan
            'azurerm_windows_web_app' = 13           # Basic B1 plan
            'azurerm_app_service' = 13               # Classic Basic B1
            'azurerm_function_app' = 10              # Dedicated plan basic
            'azurerm_linux_function_app' = 10        # Dedicated plan basic
            'azurerm_windows_function_app' = 10      # Dedicated plan basic
            'azurerm_app_service_plan' = 13          # Basic B1 ($13.14/mo)
            'azurerm_service_plan' = 13              # Same as above
            'azurerm_batch_account' = 0              # Account free, compute separate
            'azurerm_batch_pool' = 140               # Depends on VM size
            'azurerm_spring_cloud_service' = 50      # Basic tier
            'azurerm_cognitive_account' = 10         # S0 varies by service
            'azurerm_machine_learning_workspace' = 0 # Workspace free, compute separate
            'azurerm_machine_learning_compute_cluster' = 140  # 2-node default
            'azurerm_machine_learning_compute_instance' = 70  # Single small VM
            'azurerm_logic_app_workflow' = 0         # Consumption per-execution
            'azurerm_api_management' = 50            # Developer tier ($0.07/hr)
            'azurerm_signalr_service' = 49           # Standard_S1 1 unit
            'azurerm_web_pubsub' = 49                # Standard_S1 1 unit
            'azurerm_dedicated_host_group' = 0       # Group definition, no cost
            'azurerm_dedicated_host' = 2500          # Dsv3 host ~$3.42/hr
            'azurerm_vmware_private_cloud' = 5940    # 3 AV36 nodes ~$2.72/hr each
            'azurerm_redhat_openshift_cluster' = 1200 # 3+3 nodes + OCP license
            'azurerm_hdinsight_hadoop_cluster' = 730  # 5 D12v2 nodes
            'azurerm_hdinsight_spark_cluster' = 950   # Head + worker nodes
            'azurerm_hdinsight_hbase_cluster' = 730   # Head + region servers
            'azurerm_hdinsight_interactive_query_cluster' = 730 # Similar to Hadoop
            'azurerm_hdinsight_kafka_cluster' = 950   # Head + broker + ZK
            'azurerm_powerbi_embedded' = 740          # A1 SKU ~$1.01/hr
            'azurerm_static_site' = 0                 # Free tier available
            # --- Databases & Data ---
            'azurerm_sql_database' = 15              # Basic 5 DTU ($4.90) to S0 ($15)
            'azurerm_mssql_database' = 15            # Same
            'azurerm_mssql_server' = 0               # Logical server, no compute cost
            'azurerm_mssql_elasticpool' = 112        # Standard 50 eDTU
            'azurerm_sql_managed_instance' = 400     # GP Gen5 2 vCores (~$5.40/hr)
            'azurerm_postgresql_server' = 25         # Basic 1 vCore
            'azurerm_postgresql_flexible_server' = 25 # Burstable B1ms
            'azurerm_postgresql_database' = 0        # DB on existing server
            'azurerm_mysql_server' = 25              # Basic 1 vCore
            'azurerm_mysql_flexible_server' = 25     # Burstable B1ms
            'azurerm_mysql_database' = 0             # DB on existing server
            'azurerm_mariadb_server' = 25            # Basic 1 vCore
            'azurerm_cosmosdb_account' = 25          # 400 RU/s (~$0.008/RU-hour)
            'azurerm_cosmosdb_sql_database' = 0      # RU cost at account level
            'azurerm_cosmosdb_sql_container' = 0     # RU cost at account level
            'azurerm_cosmosdb_mongo_database' = 0
            'azurerm_cosmosdb_mongo_collection' = 0
            'azurerm_cosmosdb_table' = 0
            'azurerm_cosmosdb_cassandra_keyspace' = 0
            'azurerm_cosmosdb_gremlin_database' = 0
            'azurerm_redis_cache' = 16               # Basic C0 ($0.022/hr)
            'azurerm_redis_enterprise_cluster' = 225  # E10 (~$0.308/hr)
            'azurerm_search_service' = 75            # Basic (1 replica, $0.101/hr)
            'azurerm_data_factory' = 0               # ADF free, pay per activity run
            'azurerm_data_factory_pipeline' = 1      # ~$1/1000 activity runs
            'azurerm_synapse_workspace' = 0          # Workspace free, compute separate
            'azurerm_synapse_sql_pool' = 876         # DW100c (~$1.20/hr)
            'azurerm_synapse_spark_pool' = 0         # Pay per node-hour when running
            'azurerm_databricks_workspace' = 0       # Workspace free, cluster separate
            'azurerm_kusto_cluster' = 300            # Dev D11_v2 x2
            'azurerm_stream_analytics_job' = 80      # 1 SU ($0.11/hr)
            'azurerm_eventhub_namespace' = 11        # Basic 1 TU ($0.015/hr)
            'azurerm_eventhub' = 0                   # Included in namespace
            'azurerm_service_bus_namespace' = 10     # Basic tier ($0.05/M ops)
            'azurerm_service_bus_queue' = 0          # Included in namespace
            'azurerm_service_bus_topic' = 0          # Included in namespace
            'azurerm_eventgrid_topic' = 0            # $0.60/M operations
            'azurerm_eventgrid_domain' = 0           # $0.60/M operations
            'azurerm_iothub' = 25                    # S1 ($25/mo per unit)
            'azurerm_digital_twins_instance' = 20    # $0.05/1K operations + messages
            'azurerm_data_lake_store' = 30           # ~$0.039/GB/mo for 1TB
            'azurerm_data_lake_analytics_account' = 0 # Pay per AU-hour
            'azurerm_purview_account' = 130          # Governance ~$0.18/hr
            'azurerm_notification_hub_namespace' = 10 # Basic tier
            # --- Storage ---
            'azurerm_storage_account' = 20           # Standard LRS ~1TB
            'azurerm_storage_share' = 5              # 100GB hot tier
            'azurerm_storage_container' = 0          # Cost at account level
            'azurerm_storage_queue' = 0              # Minimal per-transaction
            'azurerm_storage_table' = 0              # Minimal per-transaction
            'azurerm_storage_blob' = 0               # Cost at account level
            'azurerm_storage_data_lake_gen2_filesystem' = 0 # Cost at account level
            'azurerm_storage_management_policy' = 0  # Policy definition, no cost
            'azurerm_managed_disk' = 6               # Standard HDD S10 128GB
            'azurerm_hpc_cache' = 680                # Standard L cache (~$0.93/hr)
            'azurerm_netapp_account' = 0             # Account free
            'azurerm_netapp_pool' = 300              # 4TB Standard ($0.000403/GiB/hr)
            'azurerm_netapp_volume' = 0              # Cost at pool level
            'azurerm_recovery_services_vault' = 10   # Vault + basic backup
            'azurerm_backup_protected_vm' = 5        # ~$5/instance/mo for <50GB
            'azurerm_backup_container_storage_account' = 2 # Per-GB backup
            'azurerm_data_protection_backup_vault' = 10 # Similar to RSV
            # --- Networking ---
            'azurerm_application_gateway' = 125      # V2 Standard (~$0.18/hr + capacity)
            'azurerm_firewall' = 912                 # Standard ($1.25/hr)
            'azurerm_vpn_gateway' = 140              # VpnGw1 ($0.19/hr)
            'azurerm_virtual_network_gateway' = 140  # VpnGw1
            'azurerm_bastion_host' = 139             # Basic ($0.19/hr)
            'azurerm_front_door' = 35                # Standard base + data transfer
            'azurerm_cdn_profile' = 0                # Pay per data transfer
            'azurerm_cdn_endpoint' = 0               # Pay per data transfer
            'azurerm_traffic_manager_profile' = 1    # ~$0.54/M queries + health checks
            'azurerm_traffic_manager_endpoint' = 0   # Included in profile
            'azurerm_dns_zone' = 0.50                # $0.50/zone/mo + $0.40/M queries
            'azurerm_private_dns_zone' = 0.25        # $0.25/zone/mo
            'azurerm_public_ip' = 4                  # Static $3.65/mo
            'azurerm_public_ip_prefix' = 4           # Per IP
            'azurerm_lb' = 18                        # Standard (~$0.025/hr + rules)
            'azurerm_lb_rule' = 1                    # $0.01/rule/hr
            'azurerm_nat_gateway' = 32               # $0.045/hr + data processing
            'azurerm_express_route_circuit' = 200    # Standard Metered 50Mbps
            'azurerm_express_route_gateway' = 200    # ~$0.28/hr
            'azurerm_virtual_wan' = 0                # Hub charged separately
            'azurerm_virtual_hub' = 182              # $0.25/hr
            'azurerm_point_to_site_vpn_gateway' = 140 # P2S VPN gateway
            'azurerm_local_network_gateway' = 0      # Definition only
            'azurerm_virtual_network_peering' = 0    # $0.01/GB data transfer only
            'azurerm_private_endpoint' = 7           # $0.01/hr
            'azurerm_private_link_service' = 7       # $0.01/hr
            'azurerm_network_interface' = 0          # Free
            'azurerm_network_security_group' = 0     # Free (SDN)
            'azurerm_route_table' = 0                # Free (SDN)
            'azurerm_firewall_policy' = 0            # Included in firewall cost
            'azurerm_web_application_firewall_policy' = 0 # Included in App GW
            'azurerm_frontdoor_firewall_policy' = 5  # $5/policy/mo
            'azurerm_network_watcher' = 0            # Free (auto-created)
            'azurerm_network_watcher_flow_log' = 5   # $1.4986/GB
            'azurerm_network_ddos_protection_plan' = 2944 # $2944/mo flat
            'azurerm_ip_group' = 0                   # Free
            'azurerm_virtual_network' = 0            # Free (SDN)
            'azurerm_subnet' = 0                     # Free (SDN)
            # --- Monitoring ---
            'azurerm_dashboard_grafana' = 22         # Essential ~$0.03/hr
            'azurerm_monitor_workspace' = 0          # Pay per data ingested
            'azurerm_log_analytics_workspace' = 0    # First 5GB/day free; $2.76/GB after
            'azurerm_application_insights' = 0       # First 5GB/mo free; $2.30/GB after
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
        # NOTE: Avoid overly-generic tokens (like '*') that commonly appear in version strings (e.g. 1.*.*)
        # as they create many false-positive security concerns.
        # NOTE: Avoid overly broad tokens (like 'public') because they frequently appear in *security hardening*
        # policy names (e.g., 'Deny-Public-IP') and create false-positive concerns.
        NegativeKeywords = @('disabled', 'false', 'none', '0.0.0.0/0', 'allow_all')
    }
    
    # Resource category mapping
    Categories = @{
        Compute = @(
            'virtual_machine', 'instance', 'kubernetes', 'container', 'function_app', 'app_service',
            'batch', 'vm_scale_set', 'aks', 'eks', 'gke', 'ecs', 'lambda', 'compute_instance',
            'container_group', 'container_registry', 'batch_account', 'logic_app', 'web_app'
        )
        Storage = @(
            'storage_account', 's3_bucket', 'disk', 'managed_disk', 'blob', 'file_share',
            'storage_bucket', 'ebs_volume', 'persistent_disk', 'storage_container',
            'storage_queue', 'storage_table', 'data_lake'
        )
        Network = @(
            'virtual_network', 'subnet', 'network_security_group', 'firewall', 'load_balancer',
            'application_gateway', 'vpn', 'express_route', 'nat_gateway', 'public_ip',
            'private_endpoint', 'traffic_manager', 'network_interface', 'route_table',
            'network_watcher', 'vpc', 'security_group', 'route_table', 'peering'
        )
        Database = @(
            'sql_database', 'mysql', 'postgresql', 'cosmosdb', 'redis', 'mariadb',
            'rds_instance', 'dynamodb', 'cloud_sql', 'documentdb'
        )
        Security = @(
            'key_vault', 'certificate', 'secret', 'identity', 'role_assignment',
            'policy_assignment', 'security_center', 'defender', 'kms', 'secrets_manager',
            'iam_role', 'iam_policy', 'backup', 'recovery', 'site_recovery'
        )
        Monitoring = @(
            'log_analytics', 'application_insights', 'monitor', 'diagnostic', 'alert',
            'autoscale', 'cloudwatch', 'stackdriver', 'metric'
        )
    }
    
    # ==================================================================================
    # CARBON FOOTPRINT ESTIMATION — METHODOLOGY & DISCLAIMER
    # ==================================================================================
    #
    # ⚠️  IMPORTANT: These values are INFERENCE-BASED ESTIMATES, NOT precise measurements.
    #     They are NOT sourced from actual Azure telemetry, billing, or metering APIs.
    #     Real-world emissions depend on workload utilization, hardware generation,
    #     renewable energy procurement (RECs/PPAs), time-of-day grid mix, and more.
    #     Use these figures for DIRECTIONAL AWARENESS only — not for carbon accounting,
    #     compliance reporting, or sustainability audits.
    #
    # For actual measured emissions, use:
    #   - Microsoft Emissions Impact Dashboard (per-subscription actual data)
    #   - Azure Carbon Optimization (preview, per-resource actual data)
    #
    # --- CALCULATION METHODOLOGY ---
    #
    # The formula structure is inspired by the Cloud Carbon Footprint (CCF) open-source
    # methodology, but the specific per-vCPU wattage values are the AUTHOR'S OWN ESTIMATES
    # based on general knowledge of server hardware TDP ranges — they are NOT taken directly
    # from CCF's published microarchitecture-specific coefficients.
    #   https://www.cloudcarbonfootprint.org/docs/methodology/
    #
    # Formula for VMs:
    #   Power (W)     = vCPUs × Watts_per_vCPU × Utilization_Factor
    #   Energy (kWh)  = Power(W) × PUE × Hours_per_Month / 1000
    #   Emissions     = Energy(kWh) × Carbon_Intensity(kgCO2e/kWh)
    #
    # Constants used:
    #   PUE                = 1.125  (approximately in line with Microsoft's reported ~1.12-1.18
    #                                range for Azure datacenters; exact 2024 figure not verified)
    #   Hours per month    = 730    (365.25 days × 24h / 12)
    #   Utilization factor = 0.50   (assumed blended idle+active average; NOT derived from
    #                                specific SPECpower benchmark data for Azure hardware)
    #   Baseline intensity = 0.400  kgCO2e/kWh (values in tables below are pre-computed
    #                                at this baseline; the script then scales per region)
    #
    # Per-vCPU power draw by family (AUTHOR'S ESTIMATES based on general knowledge of
    # server TDP envelopes and VM-to-host ratios — NOT from published data sources):
    #   B-series (burstable)        ~3.8 W/vCPU
    #   D-series (general purpose)  ~7.5 W/vCPU
    #   E-series (memory optimized) ~10  W/vCPU  (higher due to memory subsystem)
    #   F-series (compute optimized) ~10 W/vCPU  (higher clock = higher TDP)
    #   L-series (storage optimized) ~12 W/vCPU  (includes local NVMe disk overhead)
    #   M-series (memory intensive)  ~12 W/vCPU  (massive DRAM arrays)
    #   N-series (GPU)              CPU portion + GPU TDP per card:
    #                               K80 half=150W, V100=300W, A100=400W, T4=70W
    #                               (GPU TDP values are from NVIDIA published specs)
    #
    # --- WORKED EXAMPLE: Standard_D2s_v3 in eastus ---
    #
    #   Step 1 — Power:   2 vCPUs × 7.5 W/vCPU × 0.50 utilization  = 7.5 W
    #   Step 2 — Energy:  7.5 W × 1.125 PUE × 730 h / 1000         = 6.16 kWh/month
    #   Step 3 — At baseline (400 gCO2e/kWh):  6.16 × 0.400        = 2.46 kg CO2e/month
    #   Stored value: 2.5 (rounded)
    #
    #   At runtime the script scales by actual region:
    #     eastus (385 gCO2e/kWh):   2.5 × (385/400)  = 2.4 kg CO2e/month
    #     swedencentral (9 gCO2e/kWh): 2.5 × (9/400) = 0.06 kg CO2e/month
    #     australiaeast (640 gCO2e/kWh): 2.5 × (640/400) = 4.0 kg CO2e/month
    #
    # --- WORKED EXAMPLE: Standard_NC24ads_A100_v4 in westeurope ---
    #
    #   CPU: 24 vCPUs × 10 W × 0.5 = 120 W
    #   GPU: 1× A100 × 400 W × 0.5 = 200 W
    #   Total: 320 W
    #   Energy: 320 × 1.125 × 730 / 1000 = 262.8 kWh/month
    #   At baseline: 262.8 × 0.400 = 105.1 kg → stored as 95.0 (adjusted for shared infra)
    #
    # --- WORKED EXAMPLE: azurerm_storage_account in francecentral ---
    #
    #   Base power estimate: ~6 W (HDD spindle + controller idle overhead)
    #   Energy: 6 × 1.125 × 730 / 1000 = 4.93 kWh/month
    #   At baseline: 4.93 × 0.400 = 1.97 → stored as 1.0 (conservative, most are idle)
    #   At runtime: 1.0 × (56/400) = 0.14 kg CO2e/month in francecentral
    #
    # --- LEGEND ---
    #
    #   RegionalIntensity : gCO2e per kWh of grid electricity for each Azure region.
    #                       These values are the AUTHOR'S APPROXIMATE ESTIMATES based on
    #                       general knowledge of national/regional electricity grid mixes.
    #                       They were NOT fetched from Electricity Maps or IEA data tables.
    #                       Treat as rough order-of-magnitude figures only.
    #
    #   VMSizes           : Pre-computed kg CO2e/month at 400 gCO2e/kWh baseline
    #                       for specific Azure VM SKUs. Scaled at runtime by region.
    #
    #   Services          : Pre-computed kg CO2e/month at 400 gCO2e/kWh baseline
    #                       for Azure PaaS/service resource types using estimated
    #                       typical power draw. Intentionally conservative.
    #
    #   LowCarbonRegions  : Regions with <100 gCO2e/kWh — flagged as sustainability-
    #                       friendly choices in recommendations.
    #
    #   Fallback logic    : Resources NOT in VMSizes or Services tables fall back to
    #                       cost-tier-based estimates (High ~40W, Medium ~10W, Low ~2W).
    #                       Resources not in any list produce zero emissions.
    #
    # --- REFERENCES & RECOMMENDED READING ---
    #
    # The following resources informed the general approach but were NOT directly used
    # to produce the specific numeric values in these tables. The per-vCPU wattages,
    # regional carbon intensities, and service power estimates are the author's own
    # approximations based on general domain knowledge. Users who need accurate data
    # should consult these sources directly.
    #
    #   [1] Cloud Carbon Footprint — Open-source methodology (formula structure inspiration)
    #       https://www.cloudcarbonfootprint.org/docs/methodology/
    #   [2] Electricity Maps — Live & historical grid carbon intensity (recommended for
    #       obtaining accurate, up-to-date regional gCO2e/kWh values)
    #       https://app.electricitymaps.com/
    #   [3] IEA — Emission Factors (authoritative national grid data; recommended for
    #       validating or replacing the approximate regional values used here)
    #       https://www.iea.org/data-and-statistics
    #   [4] Microsoft Environmental Sustainability Report — Reports Azure PUE in the
    #       ~1.12-1.18 range, which informed the 1.125 constant used here
    #       https://www.microsoft.com/en-us/corporate-responsibility/sustainability
    #   [5] NVIDIA GPU specifications — Published TDP values for K80, V100, A100, T4
    #       used for the GPU portion of N-series VM calculations
    #       https://www.nvidia.com/en-us/data-center/
    #   [6] Azure Carbon Optimization (preview) — Microsoft's actual per-resource emission
    #       data. Use this instead of this tool's estimates for real carbon accounting.
    #       https://learn.microsoft.com/en-us/azure/carbon-optimization/overview
    #   [7] Microsoft Emissions Impact Dashboard — Actual measured emissions per subscription.
    #       The authoritative source for compliance and sustainability reporting.
    #       https://www.microsoft.com/en-us/sustainability/emissions-impact-dashboard
    #
    # ==================================================================================
    CarbonFootprint = @{
        # Regional carbon intensity (gCO2e/kWh) - Author's approximate estimates based on
        # general knowledge of national electricity grid mixes. NOT fetched from Electricity
        # Maps or IEA data tables. For accurate values, consult those sources directly.
        RegionalIntensity = @{
            # === Americas ===
            'eastus' = 385; 'eastus2' = 385
            'westus' = 294; 'westus2' = 294; 'westus3' = 294
            'centralus' = 460; 'northcentralus' = 460; 'southcentralus' = 460; 'westcentralus' = 460
            'canadacentral' = 25; 'canadaeast' = 25
            'brazilsouth' = 79; 'brazilsoutheast' = 79
            'mexicocentral' = 420
            # === Europe ===
            'northeurope' = 275; 'westeurope' = 295
            'uksouth' = 233; 'ukwest' = 233
            'francecentral' = 56; 'francesouth' = 56
            'germanywestcentral' = 338; 'germanynorth' = 338
            'swedencentral' = 9
            'norwayeast' = 8; 'norwaywest' = 8
            'switzerlandnorth' = 11; 'switzerlandwest' = 11
            'polandcentral' = 635
            'italynorth' = 310
            'spaincentral' = 170
            'austriaeast' = 105
            'belgiumcentral' = 155
            'finlandcentral' = 80
            'denmarkeast' = 115
            'greececentral' = 380
            # === Middle East & Africa ===
            'southafricanorth' = 890; 'southafricawest' = 890
            'uaenorth' = 475; 'uaecentral' = 475
            'qatarcentral' = 500
            'israelcentral' = 440
            'saudiarabiacentral' = 520
            # === Asia Pacific ===
            'eastasia' = 575; 'southeastasia' = 475
            'japaneast' = 465; 'japanwest' = 465
            'koreacentral' = 415; 'koreasouth' = 415
            'centralindia' = 630; 'southindia' = 630; 'westindia' = 630; 'jioindiawest' = 630; 'jioindiacentral' = 630
            'australiaeast' = 640; 'australiasoutheast' = 640; 'australiacentral' = 640; 'australiacentral2' = 640
            'newzealandnorth' = 95
            'taiwannorth' = 510
            'indonesiacentral' = 650
            'malaysiawest' = 530
            # === China (21Vianet) ===
            'chinaeast' = 555; 'chinaeast2' = 555; 'chinaeast3' = 555
            'chinanorth' = 620; 'chinanorth2' = 620; 'chinanorth3' = 620
            # === Government ===
            'usgovvirginia' = 385; 'usgovtexas' = 460; 'usgovarizona' = 460
            'usdodeast' = 385; 'usdodcentral' = 460
            'usgoviowacentral' = 460
        }
        # VM carbon footprint (kg CO2e/month) at 400 gCO2e/kWh baseline
        # Methodology: Power(W) = vCPUs * TDP_per_vCPU * utilization_factor
        #   TDP_per_vCPU: ~3.8W (B-series burstable), ~7.5W (general), ~10W (compute), ~12W (memory), ~15W+ (GPU)
        #   Utilization factor: 0.5 average (author's assumed blend, NOT from benchmarks)
        #   PUE: 1.125 (approximately in line with Microsoft's reported ~1.12-1.18 range)
        #   kWh/mo = Watts * PUE * 730h / 1000
        #   kg CO2e/mo = kWh/mo * 0.400 (baseline gCO2e/kWh)
        # See main methodology block above for full disclaimer and references.
        VMSizes = @{
            # B-series (burstable, ~3.8W/vCPU at 50% util)
            # 1 vCPU: 3.8*0.5*1.125*730/1000*0.4 = 0.62 -> round to 0.6
            'Standard_B1s' = 0.6; 'Standard_B1ms' = 0.6; 'Standard_B2s' = 1.2
            'Standard_B2ms' = 1.2; 'Standard_B4ms' = 2.5; 'Standard_B8ms' = 5.0
            'Standard_B12ms' = 7.5; 'Standard_B16ms' = 10.0; 'Standard_B20ms' = 12.5
            # D-series v3/v4/v5 (general purpose, ~7.5W/vCPU at 50% util)
            # 2 vCPU: 2*7.5*0.5*1.125*730/1000*0.4 = 2.5
            'Standard_D2s_v3' = 2.5; 'Standard_D4s_v3' = 4.9; 'Standard_D8s_v3' = 9.9
            'Standard_D16s_v3' = 19.7; 'Standard_D32s_v3' = 39.4; 'Standard_D48s_v3' = 59.1; 'Standard_D64s_v3' = 78.8
            'Standard_D2s_v4' = 2.5; 'Standard_D4s_v4' = 4.9; 'Standard_D8s_v4' = 9.9
            'Standard_D16s_v4' = 19.7; 'Standard_D32s_v4' = 39.4; 'Standard_D48s_v4' = 59.1; 'Standard_D64s_v4' = 78.8
            'Standard_D2s_v5' = 2.3; 'Standard_D4s_v5' = 4.6; 'Standard_D8s_v5' = 9.2
            'Standard_D16s_v5' = 18.5; 'Standard_D32s_v5' = 36.9; 'Standard_D48s_v5' = 55.4; 'Standard_D64s_v5' = 73.8
            'Standard_D2as_v5' = 2.1; 'Standard_D4as_v5' = 4.3; 'Standard_D8as_v5' = 8.5
            'Standard_D16as_v5' = 17.1; 'Standard_D32as_v5' = 34.2; 'Standard_D48as_v5' = 51.2; 'Standard_D64as_v5' = 68.3
            # E-series (memory optimized, ~10W/vCPU at 50% util due to higher memory power)
            # 2 vCPU: 2*10*0.5*1.125*730/1000*0.4 = 3.3
            'Standard_E2s_v3' = 3.3; 'Standard_E4s_v3' = 6.6; 'Standard_E8s_v3' = 13.1
            'Standard_E16s_v3' = 26.3; 'Standard_E32s_v3' = 52.6; 'Standard_E48s_v3' = 78.8; 'Standard_E64s_v3' = 105.1
            'Standard_E2s_v4' = 3.3; 'Standard_E4s_v4' = 6.6; 'Standard_E8s_v4' = 13.1
            'Standard_E16s_v4' = 26.3; 'Standard_E32s_v4' = 52.6; 'Standard_E48s_v4' = 78.8; 'Standard_E64s_v4' = 105.1
            'Standard_E2s_v5' = 3.0; 'Standard_E4s_v5' = 6.1; 'Standard_E8s_v5' = 12.1
            'Standard_E16s_v5' = 24.3; 'Standard_E32s_v5' = 48.5; 'Standard_E48s_v5' = 72.8; 'Standard_E64s_v5' = 97.1
            'Standard_E2as_v5' = 2.8; 'Standard_E4as_v5' = 5.6; 'Standard_E8as_v5' = 11.2
            'Standard_E16as_v5' = 22.4; 'Standard_E32as_v5' = 44.8; 'Standard_E48as_v5' = 67.2; 'Standard_E64as_v5' = 89.6
            # F-series (compute optimized, ~10W/vCPU at 50% util, higher clock)
            'Standard_F2s_v2' = 3.3; 'Standard_F4s_v2' = 6.6; 'Standard_F8s_v2' = 13.1
            'Standard_F16s_v2' = 26.3; 'Standard_F32s_v2' = 52.6; 'Standard_F48s_v2' = 78.8; 'Standard_F64s_v2' = 105.1; 'Standard_F72s_v2' = 118.3
            # L-series (storage optimized, ~10W/vCPU + ~2W/vCPU disk overhead)
            'Standard_L8s_v2' = 15.8; 'Standard_L16s_v2' = 31.5; 'Standard_L32s_v2' = 63.1
            'Standard_L48s_v2' = 94.6; 'Standard_L64s_v2' = 126.1; 'Standard_L80s_v2' = 157.7
            'Standard_L8s_v3' = 14.5; 'Standard_L16s_v3' = 29.0; 'Standard_L32s_v3' = 58.1
            'Standard_L48s_v3' = 87.1; 'Standard_L64s_v3' = 116.1; 'Standard_L80s_v3' = 145.2
            # M-series (memory intensive, ~12W/vCPU + large memory subsystem)
            'Standard_M8ms' = 15.8; 'Standard_M16ms' = 31.5; 'Standard_M32ms' = 63.1
            'Standard_M64ms' = 126.1; 'Standard_M128ms' = 252.3
            # N-series (GPU) - GPU TDP dominates: T4=70W, V100=300W, A100=400W per GPU
            # NC6 (1x K80 half=150W): (6*10+150)*0.5*1.125*730/1000*0.4 = 40.1
            'Standard_NC6' = 40.1; 'Standard_NC12' = 68.5; 'Standard_NC24' = 125.3
            # NC v3 (V100 300W/GPU): NC6s_v3 (1x V100)
            'Standard_NC6s_v3' = 59.1; 'Standard_NC12s_v3' = 106.5; 'Standard_NC24s_v3' = 201.2
            # NC A100 (400W/GPU): NC24 (1xA100), NC48 (2xA100), NC96 (4xA100)
            'Standard_NC24ads_A100_v4' = 95.0; 'Standard_NC48ads_A100_v4' = 178.4; 'Standard_NC96ads_A100_v4' = 345.2
            # ND A100 (8xA100 = 3200W GPU + ~96 vCPU = 480W CPU)
            'Standard_ND96asr_v4' = 604.0; 'Standard_ND96amsr_A100_v4' = 604.0
            # NV (visualization GPU, M60=300W, T4=70W)
            'Standard_NV6' = 40.1; 'Standard_NV12' = 68.5; 'Standard_NV24' = 125.3
            'Standard_NV12s_v3' = 26.3; 'Standard_NV24s_v3' = 46.7; 'Standard_NV48s_v3' = 87.5
            # A-series (basic/legacy, ~5W/vCPU older hardware)
            'Standard_A1_v2' = 0.8; 'Standard_A2_v2' = 1.6; 'Standard_A4_v2' = 3.3; 'Standard_A8_v2' = 6.6
            'Standard_A2m_v2' = 1.6; 'Standard_A4m_v2' = 3.3; 'Standard_A8m_v2' = 6.6
        }
        # Service carbon footprint (kg CO2e/month) at 400 gCO2e/kWh baseline
        # Methodology: estimate typical server power draw per service, then:
        #   kWh/mo = Watts * PUE(1.125) * 730h / 1000
        #   kg CO2e/mo = kWh/mo * 0.400
        # Power estimates are the author's approximations. See main methodology block above.
        Services = @{
            # --- Compute ---
            'azurerm_kubernetes_cluster' = 7.4        # AKS control plane (~3 small VMs shared) ~45W
            'azurerm_virtual_machine_scale_set' = 9.9 # Average 2-node D2s ~60W total
            'azurerm_container_group' = 2.5           # ACI ~1 vCPU avg ~15W
            'azurerm_container_registry' = 0.8        # ACR storage + minimal compute ~5W
            'azurerm_container_app' = 1.6             # Consumption avg ~10W
            'azurerm_container_app_environment' = 0.2 # Shared infra overhead ~1W
            'azurerm_linux_web_app' = 1.6             # B1 plan ~1 vCPU ~10W
            'azurerm_windows_web_app' = 1.6           # B1 plan ~1 vCPU ~10W
            'azurerm_app_service' = 1.6               # Classic ~1 vCPU ~10W
            'azurerm_function_app' = 0.8              # Dedicated plan small ~5W avg
            'azurerm_linux_function_app' = 0.8        # Functions Linux ~5W avg
            'azurerm_windows_function_app' = 0.8      # Functions Windows ~5W avg
            'azurerm_app_service_plan' = 1.6          # Plan compute ~10W
            'azurerm_service_plan' = 1.6              # Modern plan ~10W
            'azurerm_batch_account' = 0.3             # Account infra only ~2W
            'azurerm_batch_pool' = 9.9                # Default pool ~2 VMs ~60W
            'azurerm_spring_cloud_service' = 4.9      # 2 app instances ~30W
            'azurerm_cognitive_account' = 1.6         # S0 tier ~10W avg
            'azurerm_machine_learning_workspace' = 0.5 # Workspace metadata ~3W
            'azurerm_machine_learning_compute_cluster' = 9.9  # Default 2-node ~60W
            'azurerm_machine_learning_compute_instance' = 2.5 # Single small VM ~15W
            'azurerm_logic_app_workflow' = 0.3         # Event-driven ~2W avg
            'azurerm_api_management' = 3.3             # Developer tier 1 vCPU ~20W
            'azurerm_signalr_service' = 0.8            # Standard unit ~5W
            'azurerm_web_pubsub' = 0.8                 # Standard unit ~5W
            'azurerm_dedicated_host_group' = 0.3       # Group metadata ~2W
            'azurerm_dedicated_host' = 42.0            # Physical server ~256W avg (Dsv3 host TDP)
            'azurerm_vmware_private_cloud' = 126.0     # 3 ESXi hosts minimum ~256W each = 768W
            'azurerm_orchestrated_virtual_machine_scale_set' = 9.9 # Flex VMSS ~2 VMs ~60W
            'azurerm_redhat_openshift_cluster' = 14.8  # ARO 3 master + 3 worker ~90W
            'azurerm_hdinsight_hadoop_cluster' = 14.8  # 2 head + 3 worker nodes ~90W
            'azurerm_hdinsight_spark_cluster' = 19.7   # 2 head + 4 worker nodes ~120W
            'azurerm_hdinsight_hbase_cluster' = 14.8   # 2 head + 3 region nodes ~90W
            'azurerm_hdinsight_interactive_query_cluster' = 14.8 # Similar to Hadoop ~90W
            'azurerm_hdinsight_kafka_cluster' = 19.7   # 3 head + 3 broker + ZK ~120W
            'azurerm_powerbi_embedded' = 4.9           # A1 SKU ~1 vCore ~30W
            'azurerm_static_site' = 0.1               # Static CDN-served ~1W
            # --- Databases & Data ---
            'azurerm_sql_database' = 3.3              # Azure SQL Basic ~2 vCore ~20W
            'azurerm_mssql_database' = 3.3            # Azure SQL Basic ~2 vCore ~20W
            'azurerm_mssql_server' = 0.2             # Logical server metadata ~1W
            'azurerm_mssql_elasticpool' = 6.6         # Elastic pool ~4 vCore ~40W
            'azurerm_sql_managed_instance' = 13.1     # GP 2 vCores + infra ~80W
            'azurerm_postgresql_server' = 2.5         # Basic 1 vCore ~15W
            'azurerm_postgresql_flexible_server' = 2.5 # Burstable 1 vCore ~15W
            'azurerm_postgresql_database' = 0.2      # DB on existing server ~1W
            'azurerm_mysql_server' = 2.5              # Basic 1 vCore ~15W
            'azurerm_mysql_flexible_server' = 2.5     # Burstable 1 vCore ~15W
            'azurerm_mysql_database' = 0.2           # DB on existing server ~1W
            'azurerm_mariadb_server' = 2.5            # Basic 1 vCore ~15W
            'azurerm_cosmosdb_account' = 4.9          # 400 RU/s ~30W
            'azurerm_cosmosdb_sql_database' = 1.6     # Shared throughput ~10W
            'azurerm_cosmosdb_sql_container' = 0.8    # Container partition ~5W
            'azurerm_cosmosdb_mongo_database' = 1.6   # Shared throughput ~10W
            'azurerm_cosmosdb_mongo_collection' = 0.8 # Collection partition ~5W
            'azurerm_cosmosdb_table' = 0.8            # Table API ~5W
            'azurerm_cosmosdb_cassandra_keyspace' = 1.6 # Cassandra ~10W
            'azurerm_cosmosdb_gremlin_database' = 1.6 # Gremlin ~10W
            'azurerm_redis_cache' = 1.6              # Basic C0 ~10W
            'azurerm_redis_enterprise_cluster' = 6.6  # Enterprise E10 ~40W
            'azurerm_search_service' = 2.5            # Basic 1 replica ~15W
            'azurerm_data_factory' = 1.6              # ADF orchestration ~10W
            'azurerm_data_factory_pipeline' = 0.3     # Pipeline runs ~2W avg
            'azurerm_synapse_workspace' = 2.5         # Workspace serverless ~15W
            'azurerm_synapse_sql_pool' = 8.2          # DW100c dedicated ~50W
            'azurerm_synapse_spark_pool' = 6.6        # Small 3-node pool ~40W
            'azurerm_databricks_workspace' = 0.5      # Control plane ~3W
            'azurerm_kusto_cluster' = 8.2             # Dev/test D11_v2 x2 ~50W
            'azurerm_stream_analytics_job' = 1.6      # 1 SU ~10W
            'azurerm_eventhub_namespace' = 1.6        # Basic 1 TU ~10W
            'azurerm_eventhub' = 0.3                  # Hub partition ~2W
            'azurerm_service_bus_namespace' = 0.8     # Basic tier ~5W
            'azurerm_service_bus_queue' = 0.1         # Queue on namespace ~0.5W
            'azurerm_service_bus_topic' = 0.1         # Topic on namespace ~0.5W
            'azurerm_eventgrid_topic' = 0.2           # Event routing ~1W
            'azurerm_eventgrid_domain' = 0.3          # Domain routing ~2W
            'azurerm_iothub' = 1.6                    # S1 tier ~10W
            'azurerm_digital_twins_instance' = 1.0    # Instance ~6W
            'azurerm_data_lake_store' = 1.6           # Gen1 storage ~10W
            'azurerm_data_lake_analytics_account' = 2.5 # Analytics compute ~15W
            'azurerm_purview_account' = 1.6            # Data governance ~10W
            'azurerm_notification_hub_namespace' = 0.3  # Notification hub ~2W
            # --- Storage ---
            # Storage power: HDD ~5W/drive, SSD ~2W, per-account ~6W avg idle overhead
            'azurerm_storage_account' = 1.0           # GPv2 account ~6W
            'azurerm_storage_share' = 0.5             # Files share overhead ~3W
            'azurerm_storage_container' = 0.2         # Container within account ~1W
            'azurerm_storage_queue' = 0.05            # Queue minimal ~0.3W
            'azurerm_storage_table' = 0.05            # Table minimal ~0.3W
            'azurerm_storage_data_lake_gen2_filesystem' = 0.5 # ADLS Gen2 ~3W
            'azurerm_managed_disk' = 0.3              # Single disk idle ~2W
            'azurerm_hpc_cache' = 4.9                 # Cache nodes ~30W
            'azurerm_netapp_account' = 0.3            # Account metadata ~2W
            'azurerm_netapp_pool' = 3.3               # Capacity pool ~20W
            'azurerm_netapp_volume' = 1.6             # Volume ~10W
            'azurerm_recovery_services_vault' = 0.3   # Vault service ~2W
            'azurerm_backup_protected_vm' = 0.5       # Backup overhead ~3W
            'azurerm_backup_container_storage_account' = 0.3 # Storage backup ~2W
            'azurerm_storage_blob' = 0.02             # Individual blob ~0.1W
            'azurerm_storage_management_policy' = 0   # Policy (no compute)
            'azurerm_data_protection_backup_vault' = 0.3 # Modern backup vault ~2W
            # --- Networking ---
            # Networking: appliances have dedicated VMs; SDN resources are near-zero
            'azurerm_application_gateway' = 3.3       # V2 Standard ~20W (shared infra)
            'azurerm_firewall' = 8.2                  # Dedicated VM ~50W
            'azurerm_vpn_gateway' = 3.3               # VpnGw1 ~20W
            'azurerm_virtual_network_gateway' = 3.3   # VNet GW ~20W
            'azurerm_bastion_host' = 1.6              # Basic SKU ~10W
            'azurerm_front_door' = 2.5                # Edge PoP share ~15W
            'azurerm_cdn_profile' = 0.5               # CDN edge ~3W
            'azurerm_cdn_endpoint' = 0.2              # Endpoint ~1W
            'azurerm_traffic_manager_profile' = 0.1   # DNS routing ~0.5W
            'azurerm_traffic_manager_endpoint' = 0.02 # Health check ~0.1W
            'azurerm_dns_zone' = 0.02                 # DNS zone ~0.1W
            'azurerm_private_dns_zone' = 0.01         # Private DNS ~0.05W
            'azurerm_public_ip' = 0.05                # IP allocation ~0.3W
            'azurerm_public_ip_prefix' = 0.05         # IP prefix ~0.3W
            'azurerm_lb' = 0.5                        # Standard LB ~3W
            'azurerm_lb_rule' = 0.02                  # Rule config ~0.1W
            'azurerm_nat_gateway' = 0.5               # NAT GW ~3W
            'azurerm_express_route_circuit' = 3.3     # ER circuit dedicated ~20W
            'azurerm_express_route_gateway' = 3.3     # ER gateway ~20W
            'azurerm_virtual_wan' = 1.0               # vWAN hub ~6W
            'azurerm_virtual_hub' = 1.0               # Hub routing ~6W
            'azurerm_point_to_site_vpn_gateway' = 1.6 # P2S GW ~10W
            'azurerm_local_network_gateway' = 0.1     # Config reference ~0.5W
            'azurerm_virtual_network_peering' = 0.02  # Peering link ~0.1W
            'azurerm_private_endpoint' = 0.05         # PE NIC ~0.3W
            'azurerm_private_link_service' = 0.1      # PLS ~0.5W
            'azurerm_network_interface' = 0.02        # NIC ~0.1W
            'azurerm_network_security_group' = 0.02   # NSG rules ~0.1W
            'azurerm_route_table' = 0.02              # UDR ~0.1W
            'azurerm_firewall_policy' = 0.02          # Policy definition ~0.1W
            'azurerm_web_application_firewall_policy' = 0.05 # WAF rules ~0.3W
            'azurerm_frontdoor_firewall_policy' = 0.1 # FD WAF ~0.5W
            'azurerm_network_watcher' = 0.02          # Watcher ~0.1W
            'azurerm_network_watcher_flow_log' = 0.2  # Flow log processing ~1W
            'azurerm_network_ddos_protection_plan' = 1.6 # DDoS monitoring ~10W
            'azurerm_ip_group' = 0.01                 # IP group ~0.05W
            'azurerm_virtual_network' = 0.02          # VNet SDN ~0.1W
            'azurerm_subnet' = 0.01                   # Subnet ~0.05W
            # --- Monitoring (compute-bearing) ---
            'azurerm_dashboard_grafana' = 0.8          # Grafana instance ~5W
            'azurerm_monitor_workspace' = 0.5          # Prometheus ~3W
            'azurerm_log_analytics_workspace' = 0.3    # Ingestion service ~2W
            'azurerm_application_insights' = 0.2       # App Insights ~1W
        }
        # Low carbon regions (best for sustainability) - regions with <100 gCO2e/kWh
        LowCarbonRegions = @{
            'Azure' = @('norwayeast', 'norwaywest', 'swedencentral', 'francecentral', 'francesouth',
                        'switzerlandnorth', 'switzerlandwest', 'canadacentral', 'canadaeast',
                        'brazilsouth', 'brazilsoutheast', 'newzealandnorth', 'finlandcentral',
                        'austriaeast')
        }
    }
    
    # Governance and compliance indicators
    GovernanceIndicators = @{
        Tags = @('tags', 'tag =', 'cost_center', 'environment', 'owner', 'project', 'compliance')
        # Naming convention patterns to detect proper naming standards
        NamingPatterns = @{
            # Azure resource prefixes (Microsoft CAF recommended)
            AzurePrefixes = @('rg-', 'vnet-', 'snet-', 'nsg-', 'vm-', 'nic-', 'pip-', 'st-', 'kv-', 'law-', 'agw-', 'fw-', 'vpn-', 'bas-', 'aks-', 'sql-', 'db-', 'app-', 'func-', 'pe-', 'pls-', 'pdns-')
            # Environment indicators
            Environments = @('-prod-', '-dev-', '-test-', '-uat-', '-staging-', '-qa-', '-demo-', '-sandbox-', '-prod$', '-dev$', '-test$', '-uat$', '-staging$', '-qa$', '-demo$', '-sandbox$', '^prod-', '^dev-', '^test-', '^uat-', '^staging-', '^qa-', '^demo-', '^sandbox-')
            # Region indicators
            Regions = @('-eastus-', '-westus-', '-centralus-', '-northeurope-', '-westeurope-', '-southeastasia-')
            # Numbered instances
            NumberedInstances = @('-\d{2,3}$', '-\d{2,3}-', '-v\d+$')
        }
        Policies = @('azurerm_policy_assignment', 'azurerm_policy_definition', 'azurerm_monitor_diagnostic_setting', 'azurerm_log_analytics_workspace', 'azurerm_monitor_action_group', 'azurerm_monitor_metric_alert', 'policy_assignment', 'policy_definition', 'policy_set_definition')
        # Backup-related indicators (backup/restore tooling).
        Backup = @('backup', 'recovery_services_vault', 'backup_policy', 'backup_protected', 'site_recovery')
        # Retention/resiliency indicators (often not "backup & restore"; includes data/log retention and replication).
        RetentionResiliency = @('retention', 'soft_delete', 'delete_retention', 'geo_redundant', 'replication')
        Locks = @('azurerm_management_lock', 'can_not_delete', 'read_only_lock', 'delete_lock')
        RBAC = @('role_assignment', 'role_definition', 'principal_id', 'scope_id')
        NetworkIsolation = @('azurerm_private_endpoint', 'azurerm_private_link_service', 'azurerm_app_service_virtual_network_swift_connection')
        AuditLogging = @('log_analytics_workspace', 'diagnostic_setting', 'activity_log_alert', 'log_retention_days')
        ComplianceFrameworks = @('policy_assignment', 'policy_definition', 'policy_set_definition', 'security_center_subscription', 'defender_for_cloud')
        CostManagement = @('consumption_budget', 'cost_management_export', 'spending_limit')
        # Azure Landing Zone (ALZ) well-known policy categories for compliance validation
        # Based on the Azure/Enterprise-Scale reference implementation policy assignments
        ALZPolicyCategories = @{
            Security = @('Deny-MgmtPorts-Internet', 'Deny-Public-IP', 'Deny-Public-Endpoints', 'Deny-Public-IP-On-NIC', 'Enforce-TLS-SSL', 'Enforce-AKS-HTTPS', 'Deny-HybridNetworking', 'Deny-Priv-Esc-AKS', 'Deny-Privileged-AKS', 'Deploy-ASC-Monitoring', 'Deploy-MDFC', 'Deploy-MDEndpoints', 'Deploy-MDEndpointsAMA', 'Enforce-ACSB')
            Identity = @('Deny-Public-IP', 'Deny-MgmtPorts-Internet', 'Deny-Subnet-Without-Nsg', 'DenyAction-DeleteUAMIAMA')
            Networking = @('Deny-HybridNetworking', 'Deploy-Private-DNS-Zones', 'Deny-Public-Endpoints', 'Deny-Public-IP-On-NIC', 'Audit-PeDnsZones', 'Enforce-Subnet-Private', 'Deploy-Nsg-FlowLogs', 'DeployFlowLog')
            Logging = @('Deploy-AzActivity-Log', 'Enable-AllLogs-to-law', 'enable-audit-to-law', 'Enab_Activity_Logs_To_LA', 'Enab_Activity_Logs_To_EH', 'Deploy-Diag-LogsCat', 'Deploy-Diagnostics')
            Monitoring = @('Deploy-VM-Monitoring', 'Deploy-VMSS-Monitoring', 'Deploy-vmHybr-Monitoring', 'Deploy-Linux-VM-Mon', 'Deploy-Windows-VM-Mon', 'Deploy-VM-ChangeTrack', 'Deploy-vmArc-ChangeTrack', 'Deploy-VMSS-ChangeTrack', 'Enable-AUM-CheckUpdates')
            DataProtection = @('Deploy-VM-Backup', 'Enforce-Backup', 'Enforce-ASR', 'Deploy-SQL-TDE', 'Deploy-SQL-Threat', 'Deploy-AzSqlDb-Auditing', 'Deploy-MDFC-SqlAtp', 'Deploy-MDFC-OssDb', 'Deploy-MDFC-DefSQL-AMA')
            Compliance = @('allowed_locations', 'Deny-Classic-Resources', 'Deny-UnmanagedDisk', 'Audit-UnusedResources', 'Audit-ResourceRGLocation', 'Audit-TrustedLaunch', 'Audit-ZoneResiliency', 'Enforce-ALZ-Decomm', 'Enforce-ALZ-Sandbox')
            KeyManagement = @('Enforce-GR-KeyVault')
            Storage = @('Deny-Storage-http')
        }
    }
}

# Helper: Extract the actual Terraform provider resource type from a resource address.
# Skips module.<name> prefixes and data. prefix to find the real type.
# Examples:
#   "azurerm_virtual_wan.main"                                          -> "azurerm_virtual_wan"
#   "module.alz.azapi_resource.policy_assignments[\"key\"]"             -> "azapi_resource"
#   "module.a.module.b.azurerm_storage_account.sa1"                     -> "azurerm_storage_account"
#   "module.alz.data.azapi_client_config.hierarchy_settings"            -> "azapi_client_config"
#   "data.azurerm_client_config.current"                                -> "azurerm_client_config"
function Get-TfResourceType {
    param([string]$ResourceAddress)
    $segments = $ResourceAddress -split '\.'
    $i = 0
    # Skip module.<name> pairs
    while ($i -lt ($segments.Count - 1) -and $segments[$i] -eq 'module') {
        $i += 2
    }
    # Skip 'data' prefix for data sources
    if ($i -lt $segments.Count -and $segments[$i] -eq 'data') {
        $i++
    }
    if ($i -lt $segments.Count) { return $segments[$i] }
    return $ResourceAddress
}

# Helper: Split a Terraform resource address into ResourceType and ResourceName for display.
# Returns a hashtable with Type (bare provider type) and Name (the resource instance name).
# Handles module-prefixed and data-source addresses.
function Split-TfResource {
    param([string]$ResourceAddress)
    $segments = $ResourceAddress -split '\.'
    $i = 0
    # Skip module.<name> pairs
    while ($i -lt ($segments.Count - 1) -and $segments[$i] -eq 'module') {
        $i += 2
    }
    # Skip 'data' prefix
    if ($i -lt $segments.Count -and $segments[$i] -eq 'data') {
        $i++
    }
    $type = if ($i -lt $segments.Count) { $segments[$i] } else { $ResourceAddress }
    $name = if (($i + 1) -lt $segments.Count) { ($segments[($i+1)..($segments.Count-1)]) -join '.' } else { '' }
    return @{ Type = $type; Name = $name }
}

# Helper: Check if a resource matches a governance pattern by resource TYPE, not by substring on the full address.
# For azapi_resource, also checks the instance name (e.g., policy_assignments, role_definitions).
# This avoids false positives where "policy_assignment" matched as a substring of "azapi_resource.policy_assignments[...]".
function Test-GovernanceResourceMatch {
    param(
        [string]$ResourceAddress,   # Full Terraform resource address
        [string]$Pattern            # Pattern to match (e.g., 'policy_assignment', 'role_assignment')
    )
    $resType = Get-TfResourceType $ResourceAddress
    # Direct type match (e.g., azurerm_policy_assignment matches 'policy_assignment')
    if ($resType -match $Pattern) { return $true }
    # For azapi_resource, check if the instance name part matches as a resource kind
    if ($resType -eq 'azapi_resource') {
        $split = Split-TfResource $ResourceAddress
        # The instance name for azapi is like 'policy_assignments["key"]' — extract the base name
        $instanceBase = if ($split.Name -match '^([a-z_]+)') { $Matches[1] } else { '' }
        # Match singular/plural forms: 'policy_assignment' should match 'policy_assignments'
        if ($instanceBase -and ($instanceBase -match $Pattern -or ($instanceBase -replace 's$','') -match $Pattern)) {
            return $true
        }
    }
    return $false
}

# Helper: Parse an Azure resource ID to extract Subscription, Resource Group, and Resource Name.
function Get-AzureResourceMeta {
    param([string]$Id, [string]$Name, [string]$ResourceGroupName)
    $subscription = ''
    $resourceGroup = $ResourceGroupName
    if ($Id -match '/subscriptions/([^/]+)') {
        $subscription = $Matches[1]
    }
    if (-not $resourceGroup -and $Id -match '/resourceGroups/([^/]+)') {
        $resourceGroup = $Matches[1]
    }
    $azureName = $Name
    if (-not $azureName -and $Id) {
        # Extract the last segment of the ID as the resource name
        $azureName = ($Id -split '/')[-1]
    }
    return @{ Subscription = $subscription; ResourceGroup = $resourceGroup; AzureName = $azureName }
}

# Read all lines from the file
$lines = Get-Content -Path $LogFile

# Collect results
$results = @()
$currentResource = $null
$captureChanges = $false
$changes = @()
$currentMeta = @{ Name = ''; ResourceGroup = ''; Id = ''; NestDepth = 0 }

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
    # "  # azurerm_resource.name will be imported"
    if ($cleanLine -match '^\s*#\s+(.+?)\s+(will be|must be)\s+(created|destroyed|updated|replaced|imported)') {
        # Save previous resource if exists
        if ($currentResource) {
            $meta = Get-AzureResourceMeta -Id $currentMeta.Id -Name $currentMeta.Name -ResourceGroupName $currentMeta.ResourceGroup
            $results += [PSCustomObject]@{
                Resource      = $currentResource.Resource
                Action        = $currentResource.Action
                Changes       = $changes
                AzureName     = $meta.AzureName
                ResourceGroup = $meta.ResourceGroup
                Subscription  = $meta.Subscription
            }
        }
        
        $tfResourceName = $matches[1]
        $action = $matches[3]  # The action is now in match group 3
        
        # Map action to shorter form
        $actionType = switch ($action) {
            "created" { "Create" }
            "destroyed" { "Destroy" }
            "updated" { "Update" }
            "replaced" { "Replace" }
            "imported" { "Import" }
            default { $action }
        }
        
        $currentResource = @{
            Resource = $tfResourceName
            Action   = $actionType
        }
        $changes = @()
        $currentMeta = @{ Name = ''; ResourceGroup = ''; Id = ''; NestDepth = 0 }
        $captureChanges = $true
    }
    # Always extract Azure metadata (name, resource_group_name, id) from top-level attributes
    elseif ($captureChanges) {
        # Track nesting depth to only capture top-level attributes
        $openBraces = ([regex]::Matches($cleanLine, '\{')).Count
        $closeBraces = ([regex]::Matches($cleanLine, '\}')).Count
        $currentMeta.NestDepth += ($openBraces - $closeBraces)
        # Only capture from top-level (depth 0 or 1 which is the resource block itself)
        if ($currentMeta.NestDepth -le 1) {
            if (-not $currentMeta.Name -and $cleanLine -match '^\s*[+~-]?\s*name\s+=\s+"([^"]+)"') {
                $currentMeta.Name = $Matches[1]
            }
            if (-not $currentMeta.ResourceGroup -and $cleanLine -match '^\s*[+~-]?\s*resource_group_name\s+=\s+"([^"]+)"') {
                $currentMeta.ResourceGroup = $Matches[1]
            }
            if (-not $currentMeta.Id -and $cleanLine -match '^\s*[+~-]?\s*id\s+=\s+"([^"]+)"') {
                $currentMeta.Id = $Matches[1]
            }
        }
    }
    # Always capture attribute change content within the resource block
    if ($captureChanges -and -not ($cleanLine -match '^\s*#\s+(.+?)\s+(will be|must be)\s+(created|destroyed|updated|replaced|imported)')) {
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
        if ($cleanLine -match '^\s*([+~-])\s+(.+)') {
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
        elseif ($cleanLine -match '^\s{1,}(.+)' -and $cleanLine -notmatch '^\s*#' -and $cleanLine.Trim() -ne '') {
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
    $meta = Get-AzureResourceMeta -Id $currentMeta.Id -Name $currentMeta.Name -ResourceGroupName $currentMeta.ResourceGroup
    $results += [PSCustomObject]@{
        Resource      = $currentResource.Resource
        Action        = $currentResource.Action
        Changes       = $changes
        AzureName     = $meta.AzureName
        ResourceGroup = $meta.ResourceGroup
        Subscription  = $meta.Subscription
    }
}

if ($results.Count -eq 0) {
    Write-Host "No resources found in plan file: $LogFile" -ForegroundColor Yellow

    if ($PassThru) {
        [PSCustomObject]@{
            LogFile  = $LogFile
            Summary  = [PSCustomObject]@{
                Total   = 0
                Import  = 0
                Create  = 0
                Update  = 0
                Destroy = 0
                Replace = 0
            }
            Insights = $null
        }
    }
} else {
    # Apply filters (shared by both TableAll and normal display)
    $filteredResults = $results
    
    # Filter by Category
    if ($Category -and $Category -ne 'All') {
        $categoryPatterns = $knowledgeBase.Categories[$Category]
        $filteredResults = $filteredResults | Where-Object {
            $resourceType = Get-TfResourceType $_.Resource
            $match = $false
            foreach ($pattern in $categoryPatterns) {
                if ($resourceType -match $pattern) {
                    $match = $true
                    break
                }
            }
            $match
        }
    }
    
    # Filter by ResourceName (supports wildcards)
    if ($ResourceName) {
        $filteredResults = $filteredResults | Where-Object {
            $_.Resource -like $ResourceName
        }
    }
    
    # Filter by ResourceType (supports wildcards)
    if ($ResourceType) {
        $filteredResults = $filteredResults | Where-Object {
            $resType = Get-TfResourceType $_.Resource
            $resType -like $ResourceType
        }
    }
    
    # Filter by Action (based on List switches) — applies to both TableAll and normal display
    if ($ListCreated -or $ListChanged -or $ListDestroyed -or $ListReplaced) {
        $allowedActions = @()
        if ($ListCreated) { $allowedActions += "Create" }
        if ($ListChanged) { $allowedActions += "Update" }
        if ($ListDestroyed) { $allowedActions += "Destroy" }
        if ($ListReplaced) { $allowedActions += "Replace" }
        
        $filteredResults = $filteredResults | Where-Object {
            $allowedActions -contains $_.Action
        }
    }
    
    if ($filteredResults.Count -eq 0) {
        Write-Host "No resources match the specified filters" -ForegroundColor Yellow
        if ($Category) { Write-Host "  Category: $Category" -ForegroundColor Gray }
        if ($ResourceName) { Write-Host "  ResourceName: $ResourceName" -ForegroundColor Gray }
        if ($ResourceType) { Write-Host "  ResourceType: $ResourceType" -ForegroundColor Gray }

        if ($PassThru) {
            [PSCustomObject]@{
                LogFile  = $LogFile
                Filters  = [PSCustomObject]@{
                    Category     = $Category
                    ResourceName = $ResourceName
                    ResourceType = $ResourceType
                }
                Summary  = [PSCustomObject]@{
                    Total   = 0
                    Import  = 0
                    Create  = 0
                    Update  = 0
                    Destroy = 0
                    Replace = 0
                }
                Insights = $null
            }
        }
        return
    }
    
    # ─── Display: TableAll or Grouped ────────────────────────────────────────────
    if ($TableAll) {
        Write-Host "\n================================================================================\n" -ForegroundColor Cyan
        Write-Host "ALL RESOURCES" -ForegroundColor Cyan
        
        # Show active filters
        if ($Category -or $ResourceName -or $ResourceType) {
            Write-Host "\nActive Filters:" -ForegroundColor Cyan
            if ($Category) { Write-Host "  Category: $Category" -ForegroundColor Gray }
            if ($ResourceName) { Write-Host "  ResourceName: $ResourceName" -ForegroundColor Gray }
            if ($ResourceType) { Write-Host "  ResourceType: $ResourceType" -ForegroundColor Gray }
        }
        
        Write-Host "\n================================================================================\n" -ForegroundColor Cyan
        
        # Create table data
        $tableData = $filteredResults | ForEach-Object {
            $split = Split-TfResource $_.Resource
            [PSCustomObject]@{
                Action        = $_.Action
                ResourceType  = $split.Type
                ResourceName  = if ($split.Name) { $split.Name } else { $_.Resource }
                AzureName     = if ($_.AzureName) { $_.AzureName } else { '' }
                ResourceGroup = if ($_.ResourceGroup) { $_.ResourceGroup } else { '' }
                Subscription  = if ($_.Subscription) { $_.Subscription } else { '' }
            }
        }
        
        # Display header
        Write-Host ("{0,-10} {1,-45} {2,-30} {3,-25} {4,-20} {5}" -f "Action", "ResourceType", "ResourceName", "AzureName", "ResourceGroup", "Subscription") -ForegroundColor Cyan
        Write-Host ("{0,-10} {1,-45} {2,-30} {3,-25} {4,-20} {5}" -f "------", "------------", "------------", "---------", "-------------", "------------") -ForegroundColor Cyan
        
        # Display as table with color-coded actions
        $tableData | ForEach-Object {
            $actionColor = switch ($_.Action) {
                "Create" { "Green" }
                "Update" { "Yellow" }
                "Destroy" { "Red" }
                "Replace" { "Magenta" }
                "Import" { "Cyan" }
                default { "White" }
            }
            
            Write-Host ("{0,-10} {1,-45} {2,-30} {3,-25} {4,-20} {5}" -f $_.Action, $_.ResourceType, $_.ResourceName, $_.AzureName, $_.ResourceGroup, $_.Subscription) -ForegroundColor $actionColor
        }
        
        # Display summary
        Write-Host "\n================================================================================\n" -ForegroundColor Cyan
        $importCount = ($filteredResults | Where-Object { $_.Action -eq "Import" }).Count
        $createCount = ($filteredResults | Where-Object { $_.Action -eq "Create" }).Count
        $updateCount = ($filteredResults | Where-Object { $_.Action -eq "Update" }).Count
        $destroyCount = ($filteredResults | Where-Object { $_.Action -eq "Destroy" }).Count
        $replaceCount = ($filteredResults | Where-Object { $_.Action -eq "Replace" }).Count
        
        Write-Host "Total: $($filteredResults.Count) resources" -ForegroundColor White
        if ($importCount -gt 0) { Write-Host "  $importCount to import" -ForegroundColor Cyan }
        if ($createCount -gt 0) { Write-Host "  $createCount to create" -ForegroundColor Green }
        if ($updateCount -gt 0) { Write-Host "  $updateCount to update" -ForegroundColor Yellow }
        if ($destroyCount -gt 0) { Write-Host "  $destroyCount to destroy" -ForegroundColor Red }
        if ($replaceCount -gt 0) { Write-Host "  $replaceCount to replace" -ForegroundColor Magenta }
        Write-Host ""

        # Emit table data to the pipeline so $report = ... captures it
        $tableData
    }
    else {
    # ─── Normal grouped display ──────────────────────────────────────────────────
    # Group by action
    $grouped = $filteredResults | Group-Object -Property Action
    
    # Determine which actions to display based on switches
    $actionsToShow = @()
    if ($ListCreated -or $ListChanged -or $ListDestroyed -or $ListReplaced) {
        if ($ListCreated) { $actionsToShow += "Create" }
        if ($ListChanged) { $actionsToShow += "Update" }
        if ($ListDestroyed) { $actionsToShow += "Destroy" }
        if ($ListReplaced) { $actionsToShow += "Replace" }
    } else {
        # Show all if no filter switches are specified
        $actionsToShow = @("Import", "Create", "Update", "Destroy", "Replace")
    }
    
    Write-Host "\n================================================================================\n" -ForegroundColor Cyan
    
    # Show active filters
    if ($Category -or $ResourceName -or $ResourceType) {
        Write-Host "Active Filters:" -ForegroundColor Cyan
        if ($Category) { Write-Host "  Category: $Category" -ForegroundColor Gray }
        if ($ResourceName) { Write-Host "  ResourceName: $ResourceName" -ForegroundColor Gray }
        if ($ResourceType) { Write-Host "  ResourceType: $ResourceType" -ForegroundColor Gray }
        Write-Host ""
    }
    
    foreach ($group in $grouped) {
        # Skip this group if it's not in the actions to show
        if ($actionsToShow -notcontains $group.Name) {
            continue
        }
        
        $color = switch ($group.Name) {
            "Import" { "Cyan" }
            "Create" { "Green" }
            "Update" { "Yellow" }
            "Destroy" { "Red" }
            "Replace" { "Magenta" }
            default { "White" }
        }
        
        $icon = switch ($group.Name) {
            "Import" { "⇪" }
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
    $importCount = ($grouped | Where-Object { $_.Name -eq "Import" }).Count
    $createCount = ($grouped | Where-Object { $_.Name -eq "Create" }).Count
    $updateCount = ($grouped | Where-Object { $_.Name -eq "Update" }).Count
    $destroyCount = ($grouped | Where-Object { $_.Name -eq "Destroy" }).Count
    $replaceCount = ($grouped | Where-Object { $_.Name -eq "Replace" }).Count
    
    if ($importCount -eq $null) { $importCount = 0 }
    if ($createCount -eq $null) { $createCount = 0 }
    if ($updateCount -eq $null) { $updateCount = 0 }
    if ($destroyCount -eq $null) { $destroyCount = 0 }
    if ($replaceCount -eq $null) { $replaceCount = 0 }
    
    Write-Host "Plan: " -ForegroundColor White
    if ($importCount -gt 0) {
        Write-Host "$importCount to import" -NoNewline -ForegroundColor Cyan
        Write-Host ", "
    }
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

    # Emit a flat table of all resources to the pipeline
    foreach ($group in $grouped) {
        if ($actionsToShow -notcontains $group.Name) {
            continue
        }
        foreach ($item in $group.Group) {
            $split = Split-TfResource $item.Resource
            [PSCustomObject]@{
                Action        = $item.Action
                ResourceType  = $split.Type
                ResourceName  = if ($split.Name) { $split.Name } else { $item.Resource }
                AzureName     = if ($item.AzureName) { $item.AzureName } else { '' }
                ResourceGroup = if ($item.ResourceGroup) { $item.ResourceGroup } else { '' }
                Subscription  = if ($item.Subscription) { $item.Subscription } else { '' }
            }
        }
    }
    
    } # end else (normal grouped display)

    # Generate insights if requested or needed for HTML report
    if ($ShowInsights -or $OutputHtml) {
        if ($ShowInsights) {
            Write-Host "================================================================================`n" -ForegroundColor Cyan
            Write-Host "📊 INTELLIGENT INSIGHTS" -ForegroundColor Cyan
            Write-Host "================================================================================`n" -ForegroundColor Cyan
        }
        
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
                RetentionResiliency = @()
                Locks = @()
                RBAC = @()
                NetworkIsolation = @()
                AuditLogging = @()
                ComplianceFrameworks = @()
                CostManagement = @()
            }
            Carbon = @{
                High = @()
                Medium = @()
                Low = @()
                MonthlyEmissions = 0
                Details = @()
                EstimatedImpact = "Unknown"
                Recommendations = @()
            }
        }
        
        # Analyze each resource (using filtered results if filters are active)
        $resourcesToAnalyze = if ($Category -or $ResourceName -or $ResourceType) { $filteredResults } else { $results }
        # Track bulk azapi_resource governance matches for summarization (avoids listing hundreds of policy/role assignment individually)
        $govSummaryCounters = @{}
        foreach ($item in $resourcesToAnalyze) {
            $resourceType = Get-TfResourceType $item.Resource
            $changesText = ($item.Changes | ForEach-Object { $_.Line }) -join ' '

            # Imports add resources to state but don't represent infrastructure deltas.
            # Exclude them from cost/carbon/security delta scoring to avoid misleading insights.
            if ($item.Action -eq "Import") {
                continue
            }
            
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
            
            # === CARBON EMISSION ANALYSIS ===
            # Detect region from resource changes or use default
            $detectedRegion = 'eastus'  # default
            foreach ($regionPattern in $knowledgeBase.CarbonFootprint.RegionalIntensity.Keys) {
                if ($changesText -match [regex]::Escape($regionPattern) -or $item.Resource -match $regionPattern) {
                    $detectedRegion = $regionPattern
                    break
                }
            }
            $carbonIntensity = if ($knowledgeBase.CarbonFootprint.RegionalIntensity.ContainsKey($detectedRegion)) {
                $knowledgeBase.CarbonFootprint.RegionalIntensity[$detectedRegion]
            } else { 400 }  # Default average
            
            # Calculate carbon emissions
            $carbonEmissions = 0
            $carbonDetail = ""
            $carbonCategory = ""
            
            if ($resourceType -match 'virtual_machine|instance') {
                # Check for VM size
                foreach ($sizePattern in $knowledgeBase.CarbonFootprint.VMSizes.Keys) {
                    if ($changesText -match [regex]::Escape($sizePattern)) {
                        $carbonEmissions = $knowledgeBase.CarbonFootprint.VMSizes[$sizePattern]
                        # Adjust for regional carbon intensity (relative to 400 gCO2e/kWh baseline)
                        $carbonEmissions = $carbonEmissions * ($carbonIntensity / 400.0)
                        $carbonDetail = "$sizePattern ≈ $([Math]::Round($carbonEmissions, 1)) kg CO2e/mo ($detectedRegion)"
                        $carbonCategory = if ($carbonEmissions -gt 30) { "High" } elseif ($carbonEmissions -gt 10) { "Medium" } else { "Low" }
                        break
                    }
                }
                if ($carbonEmissions -eq 0) {
                    $carbonEmissions = 4.9 * ($carbonIntensity / 400.0)  # Default unknown VM ~30W
                    $carbonDetail = "≈ $([Math]::Round($carbonEmissions, 1)) kg CO2e/mo ($detectedRegion)"
                    $carbonCategory = "Medium"
                }
            }
            elseif ($knowledgeBase.CarbonFootprint.Services.ContainsKey($resourceType)) {
                $carbonEmissions = $knowledgeBase.CarbonFootprint.Services[$resourceType]
                $carbonEmissions = $carbonEmissions * ($carbonIntensity / 400.0)
                $carbonDetail = "≈ $([Math]::Round($carbonEmissions, 1)) kg CO2e/mo ($detectedRegion)"
                $carbonCategory = if ($carbonEmissions -gt 30) { "High" } elseif ($carbonEmissions -gt 10) { "Medium" } else { "Low" }
            }
            elseif ($knowledgeBase.CostResources.High -contains $resourceType) {
                $carbonEmissions = 6.6 * ($carbonIntensity / 400.0)  # Fallback high ~40W
                $carbonDetail = "≈ $([Math]::Round($carbonEmissions, 1)) kg CO2e/mo ($detectedRegion)"
                $carbonCategory = "High"
            }
            elseif ($knowledgeBase.CostResources.Medium -contains $resourceType) {
                $carbonEmissions = 1.6 * ($carbonIntensity / 400.0)  # Fallback medium ~10W
                $carbonDetail = "≈ $([Math]::Round($carbonEmissions, 1)) kg CO2e/mo ($detectedRegion)"
                $carbonCategory = "Medium"
            }
            elseif ($knowledgeBase.CostResources.Low -contains $resourceType) {
                $carbonEmissions = 0.3 * ($carbonIntensity / 400.0)  # Fallback low ~2W
                $carbonDetail = "≈ $([Math]::Round($carbonEmissions, 1)) kg CO2e/mo ($detectedRegion)"
                $carbonCategory = "Low"
            }
            
            if ($carbonEmissions -gt 0) {
                $carbonImpact = switch ($item.Action) {
                    "Create" { $carbonEmissions }
                    "Destroy" { -$carbonEmissions }
                    "Replace" { 0 }
                    "Update" { 0 }
                    default { 0 }
                }
                
                $insights.Carbon.MonthlyEmissions += $carbonImpact
                
                $impactLabel = switch ($item.Action) {
                    "Create" { "+$carbonCategory" }
                    "Destroy" { "-$carbonCategory" }
                    "Replace" { "~$carbonCategory" }
                    "Update" { "≈$carbonCategory" }
                    default { $carbonCategory }
                }
                
                if ($carbonCategory -eq "High") {
                    $insights.Carbon.High += "$($item.Resource) [$impactLabel] $carbonDetail"
                } elseif ($carbonCategory -eq "Medium") {
                    $insights.Carbon.Medium += "$($item.Resource) [$impactLabel] $carbonDetail"
                } else {
                    $insights.Carbon.Low += "$($item.Resource) [$impactLabel] $carbonDetail"
                }
                
                $insights.Carbon.Details += [PSCustomObject]@{
                    Resource = $item.Resource
                    Action = $item.Action
                    MonthlyEmissions = $carbonEmissions
                    Impact = $carbonImpact
                    Region = $detectedRegion
                    CarbonIntensity = $carbonIntensity
                }
            }
            
            # === SECURITY ANALYSIS ===
            $securityImprovement = 0
            
            foreach ($indicator in $knowledgeBase.SecurityIndicators.Critical) {
                # Only match generic indicators (e.g. 'identity', 'secret') from actual changes.
                # Matching those against resource names causes false positives (e.g. management group name contains '-identity').
                $indicatorInChanges = ($changesText -match [regex]::Escape($indicator))
                $allowIndicatorFromResourceName = ($indicator -match '_')
                $indicatorInResourceName = $false
                if (-not $indicatorInChanges -and $allowIndicatorFromResourceName) {
                    $indicatorInResourceName = ($item.Resource -match [regex]::Escape($indicator))
                }

                if ($indicatorInChanges -or $indicatorInResourceName) {
                    $securityRelevant = $true
                    
                    # Check if it's a positive or negative change
                    $positiveMatch = $false
                    $negativeMatch = $false

                    # Prefer evaluating keywords on the same line(s) where the indicator appears.
                    # This significantly reduces false positives where an unrelated word elsewhere in the resource
                    # (e.g., a policy name or metadata) triggers a negative/positive keyword.
                    $indicatorLines = @()
                    if ($item.Changes) {
                        $indicatorLines = $item.Changes | ForEach-Object { $_.Line } | Where-Object { $_ -match [regex]::Escape($indicator) }
                    }
                    $contextText = if ($indicatorLines.Count -gt 0) { ($indicatorLines -join ' ') } else { $changesText }

                    # Special-case: public exposure indicators.
                    # For these, setting to true/enabled is generally a risk; false/disabled is an improvement.
                    $isPublicExposureIndicator = $indicator -in @('public_network_access_enabled', 'public_access', 'publicly_accessible')
                    $alwaysNegativeIndicator = $indicator -in @('source_address_prefix = "0.0.0.0/0"', 'source_address_prefix = "*"')

                    if ($alwaysNegativeIndicator) {
                        $negativeMatch = $true
                    }
                    elseif ($isPublicExposureIndicator) {
                        $lower = $contextText.ToLowerInvariant()
                        if ($lower -match '\b(true|enabled)\b') {
                            $negativeMatch = $true
                        }
                        elseif ($lower -match '\b(false|disabled)\b') {
                            $positiveMatch = $true
                        }
                    }
                    else {
                        foreach ($positive in $knowledgeBase.SecurityIndicators.PositiveKeywords) {
                            if ($contextText -match [regex]::Escape($positive)) {
                                $positiveMatch = $true
                                break
                            }
                        }
                        
                        foreach ($negative in $knowledgeBase.SecurityIndicators.NegativeKeywords) {
                            if ($contextText -match [regex]::Escape($negative)) {
                                $negativeMatch = $true
                                break
                            }
                        }
                    }
                    
                    if ($positiveMatch -and -not $negativeMatch) {
                        # Improvement keyword found (encryption, HTTPS, etc.)
                        if ($item.Action -eq "Destroy") {
                            # Destroying a secure resource = losing security
                            $insights.Security.Negative += "$($item.Resource) - Security degradation: Removing $indicator"
                            $securityImprovement -= 1
                        } else {
                            # Creating/updating a secure resource = improvement
                            $insights.Security.Positive += "$($item.Resource) - Improved: $indicator"
                            $securityImprovement += 1
                        }
                    }
                    elseif ($negativeMatch) {
                        # Risk keyword found (public access, weak encryption, etc.)
                        if ($item.Action -eq "Destroy") {
                            # Destroying a risky resource = improvement!
                            $insights.Security.Positive += "$($item.Resource) - Security improvement: Removing $indicator risk"
                            $securityImprovement += 1
                        } else {
                            # Creating/updating a risky resource = concern
                            $insights.Security.Negative += "$($item.Resource) - Risk: $indicator"
                            $securityImprovement -= 1
                        }
                    }
                    else {
                        $insights.Security.Neutral += "$($item.Resource) - Modified: $indicator"
                    }
                    break
                }
            }
            
            # === GOVERNANCE ANALYSIS ===
            $tagMatch = $false
            # Check if tags exist in the resource (look for "tags" attribute)
            if ($changesText -match '(?i)\btags\s*=') {
                $insights.Governance.Tags += "$($item.Resource) - Tags configured"
                $tagMatch = $true
            }
            # Also check for tag-related keywords
            if (-not $tagMatch) {
                foreach ($tag in $knowledgeBase.GovernanceIndicators.Tags) {
                    if ($changesText -match "(?i)$([regex]::Escape($tag))" -or $item.Resource -match "(?i)$tag") {
                        if (-not $tagMatch) {
                            $insights.Governance.Tags += "$($item.Resource) - Tags modified"
                            $tagMatch = $true
                        }
                        break
                    }
                }
            }
            
            # Check naming conventions by analyzing the actual Azure resource name
            # Use the AzureName extracted from the plan (the real name attribute), not the Terraform address
            $namingMatch = $false
            $resourceType = Get-TfResourceType $item.Resource
            $namingReasons = @()
            
            # Determine which name to evaluate:
            #   - Prefer AzureName (the actual 'name' attribute from the plan)
            #   - Fall back to Terraform resource name part only if no Azure name exists
            $nameToEvaluate = if ($item.AzureName) { $item.AzureName } else { $null }
            
            # Skip resources where naming conventions are not applicable:
            #   - Policy definitions/assignments and role definitions/assignments (these are governance objects, not infrastructure)
            #   - Management groups (hierarchical naming, different conventions)
            #   - Data sources (read-only, not created by this plan)
            #   - Resources without a resolved Azure name (e.g. id = "known after apply" with no name attr)
            $isNamingExcluded = (
                $resourceType -match '(?i)^azapi_resource$' -and $item.Resource -match '(?i)policy_definition|policy_assignment|policy_set_definition|role_definition|role_assignment|policy_role_assignment|management_group'
            ) -or (
                $resourceType -match '(?i)policy_definition|policy_assignment|role_definition|role_assignment'
            ) -or (
                $item.Resource -match '(?i)^data\.'
            )
            
            if ($nameToEvaluate -and -not $isNamingExcluded) {
                # Skip names that are UUIDs, timestamps, or purely numeric (auto-generated, not naming conventions)
                $isAutoGenerated = (
                    $nameToEvaluate -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or  # UUID
                    $nameToEvaluate -match '^\d{4}-\d{2}-\d{2}' -or  # Timestamp / date
                    $nameToEvaluate -match '^\d+$'  # Pure number
                )
                if (-not $isAutoGenerated) {
                # Check for Azure CAF prefixes (e.g., rg-, vnet-, vm-, kv-)
                foreach ($prefix in $knowledgeBase.GovernanceIndicators.NamingPatterns.AzurePrefixes) {
                    if ($nameToEvaluate -match "^$([regex]::Escape($prefix))") {
                        $namingReasons += "Azure CAF prefix ($prefix)"
                        $namingMatch = $true
                    }
                }
                
                # Check for environment indicators (e.g., -prod-, -dev-, -test-)
                foreach ($env in $knowledgeBase.GovernanceIndicators.NamingPatterns.Environments) {
                    if ($nameToEvaluate -match $env) {
                        $envName = $env -replace '[\^\$\-]', ''
                        if (-not ($namingReasons -like "*environment*")) {
                            $namingReasons += "environment indicator ($envName)"
                            $namingMatch = $true
                        }
                    }
                }
                
                # Check for region indicators (e.g., -eastus-, -westeurope-)
                foreach ($region in $knowledgeBase.GovernanceIndicators.NamingPatterns.Regions) {
                    if ($nameToEvaluate -match $region) {
                        $regionName = $region -replace '[\-]', ''
                        if (-not ($namingReasons -like "*region*")) {
                            $namingReasons += "region indicator ($regionName)"
                            $namingMatch = $true
                        }
                    }
                }
                
                # Check for numbered instances (e.g., -01, -v2)
                foreach ($pattern in $knowledgeBase.GovernanceIndicators.NamingPatterns.NumberedInstances) {
                    if ($nameToEvaluate -match $pattern) {
                        if (-not ($namingReasons -like "*numbered*")) {
                            $namingReasons += "numbered instance"
                            $namingMatch = $true
                        }
                    }
                }
                
                # Check for multi-segment naming (e.g., prefix-purpose-env-region-number)
                $segments = $nameToEvaluate -split '-'
                if ($segments.Count -ge 3 -and -not $namingMatch) {
                    $namingReasons += "multi-segment structure ($($segments.Count) parts)"
                    $namingMatch = $true
                }
                } # end if (-not $isAutoGenerated)
            }
            
            if ($namingMatch) {
                $reasonText = $namingReasons -join ', '
                $insights.Governance.Naming += "$($item.Resource) [$nameToEvaluate] - Follows naming convention: $reasonText"
            }
            
            $policyMatch = $false
            foreach ($policy in $knowledgeBase.GovernanceIndicators.Policies) {
                # Match against actual resource type (not substring of full address)
                if (Test-GovernanceResourceMatch -ResourceAddress $item.Resource -Pattern $policy) {
                    if (-not $policyMatch) {
                        # For azapi_resource, track by kind for summarization
                        $resTypeForGov = Get-TfResourceType $item.Resource
                        if ($resTypeForGov -eq 'azapi_resource') {
                            $split = Split-TfResource $item.Resource
                            $kindBase = if ($split.Name -match '^([a-z_]+)') { $Matches[1] } else { 'unknown' }
                            $govSumKey = "policy_azapi_$kindBase"
                            if (-not $govSummaryCounters.ContainsKey($govSumKey)) { $govSummaryCounters[$govSumKey] = @{ Count = 0; Category = 'Policies'; Kind = $kindBase } }
                            $govSummaryCounters[$govSumKey].Count++
                        } else {
                            $insights.Governance.Policies += "$($item.Resource) - Policy/Compliance related"
                        }
                        $policyMatch = $true
                    }
                    break
                }
            }
            
            $backupMatch = $false
            $isPolicyResource = (Test-GovernanceResourceMatch -ResourceAddress $item.Resource -Pattern 'policy_assignment|policy_definition|policy_set_definition')

            # Policy-as-code plans often include large JSON bodies; scanning those for the word "backup" is noisy.
            # For policy resources, only mark as Backup when the policy name itself suggests backup/restore.
            if ($isPolicyResource) {
                if ($item.Resource -match '(?i)(^|[^a-z0-9])backup([^a-z0-9]|$)|site_recovery|recovery_services_vault|recovery\s*services') {
                    $insights.Governance.Backup += "$($item.Resource) - Backup configured"
                    $backupMatch = $true
                }
            }
            else {
                foreach ($backup in $knowledgeBase.GovernanceIndicators.Backup) {
                    if ($changesText -match [regex]::Escape($backup)) {
                        if (-not $backupMatch) {
                            $insights.Governance.Backup += "$($item.Resource) - Backup configured"
                            $backupMatch = $true
                        }
                        break
                    }
                }
            }

            $retentionMatch = $false
            foreach ($retention in $knowledgeBase.GovernanceIndicators.RetentionResiliency) {
                if ($changesText -match [regex]::Escape($retention)) {
                    if (-not $retentionMatch) {
                        $insights.Governance.RetentionResiliency += "$($item.Resource) - Retention/Resiliency configured"
                        $retentionMatch = $true
                    }
                    break
                }
            }
            
            $lockMatch = $false
            foreach ($lock in $knowledgeBase.GovernanceIndicators.Locks) {
                if ($changesText -match [regex]::Escape($lock) -or (Test-GovernanceResourceMatch -ResourceAddress $item.Resource -Pattern $lock)) {
                    if (-not $lockMatch) {
                        $insights.Governance.Locks += "$($item.Resource) - Resource lock configured"
                        $lockMatch = $true
                    }
                    break
                }
            }
            
            $rbacMatch = $false
            foreach ($rbac in $knowledgeBase.GovernanceIndicators.RBAC) {
                $rbacTypeMatch = Test-GovernanceResourceMatch -ResourceAddress $item.Resource -Pattern $rbac
                if ($changesText -match [regex]::Escape($rbac) -or $rbacTypeMatch) {
                    if (-not $rbacMatch) {
                        $resTypeForGov = Get-TfResourceType $item.Resource
                        if ($resTypeForGov -eq 'azapi_resource' -and $rbacTypeMatch) {
                            $split = Split-TfResource $item.Resource
                            $kindBase = if ($split.Name -match '^([a-z_]+)') { $Matches[1] } else { 'unknown' }
                            $govSumKey = "rbac_azapi_$kindBase"
                            if (-not $govSummaryCounters.ContainsKey($govSumKey)) { $govSummaryCounters[$govSumKey] = @{ Count = 0; Category = 'RBAC'; Kind = $kindBase } }
                            $govSummaryCounters[$govSumKey].Count++
                        } else {
                            $insights.Governance.RBAC += "$($item.Resource) - RBAC/IAM configured"
                        }
                        $rbacMatch = $true
                    }
                    break
                }
            }
            
            $networkMatch = $false
            foreach ($network in $knowledgeBase.GovernanceIndicators.NetworkIsolation) {
                # Match against actual resource type (not substring of full address)
                if (Test-GovernanceResourceMatch -ResourceAddress $item.Resource -Pattern $network) {
                    if (-not $networkMatch) {
                        $insights.Governance.NetworkIsolation += "$($item.Resource) - Network isolation applied"
                        $networkMatch = $true
                    }
                    break
                }
            }
            
            $auditMatch = $false
            foreach ($audit in $knowledgeBase.GovernanceIndicators.AuditLogging) {
                if ($changesText -match [regex]::Escape($audit) -or (Test-GovernanceResourceMatch -ResourceAddress $item.Resource -Pattern $audit)) {
                    if (-not $auditMatch) {
                        $insights.Governance.AuditLogging += "$($item.Resource) - Audit logging enabled"
                        $auditMatch = $true
                    }
                    break
                }
            }
            
            $complianceMatch = $false
            foreach ($compliance in $knowledgeBase.GovernanceIndicators.ComplianceFrameworks) {
                # Match against actual resource type — not substring of the full address
                if (Test-GovernanceResourceMatch -ResourceAddress $item.Resource -Pattern $compliance) {
                    if (-not $complianceMatch) {
                        $resTypeForGov = Get-TfResourceType $item.Resource
                        if ($resTypeForGov -eq 'azapi_resource') {
                            $split = Split-TfResource $item.Resource
                            $kindBase = if ($split.Name -match '^([a-z_]+)') { $Matches[1] } else { 'unknown' }
                            $govSumKey = "compliance_azapi_$kindBase"
                            if (-not $govSummaryCounters.ContainsKey($govSumKey)) { $govSummaryCounters[$govSumKey] = @{ Count = 0; Category = 'ComplianceFrameworks'; Kind = $kindBase } }
                            $govSummaryCounters[$govSumKey].Count++
                        } else {
                            $insights.Governance.ComplianceFrameworks += "$($item.Resource) - Compliance framework applied"
                        }
                        $complianceMatch = $true
                    }
                    break
                }
            }
            
            $costMgmtMatch = $false
            foreach ($costMgmt in $knowledgeBase.GovernanceIndicators.CostManagement) {
                if ($changesText -match [regex]::Escape($costMgmt) -or (Test-GovernanceResourceMatch -ResourceAddress $item.Resource -Pattern $costMgmt)) {
                    if (-not $costMgmtMatch) {
                        $insights.Governance.CostManagement += "$($item.Resource) - Cost management configured"
                        $costMgmtMatch = $true
                    }
                    break
                }
            }

            # Azure Landing Zone (ALZ) compliance check
            # For policy assignment resources, match the policy name against well-known ALZ categories
            if ($complianceMatch -and $item.Resource -match '(?i)policy_assignment') {
                # Extract the policy short name from the map key, e.g. "Costaltd-corp/Deny-Public-IP" -> "Deny-Public-IP"
                $policyShortName = ''
                if ($item.Resource -match '\["[^/]*/([^"]+)"\]') {
                    $policyShortName = $Matches[1]
                } elseif ($item.Resource -match '\["([^"]+)"\]') {
                    $policyShortName = $Matches[1]
                }
                if ($policyShortName) {
                    foreach ($cat in $knowledgeBase.GovernanceIndicators.ALZPolicyCategories.Keys) {
                        foreach ($pattern in $knowledgeBase.GovernanceIndicators.ALZPolicyCategories[$cat]) {
                            if ($policyShortName -match [regex]::Escape($pattern)) {
                                $alzKey = "alz_$cat"
                                if (-not $govSummaryCounters.ContainsKey($alzKey)) {
                                    $govSummaryCounters[$alzKey] = @{ Count = 0; Category = 'ALZCompliance'; Kind = $cat; Policies = @() }
                                }
                                $govSummaryCounters[$alzKey].Count++
                                if ($govSummaryCounters[$alzKey].Policies.Count -lt 5) {
                                    $govSummaryCounters[$alzKey].Policies += $policyShortName
                                }
                                break
                            }
                        }
                    }
                }
            }
        }

        # Post-loop: Add summarized entries for bulk azapi_resource governance matches
        foreach ($key in $govSummaryCounters.Keys) {
            $entry = $govSummaryCounters[$key]
            if ($entry.Category -eq 'ALZCompliance') {
                # ALZ policy category summary with example policies
                $examples = if ($entry.Policies.Count -gt 0) { " (e.g., $($entry.Policies[0..([Math]::Min(2, $entry.Policies.Count - 1))] -join ', '))" } else { '' }
                $insights.Governance.ComplianceFrameworks += "ALZ $($entry.Kind): $($entry.Count) policy assignments detected$examples"
            } else {
                $summaryText = "$($entry.Count) azapi_resource.$($entry.Kind) resources detected"
                switch ($entry.Category) {
                    'Policies'             { $insights.Governance.Policies += "$summaryText - Policy/Compliance related" }
                    'RBAC'                 { $insights.Governance.RBAC += "$summaryText - RBAC/IAM configured" }
                    'ComplianceFrameworks' { $insights.Governance.ComplianceFrameworks += "$summaryText - Compliance framework applied" }
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
        
        # Display insights (only when -ShowInsights is active; HTML generates its own output)
        if ($ShowInsights) {
        Write-Host "💰 COST IMPACT ANALYSIS" -ForegroundColor Yellow
        Write-Host "   Overall Impact: " -NoNewline
        $costColor = if ($insights.Cost.EstimatedImpact -match "Increase") { "Red" } 
                    elseif ($insights.Cost.EstimatedImpact -match "Decrease") { "Green" } 
                    else { "Gray" }
        Write-Host $insights.Cost.EstimatedImpact -ForegroundColor $costColor
        Write-Host "   ⚠️  DISCLAIMER: These are INFERENCE-BASED ESTIMATES, not actual Azure pricing." -ForegroundColor DarkGray
        Write-Host "   Based on author's approximate knowledge of PAYG Linux East US pricing." -ForegroundColor DarkGray
        Write-Host "   No region adjustment, no reserved instance discounts, no EA pricing." -ForegroundColor DarkGray
        Write-Host "   For actual costs use Azure Pricing Calculator or Cost Management." -ForegroundColor DarkGray
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
        Write-Host "   ⚠️  Heuristic analysis — not a security audit. May include false positives." -ForegroundColor DarkGray
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
        
        # Calculate carbon emission impact
        $monthlyCarbon = $insights.Carbon.MonthlyEmissions
        $insights.Carbon.EstimatedImpact = if ($monthlyCarbon -gt 100) { "High Impact 🌡️🌡️🌡️ (+$([Math]::Round($monthlyCarbon, 1)) kg CO2e/mo)" }
                                          elseif ($monthlyCarbon -gt 30) { "Moderate Impact 🌡️🌡️ (+$([Math]::Round($monthlyCarbon, 1)) kg CO2e/mo)" }
                                          elseif ($monthlyCarbon -gt 0) { "Minor Impact 🌡️ (+$([Math]::Round($monthlyCarbon, 1)) kg CO2e/mo)" }
                                          elseif ($monthlyCarbon -eq 0) { "No Change ≈" }
                                          elseif ($monthlyCarbon -gt -30) { "Minor Reduction 🌱 ($([Math]::Round($monthlyCarbon, 1)) kg CO2e/mo)" }
                                          elseif ($monthlyCarbon -gt -100) { "Moderate Reduction 🌱🌱 ($([Math]::Round($monthlyCarbon, 1)) kg CO2e/mo)" }
                                          else { "Significant Reduction 🌱🌱🌱 ($([Math]::Round($monthlyCarbon, 1)) kg CO2e/mo)" }
        
        # Generate carbon recommendations based on detected resources and patterns
        if ($insights.Carbon.Details.Count -gt 0) {
            # Check for high carbon intensity regions
            $highCarbonRegions = $insights.Carbon.Details | Where-Object { $_.CarbonIntensity -gt 400 } | Select-Object -ExpandProperty Region -Unique
            if ($highCarbonRegions.Count -gt 0) {
                $lowCarbonAlternatives = @{
                    'eastus' = 'Canada East, France Central'
                    'eastus2' = 'Canada East, France Central'
                    'westus' = 'Canada Central, West Europe'
                    'westus2' = 'Canada Central, West Europe'
                    'centralus' = 'Canada Central, North Europe'
                    'southeastasia' = 'West Europe, France Central'
                    'australiaeast' = 'West Europe, Norway East, Sweden Central'
                    'australiasoutheast' = 'West Europe, Norway East, Sweden Central'
                    'southafricanorth' = 'France Central, West Europe, Canada East'
                    'centralindia' = 'France Central, Norway East, Sweden Central'
                }
                foreach ($region in $highCarbonRegions) {
                    $alternatives = $lowCarbonAlternatives[$region]
                    if ($alternatives) {
                        $insights.Carbon.Recommendations += "⚠️ Region '$region' has high carbon intensity ($($insights.Carbon.Details | Where-Object { $_.Region -eq $region } | Select-Object -First 1 -ExpandProperty CarbonIntensity) gCO2e/kWh). Consider: $alternatives"
                    } else {
                        $insights.Carbon.Recommendations += "⚠️ Region '$region' has high carbon intensity. Consider low-carbon regions: Norway East, Sweden Central, France Central, Canada East/Central, Brazil South"
                    }
                }
            }
            
            # Analyze VM types and sizes
            $vmDetails = $insights.Carbon.Details | Where-Object { $_.Resource -match 'virtual_machine|azurerm_linux_virtual_machine|azurerm_windows_virtual_machine' }
            if ($vmDetails.Count -gt 0) {
                $highPerfVMs = $vmDetails | Where-Object { $_.Resource -match 'Standard_D\d+s|Standard_E\d+|Standard_F\d+' }
                $devTestVMs = $vmDetails | Where-Object { $_.Resource -match '\b(dev|test|sandbox|nonprod)\b' }
                
                if ($highPerfVMs.Count -gt 0) {
                    $insights.Carbon.Recommendations += "💡 $($highPerfVMs.Count) high-performance VM(s) detected. Evaluate if workload requires this capacity or if downsizing is possible"
                }
                
                if ($devTestVMs.Count -gt 0) {
                    $insights.Carbon.Recommendations += "💡 $($devTestVMs.Count) dev/test VM(s) detected. Consider B-series burstable VMs (up to 60% carbon reduction) and auto-shutdown policies"
                } elseif ($vmDetails.Count -gt 2) {
                    $insights.Carbon.Recommendations += "💡 Enable auto-shutdown schedules for non-production VMs during non-business hours (weekends, nights)"
                }
            }
            
            # Analyze AKS/Container workloads
            $aksDetails = $insights.Carbon.Details | Where-Object { $_.Resource -match 'kubernetes_cluster|container_registry|container_instance' }
            if ($aksDetails.Count -gt 0) {
                $insights.Carbon.Recommendations += "💡 $($aksDetails.Count) container workload(s) detected. Enable cluster autoscaling and node pool spot instances to optimize carbon footprint"
            }
            
            # Analyze storage resources
            $storageDetails = $insights.Carbon.Details | Where-Object { $_.Resource -match 'storage_account|managed_disk' }
            if ($storageDetails.Count -gt 5) {
                $insights.Carbon.Recommendations += "💡 $($storageDetails.Count) storage resources detected. Implement lifecycle management policies to move cold data to Cool/Archive tiers"
            }
            
            # Check for database resources
            $dbDetails = $insights.Carbon.Details | Where-Object { $_.Resource -match 'sql_database|postgresql|mysql|cosmosdb' }
            if ($dbDetails.Count -gt 0) {
                $insights.Carbon.Recommendations += "💡 $($dbDetails.Count) database(s) detected. Consider serverless tiers for dev/test, and auto-pause capabilities for infrequent workloads"
            }
            
            # Overall carbon footprint recommendations
            if ($monthlyCarbon -gt 100) {
                $insights.Carbon.Recommendations += "🎯 High carbon footprint detected (>100 kg CO2e/mo). Prioritize: reserved instances for predictable workloads, spot instances for fault-tolerant jobs, and infrastructure optimization"
            } elseif ($monthlyCarbon -gt 50) {
                $insights.Carbon.Recommendations += "🎯 Moderate carbon footprint detected. Consider reserved instances for long-running workloads and enable cost/carbon optimization features"
            }
            
            # Check for resources being created in multiple regions
            $regions = $insights.Carbon.Details | Select-Object -ExpandProperty Region -Unique
            if ($regions.Count -gt 2) {
                $insights.Carbon.Recommendations += "🌍 Resources deployed across $($regions.Count) regions. Consider consolidating to fewer low-carbon regions to reduce overall footprint"
            }
        }
        
        # Add general recommendations if no specific ones generated
        if ($insights.Carbon.Recommendations.Count -eq 0 -and $insights.Carbon.Details.Count -gt 0) {
            $insights.Carbon.Recommendations += "✅ Current deployment has relatively low carbon impact. Continue monitoring and optimizing resource utilization"
        }
        
        Write-Host "🌍 CARBON IMPACT ANALYSIS" -ForegroundColor Green
        Write-Host "   Carbon Impact: " -NoNewline
        $carbonColor = if ($insights.Carbon.EstimatedImpact -match "High Impact") { "Red" }
                      elseif ($insights.Carbon.EstimatedImpact -match "Moderate Impact") { "Yellow" }
                      elseif ($insights.Carbon.EstimatedImpact -match "Reduction") { "Green" }
                      else { "Gray" }
        Write-Host $insights.Carbon.EstimatedImpact -ForegroundColor $carbonColor
        Write-Host "   ⚠️  DISCLAIMER: These are INFERENCE-BASED ESTIMATES, not actual measurements." -ForegroundColor DarkGray
        Write-Host "   Formula inspired by CCF; per-vCPU wattages are the author's own approximations." -ForegroundColor DarkGray
        Write-Host "   Regional carbon intensities are approximate, NOT from Electricity Maps or IEA." -ForegroundColor DarkGray
        Write-Host "   For actual emissions use Azure Carbon Optimization or Emissions Impact Dashboard." -ForegroundColor DarkGray
        Write-Host ""
        
        if ($insights.Carbon.High.Count -gt 0) {
            Write-Host "   High Emission Resources ($($insights.Carbon.High.Count)):" -ForegroundColor Red
            $insights.Carbon.High | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkRed }
            Write-Host ""
        }
        if ($insights.Carbon.Medium.Count -gt 0) {
            Write-Host "   Medium Emission Resources ($($insights.Carbon.Medium.Count)):" -ForegroundColor Yellow
            $insights.Carbon.Medium | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkYellow }
            Write-Host ""
        }
        if ($insights.Carbon.Low.Count -gt 0) {
            Write-Host "   Low Emission Resources ($($insights.Carbon.Low.Count)):" -ForegroundColor Green
            $insights.Carbon.Low | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkGreen }
            Write-Host ""
        }
        
        if ($insights.Carbon.Recommendations.Count -gt 0) {
            Write-Host "   💡 Sustainability Recommendations:" -ForegroundColor Cyan
            $insights.Carbon.Recommendations | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkCyan }
            Write-Host ""
        }
        
        # Calculate governance score (0-10 scale)
        $govScore = 0
        if ($insights.Governance.Tags.Count -gt 0) { $govScore += 1 }
        if ($insights.Governance.Naming.Count -gt 0) { $govScore += 1 }
        if ($insights.Governance.Policies.Count -gt 0) { $govScore += 1 }
        if (($insights.Governance.Backup.Count + $insights.Governance.RetentionResiliency.Count) -gt 0) { $govScore += 1 }
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
        $govPct = [Math]::Round(($govScore / 12) * 100)
        Write-Host "$govScore/12 ($govPct%)" -ForegroundColor $govColor
        Write-Host "   ⚠️  Presence detection only — checks if patterns exist, not if correctly configured." -ForegroundColor DarkGray
        
        # Show comprehensive score breakdown
        Write-Host "   Breakdown:" -ForegroundColor Gray
        Write-Host "   • Tags: " -NoNewline -ForegroundColor Gray
        Write-Host $(if ($insights.Governance.Tags.Count -gt 0) { "✓ +1" } else { "✗ +0" }) -ForegroundColor $(if ($insights.Governance.Tags.Count -gt 0) { "Green" } else { "DarkGray" })
        Write-Host "   • Naming: " -NoNewline -ForegroundColor Gray
        Write-Host $(if ($insights.Governance.Naming.Count -gt 0) { "✓ +1" } else { "✗ +0" }) -ForegroundColor $(if ($insights.Governance.Naming.Count -gt 0) { "Green" } else { "DarkGray" })
        Write-Host "   • Policies/Monitoring: " -NoNewline -ForegroundColor Gray
        Write-Host $(if ($insights.Governance.Policies.Count -gt 0) { "✓ +1" } else { "✗ +0" }) -ForegroundColor $(if ($insights.Governance.Policies.Count -gt 0) { "Green" } else { "DarkGray" })
        Write-Host "   • Backup/Retention: " -NoNewline -ForegroundColor Gray
        $hasBackupOrRetention = (($insights.Governance.Backup.Count + $insights.Governance.RetentionResiliency.Count) -gt 0)
        Write-Host $(if ($hasBackupOrRetention) { "✓ +1" } else { "✗ +0" }) -ForegroundColor $(if ($hasBackupOrRetention) { "Green" } else { "DarkGray" })
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
                $insights.Governance.Policies.Count + $insights.Governance.Backup.Count + $insights.Governance.RetentionResiliency.Count +
                        $insights.Governance.Locks.Count + $insights.Governance.RBAC.Count +
                        $insights.Governance.NetworkIsolation.Count + $insights.Governance.AuditLogging.Count +
                        $insights.Governance.ComplianceFrameworks.Count + $insights.Governance.CostManagement.Count
        
        if ($totalGovItems -gt 0) {
            if ($insights.Governance.Tags.Count -gt 0) {
                Write-Host "   🏷️  Tags ($($insights.Governance.Tags.Count)):" -ForegroundColor Blue
                $insights.Governance.Tags | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkBlue }
                Write-Host ""
            }
            if ($insights.Governance.Naming.Count -gt 0) {
                Write-Host "   📝 Naming Conventions ($($insights.Governance.Naming.Count)):" -ForegroundColor Cyan
                $insights.Governance.Naming | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkCyan }
                Write-Host ""
            }
            if ($insights.Governance.Policies.Count -gt 0) {
                Write-Host "   📜 Policies & Monitoring ($($insights.Governance.Policies.Count)):" -ForegroundColor Magenta
                $insights.Governance.Policies | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkMagenta }
                Write-Host ""
            }
            if ($insights.Governance.Backup.Count -gt 0) {
                Write-Host "   💾 Backup ($($insights.Governance.Backup.Count)):" -ForegroundColor Green
                $insights.Governance.Backup | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkGreen }
                Write-Host ""
            }
            if ($insights.Governance.RetentionResiliency.Count -gt 0) {
                Write-Host "   🗄️  Retention & Resiliency ($($insights.Governance.RetentionResiliency.Count)):" -ForegroundColor Green
                $insights.Governance.RetentionResiliency | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkGreen }
                Write-Host ""
            }
            if ($insights.Governance.Locks.Count -gt 0) {
                Write-Host "   🔒 Resource Locks ($($insights.Governance.Locks.Count)):" -ForegroundColor Yellow
                $insights.Governance.Locks | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkYellow }
                Write-Host ""
            }
            if ($insights.Governance.RBAC.Count -gt 0) {
                Write-Host "   👤 RBAC/IAM ($($insights.Governance.RBAC.Count)):" -ForegroundColor Cyan
                $insights.Governance.RBAC | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkCyan }
                Write-Host ""
            }
            if ($insights.Governance.NetworkIsolation.Count -gt 0) {
                Write-Host "   🌐 Network Isolation ($($insights.Governance.NetworkIsolation.Count)):" -ForegroundColor Blue
                $insights.Governance.NetworkIsolation | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkBlue }
                Write-Host ""
            }
            if ($insights.Governance.AuditLogging.Count -gt 0) {
                Write-Host "   📊 Audit Logging ($($insights.Governance.AuditLogging.Count)):" -ForegroundColor Magenta
                $insights.Governance.AuditLogging | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkMagenta }
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
        
        # === EXECUTIVE SUMMARY ===
        Write-Host "📊 EXECUTIVE SUMMARY" -ForegroundColor White -BackgroundColor DarkBlue
        Write-Host "================================================================================`n" -ForegroundColor Cyan
        
        # Resource Changes Summary
        Write-Host "📦 Resource Changes:" -ForegroundColor White
        $totalImport = ($resourcesToAnalyze | Where-Object { $_.Action -eq "Import" }).Count
        $totalCreate = ($resourcesToAnalyze | Where-Object { $_.Action -eq "Create" }).Count
        $totalUpdate = ($resourcesToAnalyze | Where-Object { $_.Action -eq "Update" }).Count
        $totalDestroy = ($resourcesToAnalyze | Where-Object { $_.Action -eq "Destroy" }).Count
        $totalReplace = ($resourcesToAnalyze | Where-Object { $_.Action -eq "Replace" }).Count
        $totalResources = $totalImport + $totalCreate + $totalUpdate + $totalDestroy + $totalReplace
        
        Write-Host "   Total Resources Affected: " -NoNewline -ForegroundColor Gray
        Write-Host $totalResources -ForegroundColor White
        Write-Host "   • Importing: " -NoNewline -ForegroundColor Gray
        Write-Host $totalImport -NoNewline -ForegroundColor Cyan
        Write-Host "   • Creating: " -NoNewline -ForegroundColor Gray
        Write-Host $totalCreate -NoNewline -ForegroundColor Green
        Write-Host " | Updating: " -NoNewline -ForegroundColor Gray
        Write-Host $totalUpdate -NoNewline -ForegroundColor Yellow
        Write-Host " | Destroying: " -NoNewline -ForegroundColor Gray
        Write-Host $totalDestroy -NoNewline -ForegroundColor Red
        Write-Host " | Replacing: " -NoNewline -ForegroundColor Gray
        Write-Host $totalReplace -ForegroundColor Magenta
        Write-Host ""
        
        # Cost Summary
        Write-Host "💰 Cost Impact:" -ForegroundColor White
        $totalCostResources = $insights.Cost.High.Count + $insights.Cost.Medium.Count + $insights.Cost.Low.Count
        Write-Host "   Monthly Cost Change: " -NoNewline -ForegroundColor Gray
        if ($insights.Cost.MonthlyEstimate -gt 0) {
            Write-Host "+`$$([Math]::Round([Math]::Abs($insights.Cost.MonthlyEstimate), 2))" -NoNewline -ForegroundColor Red
            Write-Host "/month" -ForegroundColor Gray
        } elseif ($insights.Cost.MonthlyEstimate -lt 0) {
            Write-Host "-`$$([Math]::Round([Math]::Abs($insights.Cost.MonthlyEstimate), 2))" -NoNewline -ForegroundColor Green
            Write-Host "/month" -ForegroundColor Gray
        } elseif ($totalCostResources -gt 0) {
            Write-Host "No Change ≈" -ForegroundColor Gray
        } else {
            Write-Host "None" -ForegroundColor Gray
        }
        if ($totalCostResources -gt 0) {
            Write-Host "   Cost-Impacting Resources: " -NoNewline -ForegroundColor Gray
            Write-Host "$totalCostResources " -NoNewline -ForegroundColor White
            Write-Host "(" -NoNewline -ForegroundColor Gray
            Write-Host "$($insights.Cost.High.Count) High" -NoNewline -ForegroundColor Red
            Write-Host ", " -NoNewline -ForegroundColor Gray
            Write-Host "$($insights.Cost.Medium.Count) Medium" -NoNewline -ForegroundColor Yellow
            Write-Host ", " -NoNewline -ForegroundColor Gray
            Write-Host "$($insights.Cost.Low.Count) Low" -NoNewline -ForegroundColor Green
            Write-Host ")" -ForegroundColor Gray
        }
        Write-Host ""
        
        # Carbon Summary
        Write-Host "🌍 Carbon Footprint:" -ForegroundColor White
        $totalCarbonResources = $insights.Carbon.High.Count + $insights.Carbon.Medium.Count + $insights.Carbon.Low.Count
        Write-Host "   Monthly Emissions Change: " -NoNewline -ForegroundColor Gray
        if ($insights.Carbon.MonthlyEmissions -gt 0) {
            Write-Host "+$([Math]::Round([Math]::Abs($insights.Carbon.MonthlyEmissions), 1))" -NoNewline -ForegroundColor Red
            Write-Host " kg CO2e/month" -ForegroundColor Gray
        } elseif ($insights.Carbon.MonthlyEmissions -lt 0) {
            Write-Host "-$([Math]::Round([Math]::Abs($insights.Carbon.MonthlyEmissions), 1))" -NoNewline -ForegroundColor Green
            Write-Host " kg CO2e/month" -ForegroundColor Gray
        } elseif ($totalCarbonResources -gt 0) {
            Write-Host "No Change ≈" -ForegroundColor Gray
        } else {
            Write-Host "None" -ForegroundColor Gray
        }
        if ($totalCarbonResources -gt 0) {
            Write-Host "   Carbon-Emitting Resources: " -NoNewline -ForegroundColor Gray
            Write-Host "$totalCarbonResources " -NoNewline -ForegroundColor White
            Write-Host "(" -NoNewline -ForegroundColor Gray
            Write-Host "$($insights.Carbon.High.Count) High" -NoNewline -ForegroundColor Red
            Write-Host ", " -NoNewline -ForegroundColor Gray
            Write-Host "$($insights.Carbon.Medium.Count) Medium" -NoNewline -ForegroundColor Yellow
            Write-Host ", " -NoNewline -ForegroundColor Gray
            Write-Host "$($insights.Carbon.Low.Count) Low" -NoNewline -ForegroundColor Green
            Write-Host ")" -ForegroundColor Gray
        }
        if ($insights.Carbon.Recommendations.Count -gt 0) {
            Write-Host "   Sustainability Recommendations: " -NoNewline -ForegroundColor Gray
            Write-Host $insights.Carbon.Recommendations.Count -ForegroundColor Cyan
        }
        Write-Host ""
        
        # Security Summary
        Write-Host "🔒 Security Impact:" -ForegroundColor White
        $totalSecurityChanges = $insights.Security.Positive.Count + $insights.Security.Negative.Count + $insights.Security.Neutral.Count
        if ($totalSecurityChanges -gt 0) {
            Write-Host "   Security-Related Changes: " -NoNewline -ForegroundColor Gray
            Write-Host "$totalSecurityChanges " -NoNewline -ForegroundColor White
            Write-Host "(" -NoNewline -ForegroundColor Gray
            Write-Host "$($insights.Security.Positive.Count) Improvements" -NoNewline -ForegroundColor Green
            Write-Host ", " -NoNewline -ForegroundColor Gray
            Write-Host "$($insights.Security.Negative.Count) Concerns" -NoNewline -ForegroundColor Red
            Write-Host ", " -NoNewline -ForegroundColor Gray
            Write-Host "$($insights.Security.Neutral.Count) Modifications" -NoNewline -ForegroundColor Gray
            Write-Host ")" -ForegroundColor Gray
            
            Write-Host "   Security Trend: " -NoNewline -ForegroundColor Gray
            if ($insights.Security.OverallTrend -match "Improved") {
                Write-Host $insights.Security.OverallTrend -ForegroundColor Green
            } elseif ($insights.Security.OverallTrend -match "Degraded") {
                Write-Host $insights.Security.OverallTrend -ForegroundColor Red
            } else {
                Write-Host $insights.Security.OverallTrend -ForegroundColor Gray
            }
        } else {
            Write-Host "   No security-related changes detected" -ForegroundColor Gray
        }
        Write-Host ""
        
        # Governance Summary
        Write-Host "📋 Governance & Compliance:" -ForegroundColor White
        Write-Host "   Governance Score: " -NoNewline -ForegroundColor Gray
        $govScoreColor = if ($govScore -ge 8) { "Green" } elseif ($govScore -ge 5) { "Yellow" } else { "Red" }
        Write-Host "$govScore/12 " -NoNewline -ForegroundColor $govScoreColor
        $govPercentage = [Math]::Round(($govScore / 12) * 100, 0)
        Write-Host "($govPercentage%)" -ForegroundColor Gray
        
        $govCategoriesFound = 0
        if ($insights.Governance.Tags.Count -gt 0) { $govCategoriesFound++ }
        if ($insights.Governance.Naming.Count -gt 0) { $govCategoriesFound++ }
        if ($insights.Governance.Policies.Count -gt 0) { $govCategoriesFound++ }
        if (($insights.Governance.Backup.Count + $insights.Governance.RetentionResiliency.Count) -gt 0) { $govCategoriesFound++ }
        if ($insights.Governance.Locks.Count -gt 0) { $govCategoriesFound++ }
        if ($insights.Governance.RBAC.Count -gt 0) { $govCategoriesFound++ }
        if ($insights.Governance.NetworkIsolation.Count -gt 0) { $govCategoriesFound++ }
        if ($insights.Governance.AuditLogging.Count -gt 0) { $govCategoriesFound++ }
        if ($insights.Governance.ComplianceFrameworks.Count -gt 0) { $govCategoriesFound++ }
        if ($insights.Governance.CostManagement.Count -gt 0) { $govCategoriesFound++ }
        
        Write-Host "   Governance Categories Implemented: " -NoNewline -ForegroundColor Gray
        Write-Host "$govCategoriesFound/10" -ForegroundColor White
        
        if ($totalGovItems -gt 0) {
            Write-Host "   Total Governance Resources: " -NoNewline -ForegroundColor Gray
            Write-Host $totalGovItems -ForegroundColor White
            
            # Top governance categories
            $topGov = @()
            if ($insights.Governance.Tags.Count -gt 0) { $topGov += "Tags ($($insights.Governance.Tags.Count))" }
            if ($insights.Governance.Naming.Count -gt 0) { $topGov += "Naming ($($insights.Governance.Naming.Count))" }
            if ($insights.Governance.RBAC.Count -gt 0) { $topGov += "RBAC ($($insights.Governance.RBAC.Count))" }
            if ($insights.Governance.NetworkIsolation.Count -gt 0) { $topGov += "Network Isolation ($($insights.Governance.NetworkIsolation.Count))" }
            if ($insights.Governance.Backup.Count -gt 0) { $topGov += "Backup ($($insights.Governance.Backup.Count))" }
            if ($insights.Governance.RetentionResiliency.Count -gt 0) { $topGov += "Retention ($($insights.Governance.RetentionResiliency.Count))" }
            
            if ($topGov.Count -gt 0) {
                Write-Host "   Top Categories: " -NoNewline -ForegroundColor Gray
                Write-Host ($topGov -join ", ") -ForegroundColor Cyan
            }
        }
        Write-Host ""
        
        # Overall Assessment
        Write-Host "✅ Overall Assessment:" -ForegroundColor White
        $riskLevel = "Low"
        $riskColor = "Green"
        $riskFactors = @()
        
        if ($totalDestroy -gt 10) {
            $riskLevel = "High"
            $riskColor = "Red"
            $riskFactors += "$totalDestroy resources will be destroyed"
        } elseif ($totalDestroy -gt 5) {
            $riskLevel = "Medium"
            $riskColor = "Yellow"
            $riskFactors += "$totalDestroy resources will be destroyed"
        }
        
        if ($insights.Cost.MonthlyEstimate -gt 500) {
            $riskLevel = "High"
            $riskColor = "Red"
            $riskFactors += "High cost increase (+`$$([Math]::Round($insights.Cost.MonthlyEstimate, 0))/mo)"
        } elseif ($insights.Cost.MonthlyEstimate -gt 200) {
            if ($riskLevel -eq "Low") { $riskLevel = "Medium"; $riskColor = "Yellow" }
            $riskFactors += "Moderate cost increase (+`$$([Math]::Round($insights.Cost.MonthlyEstimate, 0))/mo)"
        }
        
        if ($insights.Security.Negative.Count -gt 0) {
            $riskLevel = "High"
            $riskColor = "Red"
            $riskFactors += "$($insights.Security.Negative.Count) security concerns identified"
        }
        
        if ($govScore -lt 5) {
            if ($riskLevel -ne "High") { $riskLevel = "Medium"; $riskColor = "Yellow" }
            $riskFactors += "Low governance score ($govScore/12)"
        }
        
        Write-Host "   Risk Level: " -NoNewline -ForegroundColor Gray
        Write-Host $riskLevel -ForegroundColor $riskColor
        
        if ($riskFactors.Count -gt 0) {
            Write-Host "   Risk Factors:" -ForegroundColor Gray
            $riskFactors | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkGray }
        } else {
            Write-Host "   No significant risks identified" -ForegroundColor Green
        }
        
        Write-Host "`n================================================================================`n" -ForegroundColor Cyan
    } # end if ($ShowInsights) display block
    } # end if ($ShowInsights -or $OutputHtml) computation block

    # ─── HTML Report Generation ─────────────────────────────────────────────────
    if ($OutputHtml) {
        $htmlResources = if ($Category -or $ResourceName -or $ResourceType) { $filteredResults } else { $results }

        # Compute governance score for HTML (same logic as console)
        $htmlGovScore = 0
        if ($insights.Governance.Tags.Count -gt 0) { $htmlGovScore += 1 }
        if ($insights.Governance.Naming.Count -gt 0) { $htmlGovScore += 1 }
        if ($insights.Governance.Policies.Count -gt 0) { $htmlGovScore += 1 }
        if (($insights.Governance.Backup.Count + $insights.Governance.RetentionResiliency.Count) -gt 0) { $htmlGovScore += 1 }
        if ($insights.Governance.Locks.Count -gt 0) { $htmlGovScore += 1 }
        if ($insights.Governance.RBAC.Count -gt 0) { $htmlGovScore += 1 }
        if ($insights.Governance.NetworkIsolation.Count -gt 0) { $htmlGovScore += 2 }
        if ($insights.Governance.AuditLogging.Count -gt 0) { $htmlGovScore += 1 }
        if ($insights.Governance.ComplianceFrameworks.Count -gt 0) { $htmlGovScore += 2 }
        if ($insights.Governance.CostManagement.Count -gt 0) { $htmlGovScore += 1 }
        $htmlGovPct = [Math]::Round(($htmlGovScore / 12) * 100, 0)

        # Counts
        $hImport  = ($htmlResources | Where-Object { $_.Action -eq 'Import' }).Count
        $hCreate  = ($htmlResources | Where-Object { $_.Action -eq 'Create' }).Count
        $hUpdate  = ($htmlResources | Where-Object { $_.Action -eq 'Update' }).Count
        $hDestroy = ($htmlResources | Where-Object { $_.Action -eq 'Destroy' }).Count
        $hReplace = ($htmlResources | Where-Object { $_.Action -eq 'Replace' }).Count
        $hTotal   = $hImport + $hCreate + $hUpdate + $hDestroy + $hReplace

        # Risk calculation for HTML
        $htmlRiskLevel = "Low"
        $htmlRiskFactors = @()
        if ($hDestroy -gt 10) { $htmlRiskLevel = "High"; $htmlRiskFactors += "$hDestroy resources will be destroyed" }
        elseif ($hDestroy -gt 5) { $htmlRiskLevel = "Medium"; $htmlRiskFactors += "$hDestroy resources will be destroyed" }
        if ($insights.Cost.MonthlyEstimate -gt 500) { $htmlRiskLevel = "High"; $htmlRiskFactors += "High cost increase (+`$$([Math]::Round($insights.Cost.MonthlyEstimate, 0))/mo)" }
        elseif ($insights.Cost.MonthlyEstimate -gt 200) { if ($htmlRiskLevel -eq "Low") { $htmlRiskLevel = "Medium" }; $htmlRiskFactors += "Moderate cost increase (+`$$([Math]::Round($insights.Cost.MonthlyEstimate, 0))/mo)" }
        if ($insights.Security.Negative.Count -gt 0) { $htmlRiskLevel = "High"; $htmlRiskFactors += "$($insights.Security.Negative.Count) security concerns identified" }
        if ($htmlGovScore -lt 5) { if ($htmlRiskLevel -ne "High") { $htmlRiskLevel = "Medium" }; $htmlRiskFactors += "Low governance score ($htmlGovScore/12)" }

        # Helper to HTML-encode
        function HtmlEncode([string]$s) { [System.Net.WebUtility]::HtmlEncode($s) }

        # Build resource table rows grouped by action
        $actionOrder = @('Import','Create','Update','Destroy','Replace')
        $actionIcons = @{ Import='&#x21EA;'; Create='&#x2713;'; Update='&#x2248;'; Destroy='&#x2717;'; Replace='&#x27F3;' }
        $resourceGroupsHtml = ""
        foreach ($act in $actionOrder) {
            $group = $htmlResources | Where-Object { $_.Action -eq $act }
            if (-not $group -or $group.Count -eq 0) { continue }
            $actLower = $act.ToLower()
            $icon = $actionIcons[$act]
            $rows = ""
            foreach ($r in $group) {
                $split = Split-TfResource $r.Resource
                $rType = HtmlEncode $split.Type
                $rName = if ($split.Name) { HtmlEncode $split.Name } else { "" }
                $rAzName = if ($r.AzureName) { HtmlEncode $r.AzureName } else { "" }
                $rRG = if ($r.ResourceGroup) { HtmlEncode $r.ResourceGroup } else { "" }
                $rSub = if ($r.Subscription) { HtmlEncode $r.Subscription } else { "" }
                $rows += "        <tr class=`"$actLower`"><td>$rType</td><td>$rName</td><td>$rAzName</td><td>$rRG</td><td>$rSub</td></tr>`n"
            }
            $resourceGroupsHtml += @"
      <details class="change-block">
        <summary class="$actLower">$icon $act ($($group.Count))</summary>
        <table>
          <tr><th>Resource Type</th><th>Resource Name</th><th>Azure Name</th><th>Resource Group</th><th>Subscription</th></tr>
$rows        </table>
      </details>
"@
        }

        # Build changes detail blocks, grouped by action
        # Only show Update and Replace — Create/Destroy are full attribute dumps, not meaningful diffs
        $changesHtml = ""
        $changesActionOrder = @('Update','Replace')
        foreach ($act in $changesActionOrder) {
            $groupChanges = $htmlResources | Where-Object { $_.Action -eq $act -and $_.Changes.Count -gt 0 }
            if (-not $groupChanges -or $groupChanges.Count -eq 0) { continue }
            $actLower = $act.ToLower()
            $icon = $actionIcons[$act]
            $innerBlocks = ""
            foreach ($r in $groupChanges) {
                $resEnc = HtmlEncode $r.Resource
                $diffLines = ""
                foreach ($c in $r.Changes) {
                    $lineClass = switch ($c.Type) { '+' { 'add' } '-' { 'del' } '~' { 'mod' } default { 'ctx' } }
                    $diffLines += "        <div class=`"diff-line $lineClass`">$(HtmlEncode $c.Line)</div>`n"
                }
                $innerBlocks += @"
        <details class="change-block">
          <summary class="$actLower">$($r.Action): $resEnc</summary>
          <div class="diff">
$diffLines          </div>
        </details>
"@
            }
            $changesHtml += @"
      <details class="change-block">
        <summary class="$actLower">$icon $act ($($groupChanges.Count))</summary>
$innerBlocks      </details>
"@
        }
        $changesCount = ($htmlResources | Where-Object { $_.Action -in @('Update','Replace') -and $_.Changes.Count -gt 0 }).Count
        if (-not $changesHtml) { $changesHtml = "      <p class=`"muted`">No attribute changes to display. Only Update and Replace actions show attribute diffs.</p>" }

        # Helper: build item list HTML
        function BuildItemList([string[]]$items, [string]$cssClass) {
            if ($items.Count -eq 0) { return "" }
            $out = "<ul class=`"$cssClass`">"
            foreach ($i in $items) { $out += "<li>$(HtmlEncode $i)</li>" }
            $out += "</ul>"
            return $out
        }

        # Cost section
        $costHtml = "<p><strong>Overall Impact:</strong> $(HtmlEncode $insights.Cost.EstimatedImpact)</p>"
        if ($insights.Cost.High.Count -gt 0) { $costHtml += "<h4 class=`"high`">High Cost Resources ($($insights.Cost.High.Count))</h4>$(BuildItemList $insights.Cost.High 'high')" }
        if ($insights.Cost.Medium.Count -gt 0) { $costHtml += "<h4 class=`"medium`">Medium Cost Resources ($($insights.Cost.Medium.Count))</h4>$(BuildItemList $insights.Cost.Medium 'medium')" }
        if ($insights.Cost.Low.Count -gt 0) { $costHtml += "<h4 class=`"low`">Low Cost Resources ($($insights.Cost.Low.Count))</h4>$(BuildItemList $insights.Cost.Low 'low')" }

        # Security section
        $secHtml = "<p><strong>Security Trend:</strong> $(HtmlEncode $insights.Security.OverallTrend)</p>"
        if ($insights.Security.Positive.Count -gt 0) { $secHtml += "<h4 class=`"low`">Improvements ($($insights.Security.Positive.Count))</h4>$(BuildItemList $insights.Security.Positive 'low')" }
        if ($insights.Security.Negative.Count -gt 0) { $secHtml += "<h4 class=`"high`">Concerns ($($insights.Security.Negative.Count))</h4>$(BuildItemList $insights.Security.Negative 'high')" }
        if ($insights.Security.Neutral.Count -gt 0) { $secHtml += "<h4 class=`"medium`">Modifications ($($insights.Security.Neutral.Count))</h4>$(BuildItemList $insights.Security.Neutral 'medium')" }

        # Carbon section
        $carbonHtml = "<p><strong>Carbon Impact:</strong> $(HtmlEncode $insights.Carbon.EstimatedImpact)</p>"
        if ($insights.Carbon.High.Count -gt 0) { $carbonHtml += "<h4 class=`"high`">High Emission Resources ($($insights.Carbon.High.Count))</h4>$(BuildItemList $insights.Carbon.High 'high')" }
        if ($insights.Carbon.Medium.Count -gt 0) { $carbonHtml += "<h4 class=`"medium`">Medium Emission Resources ($($insights.Carbon.Medium.Count))</h4>$(BuildItemList $insights.Carbon.Medium 'medium')" }
        if ($insights.Carbon.Low.Count -gt 0) { $carbonHtml += "<h4 class=`"low`">Low Emission Resources ($($insights.Carbon.Low.Count))</h4>$(BuildItemList $insights.Carbon.Low 'low')" }
        if ($insights.Carbon.Recommendations.Count -gt 0) { $carbonHtml += "<h4>Sustainability Recommendations</h4>$(BuildItemList $insights.Carbon.Recommendations '')" }

        # Governance section
        $govCategories = @(
            @{ Name = 'Tags';                 Items = $insights.Governance.Tags;                 Weight = 1; WhatIsChecked = 'Scans attribute changes for <code>tags</code>, <code>cost_center</code>, <code>environment</code>, <code>owner</code>, <code>project</code>' },
            @{ Name = 'Naming';               Items = $insights.Governance.Naming;               Weight = 1; WhatIsChecked = 'Evaluates the actual Azure resource <code>name</code> attribute against CAF prefixes (<code>rg-</code>, <code>vnet-</code>, etc.), environment/region indicators, and multi-segment structure' },
            @{ Name = 'Policies/Monitoring';   Items = $insights.Governance.Policies;             Weight = 1; WhatIsChecked = 'Detects policy assignments, policy definitions, diagnostic settings, log analytics, and monitoring resources by resource type' },
            @{ Name = 'Backup/Retention';      Items = ($insights.Governance.Backup + $insights.Governance.RetentionResiliency); Weight = 1; WhatIsChecked = 'Scans for <code>backup</code>, <code>recovery_services_vault</code>, <code>retention</code>, <code>soft_delete</code>, <code>geo_redundant</code> in attributes or resource type' },
            @{ Name = 'Resource Locks';        Items = $insights.Governance.Locks;                Weight = 1; WhatIsChecked = 'Detects <code>azurerm_management_lock</code> resource type or <code>delete_lock</code>/<code>read_only_lock</code> attributes' },
            @{ Name = 'RBAC/IAM';             Items = $insights.Governance.RBAC;                 Weight = 1; WhatIsChecked = 'Detects role assignment/definition resource types or <code>principal_id</code> attributes' },
            @{ Name = 'Network Isolation';     Items = $insights.Governance.NetworkIsolation;     Weight = 2; WhatIsChecked = 'Detects <code>azurerm_private_endpoint</code>, private link, or VNet integration resource types' },
            @{ Name = 'Audit Logging';         Items = $insights.Governance.AuditLogging;         Weight = 1; WhatIsChecked = 'Detects log analytics workspace, diagnostic setting resource types or <code>log_retention_days</code> attributes' },
            @{ Name = 'Compliance Frameworks'; Items = $insights.Governance.ComplianceFrameworks; Weight = 2; WhatIsChecked = 'Detects policy assignment/definition types and Azure Security Center resources. For ALZ plans, categorizes policies against Enterprise-Scale patterns' },
            @{ Name = 'Cost Management';       Items = $insights.Governance.CostManagement;       Weight = 1; WhatIsChecked = 'Detects <code>azurerm_consumption_budget</code> or <code>cost_management_export</code> resource types' }
        )
        $govScoreColor = if ($htmlGovScore -ge 8) { '#27ae60' } elseif ($htmlGovScore -ge 5) { '#f39c12' } else { '#e74c3c' }
        $govHtml = "<p><strong>Governance Score:</strong> <span style=`"color:$govScoreColor;font-weight:bold;font-size:1.2em`">$htmlGovScore/12 ($htmlGovPct%)</span></p>"
        $govHtml += "<table class=`"gov-table`"><tr><th>Category</th><th>Weight</th><th>Status</th><th>Count</th><th>What Is Checked</th></tr>"
        foreach ($gc in $govCategories) {
            $statusIcon = if ($gc.Items.Count -gt 0) { '<span class="pass">&#10003;</span>' } else { '<span class="fail">&#10007;</span>' }
            $countText = if ($gc.Items.Count -gt 0) { "$($gc.Items.Count) found" } else { '&mdash;' }
            $countColor = if ($gc.Items.Count -gt 0) { 'var(--green)' } else { 'var(--muted)' }
            $govHtml += "<tr><td><strong>$($gc.Name)</strong></td><td>+$($gc.Weight)</td><td>$statusIcon</td><td style=`"color:$countColor`">$countText</td><td style=`"color:var(--muted);font-size:0.82em`">$($gc.WhatIsChecked)</td></tr>"
        }
        $govHtml += "</table>"
        $govHtml += "<p style=`"font-size:0.82em;color:var(--muted);margin:8px 0 14px`"><span class=`"pass`">&#10003;</span> <strong>Detected</strong> = this governance pattern was found in the plan (weight is added to score) &nbsp;&bull;&nbsp; <span class=`"fail`">&#10007;</span> <strong>Not found</strong> = no matching resources or attributes detected in this plan (weight is not added). A &#10007; does not mean non-compliant &mdash; the control may exist outside this plan.</p>"
        foreach ($gc in $govCategories) {
            if ($gc.Items.Count -gt 0) {
                $govHtml += "<details><summary>$($gc.Name) ($($gc.Items.Count))</summary>$(BuildItemList $gc.Items '')</details>"
            }
        }

        # Risk factors HTML
        $riskHtml = ""
        if ($htmlRiskFactors.Count -gt 0) {
            $riskHtml = "<ul>"
            foreach ($rf in $htmlRiskFactors) { $riskHtml += "<li>$(HtmlEncode $rf)</li>" }
            $riskHtml += "</ul>"
        } else {
            $riskHtml = "<p class=`"muted`">No significant risks identified.</p>"
        }
        $riskColorHtml = switch ($htmlRiskLevel) { 'High' { '#e74c3c' } 'Medium' { '#f39c12' } default { '#27ae60' } }

        # Filters info
        $filtersHtml = ""
        if ($Category -or $ResourceName -or $ResourceType) {
            $filtersHtml = "<p class=`"filters`">Active Filters:"
            if ($Category)     { $filtersHtml += " <strong>Category:</strong> $(HtmlEncode $Category)" }
            if ($ResourceName) { $filtersHtml += " <strong>ResourceName:</strong> $(HtmlEncode $ResourceName)" }
            if ($ResourceType) { $filtersHtml += " <strong>ResourceType:</strong> $(HtmlEncode $ResourceType)" }
            $filtersHtml += "</p>"
        }

        # Cost delta display
        $costDelta = $insights.Cost.MonthlyEstimate
        $totalCostRes = $insights.Cost.High.Count + $insights.Cost.Medium.Count + $insights.Cost.Low.Count
        if ($costDelta -gt 0) {
            $costDeltaStr = "+`$$([Math]::Round($costDelta,2))/mo"
            $costDeltaColor = '#e74c3c'
        } elseif ($costDelta -lt 0) {
            $costDeltaStr = "-`$$([Math]::Round([Math]::Abs($costDelta),2))/mo"
            $costDeltaColor = '#27ae60'
        } elseif ($totalCostRes -gt 0) {
            $costDeltaStr = "No Change ≈"
            $costDeltaColor = '#7f8c8d'
        } else {
            $costDeltaStr = "None"
            $costDeltaColor = '#7f8c8d'
        }
        $costBreakdown = if ($totalCostRes -gt 0) {
            "<br><small style=`"color:var(--muted)`">$totalCostRes cost-relevant: <span style=`"color:var(--red)`">$($insights.Cost.High.Count) High</span>, <span style=`"color:var(--yellow)`">$($insights.Cost.Medium.Count) Medium</span>, <span style=`"color:var(--green)`">$($insights.Cost.Low.Count) Low</span></small>"
        } else { "" }

        $carbonDelta = $insights.Carbon.MonthlyEmissions
        $totalCarbonRes = $insights.Carbon.High.Count + $insights.Carbon.Medium.Count + $insights.Carbon.Low.Count
        if ($carbonDelta -gt 0) {
            $carbonDeltaStr = "+$([Math]::Round($carbonDelta,1)) kg CO2e/mo"
            $carbonDeltaColor = '#e74c3c'
        } elseif ($carbonDelta -lt 0) {
            $carbonDeltaStr = "-$([Math]::Round([Math]::Abs($carbonDelta),1)) kg CO2e/mo"
            $carbonDeltaColor = '#27ae60'
        } elseif ($totalCarbonRes -gt 0) {
            $carbonDeltaStr = "No Change ≈"
            $carbonDeltaColor = '#7f8c8d'
        } else {
            $carbonDeltaStr = "None"
            $carbonDeltaColor = '#7f8c8d'
        }
        $carbonBreakdown = if ($totalCarbonRes -gt 0) {
            "<br><small style=`"color:var(--muted)`">$totalCarbonRes carbon-relevant: <span style=`"color:var(--red)`">$($insights.Carbon.High.Count) High</span>, <span style=`"color:var(--yellow)`">$($insights.Carbon.Medium.Count) Medium</span>, <span style=`"color:var(--green)`">$($insights.Carbon.Low.Count) Low</span></small>"
        } else { "" }

        $totalSecChanges = $insights.Security.Positive.Count + $insights.Security.Negative.Count + $insights.Security.Neutral.Count
        $secBreakdown = if ($totalSecChanges -gt 0) {
            "<br><small style=`"color:var(--muted)`">$totalSecChanges security-related changes ($($insights.Security.Neutral.Count) modifications)</small>"
        } elseif ($totalSecChanges -eq 0) { "" }
        else { "<br><small style=`"color:var(--muted)`">No security-related changes detected</small>" }

        # Assemble the full HTML document
        $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Terraform Plan Report - $(HtmlEncode (Split-Path $LogFile -Leaf))</title>
<style>
  :root{--bg:#1a1a2e;--surface:#16213e;--card:#0f3460;--text:#e6e6e6;--muted:#7f8c8d;
        --green:#27ae60;--yellow:#f39c12;--red:#e74c3c;--cyan:#00bcd4;--magenta:#9b59b6;--blue:#3498db}
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,-apple-system,sans-serif;line-height:1.6;padding:20px}
  .container{max-width:1200px;margin:0 auto}
  h1{color:var(--cyan);margin-bottom:5px;font-size:1.8em}
  h2{color:var(--cyan);margin:25px 0 10px;border-bottom:2px solid var(--card);padding-bottom:5px}
  h3{color:var(--text);margin:15px 0 8px}
  h4{margin:10px 0 5px}
  h4.high{color:var(--red)} h4.medium{color:var(--yellow)} h4.low{color:var(--green)}
  .meta{color:var(--muted);font-size:0.9em;margin-bottom:20px}
  .filters{background:var(--card);padding:8px 14px;border-radius:6px;margin-bottom:15px;font-size:0.9em}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:15px 0 25px}
  .card{background:var(--surface);border-radius:10px;padding:18px;text-align:center;border-left:4px solid var(--muted)}
  .card .count{font-size:2em;font-weight:bold;display:block}
  .card .label{font-size:0.85em;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
  .card.import{border-color:var(--cyan)} .card.import .count{color:var(--cyan)}
  .card.create{border-color:var(--green)} .card.create .count{color:var(--green)}
  .card.update{border-color:var(--yellow)} .card.update .count{color:var(--yellow)}
  .card.destroy{border-color:var(--red)} .card.destroy .count{color:var(--red)}
  .card.replace{border-color:var(--magenta)} .card.replace .count{color:var(--magenta)}
  .card.total{border-color:var(--blue)} .card.total .count{color:var(--blue)}
  table{width:100%;border-collapse:collapse;margin:10px 0;font-size:0.92em}
  th{background:var(--card);color:var(--cyan);padding:10px 12px;text-align:left;font-weight:600}
  td{padding:8px 12px;border-bottom:1px solid #1a2744}
  tr:hover td{background:rgba(255,255,255,0.03)}
  tr.import td:first-child{color:var(--cyan);font-weight:600}
  tr.create td:first-child{color:var(--green);font-weight:600}
  tr.update td:first-child{color:var(--yellow);font-weight:600}
  tr.destroy td:first-child{color:var(--red);font-weight:600}
  tr.replace td:first-child{color:var(--magenta);font-weight:600}
  details{margin:6px 0} summary{cursor:pointer;padding:6px 10px;background:var(--surface);border-radius:5px;font-weight:500}
  .container>details{margin:16px 0;border:1px solid var(--surface);border-radius:8px;padding:4px}
  .container>details>summary{padding:10px 14px;font-size:1em}
  .container>details[open]>summary{border-bottom:1px solid var(--surface);margin-bottom:8px}
  summary:hover{background:var(--card)}
  summary.import{color:var(--cyan)} summary.create{color:var(--green)} summary.update{color:var(--yellow)}
  summary.destroy{color:var(--red)} summary.replace{color:var(--magenta)}
  .diff{background:#0d1117;border-radius:5px;padding:10px;margin:5px 0;font-family:'Cascadia Code','Fira Code',Consolas,monospace;font-size:0.85em;overflow-x:auto}
  .diff-line{white-space:pre;padding:1px 4px}
  .diff-line.add{color:#3fb950;background:rgba(63,185,80,0.1)}
  .diff-line.del{color:#f85149;background:rgba(248,81,73,0.1)}
  .diff-line.mod{color:#d29922;background:rgba(210,153,34,0.1)}
  .diff-line.ctx{color:var(--muted)}
  .insight-section{background:var(--surface);border-radius:10px;padding:18px 22px;margin:12px 0}
  ul{padding-left:20px;margin:5px 0} li{margin:3px 0;font-size:0.92em}
  ul.high li{color:#e88} ul.medium li{color:#ec9} ul.low li{color:#8d8}
  .muted{color:var(--muted);font-style:italic}
  .risk-badge{display:inline-block;padding:4px 14px;border-radius:15px;font-weight:bold;font-size:1em}
  .gov-table{width:auto;margin:10px 0} .gov-table th,.gov-table td{padding:5px 14px;font-size:0.9em}
  .pass{color:var(--green);font-weight:bold;font-size:1.2em} .fail{color:var(--red);font-size:1.2em}
  .exec-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px;margin:10px 0}
  .exec-card{background:var(--surface);border-radius:10px;padding:16px;border-top:3px solid var(--card)}
  .exec-card h4{margin:0 0 8px;color:var(--cyan)}
  .exec-val{font-size:1.3em;font-weight:bold}
  .info-wrap{position:relative;display:inline-block;vertical-align:middle;margin-left:8px}
  .info-btn{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:50%;background:var(--card);color:var(--cyan);font-size:0.75em;font-weight:700;cursor:pointer;border:1px solid var(--cyan);line-height:1;vertical-align:middle;text-decoration:none;transition:background 0.2s}
  .info-btn:hover{background:var(--cyan);color:var(--bg)}
  .info-tip{display:none;position:absolute;left:30px;top:-8px;z-index:100;background:var(--card);border:1px solid var(--cyan);border-radius:8px;padding:12px 16px;min-width:320px;max-width:420px;font-size:0.82em;font-weight:normal;color:var(--text);line-height:1.5;box-shadow:0 4px 20px rgba(0,0,0,0.5)}
  .info-wrap:hover .info-tip,.info-btn:focus+.info-tip{display:block}
  .info-tip strong{color:var(--cyan)}
  .info-tip .swatch{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:middle}
  .disclaimer{background:var(--surface);border:1px solid var(--yellow);border-radius:8px;padding:14px 20px;margin:25px 0 10px;font-size:0.82em;color:var(--muted);line-height:1.6}
  .disclaimer strong{color:var(--yellow)}
  .legend-section{margin:16px 0;border:1px solid var(--card);border-radius:8px;padding:4px}
  .legend-section>summary{padding:10px 14px;font-size:1em;background:var(--surface);border-radius:5px;cursor:pointer}
  .legend-section>summary:hover{background:var(--card)}
  .legend-section h3{border-bottom:1px solid var(--card);padding-bottom:6px;margin-bottom:10px}
  .legend-section table{margin:8px 0 16px}
  .legend-section p{margin:6px 0}
  .legend-section code{background:var(--card);padding:1px 5px;border-radius:3px;font-size:0.9em}
  footer{text-align:center;color:var(--muted);font-size:0.8em;margin-top:30px;padding-top:15px;border-top:1px solid var(--card)}
</style>
</head>
<body>
<div class="container">

  <h1>&#x1F4CB; Terraform Plan Report</h1>
  <p class="meta">Log: <strong>$(HtmlEncode (Split-Path $LogFile -Leaf))</strong> &nbsp;|&nbsp; Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
  $filtersHtml

  <!-- Summary Cards -->
  <div class="cards">
    <div class="card total"><span class="count">$hTotal</span><span class="label">Total</span></div>
    <div class="card import"><span class="count">$hImport</span><span class="label">Import</span></div>
    <div class="card create"><span class="count">$hCreate</span><span class="label">Create</span></div>
    <div class="card update"><span class="count">$hUpdate</span><span class="label">Update</span></div>
    <div class="card destroy"><span class="count">$hDestroy</span><span class="label">Destroy</span></div>
    <div class="card replace"><span class="count">$hReplace</span><span class="label">Replace</span></div>
  </div>

  <!-- Resource Table -->
  <details>
    <summary><h2 style="display:inline">&#x1F4E6; Resources ($hTotal)</h2></summary>
    <span class="info-wrap"><span class="info-btn" tabindex="0">i</span><span class="info-tip">Lists every resource affected by this plan.<br><span class="swatch" style="background:var(--cyan)"></span> <strong>Import</strong> &mdash; adopted into Terraform state<br><span class="swatch" style="background:var(--green)"></span> <strong>Create</strong> &mdash; new resource<br><span class="swatch" style="background:var(--yellow)"></span> <strong>Update</strong> &mdash; in-place modification<br><span class="swatch" style="background:var(--red)"></span> <strong>Destroy</strong> &mdash; permanent removal<br><span class="swatch" style="background:var(--magenta)"></span> <strong>Replace</strong> &mdash; destroy &amp; re-create</span></span>
$resourceGroupsHtml
  </details>

  <!-- Attribute Changes (Update & Replace only) -->
  <details>
    <summary><h2 style="display:inline">&#x1F50D; Attribute Changes ($changesCount)</h2></summary>
    <span class="info-wrap"><span class="info-btn" tabindex="0">i</span><span class="info-tip">Shows the detailed attribute-level diff for resources being <strong>updated</strong> or <strong>replaced</strong>.<br>Create and Destroy actions are excluded because they show full attribute dumps rather than meaningful diffs.<br><span style="color:#3fb950;font-weight:bold">+</span> Added value &nbsp; <span style="color:#f85149;font-weight:bold">&minus;</span> Removed value &nbsp; <span style="color:#d29922;font-weight:bold">~</span> Modified value</span></span>
$changesHtml
  </details>

  <!-- Cost Impact -->
  <details>
    <summary><h2 style="display:inline">&#x1F4B0; Cost Impact Analysis ($totalCostRes)</h2></summary>
    <span class="info-wrap"><span class="info-btn" tabindex="0">i</span><span class="info-tip"><strong>&#x26A0;&#xFE0F; Inference-based cost estimates &mdash; NOT actual Azure pricing.</strong><br><br>Values are the <strong>author's approximations</strong> of PAYG Linux East US pricing (base/entry-level tiers). They were NOT fetched from the Azure Pricing API or Calculator at runtime.<br><br>Actual costs depend on SKU tier, region, reserved instances, dev/test pricing, enterprise agreements, and consumption patterns. For accurate pricing use the <strong>Azure Pricing Calculator</strong> or <strong>Azure Cost Management</strong>.<br>Use these figures for <strong>directional awareness only</strong>.</span></span>
    <div class="insight-section">
$costHtml
    </div>
  </details>

  <!-- Security Impact -->
  <details>
    <summary><h2 style="display:inline">&#x1F512; Security Impact Analysis ($totalSecChanges)</h2></summary>
    <span class="info-wrap"><span class="info-btn" tabindex="0">i</span><span class="info-tip"><strong>Heuristic security analysis &mdash; not a security audit.</strong><br>Detects changes to security-sensitive attributes (encryption, access control, network exposure, authentication) by pattern matching on attribute names and values.<br>Results may include false positives or miss context-specific risks. Always perform a proper security review for production changes.</span></span>
    <div class="insight-section">
$secHtml
    </div>
  </details>

  <!-- Carbon Impact -->
  <details>
    <summary><h2 style="display:inline">&#x1F30D; Carbon Impact Analysis ($totalCarbonRes)</h2></summary>
    <span class="info-wrap"><span class="info-btn" tabindex="0">i</span><span class="info-tip"><strong>&#x26A0;&#xFE0F; Inference-based estimates &mdash; NOT actual measurements.</strong><br><br><strong>Methodology:</strong> Formula inspired by Cloud Carbon Footprint (CCF), but per-vCPU wattages and service power draws are the <strong>author's own approximations</strong>.<br><strong>Formula:</strong> <code>kgCO2e = vCPUs &times; W/vCPU &times; 0.5 util &times; PUE(1.125) &times; 730h &divide; 1000 &times; regional gCO2e/kWh</code><br>Regional carbon intensities are approximate estimates, not from Electricity Maps or IEA.<br><br>Values do <strong>not</strong> reflect actual Azure telemetry, workload utilization, renewable energy procurement, or hardware generation. For actual data use <strong>Azure Carbon Optimization</strong> or the <strong>Emissions Impact Dashboard</strong>.<br>Use these figures for <strong>directional awareness only</strong>.</span></span>
    <div class="insight-section">
$carbonHtml
    </div>
  </details>

  <!-- Governance -->
  <details>
    <summary><h2 style="display:inline">&#x1F4CB; Governance &amp; Compliance ($htmlGovScore/12)</h2></summary>
    <span class="info-wrap"><span class="info-btn" tabindex="0">i</span><span class="info-tip">Evaluates plan resources against 12 governance criteria: tags, naming conventions, policies, monitoring, backup, resource locks, RBAC, network isolation, audit logging, compliance, cost management, and encryption.<br>Score reflects the <strong>presence</strong> of these patterns in the plan &mdash; it does not verify correctness or completeness. <span style="color:var(--green)">&#x2705; Pass</span> = pattern detected &nbsp; <span style="color:var(--red)">&#x274C; Fail</span> = not detected.</span></span>
    <div class="insight-section">
$govHtml
    </div>
  </details>

  <!-- Executive Summary -->
  <details open>
    <summary><h2 style="display:inline">&#x1F4CA; Executive Summary</h2></summary>
    <span class="info-wrap"><span class="info-btn" tabindex="0">i</span><span class="info-tip">High-level overview consolidating all analysis areas.<br><span style="color:var(--red)">&#x25B2;</span> = increase &nbsp; <span style="color:var(--green)">&#x25BC;</span> = decrease &nbsp; <span style="color:var(--muted)">&#x25CF;</span> = no change/none<br>All figures are inferred estimates, not exact calculations. See individual sections for details.</span></span>
    <div class="exec-grid">
    <div class="exec-card">
      <h4>&#x1F4E6; Resource Changes</h4>
      <span class="exec-val">$hTotal</span> resources affected<br>
      <span style="color:var(--cyan)">$hImport import</span> &bull;
      <span style="color:var(--green)">$hCreate create</span> &bull;
      <span style="color:var(--yellow)">$hUpdate update</span> &bull;
      <span style="color:var(--red)">$hDestroy destroy</span> &bull;
      <span style="color:var(--magenta)">$hReplace replace</span>
    </div>
    <div class="exec-card">
      <h4>&#x1F4B0; Cost Impact</h4>
      <span class="exec-val" style="color:$costDeltaColor">$costDeltaStr</span>
$costBreakdown
    </div>
    <div class="exec-card">
      <h4>&#x1F30D; Carbon Footprint</h4>
      <span class="exec-val" style="color:$carbonDeltaColor">$carbonDeltaStr</span>
$carbonBreakdown
    </div>
    <div class="exec-card">
      <h4>&#x1F512; Security</h4>
      <span style="color:var(--green)">$($insights.Security.Positive.Count) improvements</span> &bull;
      <span style="color:var(--red)">$($insights.Security.Negative.Count) concerns</span><br>
      Trend: <strong>$(HtmlEncode $insights.Security.OverallTrend)</strong>
$secBreakdown
    </div>
    <div class="exec-card">
      <h4>&#x1F4CB; Governance</h4>
      <span class="exec-val" style="color:$govScoreColor">$htmlGovScore/12 ($htmlGovPct%)</span>
    </div>
    <div class="exec-card">
      <h4>&#x2705; Risk Level</h4>
      <span class="risk-badge" style="background:$riskColorHtml;color:#fff">$htmlRiskLevel</span>
$riskHtml
    </div>
  </div>
  </details>

  <!-- Disclaimer -->
  <div class="disclaimer">
    <strong>&#x26A0;&#xFE0F; Disclaimer:</strong> This report is generated automatically using heuristic inference and pattern matching. Cost estimates, carbon footprint figures, and security assessments are <strong>approximate</strong> and <strong>do not</strong> represent actual cloud provider billing, measured emissions, or a formal security audit. The author(s) of this tool accept <strong>no responsibility</strong> for decisions made based on this output. Always validate critical changes through official cloud pricing calculators, security reviews, and compliance audits before applying Terraform plans to production environments.
  </div>

  <!-- Legend: How This Report Works -->
  <details class="legend-section">
    <summary><h2 style="display:inline">&#x1F4D6; How This Report Works &mdash; Legend &amp; Methodology</h2></summary>
    <div class="insight-section" style="font-size:0.9em;line-height:1.7">

      <h3 style="color:var(--cyan);margin-top:0">&#x1F3AF; Overview</h3>
      <p>This report parses the text output of <code>terraform plan</code> and generates insights using <strong>heuristic pattern matching</strong>. It does <em>not</em> query cloud APIs or evaluate runtime state &mdash; everything is inferred from what Terraform prints.</p>
      <p>The parser reads the plan line by line, identifies resource change blocks (lines starting with <code># resource.name will be created/destroyed/updated/replaced</code>), and extracts metadata from each resource's attribute lines (e.g., <code>name</code>, <code>resource_group_name</code>, <code>id</code>).</p>

      <h3 style="color:var(--cyan)">&#x1F4CA; Resource Table &mdash; Column Explanations</h3>
      <table style="font-size:0.92em">
        <tr><th>Column</th><th>Source</th><th>How It Is Determined</th><th>Example</th></tr>
        <tr><td><strong>Resource Type</strong></td><td>Terraform address</td><td>Extracted from the resource address by skipping <code>module.&lt;name&gt;</code> and <code>data.</code> prefixes to get the bare provider resource type</td><td><code>module.alz.azurerm_storage_account.sa</code> &rarr; <code>azurerm_storage_account</code></td></tr>
        <tr><td><strong>Resource Name</strong></td><td>Terraform address</td><td>The instance name part after the resource type. This is the Terraform logical name, not the Azure name</td><td><code>sa</code>, <code>policy_assignments["Costaltd/Deploy-VM-Backup"]</code></td></tr>
        <tr><td><strong>Azure Name</strong></td><td>Plan attributes</td><td>Read from the <code>name = "..."</code> top-level attribute in the plan output. If not found, falls back to the last segment of the <code>id</code></td><td><code>security-dcr-linux</code>, <code>sacostatestflowlogs</code></td></tr>
        <tr><td><strong>Resource Group</strong></td><td>Plan attributes</td><td>Read from <code>resource_group_name = "..."</code> attribute. If not present, parsed from the <code>id</code> path segment <code>/resourceGroups/&lt;name&gt;/</code></td><td><code>rg-logs</code>, <code>rg-network-prod</code></td></tr>
        <tr><td><strong>Subscription</strong></td><td>Plan attributes</td><td>Parsed from the <code>id</code> attribute path segment <code>/subscriptions/&lt;guid&gt;/</code>. Empty for new resources where <code>id = (known after apply)</code></td><td><code>16bd14c8-b405-4fd2-9e23-7ef93ef93141</code></td></tr>
      </table>
      <p style="color:var(--muted);font-size:0.88em"><strong>Why is Subscription empty for some resources?</strong> When Terraform creates a new resource, its <code>id</code> is not yet known (<code>known after apply</code>), so subscription cannot be extracted. Existing resources (update/destroy) always have an <code>id</code> and will show the subscription.</p>

      <h3 style="color:var(--cyan)">&#x1F3F7;&#xFE0F; Action Symbols &amp; Colors</h3>
      <table style="font-size:0.92em">
        <tr><th>Symbol</th><th>Action</th><th>Color</th><th>Meaning</th><th>Example in Plan</th></tr>
        <tr><td>&#x21EA;</td><td>Import</td><td style="color:var(--cyan)">Cyan</td><td>Resource is being imported into Terraform state &mdash; no infrastructure change, just adopting an existing resource</td><td><code># azurerm_log_analytics_workspace.law will be imported</code></td></tr>
        <tr><td>&#x2713;</td><td>Create</td><td style="color:var(--green)">Green</td><td>A new resource will be provisioned in the cloud</td><td><code># azurerm_monitor_data_collection_rule.dcr_linux will be created</code></td></tr>
        <tr><td>&#x2248;</td><td>Update</td><td style="color:var(--yellow)">Yellow</td><td>An existing resource will be modified in-place (no downtime typically)</td><td><code># azurerm_storage_account.SAFlowLog will be updated in-place</code></td></tr>
        <tr><td>&#x2717;</td><td>Destroy</td><td style="color:var(--red)">Red</td><td>An existing resource will be permanently deleted &mdash; <strong>review carefully!</strong></td><td><code># azurerm_monitor_data_collection_rule.dcrsecurity will be destroyed</code></td></tr>
        <tr><td>&#x27F3;</td><td>Replace</td><td style="color:var(--magenta)">Magenta</td><td>Resource must be destroyed and recreated (Terraform cannot update in-place). This causes <strong>downtime</strong> and may change the resource's ID</td><td><code># azurerm_subnet.config must be replaced</code></td></tr>
      </table>

      <h3 style="color:var(--cyan)">&#x1F4B0; Cost Impact Analysis</h3>
      <p style="background:rgba(255,165,0,0.15);border-left:3px solid orange;padding:8px 12px;border-radius:4px">&#x26A0;&#xFE0F; <strong>DISCLAIMER:</strong> These are <strong>inference-based estimates</strong>, NOT actual Azure pricing. Values are the author's approximations of Pay-As-You-Go (PAYG) Linux pricing for East US. They are NOT fetched from the Azure Pricing API or Calculator. Actual costs depend on SKU tier, region, reserved instances, dev/test pricing, and enterprise agreements. For accurate pricing, use <a href="https://azure.microsoft.com/en-us/pricing/calculator/" style="color:var(--cyan)">Azure Pricing Calculator</a> or <a href="https://learn.microsoft.com/en-us/azure/cost-management-billing/" style="color:var(--cyan)">Azure Cost Management</a>.</p>

      <p><strong>What it does:</strong> Estimates the monthly cost change (USD/month) caused by this Terraform plan.</p>

      <h4 style="color:var(--cyan);margin-top:1em">Methodology</h4>
      <p>All values are the <strong>author's approximate estimates</strong> based on general knowledge of Azure PAYG pricing:</p>
      <table style="font-size:0.88em">
        <tr><th>Data Source</th><th>What It Contains</th><th>How Derived</th></tr>
        <tr><td><strong>VMSizes</strong></td><td>~90 VM SKUs with monthly USD</td><td>Author's approximation of PAYG Linux East US pricing. Scales linearly with vCPUs per family. NOT from Azure Pricing API.</td></tr>
        <tr><td><strong>Storage</strong></td><td>8 redundancy tiers</td><td>Approximate cost per ~1TB stored. NOT from Azure Pricing API.</td></tr>
        <tr><td><strong>Services</strong></td><td>~120 resource types</td><td>Base/entry-level tier pricing. Many services have &#36;0 because cost depends on usage (e.g., serverless, per-transaction).</td></tr>
      </table>

      <h4 style="color:var(--cyan);margin-top:1em">Worked Example</h4>
      <table style="font-size:0.88em">
        <tr><th>Step</th><th>Description</th><th>Result</th></tr>
        <tr><td>1</td><td>Resource: <code>azurerm_linux_virtual_machine</code> with size <code>Standard_D4s_v3</code></td><td>VM size detected in plan text</td></tr>
        <tr><td>2</td><td>Lookup VMSizes table: <code>Standard_D4s_v3</code> &rarr; &#36;140/mo</td><td><strong>&#36;140/mo</strong></td></tr>
        <tr><td>3</td><td>Action is <code>Create</code> &rarr; cost impact = +&#36;140/mo</td><td style="color:var(--red)">+&#36;140</td></tr>
      </table>
      <table style="font-size:0.88em;margin-top:0.5em">
        <tr><th>Step</th><th>Description</th><th>Result</th></tr>
        <tr><td>1</td><td>Resource: <code>azurerm_storage_account</code> (no size detected)</td><td>Lookup Services table</td></tr>
        <tr><td>2</td><td>Services[azurerm_storage_account] &rarr; &#36;20/mo</td><td><strong>&#36;20/mo</strong></td></tr>
        <tr><td>3</td><td>Action is <code>Update</code> &rarr; cost impact = &#36;0 (in-place)</td><td style="color:var(--yellow)">&#36;0</td></tr>
      </table>

      <h4 style="color:var(--cyan);margin-top:1em">Cost Tiers</h4>
      <table style="font-size:0.88em">
        <tr><th>Impact Level</th><th>Typical Cost Range</th><th>Example Resources</th></tr>
        <tr><td style="color:#e88"><strong>High (&gt;&#36;50/mo)</strong></td><td>&#36;50&ndash;&#36;22,000+/mo</td><td>VMs, AKS, SQL MI, Firewall (&#36;912), Azure VMware (&#36;5,940), GPU VMs (&#36;2,700+), HDInsight clusters</td></tr>
        <tr><td style="color:#ec9"><strong>Medium (&#36;5&ndash;&#36;100/mo)</strong></td><td>&#36;5&ndash;&#36;200/mo</td><td>Storage accounts (&#36;20), Redis (&#36;16), App Service (&#36;13), Bastion (&#36;139), IoT Hub (&#36;25)</td></tr>
        <tr><td style="color:#8d8"><strong>Low (&#36;0&ndash;&#36;10/mo)</strong></td><td>&#36;0&ndash;&#36;10/mo</td><td>VNets (&#36;0), NSGs (&#36;0), DNS zones (&#36;0.50), Managed Disk (&#36;6), Private Endpoints (&#36;7)</td></tr>
      </table>

      <h4 style="color:var(--cyan);margin-top:1em">Color Coding &amp; Labels</h4>
      <table style="font-size:0.88em">
        <tr><th>Label</th><th>Meaning</th><th>Action</th></tr>
        <tr><td><code>[+High]</code> / <code>[+Medium]</code> / <code>[+Low]</code></td><td style="color:var(--red)">Plan <strong>adds</strong> cost</td><td>Create / Replace</td></tr>
        <tr><td><code>[-High]</code> / <code>[-Medium]</code> / <code>[-Low]</code></td><td style="color:var(--green)">Plan <strong>reduces</strong> cost</td><td>Destroy</td></tr>
        <tr><td><code>[~High]</code> etc.</td><td style="color:var(--yellow)">Net zero</td><td>Replace (destroy + create)</td></tr>
        <tr><td><code>[&asymp;High]</code> etc.</td><td style="color:var(--yellow)">Net zero</td><td>Update in-place</td></tr>
      </table>

      <h4 style="color:var(--cyan);margin-top:1em">Limitations</h4>
      <ul style="font-size:0.9em">
        <li><strong>No region adjustment</strong> &mdash; all prices use a single East US baseline; actual costs vary ±30% by region</li>
        <li><strong>No reservation/savings plans</strong> &mdash; 1-year RI saves ~35%, 3-year saves ~55-72%; this tool uses PAYG only</li>
        <li><strong>No enterprise discounts</strong> &mdash; EA/MCA/CSP pricing is often significantly lower</li>
        <li><strong>Base tier only</strong> &mdash; services are priced at entry-level; production tiers are usually 2-10x more</li>
        <li><strong>No usage-based costs</strong> &mdash; data transfer, transactions, API calls, and consumption-based charges are not estimated</li>
        <li><strong>Partial coverage</strong> &mdash; ~90 VM SKUs and ~120 service types; unrecognized resources use tier-based fallbacks</li>
        <li><strong>Linux only</strong> &mdash; Windows VM pricing is typically 40-100% higher due to license costs</li>
      </ul>

      <h4 style="color:var(--cyan);margin-top:1em">References &amp; Recommended Reading</h4>
      <p style="font-size:0.88em">Values in this tool are the author's approximations. For accurate, current pricing consult these sources directly:</p>
      <ol style="font-size:0.85em">
        <li><a href="https://azure.microsoft.com/en-us/pricing/calculator/" style="color:var(--cyan)">Azure Pricing Calculator</a></li>
        <li><a href="https://learn.microsoft.com/en-us/azure/cost-management-billing/" style="color:var(--cyan)">Azure Cost Management + Billing</a></li>
        <li><a href="https://azure.microsoft.com/en-us/pricing/details/virtual-machines/linux/" style="color:var(--cyan)">Azure VM Pricing (Linux)</a></li>
        <li><a href="https://azure.microsoft.com/en-us/pricing/" style="color:var(--cyan)">Azure Pricing Overview (all services)</a></li>
      </ol>

      <h3 style="color:var(--cyan)">&#x1F512; Security Impact Analysis</h3>
      <p><strong>What it does:</strong> Identifies security-sensitive attribute changes and classifies them as improvements (tightening security) or concerns (loosening security).</p>
      <p><strong>How:</strong> The script scans each resource's attribute change lines looking for <strong>security indicators</strong> &mdash; attribute names that relate to security:</p>
      <ul style="font-size:0.88em;columns:2">
        <li><code>public_network_access_enabled</code></li>
        <li><code>enable_rbac</code></li>
        <li><code>identity</code></li>
        <li><code>encryption</code></li>
        <li><code>key_vault</code></li>
        <li><code>password</code> / <code>secret</code></li>
        <li><code>tls</code> / <code>ssl</code></li>
        <li><code>source_address_prefix</code></li>
      </ul>
      <p>When an indicator is found, the surrounding text is checked for <strong>positive keywords</strong> (e.g., <code>enabled</code>, <code>required</code>, <code>true</code>, <code>encrypted</code>) and <strong>negative keywords</strong> (e.g., <code>public</code>, <code>0.0.0.0/0</code>, <code>disabled</code>, <code>false</code>, <code>*</code>):</p>
      <table style="font-size:0.88em">
        <tr><th>What Was Found</th><th>Terraform Action</th><th>Classification</th><th>Example</th></tr>
        <tr><td>Indicator + Positive keyword</td><td>Create / Update</td><td style="color:var(--green)">&#x2705; Improvement</td><td><code>+ enable_https_traffic_only = true</code> &rarr; security tightened</td></tr>
        <tr><td>Indicator + Positive keyword</td><td>Destroy</td><td style="color:var(--red)">&#x26A0; Concern</td><td>Destroying a resource that had encryption enabled &rarr; losing a security control</td></tr>
        <tr><td>Indicator + Negative keyword</td><td>Create / Update</td><td style="color:var(--red)">&#x26A0; Concern</td><td><code>~ public_network_access_enabled = true</code> &rarr; exposing to public</td></tr>
        <tr><td>Indicator + Negative keyword</td><td>Destroy</td><td style="color:var(--green)">&#x2705; Improvement</td><td>Destroying a resource with <code>source_address_prefix = "0.0.0.0/0"</code> &rarr; removing risk</td></tr>
        <tr><td>Indicator only</td><td>Any</td><td style="color:var(--yellow)">&#x2248; Modification</td><td><code>~ identity { ... }</code> &rarr; security-related change but intent unclear</td></tr>
      </table>
      <p><em>&#x26A0; Known false positives:</em> Policy names like <code>Deny-Public-IP</code> contain the word <code>public</code>, which may be flagged as a concern even though the policy <em>hardens</em> security. When in doubt, check the attribute diff with <code>-ShowChanges</code>.</p>

      <h3 style="color:var(--cyan)">&#x1F30D; Carbon Impact Analysis</h3>
      <p style="background:rgba(255,165,0,0.15);border-left:3px solid orange;padding:8px 12px;border-radius:4px">&#x26A0;&#xFE0F; <strong>DISCLAIMER:</strong> These are <strong>inference-based estimates</strong>, NOT actual measured emissions. They are NOT sourced from Azure telemetry, billing, or metering APIs. Use for <strong>directional awareness only</strong> &mdash; not for carbon accounting, compliance reporting, or sustainability audits. For actual data, use <a href="https://learn.microsoft.com/en-us/azure/carbon-optimization/overview" style="color:var(--cyan)">Azure Carbon Optimization</a> or the <a href="https://www.microsoft.com/en-us/sustainability/emissions-impact-dashboard" style="color:var(--cyan)">Emissions Impact Dashboard</a>.</p>

      <p><strong>What it does:</strong> Estimates the monthly CO2 emissions change (kg CO2e/month) caused by this Terraform plan.</p>

      <h4 style="color:var(--cyan);margin-top:1em">Methodology</h4>
      <p>Formula structure inspired by <a href="https://www.cloudcarbonfootprint.org/docs/methodology/" style="color:var(--cyan)">Cloud Carbon Footprint (CCF)</a>. However, the specific per-vCPU wattage values and service power estimates are the <strong>author's own approximations</strong> based on general knowledge of server hardware TDP ranges &mdash; they are NOT taken directly from CCF's published coefficients.</p>
      <table style="font-size:0.88em">
        <tr><th>Step</th><th>Formula</th><th>Details</th></tr>
        <tr><td>1. Power</td><td><code>W = vCPUs &times; W/vCPU &times; 0.5</code></td><td>50% assumed avg utilization (author's estimate, not from benchmarks)</td></tr>
        <tr><td>2. Energy</td><td><code>kWh = W &times; PUE &times; 730h &divide; 1000</code></td><td>PUE = 1.125 (~Microsoft's reported 1.12-1.18 range)</td></tr>
        <tr><td>3. Emissions</td><td><code>kg CO2e = kWh &times; gCO2e/kWh</code></td><td>Regional grid carbon intensity (see note below)</td></tr>
      </table>

      <h4 style="color:var(--cyan);margin-top:1em">Per-vCPU Power by VM Family</h4>
      <p style="background:rgba(255,165,0,0.1);border-left:3px solid orange;padding:6px 10px;border-radius:4px;font-size:0.88em">&#x26A0;&#xFE0F; These per-vCPU wattage values are the <strong>author's approximations</strong> based on general knowledge of server hardware TDP envelopes. They are NOT sourced from published benchmark data (SPECpower) or cloud provider measurements.</p>
      <table style="font-size:0.88em">
        <tr><th>Family</th><th>W/vCPU</th><th>Notes</th></tr>
        <tr><td>B-series (burstable)</td><td>3.8</td><td>Low baseline, burst on demand</td></tr>
        <tr><td>D-series (general purpose)</td><td>7.5</td><td>Standard workloads</td></tr>
        <tr><td>E-series (memory optimized)</td><td>10</td><td>Higher due to memory subsystem</td></tr>
        <tr><td>F-series (compute optimized)</td><td>10</td><td>Higher clock &rarr; higher TDP</td></tr>
        <tr><td>L-series (storage optimized)</td><td>12</td><td>Includes local NVMe disk overhead</td></tr>
        <tr><td>M-series (memory intensive)</td><td>12</td><td>Massive DRAM arrays</td></tr>
        <tr><td>N-series (GPU)</td><td>CPU + GPU TDP</td><td>K80=150W, V100=300W, A100=400W, T4=70W per GPU (NVIDIA published TDP)</td></tr>
      </table>

      <h4 style="color:var(--cyan);margin-top:1em">Worked Example: Standard_D2s_v3 in eastus</h4>
      <table style="font-size:0.88em">
        <tr><td>Power</td><td>2 vCPUs &times; 7.5 W &times; 0.5</td><td>= 7.5 W</td></tr>
        <tr><td>Energy</td><td>7.5 W &times; 1.125 &times; 730h &divide; 1000</td><td>= 6.16 kWh/mo</td></tr>
        <tr><td>Baseline (400 gCO2e/kWh)</td><td>6.16 &times; 0.400</td><td>= <strong>2.5 kg CO2e/mo</strong> (stored)</td></tr>
        <tr><td>eastus (385 gCO2e/kWh)</td><td>2.5 &times; 385/400</td><td>= <strong>2.4 kg CO2e/mo</strong></td></tr>
        <tr><td>swedencentral (9 gCO2e/kWh)</td><td>2.5 &times; 9/400</td><td>= <strong>0.06 kg CO2e/mo</strong></td></tr>
      </table>

      <h4 style="color:var(--cyan);margin-top:1em">Regional Carbon Intensity</h4>
      <table style="font-size:0.88em">
        <tr><th>Region Category</th><th>Intensity</th><th>Example Regions</th></tr>
        <tr><td style="color:var(--green)"><strong>Low carbon (&lt;100)</strong></td><td>8&ndash;95 gCO2e/kWh</td><td>Norway (8), Sweden (9), Switzerland (11), Canada (25), France (56), Brazil (79), New Zealand (95)</td></tr>
        <tr><td style="color:var(--yellow)"><strong>Medium carbon (100&ndash;500)</strong></td><td>105&ndash;500 gCO2e/kWh</td><td>UK (233), West Europe (295), East US (385), Japan (465), UAE (475), Qatar (500)</td></tr>
        <tr><td style="color:var(--red)"><strong>High carbon (&gt;500)</strong></td><td>510&ndash;890 gCO2e/kWh</td><td>Taiwan (510), East Asia (575), India (630), Australia (640), Poland (635), South Africa (890)</td></tr>
      </table>
      <p style="background:rgba(255,165,0,0.1);border-left:3px solid orange;padding:6px 10px;border-radius:4px;font-size:0.88em">&#x26A0;&#xFE0F; These regional values are the <strong>author's approximate estimates</strong> based on general knowledge of national electricity grid mixes. They were NOT fetched from Electricity Maps or IEA data tables. The sources below are listed as <strong>recommended reading</strong> for obtaining accurate, up-to-date values. Real-time intensity fluctuates hourly and seasonally.</p>

      <h4 style="color:var(--cyan);margin-top:1em">Color Coding &amp; Labels</h4>
      <table style="font-size:0.88em">
        <tr><th>Label</th><th>Meaning</th><th>Action</th></tr>
        <tr><td><code>[+High]</code> / <code>[+Medium]</code> / <code>[+Low]</code></td><td style="color:var(--red)">Plan <strong>adds</strong> emissions</td><td>Resource being created</td></tr>
        <tr><td><code>[-High]</code> / <code>[-Medium]</code> / <code>[-Low]</code></td><td style="color:var(--green)">Plan <strong>reduces</strong> emissions</td><td>Resource being destroyed</td></tr>
        <tr><td><code>[~High]</code> etc.</td><td style="color:var(--yellow)">Net zero change</td><td>Resource being replaced (destroy+create)</td></tr>
        <tr><td><code>[&asymp;High]</code> etc.</td><td style="color:var(--yellow)">Net zero change</td><td>Resource being updated in-place</td></tr>
      </table>
      <p>Thresholds: <strong>High</strong> &gt; 30 kg/mo, <strong>Medium</strong> &gt; 10 kg/mo, <strong>Low</strong> &le; 10 kg/mo</p>

      <h4 style="color:var(--cyan);margin-top:1em">Limitations &amp; Known Gaps</h4>
      <ul style="font-size:0.9em">
        <li><strong>No real telemetry</strong> &mdash; values are static estimates, not from Azure Carbon Optimization or any metering API</li>
        <li><strong>Static utilization</strong> &mdash; assumes 50% average; real workloads vary from near-idle to 100%</li>
        <li><strong>No embodied carbon</strong> &mdash; only operational (Scope 2) emissions; hardware manufacturing (Scope 3) is excluded</li>
        <li><strong>Annual average intensity</strong> &mdash; real grid mix fluctuates hourly/seasonally; the tool uses annual means</li>
        <li><strong>No renewable energy credits</strong> &mdash; Microsoft purchases RECs/PPAs that reduce actual Scope 2 to near-zero in many regions; this tool uses grid-average intensity</li>
        <li><strong>Partial resource coverage</strong> &mdash; ~100 resource types and ~90 VM SKUs are covered; uncovered resources fall back to cost-tier estimates or produce zero</li>
        <li><strong>PaaS services</strong> &mdash; serviced resources (e.g., Cosmos DB, Event Hubs) use rough power-draw estimates since no per-resource TDP data exists</li>
      </ul>

      <h4 style="color:var(--cyan);margin-top:1em">References &amp; Recommended Reading</h4>
      <p style="font-size:0.88em">The following resources informed the general approach but were <strong>NOT directly used</strong> to produce the specific numeric values. The per-vCPU wattages, regional carbon intensities, and service power estimates are the author's approximations. Users who need accurate data should consult these sources directly.</p>
      <ol style="font-size:0.85em">
        <li><a href="https://www.cloudcarbonfootprint.org/docs/methodology/" style="color:var(--cyan)">Cloud Carbon Footprint &mdash; Methodology</a> (formula structure inspiration)</li>
        <li><a href="https://app.electricitymaps.com/" style="color:var(--cyan)">Electricity Maps</a> (recommended for accurate, live regional gCO2e/kWh)</li>
        <li><a href="https://www.iea.org/data-and-statistics" style="color:var(--cyan)">IEA &mdash; Emission Factors</a> (authoritative national grid data)</li>
        <li><a href="https://www.microsoft.com/en-us/corporate-responsibility/sustainability" style="color:var(--cyan)">Microsoft Environmental Sustainability Report</a> (PUE ~1.12-1.18 range)</li>
        <li><a href="https://www.nvidia.com/en-us/data-center/" style="color:var(--cyan)">NVIDIA GPU Specifications</a> (published TDP for K80, V100, A100, T4)</li>
        <li><a href="https://learn.microsoft.com/en-us/azure/carbon-optimization/overview" style="color:var(--cyan)">Azure Carbon Optimization (preview)</a> (use instead of this tool for actual data)</li>
        <li><a href="https://www.microsoft.com/en-us/sustainability/emissions-impact-dashboard" style="color:var(--cyan)">Microsoft Emissions Impact Dashboard</a> (actual measured emissions per subscription)</li>
      </ol>

      <h3 style="color:var(--cyan)">&#x1F4CB; Governance &amp; Compliance Analysis</h3>
      <p><strong>What it does:</strong> Scores your plan against 12 governance best practices to give a quick compliance posture overview. Each criterion that is <strong>detected</strong> in the plan adds points to the total score (max 12).</p>
      <p><strong>Important:</strong> This is <strong>presence detection</strong> &mdash; it checks whether governance patterns <em>exist</em> in the plan, not whether they are correctly configured. A &#x2713; means the pattern was found; &#x2717; means it was not found in this plan.</p>

      <table style="font-size:0.85em">
        <tr><th>Criterion</th><th>Weight</th><th>What Is Checked</th><th>Example That Would Match</th></tr>
        <tr><td><strong>Tags</strong></td><td>+1</td><td>Searches attribute change lines for <code>tags</code>, <code>cost_center</code>, <code>environment</code>, <code>owner</code>, <code>project</code></td><td><code>+ tags = { Environment = "prod", Owner = "team-infra" }</code></td></tr>
        <tr><td><strong>Naming Conventions</strong></td><td>+1</td><td>Evaluates the <strong>actual Azure resource name</strong> (the <code>name</code> attribute from the plan, not the Terraform address) against:<br>&bull; CAF prefixes: <code>rg-</code>, <code>vnet-</code>, <code>vm-</code>, <code>kv-</code>, <code>st-</code>, etc.<br>&bull; Environment: <code>-prod-</code>, <code>-dev-</code>, <code>-test-</code><br>&bull; Region: <code>-eastus-</code>, <code>-westeurope-</code><br>&bull; Numbered: <code>-01</code>, <code>-v2</code><br>&bull; Multi-segment: &ge;3 hyphenated parts<br><em>Excludes policy/RBAC resources and auto-generated names (UUIDs, timestamps)</em></td><td>Azure name <code>rg-myapp-prod-eastus</code> matches: CAF prefix (<code>rg-</code>), environment (<code>prod</code>), region (<code>eastus</code>), multi-segment (4 parts)</td></tr>
        <tr><td><strong>Policies / Monitoring</strong></td><td>+1</td><td>Detects resources whose <strong>type</strong> is a policy, diagnostic, or monitoring resource</td><td><code>azurerm_policy_assignment</code>, <code>azurerm_monitor_diagnostic_setting</code>, <code>azurerm_log_analytics_workspace</code>, or <code>azapi_resource.policy_assignments[...]</code></td></tr>
        <tr><td><strong>Backup / Retention</strong></td><td>+1</td><td>For infrastructure resources: scans attribute text for <code>backup</code>, <code>recovery_services_vault</code>, <code>retention</code>, <code>soft_delete</code>, <code>geo_redundant</code>.<br>For policy resources: only matches if the <em>policy name</em> indicates backup (e.g., key contains <code>backup</code>)</td><td><code>azurerm_backup_protected_vm.prod</code>, or a policy named <code>Deploy-VM-Backup</code></td></tr>
        <tr><td><strong>Resource Locks</strong></td><td>+1</td><td>Detects <code>azurerm_management_lock</code> resource type, or attributes like <code>delete_lock</code>, <code>read_only_lock</code></td><td><code>azurerm_management_lock.prod_lock</code></td></tr>
        <tr><td><strong>RBAC / IAM</strong></td><td>+1</td><td>Detects role assignment or role definition resource types, or attributes like <code>principal_id</code></td><td><code>azurerm_role_assignment.reader</code>, or <code>azapi_resource.role_definitions["App-Owners"]</code> (summarized as &ldquo;5 azapi_resource.role_definitions detected&rdquo;)</td></tr>
        <tr><td><strong>Network Isolation</strong></td><td>+2</td><td>Detects private endpoint, private link, or VNet integration resource types</td><td><code>azurerm_private_endpoint.storage_pe</code>, <code>azurerm_private_link_service.pls</code></td></tr>
        <tr><td><strong>Audit Logging</strong></td><td>+1</td><td>Detects log analytics workspace or diagnostic setting resource types, or <code>log_retention_days</code> in attribute text</td><td><code>azurerm_monitor_diagnostic_setting.diag</code>, or attribute <code>log_retention_days = 90</code></td></tr>
        <tr><td><strong>Compliance Frameworks</strong></td><td>+2</td><td>Detects resources that <strong>enforce organizational compliance</strong> &mdash; specifically, resources whose <strong>type</strong> is one of:<br>&bull; <code>azurerm_policy_assignment</code> or <code>azurerm_policy_definition</code> (Azure Policy)<br>&bull; <code>azapi_resource.policy_assignments[...]</code> or <code>azapi_resource.policy_definitions[...]</code> (Azure policy via AzAPI)<br>&bull; <code>azurerm_security_center_subscription</code> (Microsoft Defender for Cloud)<br><br><strong>In plain terms:</strong> If your plan includes Azure Policy assignments or policy definitions, it means your infrastructure has compliance frameworks applied.<br><br>For Azure Landing Zone (ALZ) plans, detected policy assignments are further <strong>categorized against well-known ALZ policy patterns</strong> from the <a href="https://github.com/Azure/Enterprise-Scale" style="color:var(--cyan)">Azure/Enterprise-Scale</a> reference implementation.<br><br>See the <strong>ALZ Compliance Categories</strong> section below for the full breakdown</td><td>&ldquo;ALZ Security: 12 policy assignments detected (e.g., Deny-MgmtPorts-Internet, Deny-Public-IP)&rdquo;<br><br>&ldquo;ALZ DataProtection: 5 policy assignments detected (e.g., Deploy-VM-Backup, Deploy-SQL-TDE)&rdquo;</td></tr>
        <tr><td><strong>Cost Management</strong></td><td>+1</td><td>Detects budget or cost export resources</td><td><code>azurerm_consumption_budget.monthly</code>, <code>azurerm_cost_management_export.daily</code></td></tr>
      </table>

      <h4 style="color:var(--cyan);margin-top:16px">Score Interpretation</h4>
      <table style="font-size:0.88em">
        <tr><th>Score Range</th><th>Meaning</th></tr>
        <tr><td style="color:var(--green)"><strong>10&ndash;12 / 12</strong></td><td>Excellent governance posture &mdash; most best practices detected in the plan</td></tr>
        <tr><td style="color:var(--yellow)"><strong>5&ndash;9 / 12</strong></td><td>Moderate governance &mdash; some controls present, consider adding missing ones</td></tr>
        <tr><td style="color:var(--red)"><strong>0&ndash;4 / 12</strong></td><td>Low governance &mdash; significant gaps in compliance controls detected in the plan</td></tr>
      </table>
      <p style="color:var(--muted);font-size:0.85em"><strong>Note:</strong> A low score does not necessarily mean your environment is non-compliant &mdash; it may simply mean those controls are managed outside of this specific Terraform plan (e.g., in a separate management plan, Azure Policy at subscription level, or manual configuration).</p>

      <h4 style="color:var(--cyan);margin-top:16px">&#x1F3DB;&#xFE0F; Azure Landing Zone (ALZ) Compliance Categories</h4>
      <p>When the plan contains Azure Policy assignments (common in ALZ/Enterprise-Scale deployments), the report categorizes them against <strong>well-known ALZ policy patterns</strong> from the <a href="https://github.com/Azure/Enterprise-Scale" style="color:var(--cyan)">Azure/Enterprise-Scale</a> reference implementation. This gives visibility into which compliance areas your landing zone covers:</p>
      <table style="font-size:0.85em">
        <tr><th>ALZ Category</th><th>Purpose</th><th>Example Policies Detected</th></tr>
        <tr><td style="color:var(--red)"><strong>Security</strong></td><td>Prevents insecure configurations and enforces security baselines</td><td><code>Deny-MgmtPorts-Internet</code>, <code>Deny-Public-IP</code>, <code>Deny-Public-Endpoints</code>, <code>Deploy-MDFC</code>, <code>Enforce-TLS-SSL</code>, <code>Enforce-AKS-HTTPS</code></td></tr>
        <tr><td style="color:var(--cyan)"><strong>Identity</strong></td><td>Protects identity-scoped management groups with network restrictions</td><td><code>Deny-Public-IP</code>, <code>Deny-MgmtPorts-Internet</code>, <code>Deny-Subnet-Without-Nsg</code>, <code>DenyAction-DeleteUAMIAMA</code></td></tr>
        <tr><td style="color:var(--green)"><strong>Networking</strong></td><td>Enforces network segmentation, private endpoints, and DNS</td><td><code>Deploy-Private-DNS-Zones</code>, <code>Deny-HybridNetworking</code>, <code>Audit-PeDnsZones</code>, <code>Enforce-Subnet-Private</code>, <code>Deploy-Nsg-FlowLogs</code></td></tr>
        <tr><td style="color:var(--yellow)"><strong>Logging</strong></td><td>Ensures activity logs and diagnostics are sent to central logging</td><td><code>Deploy-AzActivity-Log</code>, <code>Enable-AllLogs-to-law</code>, <code>enable-audit-to-law</code>, <code>Enab_Activity_Logs_To_LA</code>, <code>Deploy-Diag-LogsCat</code></td></tr>
        <tr><td><strong>Monitoring</strong></td><td>Deploys VM monitoring, change tracking, and update management</td><td><code>Deploy-VM-Monitoring</code>, <code>Deploy-VMSS-Monitoring</code>, <code>Deploy-VM-ChangeTrack</code>, <code>Deploy-vmArc-ChangeTrack</code>, <code>Enable-AUM-CheckUpdates</code></td></tr>
        <tr><td style="color:var(--magenta)"><strong>DataProtection</strong></td><td>Enables backups, SQL auditing, threat detection, and encryption</td><td><code>Deploy-VM-Backup</code>, <code>Enforce-Backup</code>, <code>Enforce-ASR</code>, <code>Deploy-SQL-TDE</code>, <code>Deploy-SQL-Threat</code>, <code>Deploy-MDFC-SqlAtp</code></td></tr>
        <tr><td><strong>Compliance</strong></td><td>Enforces organizational standards (allowed locations, resource types, zone resilience)</td><td><code>allowed_locations</code>, <code>Deny-Classic-Resources</code>, <code>Deny-UnmanagedDisk</code>, <code>Audit-ZoneResiliency</code>, <code>Enforce-ALZ-Decomm</code></td></tr>
        <tr><td><strong>KeyManagement</strong></td><td>Enforces geo-redundancy and protection for Key Vault</td><td><code>Enforce-GR-KeyVault</code></td></tr>
        <tr><td><strong>Storage</strong></td><td>Enforces secure transfer (HTTPS) for storage accounts</td><td><code>Deny-Storage-http</code></td></tr>
      </table>
      <p><strong>How it works:</strong> The policy assignment's short name (the part after the <code>/</code> in the map key, e.g., <code>Costaltd-corp/Deny-Public-IP</code> &rarr; <code>Deny-Public-IP</code>) is matched against the known ALZ policy patterns. Matches are grouped by category with counts and example policy names shown in the Compliance Frameworks section of the report.</p>
      <p style="color:var(--muted);font-size:0.85em"><strong>Note:</strong> Only policy assignments with names matching the well-known ALZ patterns are categorized. Custom policies unique to your organization will still appear in the generic compliance count but won't be categorized into an ALZ area.</p>

      <h3 style="color:var(--cyan)">&#x2705; Risk Level</h3>
      <p><strong>What it does:</strong> Assigns an overall risk rating to the plan based on multiple factors combined:</p>
      <table style="font-size:0.88em">
        <tr><th>Factor</th><th style="color:var(--green)">Low Risk</th><th style="color:var(--yellow)">Medium Risk</th><th style="color:var(--red)">High Risk</th></tr>
        <tr><td>Resources being destroyed</td><td>&le;5</td><td>6&ndash;10</td><td>&gt;10</td></tr>
        <tr><td>Monthly cost increase</td><td>&le;&#36;200/mo</td><td>&#36;201&ndash;&#36;500/mo</td><td>&gt;&#36;500/mo</td></tr>
        <tr><td>Security concerns found</td><td>None</td><td>&mdash;</td><td>&ge;1 concern</td></tr>
        <tr><td>Governance score</td><td>&ge;5/12</td><td>&lt;5/12</td><td>&mdash;</td></tr>
      </table>
      <p>The <strong>highest severity</strong> from any factor determines the final risk level. For example, if destroys are low and costs are low, but 1 security concern is found, the risk level becomes <strong>High</strong>.</p>

      <h3 style="color:var(--cyan)">&#x1F50D; Attribute Changes (Diff Viewer)</h3>
      <p><strong>What it shows:</strong> The raw Terraform plan attribute changes for each resource, exactly as Terraform outputs them, with color coding:</p>
      <ul>
        <li><span style="color:#3fb950;font-family:monospace">+ green</span> &mdash; New or added attribute (something is being set for the first time)</li>
        <li><span style="color:#f85149;font-family:monospace">- red</span> &mdash; Removed attribute (a value is being deleted or set to null)</li>
        <li><span style="color:#d29922;font-family:monospace">~ yellow</span> &mdash; Modified attribute (an existing value is changing)</li>
        <li><span style="color:var(--muted);font-family:monospace">&nbsp; gray</span> &mdash; Unchanged context lines (shown for surrounding context)</li>
      </ul>
      <p>Attribute changes are only captured when the report is generated with <code>-ShowChanges</code>, <code>-ShowInsights</code>, or <code>-OutputHtml</code>. If this section is empty, re-run with one of those flags.</p>

    </div>
  </details>

  <footer>Terraform Plan Reporter v1.7.0 &mdash; Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</footer>
</div>
</body>
</html>
"@

        # Write and open
        $htmlOutputPath = if ($OutputHtmlPath) { $OutputHtmlPath } else { "TerraformPlanReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html" }
        $htmlOutputPath = Join-Path $PWD $htmlOutputPath
        [System.IO.File]::WriteAllText($htmlOutputPath, $htmlContent, [System.Text.UTF8Encoding]::new($false))
        Write-Host "`n  HTML report generated: $htmlOutputPath" -ForegroundColor Green
        Start-Process $htmlOutputPath
    }

    if ($PassThru) {
        $resourcesForSummary = if ($Category -or $ResourceName -or $ResourceType) { $filteredResults } else { $results }

        $summary = [PSCustomObject]@{
            Total   = $resourcesForSummary.Count
            Import  = ($resourcesForSummary | Where-Object { $_.Action -eq 'Import' }).Count
            Create  = ($resourcesForSummary | Where-Object { $_.Action -eq 'Create' }).Count
            Update  = ($resourcesForSummary | Where-Object { $_.Action -eq 'Update' }).Count
            Destroy = ($resourcesForSummary | Where-Object { $_.Action -eq 'Destroy' }).Count
            Replace = ($resourcesForSummary | Where-Object { $_.Action -eq 'Replace' }).Count
        }

        [PSCustomObject]@{
            LogFile  = $LogFile
            Filters  = [PSCustomObject]@{
                Category     = $Category
                ResourceName = $ResourceName
                ResourceType = $ResourceType
            }
            Summary  = $summary
            Insights = if ($ShowInsights) { $insights } else { $null }
        }
    }
}

