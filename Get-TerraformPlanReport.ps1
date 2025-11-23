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

.EXAMPLE
    .\Get-TerraformPlanReport.ps1 -LogFile .\tfplan.out -TableAll
    Displays all resources in a table with ResourceName, ResourceType, and Action columns.

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
    [switch]$TableAll,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowInsights,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('Compute', 'Storage', 'Network', 'Database', 'Security', 'Monitoring', 'All')]
    [string]$Category,
    
    [Parameter(Mandatory=$false)]
    [string]$ResourceName,
    
    [Parameter(Mandatory=$false)]
    [string]$ResourceType
)

# Knowledge base for intelligent insights
$knowledgeBase = @{
    # Cost-impacting resources (High/Medium/Low) with approximate monthly costs in USD
    CostResources = @{
        High = @(
            'azurerm_virtual_machine', 'azurerm_windows_virtual_machine', 'azurerm_linux_virtual_machine',
            'azurerm_kubernetes_cluster', 'azurerm_app_service', 'azurerm_function_app',
            'azurerm_virtual_machine_scale_set', 'azurerm_container_registry',
            'azurerm_linux_web_app', 'azurerm_windows_web_app',
            'azurerm_container_app', 'azurerm_container_app_environment',
            'azurerm_api_management', 'azurerm_machine_learning_workspace',
            'azurerm_recovery_services_vault', 'azurerm_virtual_wan', 'azurerm_virtual_hub',
            'azurerm_sql_database', 'azurerm_mssql_database', 'azurerm_cosmosdb_account',
            'azurerm_postgresql_server', 'azurerm_postgresql_flexible_server',
            'azurerm_mysql_server', 'azurerm_mysql_flexible_server',
            'azurerm_mariadb_server', 'azurerm_sql_managed_instance',
            'azurerm_synapse_workspace', 'azurerm_databricks_workspace',
            'azurerm_application_gateway', 'azurerm_firewall', 'azurerm_vpn_gateway', 'azurerm_front_door',
            'aws_instance', 'aws_rds_instance', 'aws_eks_cluster', 'aws_ecs_cluster',
            'google_compute_instance', 'google_container_cluster', 'google_sql_database_instance'
        )
        Medium = @(
            'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_lb', 'azurerm_nat_gateway',
            'azurerm_redis_cache', 'azurerm_app_service_plan', 'azurerm_cdn_profile',
            'azurerm_virtual_network_gateway', 'azurerm_express_route_circuit', 'azurerm_frontdoor_firewall_policy',
            'azurerm_firewall_policy', 'azurerm_web_application_firewall_policy',
            'azurerm_local_network_gateway', 'azurerm_point_to_site_vpn_gateway',
            'azurerm_service_bus_namespace', 'azurerm_eventhub_namespace', 'azurerm_eventgrid_topic',
            'azurerm_container_group', 'azurerm_batch_account', 'azurerm_logic_app_workflow',
            'azurerm_cognitive_account', 'azurerm_data_lake_store',
            'aws_s3_bucket', 'aws_ebs_volume', 'aws_elasticache_cluster', 'aws_elb',
            'google_storage_bucket', 'google_compute_disk'
        )
        Low = @(
            'azurerm_resource_group', 'azurerm_virtual_network', 'azurerm_subnet',
            'azurerm_network_security_group', 'azurerm_key_vault', 'azurerm_log_analytics_workspace',
            'azurerm_key_vault_secret', 'azurerm_key_vault_key', 'azurerm_key_vault_certificate',
            'azurerm_backup_policy_vm', 'azurerm_backup_protected_vm', 'azurerm_site_recovery_fabric',
            'azurerm_site_recovery_replication_policy', 'azurerm_site_recovery_protection_container',
            'azurerm_application_insights', 'azurerm_monitor_autoscale_setting',
            'azurerm_monitor_scheduled_query_rules_alert',
            'azurerm_traffic_manager_profile', 'azurerm_traffic_manager_endpoint',
            'azurerm_dns_zone', 'azurerm_private_dns_zone',
            'azurerm_network_interface', 'azurerm_route_table', 'azurerm_network_watcher',
            'azurerm_storage_blob', 'azurerm_storage_container', 'azurerm_storage_queue', 'azurerm_storage_table',
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
            'azurerm_traffic_manager_profile' = 1    # ~$0.54/million queries + $0.36/health check
            'azurerm_front_door' = 35                # Gateway + data processing
            'azurerm_frontdoor_firewall_policy' = 20 # WAF policy
            'azurerm_dns_zone' = 1                   # Per zone per month
            'azurerm_private_dns_zone' = 1           # Per zone per month
            'azurerm_sql_database' = 15              # Basic tier minimum
            'azurerm_mssql_database' = 15            # Basic tier minimum
            'azurerm_postgresql_server' = 20         # Basic tier
            'azurerm_postgresql_flexible_server' = 20 # Burstable tier
            'azurerm_mysql_server' = 20              # Basic tier
            'azurerm_mysql_flexible_server' = 20     # Burstable tier
            'azurerm_mariadb_server' = 20            # Basic tier
            'azurerm_sql_managed_instance' = 400     # GP Gen5 2 vCores
            'azurerm_service_bus_namespace' = 10     # Basic tier
            'azurerm_eventhub_namespace' = 22        # Basic tier
            'azurerm_eventgrid_topic' = 1            # Per million operations
            'azurerm_api_management' = 50            # Developer tier
            'azurerm_cognitive_account' = 10         # S0 tier varies by service
            'azurerm_machine_learning_workspace' = 0 # Compute charged separately
            'azurerm_container_group' = 30           # 1 vCPU, 1.5GB RAM
            'azurerm_container_registry' = 5         # Basic tier
            'azurerm_batch_account' = 0              # Compute charged separately
            'azurerm_virtual_machine_scale_set' = 140 # Depends on VM size
            'azurerm_logic_app_workflow' = 0         # Per execution pricing
            'azurerm_linux_web_app' = 13             # Basic B1
            'azurerm_windows_web_app' = 13           # Basic B1
            'azurerm_container_app' = 20             # Consumption tier with requests
            'azurerm_container_app_environment' = 0  # Infrastructure cost minimal
            'azurerm_recovery_services_vault' = 10   # Vault itself, backup storage extra
            'azurerm_backup_policy_vm' = 0           # Policy definition, no cost
            'azurerm_backup_protected_vm' = 20       # ~$5/50GB backup
            'azurerm_application_insights' = 2       # Basic tier, 5GB free
            'azurerm_monitor_autoscale_setting' = 0  # No additional cost
            'azurerm_monitor_scheduled_query_rules_alert' = 0 # Included in Log Analytics
            'azurerm_firewall_policy' = 0            # Policy definition, firewall charged
            'azurerm_web_application_firewall_policy' = 0 # Policy definition
            'azurerm_local_network_gateway' = 0      # Gateway definition
            'azurerm_point_to_site_vpn_gateway' = 140 # P2S VPN gateway
            'azurerm_virtual_wan' = 0.25             # Per hub hour
            'azurerm_virtual_hub' = 0.25             # Per hub hour
            'azurerm_data_lake_store' = 30           # Per TB
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
    
    # Carbon emission estimation (kg CO2e per month)
    CarbonFootprint = @{
        # Regional carbon intensity (gCO2e/kWh) - 2024 data
        RegionalIntensity = @{
            # Azure regions
            'eastus' = 385; 'eastus2' = 385; 'westus' = 294; 'westus2' = 294; 'westus3' = 294
            'centralus' = 460; 'northcentralus' = 460; 'southcentralus' = 460
            'northeurope' = 275; 'westeurope' = 295; 'uksouth' = 233; 'ukwest' = 233
            'francecentral' = 56; 'francesouth' = 56; 'germanywestcentral' = 338
            'swedencentral' = 9; 'norwayeast' = 8; 'norwaywest' = 8
            'switzerlandnorth' = 11; 'switzerlandwest' = 11
            'eastasia' = 575; 'southeastasia' = 475; 'japaneast' = 465; 'japanwest' = 465
            'australiaeast' = 640; 'australiasoutheast' = 640; 'australiacentral' = 640
            'brazilsouth' = 79; 'canadacentral' = 25; 'canadaeast' = 25
            'southafricanorth' = 890; 'uaenorth' = 475
            # AWS regions
            'us-east-1' = 415; 'us-east-2' = 460; 'us-west-1' = 294; 'us-west-2' = 294
            'eu-west-1' = 295; 'eu-west-2' = 233; 'eu-west-3' = 56; 'eu-central-1' = 338
            'eu-north-1' = 9; 'ap-south-1' = 700; 'ap-southeast-1' = 475; 'ap-southeast-2' = 640
            'ap-northeast-1' = 465; 'ap-northeast-2' = 430; 'ap-northeast-3' = 465
            'ca-central-1' = 25; 'sa-east-1' = 79
            # GCP regions
            'us-central1' = 460; 'us-east1' = 385; 'us-west1' = 294; 'us-west2' = 294
            'europe-west1' = 118; 'europe-west2' = 233; 'europe-west3' = 338; 'europe-west4' = 432
            'europe-north1' = 9; 'asia-east1' = 475; 'asia-southeast1' = 475; 'asia-northeast1' = 465
            'australia-southeast1' = 640; 'southamerica-east1' = 79
        }
        # VM carbon footprint (kg CO2e/month) - based on vCPU hours and average PUE 1.2
        VMSizes = @{
            'Standard_B1s' = 2.5; 'Standard_B2s' = 5.0; 'Standard_B4ms' = 10.0
            'Standard_D2s_v3' = 8.5; 'Standard_D4s_v3' = 17.0; 'Standard_D8s_v3' = 34.0
            'Standard_D16s_v3' = 68.0; 'Standard_D32s_v3' = 136.0
            'Standard_E2s_v3' = 8.5; 'Standard_E4s_v3' = 17.0; 'Standard_E8s_v3' = 34.0
            'Standard_F2s_v2' = 8.5; 'Standard_F4s_v2' = 17.0; 'Standard_F8s_v2' = 34.0
            't2.micro' = 2.5; 't2.small' = 2.5; 't2.medium' = 5.0; 't2.large' = 8.5
            't3.micro' = 2.5; 't3.small' = 2.5; 't3.medium' = 5.0; 't3.large' = 8.5
            'm5.large' = 8.5; 'm5.xlarge' = 17.0; 'm5.2xlarge' = 34.0
            'e2-micro' = 2.0; 'e2-small' = 2.5; 'e2-medium' = 5.0; 'e2-standard-2' = 8.5
        }
        # Service carbon footprint (kg CO2e/month)
        Services = @{
            'azurerm_kubernetes_cluster' = 25
            'azurerm_application_gateway' = 15
            'azurerm_firewall' = 35
            'azurerm_vpn_gateway' = 8
            'azurerm_bastion_host' = 6
            'azurerm_storage_account' = 3
            'azurerm_traffic_manager_profile' = 0.2  # DNS-based routing service
            'azurerm_traffic_manager_endpoint' = 0.1 # Endpoint health checks
            'azurerm_front_door' = 12                # Global edge network
            'azurerm_frontdoor_firewall_policy' = 0.5  # Policy processing
            'azurerm_dns_zone' = 0.1                 # DNS queries minimal
            'azurerm_private_dns_zone' = 0.05        # Internal DNS minimal
            'azurerm_sql_database' = 12
            'azurerm_mssql_database' = 12
            'azurerm_postgresql_server' = 10         # Database server
            'azurerm_postgresql_flexible_server' = 10
            'azurerm_mysql_server' = 10
            'azurerm_mysql_flexible_server' = 10
            'azurerm_mariadb_server' = 10
            'azurerm_sql_managed_instance' = 45      # High compute DB
            'azurerm_service_bus_namespace' = 2      # Messaging service
            'azurerm_eventhub_namespace' = 4         # Streaming service
            'azurerm_eventgrid_topic' = 0.5          # Event routing
            'azurerm_api_management' = 8             # API gateway
            'azurerm_cognitive_account' = 6          # AI service
            'azurerm_machine_learning_workspace' = 0 # Compute charged separately
            'azurerm_container_group' = 8            # Container instances
            'azurerm_container_registry' = 2         # Registry service
            'azurerm_batch_account' = 0              # Compute charged separately
            'azurerm_virtual_machine_scale_set' = 34 # Varies by VM size
            'azurerm_logic_app_workflow' = 1         # Workflow service
            'azurerm_linux_web_app' = 5              # Web hosting
            'azurerm_windows_web_app' = 5            # Web hosting
            'azurerm_container_app' = 6              # Container hosting
            'azurerm_container_app_environment' = 0.5 # Shared infrastructure
            'azurerm_recovery_services_vault' = 1    # Vault service
            'azurerm_backup_protected_vm' = 2        # Backup overhead
            'azurerm_application_insights' = 0.5     # Monitoring service
            'azurerm_firewall_policy' = 0.1          # Policy processing
            'azurerm_web_application_firewall_policy' = 0.2 # WAF processing
            'azurerm_point_to_site_vpn_gateway' = 6  # VPN gateway
            'azurerm_virtual_wan' = 4                # WAN service
            'azurerm_virtual_hub' = 4                # Hub routing
            'azurerm_data_lake_store' = 5            # Storage service
            'azurerm_cosmosdb_account' = 18
            'aws_eks_cluster' = 25
            'aws_rds_instance' = 12
            'aws_s3_bucket' = 3
            'google_container_cluster' = 25
            'google_sql_database_instance' = 12
            'google_storage_bucket' = 3
        }
        # Low carbon regions (best for sustainability)
        LowCarbonRegions = @{
            'Azure' = @('norwayeast', 'norwaywest', 'swedencentral', 'francecentral', 'francesouth', 'switzerlandnorth', 'canadacentral', 'canadaeast', 'brazilsouth')
            'AWS' = @('eu-north-1', 'eu-west-3', 'ca-central-1', 'sa-east-1')
            'GCP' = @('europe-north1', 'europe-west1', 'southamerica-east1')
        }
    }
    
    # Governance and compliance indicators
    GovernanceIndicators = @{
        Tags = @('tags', 'tag =', 'cost_center', 'environment', 'owner', 'project', 'compliance')
        # Naming convention patterns to detect proper naming standards
        NamingPatterns = @{
            # Azure resource prefixes (Microsoft CAF recommended)
            AzurePrefixes = @('rg-', 'vnet-', 'snet-', 'nsg-', 'vm-', 'nic-', 'pip-', 'st-', 'kv-', 'law-', 'agw-', 'fw-', 'vpn-', 'bas-', 'aks-', 'sql-', 'db-', 'app-', 'func-', 'pe-', 'pls-', 'pdns-')
            # AWS resource prefixes
            AwsPrefixes = @('vpc-', 'subnet-', 'sg-', 'ec2-', 'rds-', 's3-', 'lambda-', 'eks-', 'ecs-', 'alb-', 'nlb-', 'asg-')
            # GCP resource prefixes
            GcpPrefixes = @('vpc-', 'subnet-', 'vm-', 'gke-', 'sql-', 'bucket-', 'function-', 'lb-')
            # Environment indicators
            Environments = @('-prod-', '-dev-', '-test-', '-uat-', '-staging-', '-qa-', '-demo-', '-sandbox-', '-prod$', '-dev$', '-test$', '-uat$', '-staging$', '-qa$', '-demo$', '-sandbox$', '^prod-', '^dev-', '^test-', '^uat-', '^staging-', '^qa-', '^demo-', '^sandbox-')
            # Region indicators
            Regions = @('-eastus-', '-westus-', '-centralus-', '-northeurope-', '-westeurope-', '-southeastasia-', '-us-east-1-', '-us-west-2-', '-eu-west-1-', '-ap-southeast-1-')
            # Numbered instances
            NumberedInstances = @('-\d{2,3}$', '-\d{2,3}-', '-v\d+$')
        }
        Policies = @('azurerm_policy_assignment', 'azurerm_policy_definition', 'azurerm_monitor_diagnostic_setting', 'azurerm_log_analytics_workspace', 'azurerm_monitor_action_group', 'azurerm_monitor_metric_alert', 'aws_config_rule', 'aws_cloudwatch_log_group', 'google_logging_project_sink')
        Backup = @('backup', 'retention', 'geo_redundant', 'replication')
        Locks = @('azurerm_management_lock', 'aws_resourcegroups_resource', 'can_not_delete', 'read_only_lock', 'delete_lock')
        RBAC = @('role_assignment', 'role_definition', 'iam_policy', 'iam_role', 'principal_id', 'scope_id')
        NetworkIsolation = @('azurerm_private_endpoint', 'aws_vpc_endpoint', 'google_compute_global_forwarding_rule', 'azurerm_private_link_service', 'azurerm_app_service_virtual_network_swift_connection', 'aws_vpc_endpoint_service')
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
        
        $tfResourceName = $matches[1]
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
            Resource = $tfResourceName
            Action   = $actionType
        }
        $changes = @()
        $captureChanges = $true
    }
    # Capture all content within the resource block (for ShowChanges or ShowInsights)
    elseif (($ShowChanges -or $ShowInsights) -and $captureChanges) {
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
    # If TableAll is specified, display table and exit
    if ($TableAll) {
        # Apply filters first
        $filteredResults = $results
        
        # Filter by Category
        if ($Category -and $Category -ne 'All') {
            $categoryPatterns = $knowledgeBase.Categories[$Category]
            $filteredResults = $filteredResults | Where-Object {
                $resourceType = ($_.Resource -split '\.', 2)[0]
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
                $resType = ($_.Resource -split '\.', 2)[0]
                $resType -like $ResourceType
            }
        }
        
        # Filter by Action (based on List switches)
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
            return
        }
        
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
            $parts = $_.Resource -split '\.',2
            [PSCustomObject]@{
                Action = $_.Action
                ResourceType = $parts[0]
                ResourceName = if ($parts.Count -gt 1) { $parts[1] } else { $_.Resource }
            }
        }
        
        # Display header
        Write-Host ("{0,-10} {1,-50} {2}" -f "Action", "ResourceType", "ResourceName") -ForegroundColor Cyan
        Write-Host ("{0,-10} {1,-50} {2}" -f "------", "------------", "------------") -ForegroundColor Cyan
        
        # Display as table with color-coded actions
        $tableData | ForEach-Object {
            $actionColor = switch ($_.Action) {
                "Create" { "Green" }
                "Update" { "Yellow" }
                "Destroy" { "Red" }
                "Replace" { "Magenta" }
                default { "White" }
            }
            
            Write-Host ("{0,-10} {1,-50} {2}" -f $_.Action, $_.ResourceType, $_.ResourceName) -ForegroundColor $actionColor
        }
        
        # Display summary
        Write-Host "\n================================================================================\n" -ForegroundColor Cyan
        $createCount = ($filteredResults | Where-Object { $_.Action -eq "Create" }).Count
        $updateCount = ($filteredResults | Where-Object { $_.Action -eq "Update" }).Count
        $destroyCount = ($filteredResults | Where-Object { $_.Action -eq "Destroy" }).Count
        $replaceCount = ($filteredResults | Where-Object { $_.Action -eq "Replace" }).Count
        
        Write-Host "Total: $($filteredResults.Count) resources" -ForegroundColor White
        if ($createCount -gt 0) { Write-Host "  $createCount to create" -ForegroundColor Green }
        if ($updateCount -gt 0) { Write-Host "  $updateCount to update" -ForegroundColor Yellow }
        if ($destroyCount -gt 0) { Write-Host "  $destroyCount to destroy" -ForegroundColor Red }
        if ($replaceCount -gt 0) { Write-Host "  $replaceCount to replace" -ForegroundColor Magenta }
        Write-Host ""
        
        return
    }
    
    # Apply filters
    $filteredResults = $results
    
    # Filter by Category
    if ($Category -and $Category -ne 'All') {
        $categoryPatterns = $knowledgeBase.Categories[$Category]
        $filteredResults = $filteredResults | Where-Object {
            $resourceType = ($_.Resource -split '\.')[0]
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
            $resType = ($_.Resource -split '\.')[0]
            $resType -like $ResourceType
        }
    }
    
    if ($filteredResults.Count -eq 0) {
        Write-Host "No resources match the specified filters" -ForegroundColor Yellow
        if ($Category) { Write-Host "  Category: $Category" -ForegroundColor Gray }
        if ($ResourceName) { Write-Host "  ResourceName: $ResourceName" -ForegroundColor Gray }
        if ($ResourceType) { Write-Host "  ResourceType: $ResourceType" -ForegroundColor Gray }
        return
    }
    
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
        $actionsToShow = @("Create", "Update", "Destroy", "Replace")
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
        foreach ($item in $resourcesToAnalyze) {
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
                    $carbonEmissions = 15 * ($carbonIntensity / 400.0)
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
                $carbonEmissions = 20 * ($carbonIntensity / 400.0)
                $carbonDetail = "≈ $([Math]::Round($carbonEmissions, 1)) kg CO2e/mo ($detectedRegion)"
                $carbonCategory = "High"
            }
            elseif ($knowledgeBase.CostResources.Medium -contains $resourceType) {
                $carbonEmissions = 5 * ($carbonIntensity / 400.0)
                $carbonDetail = "≈ $([Math]::Round($carbonEmissions, 1)) kg CO2e/mo ($detectedRegion)"
                $carbonCategory = "Medium"
            }
            elseif ($knowledgeBase.CostResources.Low -contains $resourceType) {
                $carbonEmissions = 1 * ($carbonIntensity / 400.0)
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
            
            # Check naming conventions by analyzing the resource name itself
            $namingMatch = $false
            $resourceNamePart = if ($item.Resource -match '\.(.+)$') { $matches[1] } else { $item.Resource }
            $namingReasons = @()
            
            # Check for Azure prefixes
            foreach ($prefix in $knowledgeBase.GovernanceIndicators.NamingPatterns.AzurePrefixes) {
                if ($resourceNamePart -match "^$([regex]::Escape($prefix))") {
                    $namingReasons += "Azure CAF prefix ($prefix)"
                    $namingMatch = $true
                }
            }
            
            # Check for AWS prefixes
            foreach ($prefix in $knowledgeBase.GovernanceIndicators.NamingPatterns.AwsPrefixes) {
                if ($resourceNamePart -match "^$([regex]::Escape($prefix))") {
                    $namingReasons += "AWS prefix ($prefix)"
                    $namingMatch = $true
                }
            }
            
            # Check for GCP prefixes
            foreach ($prefix in $knowledgeBase.GovernanceIndicators.NamingPatterns.GcpPrefixes) {
                if ($resourceNamePart -match "^$([regex]::Escape($prefix))") {
                    $namingReasons += "GCP prefix ($prefix)"
                    $namingMatch = $true
                }
            }
            
            # Check for environment indicators
            foreach ($env in $knowledgeBase.GovernanceIndicators.NamingPatterns.Environments) {
                if ($resourceNamePart -match $env) {
                    $envName = $env -replace '[\^\$\-]', ''
                    if (-not ($namingReasons -like "*environment*")) {
                        $namingReasons += "environment indicator ($envName)"
                        $namingMatch = $true
                    }
                }
            }
            
            # Check for region indicators
            foreach ($region in $knowledgeBase.GovernanceIndicators.NamingPatterns.Regions) {
                if ($resourceNamePart -match $region) {
                    $regionName = $region -replace '[\-]', ''
                    if (-not ($namingReasons -like "*region*")) {
                        $namingReasons += "region indicator ($regionName)"
                        $namingMatch = $true
                    }
                }
            }
            
            # Check for numbered instances
            foreach ($pattern in $knowledgeBase.GovernanceIndicators.NamingPatterns.NumberedInstances) {
                if ($resourceNamePart -match $pattern) {
                    if (-not ($namingReasons -like "*numbered*")) {
                        $namingReasons += "numbered instance"
                        $namingMatch = $true
                    }
                }
            }
            
            # Check for multi-segment naming (e.g., prefix-purpose-env-region-number)
            $segments = $resourceNamePart -split '-'
            if ($segments.Count -ge 4 -and -not $namingMatch) {
                $namingReasons += "multi-segment structure ($($segments.Count) parts)"
                $namingMatch = $true
            }
            
            if ($namingMatch) {
                $reasonText = $namingReasons -join ', '
                $insights.Governance.Naming += "$($item.Resource) - Follows naming convention: $reasonText"
            }
            
            $policyMatch = $false
            foreach ($policy in $knowledgeBase.GovernanceIndicators.Policies) {
                # Only match resource type/name, not content
                if ($item.Resource -match $policy) {
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
                # Only match resource type/name, not content
                if ($item.Resource -match $network) {
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
        Write-Host "   Monthly Carbon Footprint: " -NoNewline
        $carbonColor = if ($insights.Carbon.EstimatedImpact -match "High Impact") { "Red" }
                      elseif ($insights.Carbon.EstimatedImpact -match "Moderate Impact") { "Yellow" }
                      elseif ($insights.Carbon.EstimatedImpact -match "Reduction") { "Green" }
                      else { "Gray" }
        Write-Host $insights.Carbon.EstimatedImpact -ForegroundColor $carbonColor
        Write-Host "   ⚠️  Estimates based on regional carbon intensity and resource utilization" -ForegroundColor DarkGray
        Write-Host ""
        
        if ($insights.Carbon.High.Count -gt 0) {
            Write-Host "   High Carbon Resources ($($insights.Carbon.High.Count)):" -ForegroundColor Red
            $insights.Carbon.High | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkRed }
            Write-Host ""
        }
        if ($insights.Carbon.Medium.Count -gt 0) {
            Write-Host "   Medium Carbon Resources ($($insights.Carbon.Medium.Count)):" -ForegroundColor Yellow
            $insights.Carbon.Medium | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkYellow }
            Write-Host ""
        }
        if ($insights.Carbon.Low.Count -gt 0) {
            Write-Host "   Low Carbon Resources ($($insights.Carbon.Low.Count)):" -ForegroundColor Green
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
        $totalCreate = ($resourcesToAnalyze | Where-Object { $_.Action -eq "Create" }).Count
        $totalUpdate = ($resourcesToAnalyze | Where-Object { $_.Action -eq "Update" }).Count
        $totalDestroy = ($resourcesToAnalyze | Where-Object { $_.Action -eq "Destroy" }).Count
        $totalReplace = ($resourcesToAnalyze | Where-Object { $_.Action -eq "Replace" }).Count
        $totalResources = $totalCreate + $totalUpdate + $totalDestroy + $totalReplace
        
        Write-Host "   Total Resources Affected: " -NoNewline -ForegroundColor Gray
        Write-Host $totalResources -ForegroundColor White
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
        Write-Host "   Monthly Cost Change: " -NoNewline -ForegroundColor Gray
        if ($insights.Cost.MonthlyEstimate -gt 0) {
            Write-Host "+`$$([Math]::Round([Math]::Abs($insights.Cost.MonthlyEstimate), 2))" -NoNewline -ForegroundColor Red
        } elseif ($insights.Cost.MonthlyEstimate -lt 0) {
            Write-Host "`$$([Math]::Round($insights.Cost.MonthlyEstimate, 2))" -NoNewline -ForegroundColor Green
        } else {
            Write-Host "`$0.00" -NoNewline -ForegroundColor Gray
        }
        Write-Host "/month" -ForegroundColor Gray
        
        $totalCostResources = $insights.Cost.High.Count + $insights.Cost.Medium.Count + $insights.Cost.Low.Count
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
        Write-Host "   Monthly Emissions Change: " -NoNewline -ForegroundColor Gray
        if ($insights.Carbon.MonthlyEmissions -gt 0) {
            Write-Host "+$([Math]::Round([Math]::Abs($insights.Carbon.MonthlyEmissions), 1))" -NoNewline -ForegroundColor Red
        } elseif ($insights.Carbon.MonthlyEmissions -lt 0) {
            Write-Host "$([Math]::Round($insights.Carbon.MonthlyEmissions, 1))" -NoNewline -ForegroundColor Green
        } else {
            Write-Host "0.0" -NoNewline -ForegroundColor Gray
        }
        Write-Host " kg CO2e/month" -ForegroundColor Gray
        
        $totalCarbonResources = $insights.Carbon.High.Count + $insights.Carbon.Medium.Count + $insights.Carbon.Low.Count
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
        if ($insights.Governance.Backup.Count -gt 0) { $govCategoriesFound++ }
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
    }
}

