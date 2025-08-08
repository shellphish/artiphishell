terraform {
  required_version = ">=1.0"

  required_providers {
    azapi = {
      source  = "azure/azapi"
      version = "2.0.1"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.7.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.6.3"
    }
    time = {
      source  = "hashicorp/time"
      version = "0.12.1"
    }
  }
}


provider "azurerm" {
  features {}
  #Can setup your service principal here, currently commented out to use az cli apply terraform
  #subscription_id   = "<azure_subscription_id>"
  #tenant_id         = "<azure_subscription_tenant_id>"
  #client_id         = "<service_principal_appid>"
  #client_secret     = "<service_principal_password>"
}

#resource for random prefixes, helps with unique names and identifiers
resource "random_pet" "ssh_key_name" {
  prefix    = "ssh"
  separator = ""
}
#azapi_resource_action resource is used to perform specific actions on an Azure resource, such as starting or stopping a virtual machine. Here we're generating ssh keys
resource "azapi_resource_action" "ssh_public_key_gen" {
  type        = "Microsoft.Compute/sshPublicKeys@2022-11-01"
  resource_id = azapi_resource.ssh_public_key.id
  action      = "generateKeyPair"
  method      = "POST"

  response_export_values = ["publicKey", "privateKey"]
}

resource "azapi_resource" "ssh_public_key" {
  type      = "Microsoft.Compute/sshPublicKeys@2022-11-01"
  name      = random_pet.ssh_key_name.id
  location  = azurerm_resource_group.rg.location
  parent_id = azurerm_resource_group.rg.id
}

output "key_data" {
  value = azapi_resource_action.ssh_public_key_gen.output.publicKey
}


# Generate random resource group name
resource "random_pet" "rg_name" {
  prefix = "${var.resource_group_name_prefix}-${terraform.workspace}"
}

resource "azurerm_resource_group" "rg" {
  #ts:skip=AC_AZURE_0389 Locks not required
  location = var.resource_group_location
  name     = random_pet.rg_name.id
}

# Optional: Adds resource lock to prevent deletion of the RG. Requires additional configuration
#resource "azurerm_management_lock" "resource-group-level" {
#  name       = "resource-group-cannotdelete-lock"
#  scope      = azurerm_resource_group.rg.id
#  lock_level = "CanNotDelete"
#  notes      = "This Resource Group is set to CanNotDelete to prevent accidental deletion."
#}


resource "random_pet" "azurerm_kubernetes_cluster_name" {
  prefix = "cluster-"
}

resource "random_pet" "azurerm_kubernetes_cluster_dns_prefix" {
  prefix = "dns-"
}

# Create a variable for the DNS name based on the pet name
locals {
  #dns_name = "${random_pet.rg_name.id}.crs.artiphishell.com"
  dns_name = "${random_pet.rg_name.id}-frontdoor.azurefd.net"

  frontdoor_name = "${random_pet.rg_name.id}-frontdoor"
  cluster_rg = "MC_${azurerm_resource_group.rg.name}_${random_pet.azurerm_kubernetes_cluster_name.id}_${var.resource_group_location}"
}

# Output the DNS name for use in other resources
output "dns_name" {
  value = local.dns_name
  description = "The DNS name for the cluster resources"
}

output "cluster_rg" {
  value = local.cluster_rg
  description = "The resource group for the cluster"
}

resource "azurerm_public_ip" "api_ip" {
  depends_on = [ azurerm_kubernetes_cluster.primary ]
  name = "${local.dns_name}-ip"
  location = azurerm_resource_group.rg.location
  resource_group_name = local.cluster_rg
  allocation_method = "Static"
}

resource "azurerm_public_ip" "viz_ip" {
  depends_on = [ azurerm_kubernetes_cluster.primary ]
  name = "${local.dns_name}-ip-viz"
  location = azurerm_resource_group.rg.location
  resource_group_name = local.cluster_rg
  allocation_method = "Static"
}

resource "azurerm_public_ip" "nodeviz_ip" {
  depends_on = [ azurerm_kubernetes_cluster.primary ]
  name = "${local.dns_name}-ip-nodeviz"
  location = azurerm_resource_group.rg.location
  resource_group_name = local.cluster_rg
  allocation_method = "Static"
}

output "public_ip_names" {
  value = [
    azurerm_public_ip.api_ip.name,
    azurerm_public_ip.viz_ip.name,
    azurerm_public_ip.nodeviz_ip.name
  ]
}

resource "azurerm_kubernetes_cluster" "primary" {
  location            = azurerm_resource_group.rg.location
  name                = random_pet.azurerm_kubernetes_cluster_name.id
  resource_group_name = azurerm_resource_group.rg.name
  dns_prefix          = random_pet.azurerm_kubernetes_cluster_dns_prefix.id
  sku_tier            = "Standard"
  node_os_upgrade_channel      = "None"

  identity {
    type = "SystemAssigned"
  }

  default_node_pool {
    name                         = "sys"
    vm_size                      = "Standard_D2s_v3"
    max_pods                     = 100
    temporary_name_for_rotation  = "tempnodepool"
    only_critical_addons_enabled = true
    node_count                   = var.sys_node_count
    upgrade_settings {
      max_surge = "10%"
    }
  }

  linux_profile {
    admin_username = var.username

    ssh_key {
      key_data = azapi_resource_action.ssh_public_key_gen.output.publicKey
    }
  }
  network_profile {
    network_plugin = "azure"
    network_policy = "azure"
  }
  oms_agent {
    log_analytics_workspace_id      = azurerm_log_analytics_workspace.aks_logs.id
    msi_auth_for_monitoring_enabled = true
  }
}

resource "azurerm_kubernetes_cluster_node_pool" "user" {
  depends_on = [ azurerm_kubernetes_cluster.primary, azurerm_public_ip.api_ip, azurerm_public_ip.viz_ip ]
  name                  = "usr"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = var.vm_size
  max_pods              = 250
  node_count            = var.usr_node_count

  node_labels = {
    "support.shellphish.net/pool" = "user"

    # Until we support allocating replicas in multiple pools, we won't allow fuzzing on user nodes
    # "support.shellphish.net/allow-fuzzing" = "true"
  }
  
  auto_scaling_enabled = true
  min_count             = var.usr_node_count
  max_count             = var.usr_node_count_max

  upgrade_settings {
    max_surge = "10%"
  }
  os_disk_size_gb = var.vm_disk_size
}

resource "azurerm_kubernetes_cluster_node_pool" "storage" {
  depends_on = [ azurerm_kubernetes_cluster.primary ]
  name                  = "storage"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = var.storage_vm_size
  max_pods              = 100
  node_count            = 1

  auto_scaling_enabled = false

  node_labels = {
    "support.shellphish.net/pool" = "storage"
    "support.shellphish.net/only-storage" = "true"
  }

  # This taint prevents pods from being scheduled on this node pool by default
  # Only pods that explicitly tolerate the "allowed-on-storage=true:NoSchedule" taint tolerance will be scheduled here
  node_taints = [
    "support.shellphish.net/only-storage=true:NoSchedule",
  ]

  upgrade_settings {
    max_surge = "10%"
  }
  os_disk_size_gb = var.vm_disk_size
}

resource "azurerm_kubernetes_cluster_node_pool" "gpu" {
  count = var.enable_gpu_node_pool ? 1 : 0
  
  depends_on = [ azurerm_kubernetes_cluster.primary ]
  name                  = "gpu"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = var.gpu_vm_size
  max_pods              = 100

  auto_scaling_enabled = true
  min_count             = 0
  max_count             = 1

  node_labels = {
    "support.shellphish.net/pool" = "gpu"
    "support.shellphish.net/only-gpu" = "true"
  }

  # This taint prevents pods from being scheduled on this node pool by default
  # Only pods that explicitly tolerate the "allowed-on-storage=true:NoSchedule" taint tolerance will be scheduled here
  node_taints = [
    "support.shellphish.net/only-gpu=true:NoSchedule",
  ]

  upgrade_settings {
    max_surge = "10%"
  }
  os_disk_size_gb = var.vm_disk_size
}

resource "azurerm_kubernetes_cluster_node_pool" "critical" {
  depends_on = [ azurerm_kubernetes_cluster.primary ]
  name                  = "critical"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = var.critical_vm_size
  max_pods              = 100
  node_count            = var.critical_node_count

  auto_scaling_enabled = true
  min_count             = var.critical_node_count
  max_count             = 30

  node_labels = {
    "support.shellphish.net/pool" = "critical"
    "support.shellphish.net/only-critical" = "true"
  }

  # This taint prevents pods from being scheduled on this node pool by default
  # Only pods that explicitly tolerate the "allowed-on-critical=true:NoSchedule" taint tolerance will be scheduled here
  node_taints = [
    "support.shellphish.net/only-critical=true:NoSchedule",
  ]

  upgrade_settings {
    max_surge = "10%"
  }
  os_disk_size_gb = var.vm_disk_size

}

resource "azurerm_kubernetes_cluster_node_pool" "crittask" {
  count = var.task_pool_count
  depends_on = [ azurerm_kubernetes_cluster.primary ]
  name                  = "crit${var.task_pool_names[count.index]}"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = var.critical_vm_size
  max_pods              = 100
  node_count            = 1

  auto_scaling_enabled = true
  min_count             = 2
  max_count             = 30

  node_labels = {
    "support.shellphish.net/pool" = "critical-task"
    "support.shellphish.net/task-pool" = var.task_pool_names[count.index]
  }

  # This taint prevents pods from being scheduled on this node pool by default
  # Only pods that explicitly tolerate the "allowed-on-critical=true:NoSchedule" taint tolerance will be scheduled here
  node_taints = [
    "support.shellphish.net/only-critical=true:NoSchedule",
  ]

  upgrade_settings {
    max_surge = "10%"
  }
  os_disk_size_gb = var.vm_disk_size
}


resource "azurerm_kubernetes_cluster_node_pool" "coverage" {
  depends_on = [ azurerm_kubernetes_cluster.primary ]
  name                  = "cov"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = var.coverage_vm_size
  max_pods              = 250
  node_count            = 0

  auto_scaling_enabled = true
  min_count             = 0
  max_count             = var.coverage_node_count_max

  node_labels = {
    "support.shellphish.net/pool" = "coverage"
    "support.shellphish.net/allow-coverage" = "true"
    "support.shellphish.net/only-coverage" = "true"
  }

  # This taint prevents pods from being scheduled on this node pool by default
  # Only pods that explicitly tolerate the "allowed-on-coverage=true:NoSchedule" taint tolerance will be scheduled here
  node_taints = [
    "support.shellphish.net/only-coverage=true:NoSchedule",
  ]

  upgrade_settings {
    max_surge = "10%"
  }
  os_disk_size_gb = var.vm_disk_size
}

resource "azurerm_kubernetes_cluster_node_pool" "patching" {
  depends_on = [ azurerm_kubernetes_cluster.primary ]
  name                  = "patch"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = var.patching_vm_size
  max_pods              = 100
  node_count            = var.patching_node_count

  auto_scaling_enabled = true
  min_count             = var.patching_node_count
  max_count             = var.patching_node_count_max

  node_labels = {
    "support.shellphish.net/pool" = "patching"
    "support.shellphish.net/allow-patching" = "true"
    "support.shellphish.net/only-patching" = "true"
  }

  # This taint prevents pods from being scheduled on this node pool by default
  # Only pods that explicitly tolerate the "allowed-on-coverage=true:NoSchedule" taint tolerance will be scheduled here
  node_taints = [
    "support.shellphish.net/only-patching=true:NoSchedule",
  ]

  upgrade_settings {
    max_surge = "10%"
  }
  os_disk_size_gb = var.vm_disk_size
}

resource "azurerm_kubernetes_cluster_node_pool" "services" {
  depends_on = [ azurerm_kubernetes_cluster.primary ]
  name                  = "serv"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = var.services_vm_size
  max_pods              = 100
  node_count            = var.services_node_count

  auto_scaling_enabled = true
  min_count             = var.services_node_count
  max_count             = var.services_node_count_max

  node_labels = {
    "support.shellphish.net/pool" = "services"
    "support.shellphish.net/only-services" = "true"
  }

  # This taint prevents pods from being scheduled on this node pool by default
  # Only pods that explicitly tolerate the "allowed-on-coverage=true:NoSchedule" taint tolerance will be scheduled here
  node_taints = [
    "support.shellphish.net/only-services=true:NoSchedule",
  ]

  upgrade_settings {
    max_surge = "10%"
  }
  os_disk_size_gb = var.vm_disk_size
}

resource "azurerm_kubernetes_cluster_node_pool" "fuzzingspot" {
  depends_on = [ azurerm_kubernetes_cluster.primary ]
  name                  = "fzzspot"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = var.fuzzing_vm_size
  max_pods              = 250
  node_count            = 0

  # TODO(finaldeploy) set this back to 5
  auto_scaling_enabled = true
  min_count             = 0
  max_count             = 0

  # This taint prevents pods from being scheduled on this node pool by default
  # Only pods that explicitly tolerate the "allowed-on-fuzzing=true:NoSchedule" taint will be scheduled here
  node_taints = [
    "support.shellphish.net/only-fuzzing=true:NoSchedule",
    "kubernetes.azure.com/scalesetpriority=spot:NoSchedule",
  ]

  node_labels = {
    "support.shellphish.net/pool" = "fuzzing"
    "support.shellphish.net/only-fuzzing" = "true"
    "support.shellphish.net/allow-fuzzing" = "true"

    "kubernetes.azure.com/scalesetpriority" = "spot"
  }

  # https://learn.microsoft.com/en-us/azure/aks/spot-node-pool
  priority = "Spot"
  spot_max_price = -1
  eviction_policy = "Delete"

  os_disk_size_gb = var.vm_disk_size
}

# TODO(finaldeploy) Use multi size fuzzing pools
resource "azurerm_kubernetes_cluster_node_pool" "fuzzing" {
  # We will have multiple fuzzing pools, one for each tasking up to N concurrent taskings
  count = var.task_pool_count

  depends_on = [ azurerm_kubernetes_cluster.primary ]
  name                  = "fzz${var.task_pool_names[count.index]}"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  #vm_size               = var.fuzzing_vm_size
  vm_size               = var.task_pool_sizes[count.index]
  max_pods              = 250
  node_count            = 0

  auto_scaling_enabled = true
  min_count             = 0
  max_count             = var.fuzzing_node_count_max

  # This taint prevents pods from being scheduled on this node pool by default
  # Only pods that explicitly tolerate the "allowed-on-fuzzing=true:NoSchedule" taint will be scheduled here
  node_taints = [
    "support.shellphish.net/only-fuzzing=true:NoSchedule",
    # We can try to encourage fuzzer pods to go to spot nodes first
    # If no spot nodes are available, it will fall back to non-spot nodes
    "support.shellphish.net/prefer-spot-nodes=false:PreferNoSchedule",
  ]

  node_labels = {
    "support.shellphish.net/pool" = "fuzzing"
    "support.shellphish.net/only-fuzzing" = "true"
    "support.shellphish.net/allow-fuzzing" = "true"
    "support.shellphish.net/task-pool" = var.task_pool_names[count.index]
  }

  upgrade_settings {
    max_surge = "10%"
  }
  os_disk_size_gb = var.vm_disk_size
}
resource "azurerm_kubernetes_cluster_node_pool" "fuzzinglf" {
  # We will have multiple fuzzing pools, one for each tasking up to N concurrent taskings
  count = var.task_pool_count

  depends_on = [ azurerm_kubernetes_cluster.primary ]
  name                  = "fzzlf${var.task_pool_names[count.index]}"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = var.fuzzing_vm_size_lf
  #vm_size               = var.task_pool_sizes[count.index]
  max_pods              = 250
  node_count            = 0

  auto_scaling_enabled = true
  min_count             = 0
  max_count             = var.fuzzing_node_count_max_lf

  # This taint prevents pods from being scheduled on this node pool by default
  # Only pods that explicitly tolerate the "allowed-on-fuzzing=true:NoSchedule" taint will be scheduled here
  node_taints = [
    "support.shellphish.net/only-fuzzing-lf=true:NoSchedule",
    # We can try to encourage fuzzer pods to go to spot nodes first
    # If no spot nodes are available, it will fall back to non-spot nodes
    "support.shellphish.net/prefer-spot-nodes=false:PreferNoSchedule",
  ]

  node_labels = {
    "support.shellphish.net/pool" = "fuzzing-lf"
    "support.shellphish.net/only-fuzzing-lf" = "true"
    "support.shellphish.net/allow-fuzzing-lf" = "true"
    "support.shellphish.net/task-pool" = var.task_pool_names[count.index]
  }

  upgrade_settings {
    max_surge = "10%"
  }
  os_disk_size_gb = var.vm_disk_size
}

#Monitoring Log Anayltics
resource "azurerm_log_analytics_workspace" "aks_logs" {
  name                = "${random_pet.rg_name.id}-logs"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

#Create Azure Container Registry
resource "random_string" "acr_suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "azurerm_container_registry" "acr" {
  depends_on = [ azurerm_resource_group.rg ]
  name                = "artiphishellci${terraform.workspace}${random_string.acr_suffix.result}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku                 = "Premium"
  admin_enabled       = true
}


# Frontdoor will provide a TLS proxy in front of the public IPs we assigned to the services above
resource "azurerm_frontdoor" "frontdoor" {
  count = 0
  
  depends_on = [ azurerm_public_ip.api_ip, azurerm_public_ip.viz_ip, azurerm_public_ip.nodeviz_ip ]
  name = local.frontdoor_name
  resource_group_name = azurerm_resource_group.rg.name

  routing_rule {
    name = "crs-api"
    accepted_protocols = ["Http", "Https"]
    patterns_to_match  = ["/*"]
    frontend_endpoints = ["crs-api-endpoints"]
    forwarding_configuration {
      forwarding_protocol = "HttpOnly"
      backend_pool_name   = "crs-api-backend-pool"
    }
  }

  routing_rule {
    name = "crs-viz"
    accepted_protocols = ["Http", "Https"]
    patterns_to_match  = ["/viz/*"]
    frontend_endpoints = ["crs-api-endpoints"]
    forwarding_configuration {
      forwarding_protocol = "HttpOnly"
      backend_pool_name   = "crs-viz-backend-pool"
    }
  }
  
  routing_rule {
    name = "crs-nodeviz"
    accepted_protocols = ["Http", "Https"]
    patterns_to_match  = ["/nodes/*"]
    frontend_endpoints = ["crs-api-endpoints"]
    forwarding_configuration {
      forwarding_protocol = "HttpOnly"
      backend_pool_name   = "crs-nodeviz-backend-pool"
      custom_forwarding_path = "/"
    }
  }

  backend_pool {
    name = "crs-api-backend-pool"
    backend {
      host_header = "${azurerm_public_ip.api_ip.ip_address}"
      address = "${azurerm_public_ip.api_ip.ip_address}"
      http_port = 80
      https_port = 9
    }

    load_balancing_name = "crs-api-backend-pool-load-balancing"
    health_probe_name = "crs-api-backend-pool-health-probe"
  }

  backend_pool {
    name = "crs-viz-backend-pool"
    backend {
      host_header = "${azurerm_public_ip.viz_ip.ip_address}"
      address = "${azurerm_public_ip.viz_ip.ip_address}"
      http_port = 5555
      https_port = 9
    }

    load_balancing_name = "crs-viz-backend-pool-load-balancing"
    health_probe_name = "crs-api-backend-pool-health-probe"
  }

  backend_pool {
    name = "crs-nodeviz-backend-pool"
    backend {
      host_header = "${azurerm_public_ip.nodeviz_ip.ip_address}"
      address = "${azurerm_public_ip.nodeviz_ip.ip_address}"
      http_port = 8080
      https_port = 9
    }

    load_balancing_name = "crs-nodeviz-backend-pool-load-balancing"
    health_probe_name = "crs-api-backend-pool-health-probe"
  }

  frontend_endpoint {
    name = "crs-api-endpoints"
    host_name = "${local.frontdoor_name}.azurefd.net"
  }

  backend_pool_load_balancing {
    name = "crs-api-backend-pool-load-balancing"
  }
  backend_pool_load_balancing {
    name = "crs-viz-backend-pool-load-balancing"
  }
  backend_pool_load_balancing {
    name = "crs-nodeviz-backend-pool-load-balancing"
  }

  backend_pool_health_probe {
    name = "crs-api-backend-pool-health-probe"
  }

  # These settings are just here to prevent tf from making them null every time the changes are applied
  backend_pool_settings {
    backend_pools_send_receive_timeout_seconds = 0
    enforce_backend_pools_certificate_name_check = false
  }
}
