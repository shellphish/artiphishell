variable "resource_group_location" {
  type        = string
  default     = "westus"
  description = "Location of the resource group."
}

variable "resource_group_name_prefix" {
  type        = string
  default     = "ci-k8"
  description = "Prefix of the resource group name that's combined with a random ID so name is unique in your Azure subscription."
}

variable "sys_node_count" {
  type        = number
  description = "The initial quantity of nodes for the node pool."
  default     = 2
}

variable "username" {
  type        = string
  description = "The admin username for the new cluster."
  default     = "ubuntu"
}

variable "vm_size" {
  type        = string
  description = "The size of the VM to use for the cluster."
  default     = "standard_D32s_v3"
}

variable "coverage_node_count" {
  type        = number
  description = "The initial quantity of nodes for the coverage guy node pool."
  default     = 0
}

variable "coverage_node_count_max" { 
  type        = number
  description = "The maximum quantity of coverage nodes"
  default     = 20
}

variable "coverage_vm_size" {
  type        = string
  description = "The size of the VM to use for the coverage guy node pool."
  # TODO try to shrink this by cutting down size of daemonsets/containersets
  default     = "standard_D32s_v3"
}


variable "usr_node_count" {
  type        = number
  description = "The initial quantity of nodes for the node pool."
  default     = 1
}
variable "usr_node_count_max" {
  type        = number
  description = "The maximum quantity of nodes for the user node pool."
  default     = 6
}

variable "fuzzing_node_count" {
  type        = number
  description = "The initial quantity of nodes for the fuzzing node pool."
  default     = 0
}
variable "fuzzing_node_count_max" {
  type        = number
  description = "The maximum quantity of nodes for the fuzzing node pool."
  default     = 4
}

variable "fuzzing_node_count_max_lf" {
  type        = number
  description = "The maximum quantity of nodes for the fuzzing node pool."
  default     = 4
}

variable "fuzzing_vm_size" {
  type        = string
  description = "The size of the VM to use for the fuzzing node pool."
  default     = "standard_D32s_v3"
}

variable "fuzzing_vm_size_lf" {
  type        = string
  description = "The size of the VM to use for the fuzzing node pool."
  default     = "standard_D32s_v3"
}

# TODO(finaldeploy) Make sure this is the correct number of task pools
variable "task_pool_names" {
  type    = list(string)
  description = "The names of the tasking node pool labels to create"
  default     = ["task1", "task2", "task3", "task4", "task5", "task6", "task7", "task8"]
}

# TODO(finaldeploy) Make sure this is the correct sizes for the task pools
variable "task_pool_sizes" {
  type    = list(string)
  description = "The sizes of the tasking node pools"
  default     = ["standard_D64s_v4","standard_D64s_v4","standard_D64s_v4","standard_D64s_v4","standard_D64s_v4","standard_E64s_v4","standard_E64s_v4","standard_E64s_v4"]
}

variable "patching_node_count" {
  type        = number
  description = "The initial quantity of nodes for the patching node pool."
  default     = 0
}
variable "patching_node_count_max" {
  type        = number
  description = "The maximum quantity of nodes for the patching node pool."
  default     = 10
}
variable "patching_vm_size" {
  type        = string
  description = "The size of the VM to use for the patching node pool."
  default     = "standard_D16s_v3"
}

variable "services_node_count" {
  type        = number
  description = "The initial quantity of nodes for the services node pool."
  default     = 0
}
variable "services_vm_size" {
  type        = string
  description = "The size of the VM to use for the services node pool."
  default     = "standard_D32s_v3"
}
variable "services_node_count_max" {
  type        = number
  description = "The maximum quantity of nodes for the services node pool."
  default     = 10
}

variable "critical_node_count" {
  type        = number
  description = "The initial quantity of nodes for the critical node pool."
  default     = 2
}

variable "task_pool_count" {
  type        = number
  description = "The initial quantity of task pools to create"
  default     = 1
}

variable "critical_vm_size" {
  type        = string
  description = "The size of the VM to use for the critical node pool."
  default     = "Standard_D32s_v3"
}

variable "enable_public_ip" {
  type        = bool
  description = "Whether to enable public IP for any service."
  default     = true
}

variable "storage_vm_size" {
  type        = string
  description = "The size of the VM to use for the storage node pool."
  default     = "Standard_D8s_v3"
}

# TODO(finaldeploy) Make sure this is the correct size for the GPU node pool
variable "gpu_vm_size" {
  type        = string
  description = "The size of the VM to use for the GPU node pool."
  default     = "Standard_NC80adis_H100_v5"
}

variable "enable_gpu_node_pool" {
  type        = bool
  description = "Whether to create the GPU node pool. Set to false if GPU VMs are not available."
  default     = true
}

variable "vm_disk_size" {
  type        = number
  description = "The size of the disk to use for the VM."
  default     = 1024
}
