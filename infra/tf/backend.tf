terraform {
  backend "azurerm" {
    # TODO(FINALDEPLOY): Change both to PROD instead of CI
    resource_group_name  = "ARTIPHISHELL-PROD-AFC"
    storage_account_name = "artiphishellprodafc"
    container_name       = "tfstate"
    # key will be specified during initialization
  }
}