data "terraform_remote_state" "infra" {
  backend = "remote"

  config = {
    organization = "Tyk"
    workspaces = {
      name = "infra-prod"
    }
  }
}

data "terraform_remote_state" "base" {
  backend = "remote"

  config = {
    organization = "Tyk"
    workspaces = {
      name = "base-prod"
    }
  }
}

output "cd" {
  value       = data.terraform_remote_state.infra.outputs.cd
  description = "Service account for continuous deployment"
}

output "region" {
  value       = data.terraform_remote_state.base.outputs.region
  description = "Region in which the env is running"
}