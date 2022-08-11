data "terraform_remote_state" "infra" {
  backend = "remote"

  config = {
    organization = "Tyk"
    workspaces = {
      name = "infra-prod"
    }
  }
}

output "cd" {
  value       = data.terraform_remote_state.infra.outputs.cd
  description = "Service account for continuous deployment"
}