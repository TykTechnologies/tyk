# Generated by: tyk-ci/wf-gen
# Generated on: Thu 15 Apr 07:35:52 UTC 2021

# Generation commands:
# ./pr.zsh -title minor: deb location for packer -branch releng/install -base releng/install -p
# m4 -E -DxREPO=tyk


data "terraform_remote_state" "integration" {
  backend = "remote"

  config = {
    organization = "Tyk"
    workspaces = {
      name = "base-prod"
    }
  }
}

output "tyk" {
  value = data.terraform_remote_state.integration.outputs.tyk
  description = "ECR creds for tyk repo"
}

output "region" {
  value = data.terraform_remote_state.integration.outputs.region
  description = "Region in which the env is running"
}
