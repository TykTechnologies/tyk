terraform {

  #Being used until TFCloud can be used
  backend "remote" {
    hostname     = "app.terraform.io"
    organization = "Tyk"
    workspaces {
      name = "repo-policy-tyk"
    }
  }

  required_providers {
    github = {
      source = "integrations/github"
    }
  }
}

provider "github" {
  owner = "TykTechnologies"
}

# Copypasta from modules/github-repos/variables.tf
# FIXME: Unmodularise the github-repos module
variable "historical_branches" {
  type = list(object({
    branch         = string           # Name of the branch
    source_branch  = optional(string) # Source of the branch, needed when creating it
    reviewers      = number           # Min number of reviews needed
    required_tests = list(string)     # Workflows that need to pass before merging
    convos         = bool             # Should conversations be resolved before merging

  }))
  description = "List of branches managed by terraform"
}

module "tyk" {
  source                      = "./modules/github-repos"
  repo                        = "tyk"
  description                 = "Tyk Open Source API Gateway written in Go, supporting REST, GraphQL, TCP and gRPC protocols"
  default_branch              = "master"
  topics                      = ["api", "api-gateway", "api-management", "cloudnative", "go", "graphql", "grpc", "k8s", "kubernetes", "microservices", "reverse-proxy", "tyk"]
  visibility                  = "public"
  wiki                        = false
  vulnerability_alerts        = true
  squash_merge_commit_message = "PR_BODY"
  squash_merge_commit_title   = "PR_TITLE"
  release_branches = concat(var.historical_branches, [
    { branch    = "master",
      reviewers = "1",
      convos    = "false",
    required_tests = ["Go 1.21.x Redis 5", "1.21-bullseye", "api-tests (sha256, mongo44)", "api-tests (sha256, postgres15)", "api-tests (murmur64, mongo44)", "api-tests (murmur64, postgres15)"] },
    { branch        = "release-4-lts",
      reviewers     = "0",
      convos        = "false",
      source_branch = "master",
    required_tests = ["Go 1.15 Redis 6"] },
    { branch        = "release-4.0.14",
      reviewers     = "0",
      convos        = "false",
      source_branch = "release-4-lts",
    required_tests = ["Go 1.15 Redis 6"] },
    { branch        = "release-5-lts",
      reviewers     = "0",
      convos        = "false",
      source_branch = "master",
    required_tests = ["Go 1.16 Redis 5", "1.16-bullseye", "1.16-el7"] },
    { branch        = "release-5.0.4",
      reviewers     = "0",
      convos        = "false",
      source_branch = "release-5-lts",
    required_tests = ["Go 1.16 Redis 5", "1.16", "1.16-el7"] },
    { branch        = "release-5.0.5",
      reviewers     = "0",
      convos        = "false",
      source_branch = "release-5-lts",
    required_tests = ["Go 1.16 Redis 5", "1.16-bullseye", "1.16-el7"] },
    { branch        = "release-5.0.6",
      reviewers     = "0",
      convos        = "false",
      source_branch = "release-5-lts",
    required_tests = ["Go 1.16 Redis 5", "1.16-bullseye", "1.16-el7"] },
    { branch        = "release-5.0.7",
      reviewers     = "0",
      convos        = "false",
      source_branch = "release-5-lts",
    required_tests = ["Go 1.16 Redis 5", "1.16-bullseye", "1.16-el7"] },
    { branch        = "release-5.0.8",
      reviewers     = "0",
      convos        = "false",
      source_branch = "release-5-lts",
    required_tests = ["Go 1.16 Redis 5", "1.16-bullseye", "1.16-el7"] },
    { branch        = "release-5.0.9",
      reviewers     = "0",
      convos        = "false",
      source_branch = "release-5-lts",
    required_tests = ["Go 1.16 Redis 5", "1.16-bullseye", "1.16-el7"] },
    { branch        = "release-5.0.10",
      reviewers     = "0",
      convos        = "false",
      source_branch = "release-5-lts",
    required_tests = ["Go 1.16 Redis 5", "1.16-bullseye", "1.16-el7"] },
    { branch        = "release-5.1",
      reviewers     = "0",
      convos        = "false",
      source_branch = "master",
    required_tests = ["Go 1.19.x Redis 5", "1.19-bullseye"] },
    { branch        = "release-5.1.1",
      reviewers     = "0",
      convos        = "false",
      source_branch = "release-5.1",
    required_tests = ["Go 1.19.x Redis 5", "1.19-bullseye"] },
    { branch        = "release-5.1.2",
      reviewers     = "0",
      convos        = "false",
      source_branch = "release-5.1",
    required_tests = ["Go 1.19.x Redis 5", "1.19-bullseye"] },
    { branch        = "release-5.2",
      reviewers     = "0",
      convos        = "false",
      source_branch = "master",
    required_tests = ["Go 1.19.x Redis 5", "1.19-bullseye"] },
    { branch        = "release-5.2.0",
      reviewers     = "0",
      convos        = "false",
      source_branch = "release-5.2",
    required_tests = ["Go 1.19.x Redis 5", "1.19-bullseye"] },
    { branch        = "release-5.2.1",
      reviewers     = "0",
      convos        = "false",
      source_branch = "release-5.2",
    required_tests = ["Go 1.19.x Redis 5", "1.19-bullseye"] },
    { branch        = "release-5.2.2",
      reviewers     = "0",
      convos        = "false",
      source_branch = "release-5.2",
    required_tests = ["Go 1.19.x Redis 5", "1.19-bullseye"] },
    { branch        = "release-5.2.3",
      reviewers     = "0",
      convos        = "false",
      source_branch = "release-5.2",
    required_tests = ["Go 1.19.x Redis 5", "1.19-bullseye"] },
    { branch        = "release-5.2.4",
      reviewers     = "0",
      convos        = "false",
      source_branch = "release-5.2",
    required_tests = ["Go 1.19.x Redis 5", "1.19-bullseye"] },
    { branch        = "release-5.2.5",
      reviewers     = "0",
      convos        = "false",
      source_branch = "release-5.2",
    required_tests = ["Go 1.19.x Redis 5", "1.19-bullseye"] },
  ])
}
