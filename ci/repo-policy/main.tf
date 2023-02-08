terraform {

  #Being used until TFCloud can be used
  backend "s3" {
    bucket         = "terraform-state-devenv"
    key            = "github-policy/tyk"
    region         = "eu-central-1"
    dynamodb_table = "terraform-state-locks"
  }

  required_providers {
    github = {
      source  = "integrations/github"
      version = "5.16.0"
    }
  }
}

provider "github" {
  owner = "TykTechnologies"
}

module "tyk" {
  source               = "./modules/github-repos"
  repo                 = "tyk"
  description          = "Tyk Open Source API Gateway written in Go, supporting REST, GraphQL, TCP and gRPC protocols"
  default_branch       = "master"
  topics                      = ["api","api-gateway","api-management","cloudnative","go","graphql","grpc","k8s","kubernetes","microservices","reverse-proxy","tyk"]
  visibility                  = "public"
  wiki                        = false
  vulnerability_alerts        = true
  squash_merge_commit_message = "PR_BODY"
  squash_merge_commit_title   = "PR_TITLE"
  release_branches     = [
{ branch    = "master",
	reviewers = "2",
	convos    = "false",
	required_tests = ["Go 1.16 Redis 5","1.16","1.16-el7"]},
{ branch    = "release-4.0.10",
	reviewers = "0",
	convos    = "false",
	source_branch  = "release-4-lts",
	required_tests = ["Go 1.15 Redis 5","1.15","1.15-el7"]},
{ branch    = "release-4.0.11",
	reviewers = "0",
	convos    = "false",
	source_branch  = "release-4-lts",
	required_tests = ["Go 1.15 Redis 5","1.15","1.15-el7"]},
{ branch    = "release-4.0.12",
	reviewers = "0",
	convos    = "false",
	source_branch  = "release-4-lts",
	required_tests = ["Go 1.15 Redis 5","1.15","1.15-el7"]},
{ branch    = "release-4.3",
	reviewers = "0",
	convos    = "false",
	source_branch  = "release-4",
	required_tests = ["Go 1.16 Redis 5","1.16","1.16-el7"]},
{ branch    = "release-4.3.0",
	reviewers = "0",
	convos    = "false",
	source_branch  = "release-4",
	required_tests = ["Go 1.16 Redis 5","1.16","1.16-el7"]},
{ branch    = "release-4.3.1",
	reviewers = "0",
	convos    = "false",
	source_branch  = "release-4.3",
	required_tests = ["Go 1.16 Redis 5","1.16","1.16-el7"]},
{ branch    = "release-4.3.2",
	reviewers = "0",
	convos    = "false",
	source_branch  = "release-4.3",
	required_tests = ["Go 1.16 Redis 5","1.16","1.16-el7"]},
{ branch    = "release-4.3.3",
	reviewers = "0",
	convos    = "false",
	source_branch  = "release-4.3",
	required_tests = ["Go 1.16 Redis 5","1.16","1.16-el7"]},
]
}