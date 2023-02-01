terraform {
  required_providers {
    github = {
      source  = "integrations/github"
      version = "5.16.0"
    }
  }

}

resource "github_repository" "repository" {
  name                        = var.repo
  description                 = var.description
  visibility                  = var.visibility
  allow_rebase_merge          = var.rebase_merge
  allow_squash_merge          = true
  squash_merge_commit_message = var.squash_merge_commit_message
  squash_merge_commit_title   = var.squash_merge_commit_title
  allow_merge_commit          = var.merge_commit
  allow_auto_merge            = true
  delete_branch_on_merge      = var.delete_branch_on_merge
  vulnerability_alerts        = var.vulnerability_alerts
  has_downloads               = true
  has_issues                  = true
  has_wiki                    = var.wiki
  has_projects                = true
  topics                      = var.topics
}


resource "github_branch" "default" {
  repository = github_repository.repository.name
  branch     = var.default_branch
}

resource "github_branch" "release_branches" {
  for_each = { for i, b in var.release_branches :
  b.branch => b }
  repository    = github_repository.repository.name
  branch        = each.value.branch
  source_branch = each.value.source_branch
}

resource "github_branch_default" "default" {
  repository = github_repository.repository.name
  branch     = github_branch.default.branch
}


resource "github_branch_protection" "automerge" {
  for_each = { for i, b in var.release_branches :
  b.branch => b }

  repository_id = github_repository.repository.node_id
  pattern       = each.value.branch

  #checks for automerge
  require_signed_commits          = false
  require_conversation_resolution = each.value.convos
  required_linear_history         = false
  enforce_admins                  = false
  allows_deletions                = false
  allows_force_pushes             = false

  required_status_checks {
    strict   = true
    contexts = each.value.required_tests
  }

  required_pull_request_reviews {
    require_code_owner_reviews      = false
    required_approving_review_count = each.value.reviewers

  }
}
