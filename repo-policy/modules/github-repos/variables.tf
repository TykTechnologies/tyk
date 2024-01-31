variable "repo" {
  type        = string
  description = "Repository name"
}

variable "description" {
  type        = string
  description = "Repository description"
}

variable "visibility" {
  type        = string
  description = "Repository visibility , private or public"
  default     = "public"
}

variable "wiki" {
  type        = bool
  description = "Repository has wiki enabled or not"
  default     = true
}

variable "topics" {
  type        = list(string)
  description = "Github topics"
}

variable "default_branch" {
  type        = string
  description = "The default branch for the repository. This branch is used as the base when running GitHub Actions."
}

variable "merge_commit" {
  type        = bool
  description = "Set to false to disable merge commits on the repository. When running GitHub Actions, merge commits are disabled if this variable is set to false."
  default     = false
}

variable "rebase_merge" {
  type        = bool
  description = "Set to false to disable rebase merges on the repository"
  default     = false
}

variable "delete_branch_on_merge" {
  type        = bool
  description = "If enabled, the head branch will be automatically deleted after a pull request is merged."
  default     = true
}

variable "vulnerability_alerts" {
  type        = bool
  description = "Set to true to enable security alerts for vulnerable dependencies."
  default     = true
}

variable "squash_merge_commit_message" {
  type        = string
  description = "Specifies the content of the default squash merge commit message. Possible values are PR_BODY, COMMIT_MESSAGES, or BLANK. This setting is used when creating a merge commit."
  default     = "COMMIT_MESSAGES"
}

variable "squash_merge_commit_title" {
  type        = string
  description = "Specifies the content of the default squash merge commit title. Possible values are PR_TITLE or COMMIT_OR_PR_TITLE. This setting determines the title of the merge commit."
  default     = "COMMIT_OR_PR_TITLE"
}

variable "release_branches" {
  type = list(object({
    branch         = string           # Name of the branch
    source_branch  = optional(string) # Source of the branch, needed when creating it
    reviewers      = number           # Min number of reviews needed
    required_tests = list(string)     # Workflows that need to pass before merging
    convos         = bool             # Should conversations be resolved before merging
  }))
  description = "List of branches managed by terraform"
}
