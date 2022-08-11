terraform {
  required_version = ">= 0.13"
  backend "s3" {
    bucket         = "terraform-state-devenv"
    key            = "devenv"
    region         = "eu-central-1"
    dynamodb_table = "terraform-state-locks"
  }
}

provider "aws" {
  region = data.terraform_remote_state.base.outputs.region
}

# For VPC

data "terraform_remote_state" "infra" {
  backend = "remote"

  config = {
    organization = "Tyk"
    workspaces = {
      name = var.infra
    }
  }
}

# EFS, ECR

data "terraform_remote_state" "base" {
  backend = "remote"

  config = {
    organization = "Tyk"
    workspaces = {
      name = var.base
    }
  }
}

# Internal variables

locals {
  common_tags = {
    "managed" = "automation",
    "ou"      = "devops",
    "purpose" = "ci",
    "env"     = var.name
  }
  dash_license = "arn:aws:secretsmanager:eu-central-1:754489498669:secret:DashTrialLicense-7EzdZh"
  mdcb_license = "arn:aws:secretsmanager:eu-central-1:754489498669:secret:MDCBTrialLicense-9BIRjv"
}

# ECS cluster

resource "aws_ecs_cluster" "env" {
  name = var.name

  # setting {
  #   name  = "containerInsights"
  #   value = "enabled"
  # }
  tags = local.common_tags
}

# Nmae should match name given to resource ~tyk-ci/infra/iam.tf:aws_iam_role:gromit_ter
data "aws_iam_role" "ecs_task_execution_role" {
  name = "gromit-ecs-init"
}

resource "aws_cloudwatch_log_group" "env" {
  name              = var.name
  retention_in_days = 1

  tags = local.common_tags
}

# Private subnets
data "aws_subnet_ids" "private" {
  vpc_id = data.terraform_remote_state.infra.outputs.vpc_id

  tags = {
    Type = "private"
  }
}

# Public subnets
data "aws_subnet_ids" "public" {
  vpc_id = data.terraform_remote_state.infra.outputs.vpc_id

  tags = {
    Type = "public"
  }
}

# Private DNS
# Service discovery
resource "aws_service_discovery_private_dns_namespace" "internal" {
  name        = join(".", [var.name, "internal"])
  vpc         = data.terraform_remote_state.infra.outputs.vpc_id
  description = "The tyk conf files can use friendly names"
}
