module "gateway" {
  source      = "./modules/fg-sds"
  cluster     = aws_ecs_cluster.env.arn
  cdt         = "templates/cd-awsvpc.tpl"
  public_ip   = true
  sr          = aws_service_discovery_private_dns_namespace.internal.id
  tearn       = data.aws_iam_role.ecs_task_execution_role.arn
  env_name    = var.name
  vpc         = data.terraform_remote_state.infra.outputs.vpc_id
  subnets     = data.aws_subnet_ids.public.ids
  common_tags = local.common_tags
  volume_map  = { config = data.terraform_remote_state.base.outputs.config_efs }
  cd = {
    name      = "tyk",
    command   = ["--conf=/conf/tyk.conf"],
    port      = 8181,
    log_group = aws_cloudwatch_log_group.env.name,
    image     = join(":", [data.terraform_remote_state.base.outputs.tyk["ecr"], var.tyk])
    mounts = [
      { src = "config", dest = "/conf" }
    ],
    env = [],
    secrets = [],
    region = data.terraform_remote_state.base.outputs.region
  }
}

module "redis" {
  source = "./modules/fg-sds"
  cluster = aws_ecs_cluster.env.arn
  cdt = "templates/cd-awsvpc.tpl"
  public_ip = false
  sr          = aws_service_discovery_private_dns_namespace.internal.id
  tearn       = data.aws_iam_role.ecs_task_execution_role.arn
  env_name    = var.name
  vpc         = data.terraform_remote_state.infra.outputs.vpc_id
  subnets     = data.aws_subnet_ids.private.ids
  common_tags = local.common_tags
  volume_map  = {}
  cd = {
    name      = "redis",
    command   = [],
    port      = 6379,
    log_group = aws_cloudwatch_log_group.env.name,
    image     = "redis"
    mounts = [],
    env = [],
    secrets = [],
    region = data.terraform_remote_state.base.outputs.region
  }
}

module "dashboard" {
  source = "./modules/fg-sds"
  cluster = aws_ecs_cluster.env.arn
  cdt = "templates/cd-awsvpc.tpl"
  public_ip = true
  sr = aws_service_discovery_private_dns_namespace.internal.id
  tearn       = data.aws_iam_role.ecs_task_execution_role.arn
  env_name = var.name
  vpc         = data.terraform_remote_state.infra.outputs.vpc_id
  subnets     = data.aws_subnet_ids.public.ids
  common_tags = local.common_tags
  volume_map  = { config = data.terraform_remote_state.base.outputs.config_efs }
  cd = {
    name      = "tyk-analytics",
    command   = ["--conf=/conf/tyk-analytics.conf"],
    port      = 3000,
    log_group = aws_cloudwatch_log_group.env.name,
    image     = join(":", [data.terraform_remote_state.base.outputs.tyk-analytics["ecr"], var.tyk-pump])
    mounts = [
      { src = "config", dest = "/conf" }
    ],
    env = [],
    secrets = [
      { name = "TYK_DB_LICENSEKEY", from = local.dash_license }
    ],
    region = data.terraform_remote_state.base.outputs.region
  }
}

module "pump" {
  source = "./modules/fg-sds"
  cluster = aws_ecs_cluster.env.arn
  cdt = "templates/cd-awsvpc.tpl"
  public_ip = false
  sr = aws_service_discovery_private_dns_namespace.internal.id
  tearn       = data.aws_iam_role.ecs_task_execution_role.arn
  env_name    = var.name
  vpc         = data.terraform_remote_state.infra.outputs.vpc_id
  subnets     = data.aws_subnet_ids.private.ids
  common_tags = local.common_tags
  volume_map  = { config = data.terraform_remote_state.base.outputs.config_efs }
  cd = {
    name      = "tyk-pump",
    command   = ["--conf=/conf/tyk-pump.conf"],
    # pump doesn't listen, but the module expects a port
    port      = 443,
    log_group = aws_cloudwatch_log_group.env.name,
    image     = join(":", [data.terraform_remote_state.base.outputs.tyk-pump["ecr"], var.tyk-pump])
    mounts = [
      { src = "config", dest = "/conf" }
    ],
    env = [],
    secrets = [],
    region = data.terraform_remote_state.base.outputs.region
  }
}
