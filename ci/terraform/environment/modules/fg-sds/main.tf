data "template_file" "cd" {
  template = templatefile(var.cdt, var.cd)
}

resource "aws_ecs_task_definition" "td" {
  # THIS NEEDS TO BE UPDATED
  family                   = join("-", [ var.cd.name, var.env_name ])
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  execution_role_arn       = var.tearn
  cpu                      = 256
  memory                   = 512

  container_definitions = data.template_file.cd.rendered

  dynamic "volume" {
    for_each = toset(var.cd.mounts[*].src)
    content {
      name = volume.value

      efs_volume_configuration {
        file_system_id = var.volume_map[volume.value]
        root_directory = "/${var.env_name}/${var.cd.name}"
      }
    }
  }

  tags = var.common_tags

}

resource "aws_ecs_task_definition" "td-template" {
  # THIS NEEDS TO BE UPDATED
  family                   = join("-", [ var.cd.name, var.env_name, "template" ])
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  execution_role_arn       = var.tearn
  cpu                      = 256
  memory                   = 512

  container_definitions = data.template_file.cd.rendered

  dynamic "volume" {
    for_each = toset(var.cd.mounts[*].src)
    content {
      name = volume.value

      efs_volume_configuration {
        file_system_id = var.volume_map[volume.value]
        # THIS NEEDS TO BE UPDATED
        root_directory = "/${var.env_name}/${var.cd.name}"
      }
    }
  }

  tags = var.common_tags
}

resource "aws_service_discovery_service" "sds" {
  name = var.cd.name

  dns_config {
    namespace_id = var.sr

    dns_records {
      ttl  = 60
      type = "A"
    }
    routing_policy = "MULTIVALUE"
  }
}

resource "aws_security_group" "sg" {
  name        = "${var.env_name}-${var.cd.name}"
  description = "Accept tcp on one port, full egress"
  vpc_id      = var.vpc

  ingress {
    from_port   = var.cd.port
    to_port     = var.cd.port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.common_tags
}

resource "aws_ecs_service" "service" {
  name            = var.cd.name
  cluster         = var.cluster
  task_definition = aws_ecs_task_definition.td.id
  desired_count   = 1
  launch_type     = "FARGATE"
  # Needed for EFS
  platform_version = "1.4.0"
  # Restart tasks when updating definition
  force_new_deployment = true

  network_configuration {
    subnets          = var.subnets
    security_groups  = [aws_security_group.sg.id]
    assign_public_ip = var.public_ip
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sds.arn
  }

  tags = var.common_tags
  lifecycle {
    ignore_changes = [task_definition]
  }
}
