variable "cluster" {
  description = "ECS cluster arn"
  type        = string
}

variable "cdt" {
  description = "Container definition template file"
  type        = string
  default     = "templates/cd-awsvpc.tpl"
}

variable "env_name" {
  description = "Environment name, also log group name"
  type        = string
}

variable "cd" {
  description = "Container definition object to fill in the template"
  type = object({
    name      = string
    command   = list(string)
    port      = number
    log_group = string
    image     = string
    mounts    = list(object({src=string, dest=string}))
    env       = list(map(string))
    secrets   = list(map(string))
    region    = string
  })
}

variable "tearn" {
  description = "Task execution role ARN"
  type        = string
}

variable "sr" {
  description = "Service registry for the tasks, a private dns namespace"
  type        = string
  default     = ""
}

variable "public_ip" {
  description = "Should the fargate container have a public IP?"
  type        = bool
  default     = false
}

variable "common_tags" {
  description = "Tags to apply to every resource that can be tagged"
  type        = map(string)
}

variable "vpc" {
  description = "VPC to use, the task will be attached to networks below"
  type        = string
}

variable "subnets" {
  description = "Subnets that the task will access"
  type        = list(any)
}

variable "volume_map" {
  description = "map of volume name to EFS id"
  type        = map(string)
}
