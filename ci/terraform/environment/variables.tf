variable "base" {
  description = "State to use for base resources"
  type        = string
}

variable "infra" {
  description = "State to use for infra resources"
  type        = string
}

variable "name" {
  description = "The DNS record will be name-{gw,db,etc}"
  type        = string
}

variable "tyk" {
  description = "Image tag for the gateway service"
  type        = string
  default     = "master"
}

variable "tyk-analytics" {
  description = "Image tag for the dashboard service"
  type        = string
  default     = "master"
}

variable "tyk-pump" {
  description = "Image tag for the tyk-pump service"
  type        = string
  default     = "master"
}

variable "tyk-sink" {
  description = "Image tag for the mdcb service"
  type        = string
  default     = "master"
}

variable "raava" {
  description = "Image tag for the raava service"
  type        = string
  default     = "master"
}

variable "tyk-identity-broker" {
  description = "Image tag for the tib service"
  type        = string
  default     = "master"
}
