variable "deploymentname" {}
variable "relaysecretfile" {}
variable "relaysecrethandler" {}

variable "envvar" {
  type    = map(string)
  default = {}
}