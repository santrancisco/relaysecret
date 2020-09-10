
# A data source containing the lambda function
data "archive_file" "lambda" {
  source_file = "../code/lambda.py"
  type = "zip"
  output_path = "../code/lambda.zip"
}


variable "accountids" {
  type = list(string)
}


variable "deploymentname" {
  type = string
}

provider "aws" {
  version             = "~> 3.5.0"
  region              = "us-east-1"
  allowed_account_ids = var.accountids
}

variable "APPURL" {
    default="devmode"
}

module "relaysecret" {
  source             = "./modules/relaysecret"
  deploymentname     = var.deploymentname
  relaysecretfile    = "${data.archive_file.lambda.output_path}"
  relaysecrethandler = "lambda.app_handler"
  envvar = {
    "APPURL"              = var.APPURL
  }
}

output "base_url" {
  value = module.relaysecret.base_url
}