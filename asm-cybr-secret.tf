variable "secret_id" {
  type        = string
  description = "The name of the secret in AWS Secrets Manager."
}

###############################
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }
  required_version = ">= 1.2.0"
}

provider "aws" {
  region = "us-east-1"
}

#################################
# Resources

# aws_secretsmanager_secret: ASM Secret Name & tags

resource "aws_secretsmanager_secret" "cybr_secret" {
  name                    = var.secret_id
  description             = "example secret"
  recovery_window_in_days = 0
  tags = {
    "Sourced by CyberArk" = ""
    "CyberArk Safe"       = "JodyOnboard"
  }
}

# should be from template
variable "rds_secret" {
  default = {
    address              = "rdsaddress"
    username             = "rdsuser"
    password             = "rdspassword"
    engine               = "mysql"
    host                 = "foo.bar.baz"
    port                 = "3306"
    dbname               = "mysql-db1"
    dbInstanceIdentifier = "cluster2"
  }

  type = map(string)
}

# asm_secret_version: ASM Secret Value
resource "aws_secretsmanager_secret_version" "cybr" {
  secret_id     = aws_secretsmanager_secret.cybr_secret.id
  secret_string = jsonencode(var.rds_secret)
}

# standin resource for CyberArk Account
resource "terraform_data" "cybr-account" {
  input      = var.secret_id
  depends_on = [aws_secretsmanager_secret_version.cybr]

  provisioner "local-exec" {
    command = "./onboardSecret.sh ${self.input}"
  }

  provisioner "local-exec" {
    when    = destroy
    command = "./offboardSecret.sh ${self.input}"
  }
}
