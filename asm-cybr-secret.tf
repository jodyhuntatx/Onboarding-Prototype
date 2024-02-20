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
#################################
# Resources

locals {
    asset_csv = csvdecode(file("${path.module}/${var.csv_file_path}"))
}

# ### Resource example for bulk import ###
resource "dsfhub_data_source" "bulk-database-import" {


# should be from template
variable "rds_secret" {
    for_each = { for asset in local.asset_csv : asset.asset_id => asset }
    server_type = each.value["Server Type"]
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
