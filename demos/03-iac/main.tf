# Example Terraform — castellan derives a threat model straight from this.
#   castellan scan demos/03-iac/main.tf

resource "aws_s3_bucket" "uploads" {
  bucket = "acme-user-uploads"
  acl    = "public-read"            # castellan flags public exposure
}

resource "aws_db_instance" "primary" {
  engine            = "postgres"
  storage_encrypted = true          # castellan records the encryption control
  publicly_accessible = false
}

resource "aws_dynamodb_table" "sessions" {
  name = "sessions"
}

resource "aws_lambda_function" "api" {
  function_name = "acme-api"
  runtime       = "python3.12"
}

resource "aws_iam_role" "api_role" {
  name = "acme-api-role"
}

resource "aws_lb" "edge" {
  name = "acme-edge"
}
