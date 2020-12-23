// This is our bucket for storing data. Access is set to private and leveraging lifecycle rules, we can expire our objects base on their prefix.

resource "aws_s3_bucket" "bucket" {
  bucket = "relaysecret-${var.deploymentname}"
  acl    = "private"

  lifecycle_rule {
    id      = "1day"
    enabled = true
    prefix = "1day/"
    expiration {
      days = 1
    }
  }

  lifecycle_rule {
    id      = "2day"
    enabled = true
    prefix = "2day/"
    expiration {
      days = 2
    }
  }

  lifecycle_rule {
    id      = "3day"
    enabled = true
    prefix = "3day/"
    expiration {
      days = 3
    }
  }

  lifecycle_rule {
    id      = "4day"
    enabled = true
    prefix = "4day/"
    expiration {
      days = 4
    }
  }

  lifecycle_rule {
    id      = "5day"
    enabled = true
    prefix = "5day/"
    expiration {
      days = 5
    }
  }

  lifecycle_rule {
    id      = "10day"
    enabled = true
    prefix = "10day/"
    expiration {
      days = 10
    }
  }

  lifecycle_rule {
    id      = "catchall"
    enabled = true
    expiration {
      days = 11
    }
  }

   cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET","PUT", "POST"]
    allowed_origins = ["*"]
    expose_headers = ["x-amz-meta-tag"]
    max_age_seconds = 3000
  }

   server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
      }
    }
  }

}

resource "aws_s3_bucket_public_access_block" "bucket" {
  bucket                  = aws_s3_bucket.bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
