// This is our bucket for storing data. Access is set to private and leveraging lifecycle rules, we can expire our objects base on their prefix.
provider "aws" {
  alias               = "euregion"
  region              = "eu-central-1"
}


resource "aws_s3_bucket" "bucket_eu" {
  provider = aws.euregion
  bucket = "relaysecret-${var.deploymentname}-eu"
}


resource "aws_s3_bucket_acl" "bucket_eu_acl" {
  provider = aws.euregion
  bucket = aws_s3_bucket.bucket_eu.id
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_eu_encryption" {
  provider = aws.euregion
  bucket = aws_s3_bucket.bucket_eu.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "AES256"
    }
  }
}



resource "aws_s3_bucket_cors_configuration" "bucket_eu_corsheader" {
  provider = aws.euregion
  bucket = aws_s3_bucket.bucket_eu.id
  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET","PUT", "POST"]
    allowed_origins = ["*"]
    expose_headers = ["x-amz-meta-tag"]
    max_age_seconds = 3000
  }
}


resource "aws_s3_bucket_lifecycle_configuration" "bucket_eu_lifecycle" {
  provider = aws.euregion
  bucket = aws_s3_bucket.bucket_eu.id

  rule {
    id = "1day"
    status = "Enabled"
    filter {
      prefix = "1day/"
    }
    expiration {
      days = 1
    }
  }
  rule {
    id = "2day"
    status = "Enabled"
    filter {
      prefix = "2day/"
    }
    expiration {
      days = 2
    }
  }
  rule {
    id = "3day"
    status = "Enabled"
    filter {
      prefix = "3day/"
    }
    expiration {
      days = 3
    }
  }
  rule {
    id = "4day"
    status = "Enabled"
    filter {
      prefix = "4day/"
    }
    expiration {
      days = 4
    }
  }
  rule {
    id = "5day"
    status = "Enabled"
    filter {
      prefix = "5day/"
    }
    expiration {
      days = 5
    }
  }
  rule {
    id = "10day"
    status = "Enabled"
    filter {
      prefix = "10day/"
    }
    expiration {
      days = 1
    }
  }
  rule {
    id = "catchall"
    status = "Enabled"
    expiration {
      days = 11
    }
  }
}

resource "aws_s3_bucket_public_access_block" "bucket_eu" {
  provider = aws.euregion
  bucket                  = aws_s3_bucket.bucket_eu.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

output "bucketeu" {
  value = aws_s3_bucket.bucket_eu.arn
}