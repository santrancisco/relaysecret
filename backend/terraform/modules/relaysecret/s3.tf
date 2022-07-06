// This is our bucket for storing data. Access is set to private and leveraging lifecycle rules, we can expire our objects base on their prefix.



resource "aws_s3_bucket" "bucket" {
  bucket = "relaysecret-${var.deploymentname}"
}


resource "aws_s3_bucket_acl" "bucket_acl" {
  bucket = aws_s3_bucket.bucket.id
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_encryption" {
  bucket = aws_s3_bucket.bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "AES256"
    }
  }
}



resource "aws_s3_bucket_cors_configuration" "bucket_corsheader" {
  bucket = aws_s3_bucket.bucket.id
  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET","PUT", "POST"]
    allowed_origins = ["*"]
    expose_headers = ["x-amz-meta-tag"]
    max_age_seconds = 3000
  }
}


resource "aws_s3_bucket_lifecycle_configuration" "bucket_lifecycle" {
  bucket = aws_s3_bucket.bucket.id

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

resource "aws_s3_bucket_public_access_block" "bucket" {
  bucket                  = aws_s3_bucket.bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
