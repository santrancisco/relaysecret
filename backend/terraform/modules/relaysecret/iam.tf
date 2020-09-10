// This is the IAM role that our lambda use - assume role policy must allow AWS lambda service
resource "aws_iam_role" "relaysecret" {
  name = "relaysecret-${var.deploymentname}-lambda"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

// IAM role policy for relaysecret service
resource "aws_iam_role_policy" "relaysecret" {
  name   = "relaysecret-${var.deploymentname}-lambda-permissions"
  role   = aws_iam_role.relaysecret.id
  policy = data.aws_iam_policy_document.relaysecret.json
}

data "aws_iam_policy_document" "relaysecret" {
  // Allow relaysecret function to manage our bucket for creating, deleting files.
  statement {
    sid    = "S3Permission"
    effect = "Allow"

    actions = [
      "s3:*",
    ]
    resources = [
        "${aws_s3_bucket.bucket.arn}",
        "${aws_s3_bucket.bucket.arn}/*"
    ]
  }
  // Allow lambda function to create loggroup and push its execution log
  statement {
      sid  = "CloudwatchLogging"
      effect = "Allow"

      actions=[
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]

      resources = ["arn:aws:logs:*:*:*"]
  }

}

output "lambda_role_arn" {
  value = aws_iam_role.relaysecret.arn
}