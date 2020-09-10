// relaysecret lambda function
resource "aws_lambda_function" "relaysecret" {
  function_name = "relaysecret-${var.deploymentname}-function"

  filename         = var.relaysecretfile
  source_code_hash = filebase64sha256(var.relaysecretfile)

  handler = var.relaysecrethandler
  runtime = "python3.8"
  timeout = 20
  role    = aws_iam_role.relaysecret.arn

  environment {
    variables = merge(var.envvar,local.extraenvar)
  }
}

locals {
  extraenvar = {
    "BUCKETNAME" = aws_s3_bucket.bucket.id
    "SEED"       = "relaysecret-${var.deploymentname}"
  }
}

// relaysecret lambda cloudwatch log
resource "aws_cloudwatch_log_group" "relaysecret" {
  name              = "/aws/lambda/${aws_lambda_function.relaysecret.function_name}"
  retention_in_days = 5
}

// Allow api gateway to trigger our relaysecret lambda function
resource "aws_lambda_permission" "apigw_lambda" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.relaysecret.arn
  principal     = "apigateway.amazonaws.com"

  // More: http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-control-access-using-iam-policies-to-invoke-api.html
  source_arn = "${aws_api_gateway_deployment.relaysecret.execution_arn}/*/*"
  /*--*/
}

resource "aws_api_gateway_rest_api" "relaysecret" {
  name        = "relaysecret-${var.deploymentname}-api"
  description = "API gateway for ${aws_lambda_function.relaysecret.function_name}"
}

// Create an API Gateway resource, which is usually a certain path inside the REST API. {proxy+} is a wildcard that match any URL though
// https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-set-up-simple-proxy.html
resource "aws_api_gateway_resource" "proxy" {
  rest_api_id = aws_api_gateway_rest_api.relaysecret.id
  parent_id   = aws_api_gateway_rest_api.relaysecret.root_resource_id
  path_part   = "{proxy+}"
}

// Gateway method set to ANY for the proxy wildcard above.. we want our relaysecret to handle all requests
resource "aws_api_gateway_method" "proxy" {
  rest_api_id   = aws_api_gateway_rest_api.relaysecret.id
  resource_id   = aws_api_gateway_resource.proxy.id
  http_method   = "GET"
  authorization = "NONE"
}

// Trigger lambda immediately, lambda handler needs to handle requestContext from 
// https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
resource "aws_api_gateway_integration" "proxy_to_lambda" {
  rest_api_id = aws_api_gateway_rest_api.relaysecret.id
  resource_id = aws_api_gateway_method.proxy.resource_id
  http_method = aws_api_gateway_method.proxy.http_method
  # Lambda functions can only be invoked via HTTP POST - https://amzn.to/2owMYNh
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.relaysecret.invoke_arn
}

// Replicate the above setting but notice this is for the api gateway "root_resource_id"
resource "aws_api_gateway_method" "proxy_root" {
  rest_api_id   = aws_api_gateway_rest_api.relaysecret.id
  resource_id   = aws_api_gateway_rest_api.relaysecret.root_resource_id
  http_method   = "GET"
  authorization = "NONE"
}

// Trigger lambda immediately, lambda handler needs to handle requestContext from 
// https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
resource "aws_api_gateway_integration" "proxy_root_to_lambda" {
  rest_api_id = aws_api_gateway_rest_api.relaysecret.id
  resource_id = aws_api_gateway_method.proxy_root.resource_id
  http_method = aws_api_gateway_method.proxy_root.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.relaysecret.invoke_arn
}


resource "aws_api_gateway_deployment" "relaysecret" {
  depends_on = [
    aws_api_gateway_integration.proxy_to_lambda,
    aws_api_gateway_integration.proxy_root_to_lambda,
  ]

  rest_api_id = aws_api_gateway_rest_api.relaysecret.id
  stage_name  = "alpha"
}

output "base_url" {
  value = aws_api_gateway_deployment.relaysecret.invoke_url
}
