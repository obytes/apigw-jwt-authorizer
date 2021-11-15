# APIGW JWT Authorizer

<img src="docs/images/fingerprint.gif" width="100%">

JWT Authorizer to use with AWS APIGW as a Custom Lambda Authorizer for Websocket APIs

## Features

This Custom JWT Authorizer can be used by any API Gateway Websocket route, it's:

- **Interoperable**: It can validate JWT tokens for any JWT Token Provider (Firebase, Auth0 ...)
- **Fast**: It can cache public keys, so it doesn't request them every time from the Token Provider.
- **Secure**: It can validate token signature, expiration time and allowed audiences.

## Environment Variables:

- **JWT_ISSUER_JWKS_URI** - The issuer JWKs URI
    - Firebase: https://www.googleapis.com/service_accounts/v1/metadata/x509/securetoken@system.gserviceaccount.com
    - Cognito: https://cognito-idp.YOUR_REGION_NAME.amazonaws.com/YOUR_USER_POOL_ID/.well-known/jwks.json
    - Auth0: https://YOUR_DOMAIN/.well-known/jwks.json
    - etc
    
- **JWT_AUTHORIZED_AUDIENCES** - A comma separated list of the audiences authorized to consume the API.

- **JWT_VERIFY_EXPIRATION** - Whether to verify token expiration, default is "true".

- **AUTHORIZED_APIS** - A comma separated list of the APIs to authorize token's holder to.

## Usage

Create an API Gateway REQUEST Authorizer

```hcl
resource "aws_apigatewayv2_authorizer" "request_authorizer" {
  name                       = "${var.prefix}-request-authz"
  api_id                     = aws_apigatewayv2_api._.id
  authorizer_type            = "REQUEST"
  identity_sources           = [
    "route.request.querystring.authorization",
    #"route.request.header.Authorization",
  ]
  authorizer_uri             = module.request_authorizer.lambda["invoke_arn"]
  authorizer_credentials_arn = aws_iam_role._.arn
}
```

Give API Gateway permission to invoke the Authorizer

```hcl
resource "aws_lambda_permission" "allow_apigw" {
  statement_id  = local.prefix
  action        = "lambda:InvokeFunction"
  function_name = var.request_authorizer.name
  qualifier     = var.request_authorizer.alias
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api._.execution_arn}/${aws_apigatewayv2_stage._.name}/*"
}
```

Assign the authorizer to the websocket route you want to secure, usually it's the `$connect` route

```hcl
resource "aws_apigatewayv2_route" "connect" {
  api_id         = var.api_id

  # UPSTREAM
  target         = "integrations/${aws_apigatewayv2_integration.ack_presence.id}"
  route_key      = "$connect"
  operation_name = "Acknowledge user presence"

  # AUTHORIZATION
  authorizer_id      = aws_apigatewayv2_authorizer.request.id
  authorization_type = "CUSTOM"
  api_key_required   = false

  route_response_selection_expression = "$default"
}
```

Finally, pass the JWT token as query param `authorization` when connecting to websocket

```javascript
accessToken = "LONG_USER_JWT_TOKEN"
let endpoint = `wss://live.kodhive.com/push?authorization=${accessToken}`;
ws = new Sockette(endpoint);
```

## Deploy

Before deploying the authorizer, version control it on your github account and then call these Terraform modules to 
provision the authorizer lambda and CI/CD pipeline:

```hcl
# Authorizer Lambda
module "request_authorizer" {
  source      = "git::https://github.com/obytes/terraform-aws-codeless-lambda.git//modules/lambda"
  prefix      = "${local.prefix}-authorizer"
  common_tags = local.common_tags

  handler = "app.main.handle"
  envs    = {
    AUTHORIZED_APIS          = join(",", module.gateway.authorized_apis)
    JWT_ISSUER_JWKS_URI      = var.issuer_jwks_uri
    JWT_AUTHORIZED_AUDIENCES = join(",", var.authorized_audiences)
    JWT_VERIFY_EXPIRATION    = var.verify_token_expiration
  }
}

# CI/CD
module "authorizer_ci" {
  source      = "git::https://github.com/obytes/terraform-aws-lambda-ci.git//modules/ci"
  prefix      = "${local.prefix}-authorizer-ci"
  common_tags = var.common_tags

  # Lambda
  lambda                   = module.authorizer.lambda
  app_src_path             = "sources"
  packages_descriptor_path = "sources/requirements/lambda.txt"

  # Github
  pre_release = true
  s3_artifacts = {
    arn = aws_s3_bucket.artifacts.arn
    bucket = aws_s3_bucket.artifacts.bucket
  }
  github = {
    owner = "obytes"
    webhook_secret = "not-secret"
    connection_arn = "arn:aws:codestar-connections:us-east-1:{ACCOUNT_ID}:connection/{CONNECTION_ID}"
  }
  github_repository = {
    name = "apigw-jwt-authorizer"
    branch = "main"
  }
  # Notifications
  ci_notifications_slack_channels = {
    info = "ci-info"
    alert = "ci-alert"
  }
}
```