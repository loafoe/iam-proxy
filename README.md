# iam-proxy
HSDP IAM proxy. Position this in front of your app for instant HSDP IAM support. The proxy will
redirect to IAM for authentication and generate a JWT token which embeds `iam_access_token` and 
`iam_refresh_token` claims containing the IAM tokens for use in your upstream service.

## Features
- Extremely lean, should run in 16MB RAM
- Minimal configuration needs
- Stateless, so scalable if needed
- Single purpose

## TODO
- Encrypt IAM claims with `SharedSecret`
- Add group claims based on IAM Introspect
- Timely Token refreshes

## Usage
Gather all required params and deploy as a Docker container to Cloud foundry or other hosting service. Make
The upstream should check for presence of the JWT and validate it using the `SharedSecret`. You can perform
an IAM introspect with the access token claim to retrieve addtional permissions for the user.

## Parameters
Setting parameters is done through the environment:

| Name                     | Description | Default |
|--------------------------|-------------|---------|
| IAM_PROXY_APP_URL        | The browser URL of the app | `http://localhost:35444` |
| IAM_PROXY_REGION         | The HSDP IAM Region to use | `us-east` |
| IAM_PROXY_ENVIRONMENT    | The HSDP IAM Environment to use | `client-test` | 
| IAM_PROXY_CLIENT_ID      | The HSDP IAM OAuth2 client ID to use | |
| IAM_PROXY_CLIENT_SECRET  | THe HSDP IAM OAuth2 client Secret to use | |
| IAM_PROXY_SHARED_SECRET  | The `SharedSecret` to use | `secret` |
| IAM_PROXY_COOKIE_DOMAIN  | The Cookie domain | inferred from browser URL |
| IAM_PROXY_UPSTREAM_URL   | The Upstream URL of the app to proxy | |
| IAM_PROXY_PORT           | The port to listen on for connections | `35444` |

## Building
```shell
> docker buildx build --load -f Dockerfile.buildx -t iam-proxy:latest  --platform linux/amd64,linux/arm64 .
```

## Deploying
```shell
> docker run --rm -it -p 35444:35444 -e IAM_PROXY_APP_URL=... -e IAM_PROXY_REGION=... -e ... iam-proxy:latest`
```

## Contact / Getting help

Ask on the `#terraform` channel on HSDP Slack. We intend to provide a Terraform module shortly, which will be the preferred method for deployment.

# License
License is MIT
