package main

import (
	"net/http"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
)

// startLambda wraps the existing http.Handler and starts the Lambda runtime.
// It uses the API Gateway HTTP API v2 (payload format 2.0) adapter, which is
// the modern, low-latency API Gateway type.  If you are using a REST API
// (v1), swap httpadapter.NewV2 for httpadapter.New.
func startLambda(handler http.Handler) {
	lambda.Start(httpadapter.NewV2(handler).ProxyWithContext)
}
