package main

import (
	"github.com/TykTechnologies/tyk/gateway"

	_ "github.com/aws/aws-sdk-go-v2/service/kinesis"
	_ "github.com/aws/aws-sdk-go-v2/service/lambda"
)

func main() {

	gateway.Start()
}
