package main

import (
	"github.com/TykTechnologies/tyk/gateway"

	_ "github.com/TykTechnologies/tyk/ee/register"
)

func main() {
	gateway.Start()
}
