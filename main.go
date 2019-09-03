package main

import (
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/pkg/profile"
)

func main() {
	defer profile.Start(profile.ProfilePath("."), profile.MemProfile, profile.MemProfileRate(1)).Stop()
	gateway.Start()
}
