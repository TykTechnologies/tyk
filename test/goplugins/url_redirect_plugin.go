package main

import (
	"context"
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/log"
)

var logger = log.Get()

func HeaderBasedRedirect(rw http.ResponseWriter, r *http.Request) {
	routeTo := r.Header.Get("X-Route-To")
	if routeTo == "" {
		return
	}

	logger.Info("[PLUGIN] X-Route-To header: ", routeTo)

	// Use the UpstreamHostOverride context key
	// This can be either a host or a full URL
	newCtx := context.WithValue(r.Context(), ctx.UpstreamHostOverride, routeTo)
	*r = *r.WithContext(newCtx)

	logger.Info("[PLUGIN] Set UpstreamHostOverride to: ", routeTo)
}

func main() {}
