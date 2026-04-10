//go:build ee || dev

package gateway

import (
	"github.com/TykTechnologies/tyk/ee/middleware/upstreamoauth"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/storage"
)

func getUpstreamOAuthMw(base *BaseMiddleware) TykMiddleware {
	mwSpec := model.MergedAPI{APIDefinition: base.Spec.APIDefinition}
	upstreamOAuthMw := upstreamoauth.NewMiddleware(
		base.Gw,
		base,
		mwSpec,
		getClientCredentialsStorageHandler(base),
		getPasswordStorageHandler(base),
	)

	return WrapMiddleware(base, upstreamOAuthMw)
}

func getClientCredentialsStorageHandler(base *BaseMiddleware) *storage.RedisCluster {
	handler := &storage.RedisCluster{KeyPrefix: "upstreamOAuthCC-", ConnectionHandler: base.Gw.StorageConnectionHandler}
	handler.Connect()
	return handler
}

func getPasswordStorageHandler(base *BaseMiddleware) *storage.RedisCluster {
	handler := &storage.RedisCluster{KeyPrefix: "upstreamOAuthPW-", ConnectionHandler: base.Gw.StorageConnectionHandler}
	handler.Connect()
	return handler
}
