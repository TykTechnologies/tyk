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
	return &storage.RedisCluster{KeyPrefix: "upstreamOAuthCC-", ConnectionHandler: base.Gw.StorageConnectionHandler}
}

func getPasswordStorageHandler(base *BaseMiddleware) *storage.RedisCluster {
	return &storage.RedisCluster{KeyPrefix: "upstreamOAuthPW-", ConnectionHandler: base.Gw.StorageConnectionHandler}
}
