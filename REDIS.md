# Redis in the gateway

This is a summary of redis usage in the gateway and my proposal on how to decouple
redis dependency. The goal is to make redis optional for the gateway to be operation.

This document also highlights the cons/pros of decoupling redis and its impact on
the gateway operations.

# General redis storages

There are four different stores used. The stores are differentiated with key prefix.

- `base` : prefix `apiKey-`
- `org` : prefix `orgkey.`
- `health` : prefix `apihealth.`
- `rpcAuth` : prefix `apiKey-`
- `rpcOrg` : prefix `orgkey.`


## Base store

Base store stores values under the `apiKey-` key prefix.

Used by
- `FallbackKeySesionManager`
- `APISpec.AuthManager` as the default store when `APISpec.AuthProvider.StorageEngine` is not provided.
- `APISpec.SessionManager` as the default storage when `APISpec.SessionProvider.StorageEngine` is not specified to `RPCStorageEngine`

Both of about api's uses this store as key/value store so its possible to be replaced.

# Health

Health store stores values under the `apihealth.` key prefix. I have reduced the required api to to
the following interface.

```go
type Health interface {
	Connect() bool
	SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{})
	GetRollingWindow(key string, per int64, pipeline bool) (int, []interface{})
}
```

`SetRollingWindow` and `GetRollingWindow` have little documentation, need more research on the possibility of
having native implementation of that.

This is used by `DefaultHealthChecker`

# Session

This is  used for session storage, used by `DefaultSessionManager` which is used both as
`APISpec.SessionManager` and `APISpec.OrgSessionManager`.

I have reduced the required api to

```go
type Session interface {
	GetKey(string) (string, error)
	GetMultiKey([]string) ([]string, error)
	GetRawKey(string) (string, error)
	SetKey(string, string, int64) error
	SetRawKey(string, string, int64) error
	GetKeys(string) []string
	DeleteKey(string) bool
	DeleteRawKey(string) bool
	Connect() bool
	IncrememntWithExpire(string, int64) int64
	SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{})
	GetRollingWindow(key string, per int64, pipeline bool) (int, []interface{})
	GetKeyPrefix() string
}
```