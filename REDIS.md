These are notes/thoughts on state of redis usage in the gateway. This will be changing
as I uncover new details. The goal is to have a clear picture on the path to make
redis optional for the gateway to operate.

Feel free to update/comment if there is anything missing or any suggestion.


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
	GetKey(string) (string, error) // Returned string is expected to be a JSON object (user.SessionState)
	GetMultiKey([]string) ([]string, error)
	GetRawKey(string) (string, error)
	SetKey(string, string, int64) error // Second input string is expected to be a JSON object (user.SessionState)
	SetRawKey(string, string, int64) error
	GetKeys(string) []string
	DeleteKey(string) bool
	DeleteRawKey(string) bool
	Connect() bool
	IncrememntWithExpire(string, int64) int64
	SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{})
	GetRollingWindow(key string, per int64, pipeline bool) (int, []interface{})
	GetKeyPrefix() string
	DeleteAllKeys() bool
}
```
Used by
- `FallbackKeySesionManager`
- `APISpec.AuthManager`
- `APISpec.SessionManager`


# Auth store

This is more of an interface for retrieving api session. I have reduced the api to

```go
type Auth interface {
	GetKey(string) (string, error) // Returned string is expected to be a JSON object (user.SessionState)
	Connect() bool
}
```


# Analytics store

All analytics are sent to redis. This store exposes an api for storing analytics values.
It is used by `RedisAnalyticsHandler`.

I have reduced the api to

```go
type Analytics interface {
	Connect() bool
	AppendToSetPipelined(string, []string)
	GetAndDeleteSet(string) []interface{} //used in tests
}
```

There are several options for to replace the current setup. Because this sends
to redis which is then scrapped by tyk-pump and stored to mongo.

Options include

- collect but discard the analytics data.
- support specifying and endpoint that analytics data will be pushed to in interval
- send directly to mongo. This will need to refactor `tyk-pump` taking out aggregate calculations into a separate library that will be shared.



# Webhooks store

THis is used by `WebHookHandler` to cache event checksum. I have reduced the api
interface to.

```go
type WebHook interface {
	GetKey(string) (string, error)
	SetKey(key string, value string, expires int64) error
	Connect() bool
}
```

This is very easy to replace as any in memory cache with support for expiration will do.


# Host store

This is used by `HostCheckerManager` to cache hosts when checking api host uptime.

I have reduced the api to,

```go

type Host interface {
	GetKey(string) (string, error)
	SetKey(string, string, int64) error
	DeleteKey(string) bool
	Connect() bool
	// AppendToSet currently stores data direct to redis which is picked up by
	// tyk-pum because this is analytics data about host uptime.
	AppendToSet(string, string)
}
```

Replacing this with an in memory cache should be straight forward, although `AppendToSet` will require to have some kind of set data structure.


# Cache store

This is used by `RedisCacheMiddleware` to cache responses.

I have reduced the api to,

```go
type Cache interface {
	GetKey(string) (string, error)
	SetKey(string, string, int64) error
	DeleteKey(string) bool
	Connect() bool
}
```

Replacing this is also not complicated as it is just basic key/value store.

# Oauth store

This is used by `RedisOsinStorageInterface` for managing tokens.

I have reduced the api interface to,

```go
type Oauth interface {
	GetKey(string) (string, error)
	GetRawKey(string) (string, error)
	SetKey(string, string, int64) error
	SetRawKey(string, string, int64) error
	DeleteKey(string) bool
	Connect() bool
	GetKeysAndValuesWithFilter(string) map[string]string
	GetSet(string) (map[string]string, error)
	AddToSet(string, string)
	RemoveFromSet(string, string)
	AddToSortedSet(string, string, float64)
	GetSortedSetRange(string, string, string) ([]string, []float64, error)
	RemoveSortedSetRange(string, string, string) error
}
```

Replacing this will require much work, as we need to have efficient/ high performance sets
implementation also, the cache should support expirations.


# High performance cache libraries

- [x] [github.com/dgraph-io/ristretto](https://github.com/dgraph-io/ristretto)