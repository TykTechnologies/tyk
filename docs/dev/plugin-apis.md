# Package ctx

```go
import (
	"github.com/TykTechnologies/tyk/ctx"
}
```

## Types

```go
type Key uint
```

## Consts

```go
const (
	SessionData Key = iota
	// Deprecated: UpdateSession was used to trigger a session update, use *SessionData.Touch instead.
	UpdateSession
	AuthToken
	HashedAuthToken
	VersionData
	VersionName
	VersionDefault
	OrgSessionContext
	ContextData
	RetainHost
	TrackThisEndpoint
	DoNotTrackThisEndpoint
	UrlRewritePath
	RequestMethod
	OrigRequestURL
	LoopLevel
	LoopLevelLimit
	ThrottleLevel
	ThrottleLevelLimit
	Trace
	CheckLoopLimits
	UrlRewriteTarget
	TransformedRequestMethod
	Definition
	RequestStatus
	GraphQLRequest
	GraphQLIsWebSocketUpgrade
	OASOperation

	// CacheOptions holds cache options required for cache writer middleware.
	CacheOptions
	OASDefinition
	SelfLooping
)
```

## Function symbols

- `func GetAuthToken (r *http.Request) string`
- `func GetDefinition (r *http.Request) *apidef.APIDefinition`
- `func GetOASDefinition (r *http.Request) *oas.OAS`
- `func GetSession (r *http.Request) *user.SessionState`
- `func SetDefinition (r *http.Request, s *apidef.APIDefinition)`
- `func SetOASDefinition (r *http.Request, s *oas.OAS)`
- `func SetSession (r *http.Request, s *user.SessionState, scheduleUpdate bool, hashKey ...bool)`

### GetDefinition

GetDefinition will return a deep copy of the API definition valid for the request.

```go
func GetDefinition(r *http.Request) *apidef.APIDefinition
```

### GetOASDefinition

GetOASDefinition will return a deep copy of the OAS API definition valid for the request.

```go
func GetOASDefinition(r *http.Request) *oas.OAS
```

### SetDefinition

SetDefinition sets an API definition object to the request context.

```go
func SetDefinition(r *http.Request, s *apidef.APIDefinition)
```

### SetOASDefinition

SetOASDefinition sets an OAS API definition object to the request context.

```go
func SetOASDefinition(r *http.Request, s *oas.OAS)
```

### GetAuthToken

```go
func GetAuthToken(r *http.Request) string
```

### GetSession

```go
func GetSession(r *http.Request) *user.SessionState
```

### SetSession

```go
func SetSession(r *http.Request, s *user.SessionState, scheduleUpdate bool, hashKey ...bool)
```

# Package user

```go
import (
	"github.com/TykTechnologies/tyk/user"
}
```

## Types

```go
// APILimit stores quota and rate limit on ACL level (per API)
type APILimit struct {
	RateLimit
	ThrottleInterval   float64 `json:"throttle_interval" msg:"throttle_interval"`
	ThrottleRetryLimit int     `json:"throttle_retry_limit" msg:"throttle_retry_limit"`
	MaxQueryDepth      int     `json:"max_query_depth" msg:"max_query_depth"`
	QuotaMax           int64   `json:"quota_max" msg:"quota_max"`
	QuotaRenews        int64   `json:"quota_renews" msg:"quota_renews"`
	QuotaRemaining     int64   `json:"quota_remaining" msg:"quota_remaining"`
	QuotaRenewalRate   int64   `json:"quota_renewal_rate" msg:"quota_renewal_rate"`
	SetBy              string  `json:"-" msg:"-"`
}
```

```go
// AccessDefinition defines which versions of an API a key has access to
// NOTE: when adding new fields it is required to map them from DBAccessDefinition
// in the gateway/policy.go:19
// TODO: is it possible to share fields?
type AccessDefinition struct {
	APIName              string                  `json:"api_name" msg:"api_name"`
	APIID                string                  `json:"api_id" msg:"api_id"`
	Versions             []string                `json:"versions" msg:"versions"`
	AllowedURLs          []AccessSpec            `bson:"allowed_urls" json:"allowed_urls" msg:"allowed_urls"` // mapped string MUST be a valid regex
	RestrictedTypes      []graphql.Type          `json:"restricted_types" msg:"restricted_types"`
	AllowedTypes         []graphql.Type          `json:"allowed_types" msg:"allowed_types"`
	Limit                APILimit                `json:"limit" msg:"limit"`
	FieldAccessRights    []FieldAccessDefinition `json:"field_access_rights" msg:"field_access_rights"`
	DisableIntrospection bool                    `json:"disable_introspection" msg:"disable_introspection"`

	AllowanceScope string `json:"allowance_scope" msg:"allowance_scope"`

	Endpoints Endpoints `json:"endpoints,omitempty" msg:"endpoints,omitempty"`
}
```

```go
// AccessSpecs define what URLS a user has access to an what methods are enabled
type AccessSpec struct {
	URL     string   `json:"url" msg:"url"`
	Methods []string `json:"methods" msg:"methods"`
}
```

```go
type BasicAuthData struct {
	Password string   `json:"password" msg:"password"`
	Hash     HashType `json:"hash_type" msg:"hash_type"`
}
```

```go
// Endpoint holds the configuration for endpoint rate limiting.
type Endpoint struct {
	Path    string          `json:"path,omitempty" msg:"path"`
	Methods EndpointMethods `json:"methods,omitempty" msg:"methods"`
}
```

```go
// EndpointMethod holds the configuration on endpoint method level.
type EndpointMethod struct {
	Name  string    `json:"name,omitempty" msg:"name,omitempty"`
	Limit RateLimit `json:"limit,omitempty" msg:"limit,omitempty"`
}
```

```go
// EndpointMethods is a collection of EndpointMethod.
type EndpointMethods []EndpointMethod
```

```go
// EndpointRateLimitInfo holds the information to process endpoint rate limits.
type EndpointRateLimitInfo struct {
	// KeySuffix is the suffix to use for the storage key.
	KeySuffix string
	// Rate is the allowance.
	Rate float64
	// Per is the rate limiting interval.
	Per float64
}
```

```go
// Endpoints is a collection of Endpoint.
type Endpoints []Endpoint
```

```go
// EndpointsMap is the type to hold endpoint rate limit information as a map.
type EndpointsMap map[string]RateLimit
```

```go
type FieldAccessDefinition struct {
	TypeName  string      `json:"type_name" msg:"type_name"`
	FieldName string      `json:"field_name" msg:"field_name"`
	Limits    FieldLimits `json:"limits" msg:"limits"`
}
```

```go
type FieldLimits struct {
	MaxQueryDepth int `json:"max_query_depth" msg:"max_query_depth"`
}
```

```go
type GraphAccessDefinition struct {
}
```

```go
type HashType string
```

```go
type JWTData struct {
	Secret string `json:"secret" msg:"secret"`
}
```

```go
type Monitor struct {
	TriggerLimits []float64 `json:"trigger_limits" msg:"trigger_limits"`
}
```

```go
// Policy represents a user policy
// swagger:model
type Policy struct {
	MID                           model.ObjectID                   `bson:"_id,omitempty" json:"_id" gorm:"primaryKey;column:_id"`
	ID                            string                           `bson:"id,omitempty" json:"id"`
	Name                          string                           `bson:"name" json:"name"`
	OrgID                         string                           `bson:"org_id" json:"org_id"`
	Rate                          float64                          `bson:"rate" json:"rate"`
	Per                           float64                          `bson:"per" json:"per"`
	QuotaMax                      int64                            `bson:"quota_max" json:"quota_max"`
	QuotaRenewalRate              int64                            `bson:"quota_renewal_rate" json:"quota_renewal_rate"`
	ThrottleInterval              float64                          `bson:"throttle_interval" json:"throttle_interval"`
	ThrottleRetryLimit            int                              `bson:"throttle_retry_limit" json:"throttle_retry_limit"`
	MaxQueryDepth                 int                              `bson:"max_query_depth" json:"max_query_depth"`
	AccessRights                  map[string]AccessDefinition      `bson:"access_rights" json:"access_rights"`
	HMACEnabled                   bool                             `bson:"hmac_enabled" json:"hmac_enabled"`
	EnableHTTPSignatureValidation bool                             `json:"enable_http_signature_validation" msg:"enable_http_signature_validation"`
	Active                        bool                             `bson:"active" json:"active"`
	IsInactive                    bool                             `bson:"is_inactive" json:"is_inactive"`
	Tags                          []string                         `bson:"tags" json:"tags"`
	KeyExpiresIn                  int64                            `bson:"key_expires_in" json:"key_expires_in"`
	Partitions                    PolicyPartitions                 `bson:"partitions" json:"partitions"`
	LastUpdated                   string                           `bson:"last_updated" json:"last_updated"`
	MetaData                      map[string]interface{}           `bson:"meta_data" json:"meta_data"`
	GraphQL                       map[string]GraphAccessDefinition `bson:"graphql_access_rights" json:"graphql_access_rights"`

	// Smoothing contains rate limit smoothing settings.
	Smoothing *apidef.RateLimitSmoothing `json:"smoothing" bson:"smoothing"`
}
```

```go
type PolicyPartitions struct {
	Quota      bool `bson:"quota" json:"quota"`
	RateLimit  bool `bson:"rate_limit" json:"rate_limit"`
	Complexity bool `bson:"complexity" json:"complexity"`
	Acl        bool `bson:"acl" json:"acl"`
	PerAPI     bool `bson:"per_api" json:"per_api"`
}
```

```go
// RateLimit holds rate limit configuration.
type RateLimit struct {
	// Rate is the allowed number of requests per interval.
	Rate float64 `json:"rate" msg:"rate"`
	// Per is the interval at which rate limit is enforced.
	Per float64 `json:"per" msg:"per"`

	// Smoothing contains rate limit smoothing settings.
	Smoothing *apidef.RateLimitSmoothing `json:"smoothing,omitempty" bson:"smoothing,omitempty"`
}
```

```go
// SessionState objects represent a current API session, mainly used for rate limiting.
// There's a data structure that's based on this and it's used for Protocol Buffer support, make sure to update "coprocess/proto/coprocess_session_state.proto" and generate the bindings using: cd coprocess/proto && ./update_bindings.sh
//
// swagger:model
type SessionState struct {
	LastCheck                     int64                       `json:"last_check" msg:"last_check"`
	Allowance                     float64                     `json:"allowance" msg:"allowance"`
	Rate                          float64                     `json:"rate" msg:"rate"`
	Per                           float64                     `json:"per" msg:"per"`
	ThrottleInterval              float64                     `json:"throttle_interval" msg:"throttle_interval"`
	ThrottleRetryLimit            int                         `json:"throttle_retry_limit" msg:"throttle_retry_limit"`
	MaxQueryDepth                 int                         `json:"max_query_depth" msg:"max_query_depth"`
	DateCreated                   time.Time                   `json:"date_created" msg:"date_created"`
	Expires                       int64                       `json:"expires" msg:"expires"`
	QuotaMax                      int64                       `json:"quota_max" msg:"quota_max"`
	QuotaRenews                   int64                       `json:"quota_renews" msg:"quota_renews"`
	QuotaRemaining                int64                       `json:"quota_remaining" msg:"quota_remaining"`
	QuotaRenewalRate              int64                       `json:"quota_renewal_rate" msg:"quota_renewal_rate"`
	AccessRights                  map[string]AccessDefinition `json:"access_rights" msg:"access_rights"`
	OrgID                         string                      `json:"org_id" msg:"org_id"`
	OauthClientID                 string                      `json:"oauth_client_id" msg:"oauth_client_id"`
	OauthKeys                     map[string]string           `json:"oauth_keys" msg:"oauth_keys"`
	Certificate                   string                      `json:"certificate" msg:"certificate"`
	BasicAuthData                 BasicAuthData               `json:"basic_auth_data" msg:"basic_auth_data"`
	JWTData                       JWTData                     `json:"jwt_data" msg:"jwt_data"`
	HMACEnabled                   bool                        `json:"hmac_enabled" msg:"hmac_enabled"`
	EnableHTTPSignatureValidation bool                        `json:"enable_http_signature_validation" msg:"enable_http_signature_validation"`
	HmacSecret                    string                      `json:"hmac_string" msg:"hmac_string"`
	RSACertificateId              string                      `json:"rsa_certificate_id" msg:"rsa_certificate_id"`
	IsInactive                    bool                        `json:"is_inactive" msg:"is_inactive"`
	ApplyPolicyID                 string                      `json:"apply_policy_id" msg:"apply_policy_id"`
	ApplyPolicies                 []string                    `json:"apply_policies" msg:"apply_policies"`
	DataExpires                   int64                       `json:"data_expires" msg:"data_expires"`
	Monitor                       Monitor                     `json:"monitor" msg:"monitor"`
	// Deprecated: EnableDetailRecording is deprecated. Use EnableDetailedRecording
	// going forward instead
	EnableDetailRecording   bool                   `json:"enable_detail_recording" msg:"enable_detail_recording"`
	EnableDetailedRecording bool                   `json:"enable_detailed_recording" msg:"enable_detailed_recording"`
	MetaData                map[string]interface{} `json:"meta_data" msg:"meta_data"`
	Tags                    []string               `json:"tags" msg:"tags"`
	Alias                   string                 `json:"alias" msg:"alias"`
	LastUpdated             string                 `json:"last_updated" msg:"last_updated"`
	IdExtractorDeadline     int64                  `json:"id_extractor_deadline" msg:"id_extractor_deadline"`
	SessionLifetime         int64                  `bson:"session_lifetime" json:"session_lifetime"`

	// Used to store token hash
	keyHash string
	KeyID   string `json:"-"`

	// Smoothing contains rate limit smoothing settings.
	Smoothing *apidef.RateLimitSmoothing `json:"smoothing" bson:"smoothing"`

	// modified holds the hint if a session has been modified for update.
	// use Touch() to set it, and IsModified() to get it.
	modified bool
}
```

## Consts

```go
const (
	HashPlainText HashType = ""
	HashBCrypt             = "bcrypt"
	HashSha256             = "sha256"
	HashMurmur32           = "murmur32"
	HashMurmur64           = "murmur64"
	HashMurmur128          = "murmur128"
)
```

## Function symbols

- `func IsHashType (t string) bool`
- `func NewSessionState () *SessionState`
- `func (*Policy) APILimit () APILimit`
- `func (*SessionState) CustomPolicies () (map[string]Policy, error)`
- `func (*SessionState) GetCustomPolicies () ([]Policy, error)`
- `func (*SessionState) GetQuotaLimitByAPIID (apiID string) (int64, int64, int64, int64)`
- `func (*SessionState) IsBasicAuth () bool`
- `func (*SessionState) IsModified () bool`
- `func (*SessionState) KeyHash () string`
- `func (*SessionState) KeyHashEmpty () bool`
- `func (*SessionState) Lifetime (respectKeyExpiration bool, fallback int64, forceGlobalSessionLifetime bool, globalSessionLifetime int64) int64`
- `func (*SessionState) MD5Hash () string`
- `func (*SessionState) PoliciesEqualTo (ids []string) bool`
- `func (*SessionState) PolicyIDs () []string`
- `func (*SessionState) Reset ()`
- `func (*SessionState) SetCustomPolicies (list []Policy)`
- `func (*SessionState) SetKeyHash (hash string)`
- `func (*SessionState) SetPolicies (ids ...string)`
- `func (*SessionState) TagsFromMetadata (data map[string]interface{}) bool`
- `func (*SessionState) Touch ()`
- `func (APILimit) Clone () *APILimit`
- `func (APILimit) IsEmpty () bool`
- `func (EndpointMethods) Contains (method string) bool`
- `func (Endpoints) Len () int`
- `func (Endpoints) Less (i,j int) bool`
- `func (Endpoints) Map () EndpointsMap`
- `func (Endpoints) Swap (i,j int)`
- `func (EndpointsMap) Endpoints () Endpoints`
- `func (PolicyPartitions) Enabled () bool`
- `func (RateLimit) Duration () time.Duration`

### CustomPolicies

CustomPolicies returns a map of custom policies on the session. To preserve policy order, use GetCustomPolicies instead.

```go
func (*SessionState) CustomPolicies() (map[string]Policy, error)
```

### GetCustomPolicies

GetCustomPolicies is like CustomPolicies but returns the list, preserving order.

```go
func (*SessionState) GetCustomPolicies() ([]Policy, error)
```

### GetQuotaLimitByAPIID

GetQuotaLimitByAPIID return quota max, quota remaining, quota renewal rate and quota renews for the given session

```go
func (*SessionState) GetQuotaLimitByAPIID(apiID string) (int64, int64, int64, int64)
```

### IsBasicAuth

IsBasicAuth returns whether the key is basic auth or not.

```go
func (*SessionState) IsBasicAuth() bool
```

### IsModified

IsModified will return true if session has been modified to trigger an update.

```go
func (*SessionState) IsModified() bool
```

### Lifetime

Lifetime returns the lifetime of a session. Global session lifetime has always precedence. Then, the session lifetime value in the key level takes precedence. However, if key `respectKeyExpiration` is `true`, when the key expiration has longer than the session lifetime, the key expiration is returned. It means even if the session lifetime finishes, it waits for the key expiration for physical removal.

```go
func (*SessionState) Lifetime(respectKeyExpiration bool, fallback int64, forceGlobalSessionLifetime bool, globalSessionLifetime int64) int64
```

### PoliciesEqualTo

PoliciesEqualTo compares and returns true if passed slice if IDs contains only current ApplyPolicies

```go
func (*SessionState) PoliciesEqualTo(ids []string) bool
```

### PolicyIDs

PolicyIDs returns the IDs of all the policies applied to this session. For backwards compatibility reasons, this falls back to ApplyPolicyID if ApplyPolicies is empty.

```go
func (*SessionState) PolicyIDs() []string
```

### Reset

Reset marks the session as not modified, skipping related updates.

```go
func (*SessionState) Reset()
```

### SetCustomPolicies

SetCustomPolicies sets custom policies into session metadata.

```go
func (*SessionState) SetCustomPolicies(list []Policy)
```

### TagsFromMetadata

TagsFromMetadata updates the session state with the tags from the metadata.

```go
func (*SessionState) TagsFromMetadata(data map[string]interface{}) bool
```

### Touch

Touch marks the session as modified, indicating that it should be updated.

```go
func (*SessionState) Touch()
```

### Clone

Clone does a deepcopy of APILimit.

```go
func (APILimit) Clone() *APILimit
```

### IsEmpty

IsEmpty checks if APILimit is empty.

```go
func (APILimit) IsEmpty() bool
```

### Contains

Contains is used to assert if a method exists in EndpointMethods.

```go
func (EndpointMethods) Contains(method string) bool
```

### Len

Len is used to implement sort interface.

```go
func (Endpoints) Len() int
```

### Less

Less is used to implement sort interface.

```go
func (Endpoints) Less(i, j int) bool
```

### Map

Map returns EndpointsMap of Endpoints using the key format [method:path]. If duplicate entries are found, it would get overwritten with latest entries Endpoints.

```go
func (Endpoints) Map() EndpointsMap
```

### Swap

Swap is used to implement sort interface.

```go
func (Endpoints) Swap(i, j int)
```

### Endpoints

Endpoints coverts EndpointsMap to Endpoints.

```go
func (EndpointsMap) Endpoints() Endpoints
```

### Enabled

Enabled reports if partitioning is enabled.

```go
func (PolicyPartitions) Enabled() bool
```

### Duration

Duration returns the time between two allowed requests at the defined rate. It's used to decide which rate limit has a bigger allowance.

```go
func (RateLimit) Duration() time.Duration
```

### IsHashType

```go
func IsHashType(t string) bool
```

### NewSessionState

```go
func NewSessionState() *SessionState
```

### APILimit

```go
func (*Policy) APILimit() APILimit
```

### KeyHash

```go
func (*SessionState) KeyHash() string
```

### KeyHashEmpty

```go
func (*SessionState) KeyHashEmpty() bool
```

### MD5Hash

```go
func (*SessionState) MD5Hash() string
```

### SetKeyHash

```go
func (*SessionState) SetKeyHash(hash string)
```

### SetPolicies

```go
func (*SessionState) SetPolicies(ids ...string)
```

# Package storage

```go
import (
	"github.com/TykTechnologies/tyk/storage"
}
```

## Types

```go
type AnalyticsHandler interface {
	Connect() bool
	AppendToSetPipelined(string, [][]byte)
	GetAndDeleteSet(string) []interface{}
	SetExp(string, int64) error   // Set key expiration
	GetExp(string) (int64, error) // Returns expiry of a key
}
```

```go
// ConnectionHandler is a wrapper around the storage connection.
// It allows to dynamically enable/disable talking with storage and
// mantain a connection map to different storage types.
type ConnectionHandler struct {
	connections   map[string]model.Connector
	connectionsMu *sync.RWMutex

	storageUp      atomic.Value
	disableStorage atomic.Value

	ctx       context.Context
	reconnect chan struct{}
}
```

```go
// DummyStorage is a simple in-memory storage structure used for testing or
// demonstration purposes. It simulates a storage system.
type DummyStorage struct {
	Data      map[string]string
	IndexList map[string][]string
}
```

```go
// Handler is a standard interface to a storage backend, used by
// AuthorisationManager to read and write key values to the backend
type Handler interface {
	GetKey(string) (string, error) // Returned string is expected to be a JSON object (user.SessionState)
	GetMultiKey([]string) ([]string, error)
	GetRawKey(string) (string, error)
	SetKey(string, string, int64) error // Second input string is expected to be a JSON object (user.SessionState)
	SetRawKey(string, string, int64) error
	SetExp(string, int64) error   // Set key expiration
	GetExp(string) (int64, error) // Returns expiry of a key
	GetKeys(string) []string
	DeleteKey(string) bool
	DeleteAllKeys() bool
	DeleteRawKey(string) bool
	DeleteRawKeys([]string) bool
	Connect() bool
	GetKeysAndValues() map[string]string
	GetKeysAndValuesWithFilter(string) map[string]string
	DeleteKeys([]string) bool
	Decrement(string)
	IncrememntWithExpire(string, int64) int64
	SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{})
	GetRollingWindow(key string, per int64, pipeline bool) (int, []interface{})
	GetSet(string) (map[string]string, error)
	AddToSet(string, string)
	GetAndDeleteSet(string) []interface{}
	RemoveFromSet(string, string)
	DeleteScanMatch(string) bool
	GetKeyPrefix() string
	AddToSortedSet(string, string, float64)
	GetSortedSetRange(string, string, string) ([]string, []float64, error)
	RemoveSortedSetRange(string, string, string) error
	GetListRange(string, int64, int64) ([]string, error)
	RemoveFromList(string, string) error
	AppendToSet(string, string)
	Exists(string) (bool, error)
}
```

```go
type MdcbStorage struct {
	local         Handler
	rpc           Handler
	logger        *logrus.Entry
	OnRPCCertPull func(key string, val string) error
}
```

```go
// RedisCluster is a storage manager that uses the redis database.
type RedisCluster struct {
	KeyPrefix   string
	HashKeys    bool
	IsCache     bool
	IsAnalytics bool

	ConnectionHandler *ConnectionHandler
	// RedisController must remain for compatibility with goplugins
	RedisController *RedisController

	storageMu        sync.Mutex
	kvStorage        model.KeyValue
	flusherStorage   model.Flusher
	queueStorage     model.Queue
	listStorage      model.List
	setStorage       model.Set
	sortedSetStorage model.SortedSet
}
```

```go
// RedisController acts as a shim to provide backward compatibility for Go plugins users.
// It facilitates connecting to Redis using Tyk's storage package in a way that doesn't break existing implementations.
// changes here are sensible
type RedisController struct {
	connection *ConnectionHandler
}
```

## Consts

```go
const (
	HashSha256    = crypto.HashSha256
	HashMurmur32  = crypto.HashMurmur32
	HashMurmur64  = crypto.HashMurmur64
	HashMurmur128 = crypto.HashMurmur128
)
```

```go
const (
	// DefaultConn is the default connection type. Not analytics and Not cache.
	DefaultConn = "default"
	// CacheConn is the cache connection type
	CacheConn = "cache"
	// AnalyticsConn is the analytics connection type
	AnalyticsConn = "analytics"
)
```

## Vars

```go
// ErrKeyNotFound is a standard error for when a key is not found in the storage engine
var ErrKeyNotFound = errors.New("key not found")
```

```go
var ErrMDCBConnectionLost = errors.New("mdcb connection is lost")
```

```go
var (
	HashStr = crypto.HashStr
	HashKey = crypto.HashKey
)
```

```go
var (
	GenerateToken = crypto.GenerateToken
	TokenHashAlgo = crypto.TokenHashAlgo
	TokenID       = crypto.TokenID
	TokenOrg      = crypto.TokenOrg
)
```

```go
var (
	// ErrRedisIsDown is returned when we can't communicate with redis
	ErrRedisIsDown = errors.New("storage: Redis is either down or was not configured")

	// ErrStorageConn is returned when we can't get a connection from the ConnectionHandler
	ErrStorageConn = fmt.Errorf("Error trying to get singleton instance: %w", ErrRedisIsDown)
)
```

## Function symbols

- `func NewConnectionHandler (ctx context.Context) *ConnectionHandler`
- `func NewConnector (connType string, conf config.Config) (model.Connector, error)`
- `func NewDummyStorage () *DummyStorage`
- `func NewMdcbStorage (local,rpc Handler, log *logrus.Entry, OnRPCCertPull func(key string, val string) error) *MdcbStorage`
- `func NewRedisController (ctx context.Context) *RedisController`
- `func (*ConnectionHandler) Connect (ctx context.Context, onConnect func(), conf *config.Config)`
- `func (*ConnectionHandler) Connected () bool`
- `func (*ConnectionHandler) DisableStorage (setStorageDown bool)`
- `func (*ConnectionHandler) Disconnect () error`
- `func (*ConnectionHandler) WaitConnect (ctx context.Context) bool`
- `func (*DummyStorage) AddToSet ( string, string)`
- `func (*DummyStorage) AddToSortedSet ( string, string, float64)`
- `func (*DummyStorage) AppendToSet (keyName string, value string)`
- `func (*DummyStorage) Decrement ( string)`
- `func (*DummyStorage) DeleteAllKeys () bool`
- `func (*DummyStorage) DeleteKey (key string) bool`
- `func (*DummyStorage) DeleteKeys ( []string) bool`
- `func (*DummyStorage) DeleteRawKey ( string) bool`
- `func (*DummyStorage) DeleteRawKeys ( []string) bool`
- `func (*DummyStorage) DeleteScanMatch (pattern string) bool`
- `func (*DummyStorage) Exists (keyName string) (bool, error)`
- `func (*DummyStorage) GetAndDeleteSet ( string) []interface{}`
- `func (*DummyStorage) GetExp ( string) (int64, error)`
- `func (*DummyStorage) GetKey (key string) (string, error)`
- `func (*DummyStorage) GetKeyPrefix () string`
- `func (*DummyStorage) GetKeys (pattern string) []string`
- `func (*DummyStorage) GetKeysAndValues () map[string]string`
- `func (*DummyStorage) GetKeysAndValuesWithFilter ( string) map[string]string`
- `func (*DummyStorage) GetListRange (keyName string, _,_ int64) ([]string, error)`
- `func (*DummyStorage) GetMultiKey (keys []string) ([]string, error)`
- `func (*DummyStorage) GetRawKey (key string) (string, error)`
- `func (*DummyStorage) GetRollingWindow ( string, int64, bool) (int, []interface{})`
- `func (*DummyStorage) GetSet ( string) (map[string]string, error)`
- `func (*DummyStorage) GetSortedSetRange ( string, string, string) ([]string, []float64, error)`
- `func (*DummyStorage) IncrememntWithExpire ( string, int64) int64`
- `func (*DummyStorage) RemoveFromList (keyName,value string) error`
- `func (*DummyStorage) RemoveFromSet ( string, string)`
- `func (*DummyStorage) RemoveSortedSetRange ( string, string, string) error`
- `func (*DummyStorage) SetExp ( string, int64) error`
- `func (*DummyStorage) SetKey (key,value string, _ int64) error`
- `func (*DummyStorage) SetRawKey ( string, string, int64) error`
- `func (*DummyStorage) SetRollingWindow ( string, int64, string, bool) (int, []interface{})`
- `func (*RedisCluster) AppendToSetPipelined (key string, values [][]byte)`
- `func (*RedisCluster) Client () (redis.UniversalClient, error)`
- `func (*RedisCluster) ControllerInitiated () bool`
- `func (*RedisCluster) GetKeyTTL (keyName string) (int64, error)`
- `func (*RedisCluster) IsMemberOfSet (keyName,value string) bool`
- `func (*RedisCluster) Lock (key string, timeout time.Duration) (bool, error)`
- `func (*RedisCluster) Publish (channel,message string) error`
- `func (*RedisCluster) ScanKeys (pattern string) ([]string, error)`
- `func (*RedisCluster) StartPubSubHandler (ctx context.Context, channel string, callback func(interface{})) error`
- `func (*RedisController) ConnectToRedis (ctx context.Context, onReconnect func(), conf *config.Config)`
- `func (*RedisController) DisableRedis (setRedisDown bool)`

### NewConnectionHandler

NewConnectionHandler creates a new connection handler not connected

```go
func NewConnectionHandler(ctx context.Context) *ConnectionHandler
```

### NewConnector

NewConnector creates a new storage connection.

```go
func NewConnector(connType string, conf config.Config) (model.Connector, error)
```

### NewDummyStorage

NewDummyStorage creates and returns a new instance of DummyStorage.

```go
func NewDummyStorage() *DummyStorage
```

### NewRedisController

NewRedisController initializes a new RedisController. This method ensures Go plugins can connect to Redis leveraging Tyk's internal storage mechanisms with minimal changes to their code.

```go
func NewRedisController(ctx context.Context) *RedisController
```

### Connect

Connect starts a go routine that periodically tries to connect to storage.

onConnect will be called when we have established a successful storage reconnection

```go
func (*ConnectionHandler) Connect(ctx context.Context, onConnect func(), conf *config.Config)
```

### Connected

Connected returns true if we are connected to redis

```go
func (*ConnectionHandler) Connected() bool
```

### DisableStorage

DisableStorage allows to dynamically enable/disable talking with storage

```go
func (*ConnectionHandler) DisableStorage(setStorageDown bool)
```

### Disconnect

Disconnect closes the connection to the storage

```go
func (*ConnectionHandler) Disconnect() error
```

### WaitConnect

WaitConnect waits until we are connected to the storage

```go
func (*ConnectionHandler) WaitConnect(ctx context.Context) bool
```

### AddToSet

AddToSet adds a value to a set associated with a key in DummyStorage; implementation pending.

```go
func (*DummyStorage) AddToSet(string, string)
```

### AddToSortedSet

AddToSortedSet inserts a value with a score into a sorted set in DummyStorage; implementation pending.

```go
func (*DummyStorage) AddToSortedSet(string, string, float64)
```

### AppendToSet

AppendToSet adds a new value to the end of a list associated with a key in DummyStorage.

```go
func (*DummyStorage) AppendToSet(keyName string, value string)
```

### Decrement

Decrement reduces the value of a specified key in DummyStorage; implementation pending.

```go
func (*DummyStorage) Decrement(string)
```

### DeleteAllKeys

DeleteAllKeys removes all keys and their associated data from the DummyStorage. This method is intended to provide a way to clear the entire storage, which can be particularly useful in testing scenarios to ensure a clean state before tests.

```go
func (*DummyStorage) DeleteAllKeys() bool
```

### DeleteKey

DeleteKey removes a specified key from DummyStorage, returning true if successful.

```go
func (*DummyStorage) DeleteKey(key string) bool
```

### DeleteKeys

DeleteKeys removes a list of keys from DummyStorage, returning a success status; not yet implemented.

```go
func (*DummyStorage) DeleteKeys([]string) bool
```

### DeleteRawKey

DeleteRawKey removes a specified key from DummyStorage, returning success status; not yet implemented.

```go
func (*DummyStorage) DeleteRawKey(string) bool
```

### DeleteRawKeys

DeleteRawKeys removes a set of raw keys from DummyStorage, returning success status; not yet implemented.

```go
func (*DummyStorage) DeleteRawKeys([]string) bool
```

### DeleteScanMatch

DeleteScanMatch deletes keys matching a pattern from DummyStorage, returning true if successful.

```go
func (*DummyStorage) DeleteScanMatch(pattern string) bool
```

### Exists

Exists checks if a key exists in either the IndexList or Data in DummyStorage; returns true if found.

```go
func (*DummyStorage) Exists(keyName string) (bool, error)
```

### GetAndDeleteSet

GetAndDeleteSet retrieves and then deletes a set associated with a key in DummyStorage; not implemented.

```go
func (*DummyStorage) GetAndDeleteSet(string) []interface{}
```

### GetExp

GetExp retrieves the expiration time of a specific key from the DummyStorage. This method accepts a string parameter representing the key and returns an int64 which is the expiration time associated with that key, along with an error.

```go
func (*DummyStorage) GetExp(string) (int64, error)
```

### GetKey

GetKey retrieves the value for a given key from DummyStorage, or an error if not found.

```go
func (*DummyStorage) GetKey(key string) (string, error)
```

### GetKeyPrefix

GetKeyPrefix returns the prefix used for keys in DummyStorage; not yet implemented.

```go
func (*DummyStorage) GetKeyPrefix() string
```

### GetKeys

GetKeys retrieves all keys matching a specified pattern from DummyStorage; currently supports only '*'.

```go
func (*DummyStorage) GetKeys(pattern string) []string
```

### GetKeysAndValues

GetKeysAndValues retrieves all key-value pairs from DummyStorage; currently not implemented.

```go
func (*DummyStorage) GetKeysAndValues() map[string]string
```

### GetKeysAndValuesWithFilter

GetKeysAndValuesWithFilter fetches key-value pairs matching a filter from DummyStorage; not implemented.

```go
func (*DummyStorage) GetKeysAndValuesWithFilter(string) map[string]string
```

### GetListRange

GetListRange retrieves a range of list elements from DummyStorage for a specified key; returns an error if not found.

```go
func (*DummyStorage) GetListRange(keyName string, _, _ int64) ([]string, error)
```

### GetMultiKey

GetMultiKey retrieves multiple values from the DummyStorage based on a slice of keys. It returns a slice of strings containing the values corresponding to each provided key, and an error if the operation cannot be completed.

```go
func (*DummyStorage) GetMultiKey(keys []string) ([]string, error)
```

### GetRawKey

GetRawKey retrieves the value associated with a given key from the DummyStorage. The method accepts a single string as the key and returns the corresponding string value. An error is also returned to indicate whether the retrieval was successful. Currently, this method is not implemented and will cause a panic if invoked.

```go
func (*DummyStorage) GetRawKey(key string) (string, error)
```

### GetRollingWindow

GetRollingWindow retrieves data for a specified rolling window; currently not implemented.

```go
func (*DummyStorage) GetRollingWindow(string, int64, bool) (int, []interface{})
```

### GetSet

GetSet retrieves a set of values associated with a key in DummyStorage; not yet implemented.

```go
func (*DummyStorage) GetSet(string) (map[string]string, error)
```

### GetSortedSetRange

GetSortedSetRange retrieves a range of values and scores from a sorted set in DummyStorage; not implemented.

```go
func (*DummyStorage) GetSortedSetRange(string, string, string) ([]string, []float64, error)
```

### IncrememntWithExpire

IncrememntWithExpire increments the value of a key and sets an expiry; not yet implemented.

```go
func (*DummyStorage) IncrememntWithExpire(string, int64) int64
```

### RemoveFromList

RemoveFromList eliminates a specific value from a list within DummyStorage; always returns nil.

```go
func (*DummyStorage) RemoveFromList(keyName, value string) error
```

### RemoveFromSet

RemoveFromSet deletes a specific value from a set in DummyStorage; currently not implemented.

```go
func (*DummyStorage) RemoveFromSet(string, string)
```

### RemoveSortedSetRange

RemoveSortedSetRange deletes a range of values from a sorted set in DummyStorage; yet to be implemented.

```go
func (*DummyStorage) RemoveSortedSetRange(string, string, string) error
```

### SetExp

SetExp updates the expiration time of a specific key in the DummyStorage. This method accepts two parameters: a string representing the key, and an int64 indicating the new expiration time.

```go
func (*DummyStorage) SetExp(string, int64) error
```

### SetKey

SetKey assigns a value to a key in DummyStorage with an expiration time; returns nil for success.

```go
func (*DummyStorage) SetKey(key, value string, _ int64) error
```

### SetRawKey

SetRawKey stores a value with a specified key in the DummyStorage. It takes three parameters: the key and value as strings, and an expiry time as int64. The expiry time could be used to simulate time-sensitive data storage or caching behavior. Currently, this method is not implemented and will trigger a panic if it is called. TODO: Proper implementation is needed for this method to handle data storage, or manage

```go
func (*DummyStorage) SetRawKey(string, string, int64) error
```

### SetRollingWindow

SetRollingWindow sets a rolling window for a key with specified parameters; implementation pending.

```go
func (*DummyStorage) SetRollingWindow(string, int64, string, bool) (int, []interface{})
```

### Client

Client will return a redis v8 RedisClient. This function allows implementation using the old storage clients.

```go
func (*RedisCluster) Client() (redis.UniversalClient, error)
```

### Lock

Lock implements a distributed lock in a cluster.

```go
func (*RedisCluster) Lock(key string, timeout time.Duration) (bool, error)
```

### ScanKeys

ScanKeys will return all keys according to the pattern.

```go
func (*RedisCluster) ScanKeys(pattern string) ([]string, error)
```

### StartPubSubHandler

StartPubSubHandler will listen for a signal and run the callback for every subscription and message event.

```go
func (*RedisCluster) StartPubSubHandler(ctx context.Context, channel string, callback func(interface{})) error
```

### ConnectToRedis

ConnectToRedis sets up the connection to Redis using specified configuration. It abstracts the connection logic, allowing Go plugins to seamlessly integrate without direct interaction with the underlying storage logic.

```go
func (*RedisController) ConnectToRedis(ctx context.Context, onReconnect func(), conf *config.Config)
```

### DisableRedis

DisableRedis toggles the Redis connection's active status, providing a mechanism to dynamically manage the connection state in response to runtime conditions or configurations.

```go
func (*RedisController) DisableRedis(setRedisDown bool)
```

### NewMdcbStorage

```go
func NewMdcbStorage(local, rpc Handler, log *logrus.Entry, OnRPCCertPull func(key string, val string) error) *MdcbStorage
```

### AppendToSetPipelined

```go
func (*RedisCluster) AppendToSetPipelined(key string, values [][]byte)
```

### ControllerInitiated

```go
func (*RedisCluster) ControllerInitiated() bool
```

### GetKeyTTL

```go
func (*RedisCluster) GetKeyTTL(keyName string) (int64, error)
```

### IsMemberOfSet

```go
func (*RedisCluster) IsMemberOfSet(keyName, value string) bool
```

### Publish

```go
func (*RedisCluster) Publish(channel, message string) error
```

# Package log

```go
import (
	"github.com/TykTechnologies/tyk/log"
}
```

## Types

```go
// JSONFormatter formats logs into parsable json.
type JSONFormatter struct {
	// TimestampFormat sets the format used for marshaling timestamps.
	// The format to use is the same than for time.Format or time.Parse from the standard
	// library.
	// The standard Library already provides a set of predefined format.
	TimestampFormat string

	// DisableTimestamp allows disabling automatic timestamps in output.
	DisableTimestamp bool

	// DataKey allows users to put all the log entry parameters into a nested dictionary at a given key.
	DataKey string
}
```

```go
// RawFormatter returns the logrus entry message as bytes.
type RawFormatter struct{}
```

```go
// TranslationFormatter handles message reformatting with translations.
type TranslationFormatter struct {
	logrus.Formatter
}
```

## Function symbols

- `func Get () *logrus.Logger`
- `func GetRaw () *logrus.Logger`
- `func LoadTranslations (thing map[string]interface{})`
- `func NewFormatter (format string) logrus.Formatter`
- `func (*JSONFormatter) Format (entry *logrus.Entry) ([]byte, error)`

### Get

Get returns the default configured logger.

```go
func Get() *logrus.Logger
```

### GetRaw

GetRaw is used internally. Should likely be removed first, do not rely on it.

```go
func GetRaw() *logrus.Logger
```

### LoadTranslations

LoadTranslations takes a map[string]interface and flattens it to map[string]string. Because translations have been loaded - we internally override log the formatter. Nested entries are accessible using dot notation.

Example: `{"foo": {"bar": "baz"}}` Flattened: `foo.bar: baz`

```go
func LoadTranslations(thing map[string]interface{})
```

### Format

Format renders a single log entry

```go
func (*JSONFormatter) Format(entry *logrus.Entry) ([]byte, error)
```

### NewFormatter

```go
func NewFormatter(format string) logrus.Formatter
```
