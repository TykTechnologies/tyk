# Package ./build

```go
import (
	"github.com/TykTechnologies/tyk/internal/build"
}
```

## Vars

```go
// These values are injected at build-time from CI.
var (
	// Version contains the tagged gateway version. It may contain a `rc` suffix,
	// which may be delimited with `-rc` or any other suffix. Follows Semver+Tag.
	Version = "v5.5.0-dev"

	// BuiltBy contains the environment name from the build (goreleaser).
	BuiltBy string = "dev"

	// BuildDate is the date the build was made at.
	BuildDate string

	// Commit is the commit hash for the build source.
	Commit string
)
```

# Package ./cache

```go
import (
	"github.com/TykTechnologies/tyk/internal/cache"
}
```

## Types

```go
// Cache holds key-value pairs with a TTL.
type Cache struct {
	// expiration (<= 0 means never expire).
	expiration time.Duration

	// janitor holds a clean up goroutine
	janitor *Janitor

	// cache items and protecting mutex
	mu    sync.RWMutex
	items map[string]Item
}
```

```go
type Item struct {
	Object     any
	Expiration int64
}
```

```go
// Janitor is responsible for performing periodic cleanup operations.
type Janitor struct {
	Interval time.Duration
	stop     chan bool
}
```

```go
// Repository interface is the API signature for an object cache.
type Repository interface {
	Get(string) (interface{}, bool)
	Set(string, interface{}, int64)
	Delete(string)
	Count() int
	Flush()

	Close()
}
```

## Consts

```go
const (
	// For use with functions that take an expiration time. Equivalent to
	// passing in the same expiration duration as was given to NewCache().
	DefaultExpiration = 0
)
```

## Function symbols

- `func New (defaultExpiration,cleanupInterval int64) Repository`
- `func NewCache (expiration,cleanupInterval time.Duration) *Cache`
- `func NewJanitor (interval time.Duration, cleanup func()) *Janitor`
- `func (*Cache) Cleanup ()`
- `func (*Cache) Close ()`
- `func (*Cache) Count () int`
- `func (*Cache) Delete (k string)`
- `func (*Cache) Flush ()`
- `func (*Cache) Get (k string) (any, bool)`
- `func (*Cache) Items () map[string]Item`
- `func (*Cache) Set (k string, x any, d time.Duration)`
- `func (*Janitor) Run (cleanup func())`
- `func (Item) Expired () bool`

### New

New creates a new cache instance.

```go
func New(defaultExpiration, cleanupInterval int64) Repository
```

### NewCache

NewCache creates a new *Cache for storing items with a TTL.

```go
func NewCache(expiration, cleanupInterval time.Duration) *Cache
```

### NewJanitor

NewJanitor returns a new Janitor that performs cleanup at the specified interval.

```go
func NewJanitor(interval time.Duration, cleanup func()) *Janitor
```

### Cleanup

Cleanup will delete all expired items from the cache map.

```go
func (*Cache) Cleanup()
```

### Close

Close implements an io.Closer; Invoke it to cancel the cleanup goroutine.

```go
func (*Cache) Close()
```

### Count

Count returns the number of items in cache, including expired items. Expired items get cleaned up by the janitor periodically.

```go
func (*Cache) Count() int
```

### Delete

Delete an item from the cache. Does nothing if the key is not in the cache.

```go
func (*Cache) Delete(k string)
```

### Flush

Flush deletes all items from the cache.

```go
func (*Cache) Flush()
```

### Get

Get an item from the cache. Returns the item or nil, and a bool indicating whether the key was found.

```go
func (*Cache) Get(k string) (any, bool)
```

### Items

Items copies all unexpired items in the cache into a new map and returns it.

```go
func (*Cache) Items() map[string]Item
```

### Set

Add an item to the cache, replacing any existing item. If the duration is 0, the cache's expiration time is used. If it is -1, the item never expires.

```go
func (*Cache) Set(k string, x any, d time.Duration)
```

### Run

Run starts the janitor which calls the provided cleanup function at every interval.

```go
func (*Janitor) Run(cleanup func())
```

### Expired

Returns true if the item has expired.

```go
func (Item) Expired() bool
```

# Package ./uuid

```go
import (
	"github.com/TykTechnologies/tyk/internal/uuid"
}
```

## Function symbols

- `func New () string`
- `func NewHex () string`
- `func Valid (id string) bool`

### New

New returns a V4 UUID.

```go
func New() string
```

### NewHex

NewHex returns a V4 UUID without dashes.

```go
func NewHex() string
```

### Valid

Valid returns true if id is parsed as UUID without error.

```go
func Valid(id string) bool
```

# Package ./crypto

```go
import (
	"github.com/TykTechnologies/tyk/internal/crypto"
}
```

## Types

```go
// CipherSuite stores information about a cipher suite.
// It shadows tls.CipherSuite but translates TLS versions to strings.
type CipherSuite struct {
	ID       uint16   `json:"id"`
	Name     string   `json:"name"`
	Insecure bool     `json:"insecure"`
	TLS      []string `json:"tls"`
}
```

```go
type Hash = crypto.Hash
```

## Consts

```go
// `{"` in base64
const B64JSONPrefix = "ey"
```

```go
const DefaultHashAlgorithm = "murmur64"
```

```go
const MongoBsonIdLength = 24
```

```go
const SHA256 = crypto.SHA256
```

```go
const (
	HashSha256    = "sha256"
	HashMurmur32  = "murmur32"
	HashMurmur64  = "murmur64"
	HashMurmur128 = "murmur128"
)
```

## Vars

```go
var (
	ErrCertExpired = errors.New("Certificate has expired")
)
```

## Function symbols

- `func Decrypt (key []byte, cryptoText string) string`
- `func Encrypt (key []byte, str string) string`
- `func GenCertificate (template *x509.Certificate, setLeaf bool) ([]byte, []byte, []byte, tls.Certificate)`
- `func GenServerCertificate () ([]byte, []byte, []byte, tls.Certificate)`
- `func GenerateClientCertAndKeyChain (tb testing.TB, rootCertPEM,rootKeyPEM []byte) (*bytes.Buffer, *bytes.Buffer, error)`
- `func GenerateClientCertAndKeyPEM (tb testing.TB, rootCertPEM,rootKeyPEM []byte) (*bytes.Buffer, *bytes.Buffer, error)`
- `func GenerateRSAPublicKey (tb testing.TB) []byte`
- `func GenerateRootCertAndKey (tb testing.TB) ([]byte, []byte, error)`
- `func GenerateServerCertAndKeyChain (tb testing.TB, rootCertPEM,rootKeyPEM []byte) (*bytes.Buffer, *bytes.Buffer, error)`
- `func GenerateServerCertAndKeyPEM (tb testing.TB, rootCertPEM,rootKeyPEM []byte) (*bytes.Buffer, *bytes.Buffer, error)`
- `func GenerateToken (orgID,keyID,hashAlgorithm string) (string, error)`
- `func GetCiphers () []*CipherSuite`
- `func GetPaddedString (str string) []byte`
- `func HashKey (in string, hashKey bool) string`
- `func HashStr (in string, withAlg ...string) string`
- `func HexSHA256 (cert []byte) string`
- `func IsPublicKey (cert *tls.Certificate) bool`
- `func NewCipher (in *tls.CipherSuite) *CipherSuite`
- `func PrefixPublicKeyCommonName (blockBytes []byte) *x509.Certificate`
- `func ResolveCipher (cipherName string) (uint16, error)`
- `func RightPad2Len (s,padStr string, overallLen int) string`
- `func TLSVersions (in []uint16) []string`
- `func TokenHashAlgo (token string) string`
- `func TokenID (token string) (string, error)`
- `func TokenOrg (token string) string`
- `func ValidateRequestCerts (r *http.Request, certs []*tls.Certificate) error`
- `func (*CipherSuite) String () string`

### Decrypt

Decrypt from base64 to decrypted string

```go
func Decrypt(key []byte, cryptoText string) string
```

### Encrypt

encrypt string to base64 crypto using AES

```go
func Encrypt(key []byte, str string) string
```

### GenCertificate

GenCertificate generates a self-signed X.509 certificate based on the provided template. It returns the certificate, private key, combined PEM bytes, and a tls.Certificate.

The function generates a private key, sets the certificate fields if not already set, and creates the certificate in PEM format. Use NotBefore and NotAfter in template to control the certificate expiry. If the NotBefore field of the template is zero-valued, it is set to the current time. If the NotAfter field is zero-valued, it is set to one hour after the NotBefore time. The generated certificate is then encoded to PEM format along with the private key.

A tls.Certificate is created using the PEM-encoded certificate and private key. If setLeaf is true, the certificate's Leaf field is set to the template.

```go
func GenCertificate(template *x509.Certificate, setLeaf bool) ([]byte, []byte, []byte, tls.Certificate)
```

### GenServerCertificate

GenServerCertificate generates a self-signed server certificate for "localhost" with DNS names "localhost" and IP addresses 127.0.0.1 and ::. It returns the certificate, private key, combined PEM bytes, and a tls.Certificate.

```go
func GenServerCertificate() ([]byte, []byte, []byte, tls.Certificate)
```

### GenerateClientCertAndKeyChain

GenerateClientCertAndKeyChain generates a client certificate and private key signed by the given root certificate and key, and includes the root certificate in the chain for testing purposes. It returns the client certificate chain and private key in PEM format along with an error, if any.

Parameters:
- tb: The testing.TB instance to log errors and fail the test if necessary.
- rootCertPEM: The root certificate in PEM format.
- rootKeyPEM: The root private key in PEM format.

Returns:
- *bytes.Buffer: The client certificate chain in PEM format.
- *bytes.Buffer: The client private key in PEM format.
- error: Any error encountered during the generation.

```go
func GenerateClientCertAndKeyChain(tb testing.TB, rootCertPEM, rootKeyPEM []byte) (*bytes.Buffer, *bytes.Buffer, error)
```

### GenerateClientCertAndKeyPEM

GenerateClientCertAndKeyPEM generates a client certificate and private key signed by the given root certificate and key for testing purposes. It returns the client certificate and private key in PEM format along with an error, if any.

Parameters:
- tb: The testing.TB instance to log errors and fail the test if necessary.
- rootCertPEM: The root certificate in PEM format.
- rootKeyPEM: The root private key in PEM format.

Returns:
- *bytes.Buffer: The client certificate in PEM format.
- *bytes.Buffer: The client private key in PEM format.
- error: Any error encountered during the generation.

```go
func GenerateClientCertAndKeyPEM(tb testing.TB, rootCertPEM, rootKeyPEM []byte) (*bytes.Buffer, *bytes.Buffer, error)
```

### GenerateRSAPublicKey

GenerateRSAPublicKey generates an RSA public key.

```go
func GenerateRSAPublicKey(tb testing.TB) []byte
```

### GenerateRootCertAndKey

GenerateRootCertAndKey generates a root certificate and private key for testing purposes. It returns the root certificate and private key in PEM format along with an error, if any.

Parameters:
- tb: The testing.TB instance to log errors and fail the test if necessary.

Returns:
- []byte: The root certificate in PEM format.
- []byte: The root private key in PEM format.
- error: Any error encountered during the generation.

```go
func GenerateRootCertAndKey(tb testing.TB) ([]byte, []byte, error)
```

### GenerateServerCertAndKeyChain

GenerateServerCertAndKeyChain generates a server certificate and private key signed by the given root certificate and key, and includes the root certificate in the chain for testing purposes. It returns the server certificate chain and private key in PEM format along with an error, if any.

Parameters:
- tb: The testing.TB instance to log errors and fail the test if necessary.
- rootCertPEM: The root certificate in PEM format.
- rootKeyPEM: The root private key in PEM format.

Returns:
- *bytes.Buffer: The server certificate chain in PEM format.
- *bytes.Buffer: The server private key in PEM format.
- error: Any error encountered during the generation.

```go
func GenerateServerCertAndKeyChain(tb testing.TB, rootCertPEM, rootKeyPEM []byte) (*bytes.Buffer, *bytes.Buffer, error)
```

### GenerateServerCertAndKeyPEM

GenerateServerCertAndKeyPEM generates a server certificate and private key signed by the given root certificate and key for testing purposes. It returns the server certificate and private key in PEM format along with an error, if any.

Parameters:
- tb: The testing.TB instance to log errors and fail the test if necessary.
- rootCertPEM: The root certificate in PEM format.
- rootKeyPEM: The root private key in PEM format.

Returns:
- *bytes.Buffer: The server certificate in PEM format.
- *bytes.Buffer: The server private key in PEM format.
- error: Any error encountered during the generation.

```go
func GenerateServerCertAndKeyPEM(tb testing.TB, rootCertPEM, rootKeyPEM []byte) (*bytes.Buffer, *bytes.Buffer, error)
```

### GenerateToken

GenerateToken generates a token. If hashing algorithm is empty, it uses legacy key generation.

```go
func GenerateToken(orgID, keyID, hashAlgorithm string) (string, error)
```

### GetCiphers

GetCiphers generates a list of CipherSuite from the available ciphers.

```go
func GetCiphers() []*CipherSuite
```

### HexSHA256

HexSHA256 calculates the SHA256 hash of the provided certificate bytes and returns the result as a hexadecimal string.

```go
func HexSHA256(cert []byte) string
```

### IsPublicKey

IsPublicKey verifies if given certificate is a public key only.

```go
func IsPublicKey(cert *tls.Certificate) bool
```

### NewCipher

NewCipher translates tls.CipherSuite to our local type.

```go
func NewCipher(in *tls.CipherSuite) *CipherSuite
```

### PrefixPublicKeyCommonName

PrefixPublicKeyCommonName returns x509.Certificate with prefixed CommonName. This is used in UI/response to hint the type certificate during listing.

```go
func PrefixPublicKeyCommonName(blockBytes []byte) *x509.Certificate
```

### ResolveCipher

ResolveCipher translates a string representation of a cipher to its uint16 ID. It's case-insensitive when matching the cipher by name.

```go
func ResolveCipher(cipherName string) (uint16, error)
```

### TLSVersions

TLSVersions will return a list of TLS versions as a string.

```go
func TLSVersions(in []uint16) []string
```

### ValidateRequestCerts

ValidateRequestCerts validates client TLS certificates against a list of allowed certificates configured in API definition. It returns an error if TLS is not enabled, the client certificate is missing, or if it is not allowed or expired.

```go
func ValidateRequestCerts(r *http.Request, certs []*tls.Certificate) error
```

### String

String returns a human-readable string for the cipher.

```go
func (*CipherSuite) String() string
```

### GetPaddedString

```go
func GetPaddedString(str string) []byte
```

### HashKey

```go
func HashKey(in string, hashKey bool) string
```

### HashStr

```go
func HashStr(in string, withAlg ...string) string
```

### RightPad2Len

```go
func RightPad2Len(s, padStr string, overallLen int) string
```

### TokenHashAlgo

```go
func TokenHashAlgo(token string) string
```

### TokenID

```go
func TokenID(token string) (string, error)
```

### TokenOrg

```go
func TokenOrg(token string) string
```

# Package ./debug2

```go
import (
	"github.com/TykTechnologies/tyk/internal/debug2"
}
```

## Types

```go
// Record captures goroutine states
type Record struct {
	buffer  *bytes.Buffer
	ignores []string
}
```

## Function symbols

- `func NewRecord () *Record`
- `func (*Record) Count () int`
- `func (*Record) SetIgnores (ignores []string)`
- `func (*Record) Since (last *Record) *Record`
- `func (*Record) String () string`

### NewRecord

NewRecord creates a new Record and populates it with the current goroutine dump.

```go
func NewRecord() *Record
```

### Count

Count returns the number of unique goroutines in the Record.

```go
func (*Record) Count() int
```

### Since

Since compares the current Record with another Record and returns a new Record containing only the goroutines found in the current Record but not in the last.

```go
func (*Record) Since(last *Record) *Record
```

### String

String implements the fmt.Stringer interface, providing a formatted view of the goroutines in the Record.

```go
func (*Record) String() string
```

### SetIgnores

```go
func (*Record) SetIgnores(ignores []string)
```

# Package ./errors

```go
import (
	"github.com/TykTechnologies/tyk/internal/errors"
}
```

## Vars

```go
var (
	New            = errors.New
	Is             = errors.Is
	Join           = errors.Join
	Unwrap         = errors.Unwrap
	ErrUnsupported = errors.ErrUnsupported
)
```

## Function symbols

- `func Formatter (errs []error) string`

### Formatter

```go
func Formatter(errs []error) string
```

# Package ./event

```go
import (
	"github.com/TykTechnologies/tyk/internal/event"
}
```

## Types

```go
// Event is the type to bind events.
type Event string
```

```go
// HandlerName to be used as handler codes in API definitions.
type HandlerName string
```

```go
// Kind is the action to be performed when an event is triggered, to be used in OAS API definition.
type Kind string
```

## Consts

```go
const (
	// QuotaExceeded is the event triggered when quota for a specific key has been exceeded.
	QuotaExceeded Event = "QuotaExceeded"
	// AuthFailure is the event triggered when key has failed authentication or has attempted access and was denied.
	AuthFailure Event = "AuthFailure"
	// UpstreamOAuthError is the event triggered when an upstream OAuth error occurs.
	UpstreamOAuthError Event = "UpstreamOAuthError"
	// KeyExpired is the event triggered when a key has attempted access but is expired.
	KeyExpired Event = "KeyExpired"
	// VersionFailure is the event triggered when a key has attempted access to a version it does not have permission to access.
	VersionFailure Event = "VersionFailure"
	// OrgQuotaExceeded is the event triggered when a quota for a specific organisation has been exceeded.
	OrgQuotaExceeded Event = "OrgQuotaExceeded"
	// OrgRateLimitExceeded is the event triggered when rate limit has been exceeded for a specific organisation.
	OrgRateLimitExceeded Event = "OrgRateLimitExceeded"
	// TriggerExceeded is the event triggered on a configured trigger point.
	TriggerExceeded Event = "TriggerExceeded"
	// BreakerTriggered is the event triggered when either a BreakerTripped, or a BreakerReset event occurs;
	// a status code in the metadata passed to the event handler will indicate which of these events was triggered.
	BreakerTriggered Event = "BreakerTriggered"
	// BreakerTripped is the event triggered when a circuit breaker on a path trips and a service is taken offline.
	BreakerTripped Event = "BreakerTripped"
	// BreakerReset is the event triggered when the circuit breaker comes back on-stream
	BreakerReset Event = "BreakerReset"
	// HostDown is the event triggered when hostchecker finds a host is down/not available.
	HostDown Event = "HostDown"
	// HostUp is the event triggered when hostchecker finds a host is back being available after being offline.
	HostUp Event = "HostUp"
	// TokenCreated is the event triggered when a token is created.
	TokenCreated Event = "TokenCreated"
	// TokenUpdated is the event triggered when a token is updated.
	TokenUpdated Event = "TokenUpdated"
	// TokenDeleted is the event triggered when a token is deleted.
	TokenDeleted Event = "TokenDeleted"
)
```

```go
// Rate limiter events
const (
	// RateLimitExceeded is the event triggered when rate limit has been exceeded for a specific key.
	RateLimitExceeded Event = "RatelimitExceeded"

	// RateLimitSmoothingUp is the event triggered when rate limit smoothing increases the currently enforced rate limit.
	RateLimitSmoothingUp Event = "RateLimitSmoothingUp"

	// RateLimitSmoothingDown is the event triggered when rate limit smoothing decreases the currently enforced rate limit.
	RateLimitSmoothingDown Event = "RateLimitSmoothingDown"
)
```

```go
const (
	// LogHandler is the HandlerName used in classic API definition for log event handler.
	LogHandler HandlerName = "eh_log_handler"
	// WebHookHandler is the HandlerName used in classic API definition for webhook event handler.
	WebHookHandler HandlerName = "eh_web_hook_handler"
	// JSVMHandler is the HandlerName used in classic API definition for javascript event handler.
	JSVMHandler HandlerName = "eh_dynamic_handler"
	// CoProcessHandler is the HandlerName used in classic API definition for coprocess event handler.
	CoProcessHandler HandlerName = "cp_dynamic_handler"
)
```

```go
const (
	// WebhookKind is the action to be specified in OAS API definition.
	WebhookKind Kind = "webhook"
	// JSVMKind represents a custom action to be executed when an event is triggered.
	JSVMKind Kind = "custom"
)
```

## Function symbols

- `func Add (r *http.Request, event Event)`
- `func EncodeRequestToEvent (r *http.Request) string`
- `func Get (ctx context.Context) []Event`
- `func Set (ctx context.Context, events []Event) context.Context`
- `func String (e Event) string`

### Add

Add adds an event to the request context. Add adds an event to the context value in the request.

```go
func Add(r *http.Request, event Event)
```

### EncodeRequestToEvent

EncodeRequestToEvent will write the request out in wire protocol and encode it to base64 and store it in an Event object

```go
func EncodeRequestToEvent(r *http.Request) string
```

### Get

Get retrieves the events from the context. Get will get the events from context. It will return nil if no events in context.

```go
func Get(ctx context.Context) []Event
```

### Set

Set updates the context with the provided events and returns the new context. Set will update the context with a new value and return the new context.

```go
func Set(ctx context.Context, events []Event) context.Context
```

### String

String will return the description for the event if any. If no description exists, it will return the event value.

```go
func String(e Event) string
```

# Package ./reflect

```go
import (
	"github.com/TykTechnologies/tyk/internal/reflect"
}
```

## Function symbols

- `func Cast (src any) (*T, error)`
- `func Clone (t T) T`
- `func IsEmpty (i interface{}) bool`
- `func IsZero (v reflect.Value) bool`

### Cast

Cast converts a value of type any to a specified type T. It does this by first marshaling the source value to JSON, and then unmarshaling the JSON byte slice into the destination type T.

This function can be useful when dealing with dynamic or untyped data, such as data obtained from external sources or user input.

The function returns a pointer to the converted value of type *T, and an error value if the conversion fails.

Example:

```
type Person struct {
	Name string
	Age  int
}

data := map[string]any{
	"Name": "Alice",
	"Age":  30,
}

var p Person
pptr, err := Cast[Person](data)
if err != nil {
	// Handle error
}
p = *pptr
```

Note: The Cast function assumes that the source value can be marshaled and unmarshaled as JSON. If the source value contains types or values that cannot be represented in JSON, the function will return an error.

```go
func Cast(src any) (*T, error)
```

### Clone

Clone is a hacky way to wrap the generic declaration. Using `var Clone = clone.Clone` is not allowed.

```go
func Clone(t T) T
```

### IsEmpty

IsEmpty checks whether a field should be set to empty and omitted from OAS JSON.

```go
func IsEmpty(i interface{}) bool
```

### IsZero

IsZero is a customized implementation of reflect.Value.IsZero. The built-in function accepts slice, map and pointer fields having 0 length as not zero. In OAS, we would like them to be counted as empty so we separated slice, map and pointer to different cases.

```go
func IsZero(v reflect.Value) bool
```

# Package ./service/gojsonschema

```go
import (
	"github.com/TykTechnologies/tyk/internal/service/gojsonschema"
}
```

## Types

```go
type JSONLoader = gojsonschema.JSONLoader
```

```go
type ResultError = gojsonschema.ResultError
```

## Vars

```go
var NewBytesLoader = gojsonschema.NewBytesLoader
```

```go
var NewGoLoader = gojsonschema.NewGoLoader
```

```go
var Validate = gojsonschema.Validate
```

# Package ./maps

```go
import (
	"github.com/TykTechnologies/tyk/internal/maps"
}
```

## Types

```go
// FlatMap is alias of map[string]string.
type FlatMap map[string]string
```

```go
// StringMap holds a concurrency safe, type safe access to map[string]string.
// Access is protected with a sync.RWMutex, optimized for reads.
type StringMap struct {
	mu   sync.RWMutex
	data map[string]string
}
```

## Function symbols

- `func Flatten (data map[string]interface{}) (FlatMap, error)`
- `func NewStringMap () *StringMap`
- `func (*StringMap) Get (key string) (string, bool)`
- `func (*StringMap) Set (key,value string)`

### Flatten

Flatten transforms deep map to flat map.

```go
func Flatten(data map[string]interface{}) (FlatMap, error)
```

### NewStringMap

NewStringMap returns a new *StringMap.

```go
func NewStringMap() *StringMap
```

### Get

Get returns the value, and if it existed in the map.

```go
func (*StringMap) Get(key string) (string, bool)
```

### Set

Set will set a value to a key in the map.

```go
func (*StringMap) Set(key, value string)
```

# Package ./otel

```go
import (
	"github.com/TykTechnologies/tyk/internal/otel"
}
```

## Types

```go
// general type aliases
type (
	TracerProvider = tyktrace.Provider

	OpenTelemetry = otelconfig.OpenTelemetry

	Sampling = otelconfig.Sampling

	SpanAttribute = tyktrace.Attribute

	Span = tyktrace.Span
)
```

## Consts

```go
const (
	NON_VERSIONED = "Non Versioned"
)
```

```go
// span const
const (
	SPAN_STATUS_OK    = tyktrace.SPAN_STATUS_OK
	SPAN_STATUS_ERROR = tyktrace.SPAN_STATUS_ERROR
	SPAN_STATUS_UNSET = tyktrace.SPAN_STATUS_UNSET
)
```

## Vars

```go
var APIKeyAliasAttribute = semconv.TykAPIKeyAlias
```

```go
var APIKeyAttribute = semconv.TykAPIKey
```

```go
var OAuthClientIDAttribute = semconv.TykOauthID
```

```go
// HTTP Handlers
var (
	HTTPHandler = tyktrace.NewHTTPHandler

	HTTPRoundTripper = tyktrace.NewHTTPTransport
)
```

## Function symbols

- `func APIVersionAttribute (version string) SpanAttribute`
- `func AddTraceID (ctx context.Context, w http.ResponseWriter)`
- `func ApidefSpanAttributes (apidef *apidef.APIDefinition) []SpanAttribute`
- `func ContextWithSpan (ctx context.Context, span tyktrace.Span) context.Context`
- `func GatewayResourceAttributes (gwID string, isDataplane bool, groupID string, isSegmented bool, segmentTags []string) []SpanAttribute`
- `func InitOpenTelemetry (ctx context.Context, logger *logrus.Logger, gwConfig *OpenTelemetry, id string, version string, useRPC bool, groupID string, isSegmented bool, segmentTags []string) TracerProvider`
- `func SpanFromContext (ctx context.Context) tyktrace.Span`

### ApidefSpanAttributes

Span attributes related functions

```go
func ApidefSpanAttributes(apidef *apidef.APIDefinition) []SpanAttribute
```

### InitOpenTelemetry

InitOpenTelemetry initializes OpenTelemetry - it returns a TracerProvider which can be used to create a tracer. If OpenTelemetry is disabled or misconfigured, a NoopProvider is returned.

```go
func InitOpenTelemetry(ctx context.Context, logger *logrus.Logger, gwConfig *OpenTelemetry, id string, version string, useRPC bool, groupID string, isSegmented bool, segmentTags []string) TracerProvider
```

### APIVersionAttribute

```go
func APIVersionAttribute(version string) SpanAttribute
```

### AddTraceID

```go
func AddTraceID(ctx context.Context, w http.ResponseWriter)
```

### ContextWithSpan

```go
func ContextWithSpan(ctx context.Context, span tyktrace.Span) context.Context
```

### GatewayResourceAttributes

```go
func GatewayResourceAttributes(gwID string, isDataplane bool, groupID string, isSegmented bool, segmentTags []string) []SpanAttribute
```

### SpanFromContext

```go
func SpanFromContext(ctx context.Context) tyktrace.Span
```

# Package ./oasutil

```go
import (
	"github.com/TykTechnologies/tyk/internal/oasutil"
}
```

## Types

```go
// PathItem holds the path to a particular OAS path item.
type PathItem struct {
	// PathItem represents an openapi3.Paths value.
	*openapi3.PathItem

	// Path is an openapi3.Paths key, the endpoint URL.
	Path string
}
```

## Function symbols

- `func ExtractPaths (in openapi3.Paths, order []string) []PathItem`
- `func SortByPathLength (in openapi3.Paths) []PathItem`

### ExtractPaths

ExtractPaths will extract paths with the given order.

```go
func ExtractPaths(in openapi3.Paths, order []string) []PathItem
```

### SortByPathLength

SortByPathLength decomposes an openapi3.Paths to a sorted []PathItem. The sorting takes the length of the paths into account, as well as path parameters, sorting them by length descending, and ordering path parameters after the statically defined paths.

Check the test function for sorting expectations.

```go
func SortByPathLength(in openapi3.Paths) []PathItem
```

# Package ./time

```go
import (
	"github.com/TykTechnologies/tyk/internal/time"
}
```

## Types

```go
// Duration is an alias maintained to be used across the project.
type Duration = time.Duration
```

```go
// ReadableDuration is a type alias for time.Duration, so that shorthand notation can be used.
// Examples of valid shorthand notations:
// - "1h"   : one hour
// - "20m"  : twenty minutes
// - "30s"  : thirty seconds
// - "1m29s": one minute and twenty-nine seconds
// - "1h30m" : one hour and thirty minutes
//
// An empty value is interpreted as "0s".
// It's important to format the string correctly, as invalid formats will
// be considered as 0s/empty.
type ReadableDuration time.Duration
```

## Consts

```go
const (
	// Nanosecond is an alias maintained to be used across the project.
	Nanosecond = time.Nanosecond
	// Microsecond is an alias maintained to be used across the project.
	Microsecond = time.Microsecond
	// Millisecond is an alias maintained to be used across the project.
	Millisecond = time.Millisecond
	// Second is an alias maintained to be used across the project.
	Second = time.Second
	// Minute is an alias maintained to be used across the project.
	Minute = time.Minute
	// Hour is an alias maintained to be used across the project.
	Hour = time.Hour
)
```

## Function symbols

- `func (*ReadableDuration) UnmarshalJSON (data []byte) error`
- `func (ReadableDuration) MarshalJSON () ([]byte, error)`
- `func (ReadableDuration) Seconds () float64`

### UnmarshalJSON

UnmarshalJSON converts human-readable shorthand notation for time.Duration into ReadableDuration from json format.

```go
func (*ReadableDuration) UnmarshalJSON(data []byte) error
```

### MarshalJSON

MarshalJSON converts ReadableDuration into human-readable shorthand notation for time.Duration into json format.

```go
func (ReadableDuration) MarshalJSON() ([]byte, error)
```

### Seconds

Seconds returns ReadableDuration in seconds.

```go
func (ReadableDuration) Seconds() float64
```

# Package ./model

```go
import (
	"github.com/TykTechnologies/tyk/internal/model"
}
```

Package model provides an internal data model for use across the gateway.

## Types

```go
// Bucket interface for interacting with leaky buckets: https://en.wikipedia.org/wiki/Leaky_bucket
type Bucket interface {
	// Capacity of the bucket.
	Capacity() uint

	// Remaining space in the bucket.
	Remaining() uint

	// Reset returns when the bucket will be drained.
	Reset() time.Time

	// Add to the bucket. Returns bucket state after adding.
	Add(uint) (BucketState, error)
}
```

```go
// BucketState is a snapshot of a bucket's properties.
type BucketState struct {
	Capacity  uint
	Remaining uint
	Reset     time.Time
}
```

```go
// BucketStorage interface for generating buckets keyed by a string.
type BucketStorage interface {
	// Create a bucket with a name, capacity, and rate.
	// rate is how long it takes for full capacity to drain.
	Create(name string, capacity uint, rate time.Duration) (Bucket, error)
}
```

```go
// ConfigProvider provides a typical config getter signature.
type ConfigProvider interface {
	GetConfig() config.Config
}
```

```go
// EventMetaDefault is a standard embedded struct to be used with custom event metadata types, gives an interface for
// easily extending event metadata objects
type EventMetaDefault struct {
	Message            string
	OriginatingRequest string
}
```

```go
// Gateway is a collection of well defined gateway interfaces. It should only
// be implemented in full by gateway.Gateway, and is used for a built-time
// type assertion. Do not use the symbol elsewhere, use the smaller interfaces.
type Gateway interface {
	ConfigProvider
	PolicyProvider

	ReplaceTykVariables
}
```

```go
// LoggerProvider returns a new *logrus.Entry for the request.
// It's implemented by gateway and middleware. Middleware typically
// adds the `mw` field with the middleware name.
type LoggerProvider interface {
	Logger() *logrus.Entry
}
```

```go
// MergedAPI combines the embeds the classic and adds the OAS API definition as a field.
type MergedAPI struct {
	*apidef.APIDefinition `json:"api_definition,inline"`
	OAS                   *oas.OAS `json:"oas"`
}
```

```go
// MergedAPIList is the response body for FromDashboardService.
type MergedAPIList struct {
	Message []MergedAPI
	Nonce   string
}
```

```go
// Middleware is a subset of the gateway.Middleware interface, that can be
// implemented outside of gateway scope.
type Middleware interface {
	Init()
	Name() string
	Logger() *logrus.Entry
	ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) // Handles request
	EnabledForSpec() bool
}
```

```go
// MockUpstreamAuthProvider is a mock implementation of UpstreamAuthProvider.
type MockUpstreamAuthProvider struct{}
```

```go
// PolicyProvider is a storage interface encapsulating policy retrieval.
type PolicyProvider interface {
	PolicyCount() int
	PolicyIDs() []string
	PolicyByID(string) (user.Policy, bool)
}
```

```go
// UpstreamAuthProvider is an interface that can fill in upstream authentication details to the request.
type UpstreamAuthProvider interface {
	Fill(r *http.Request)
}
```

```go
// This contains the shim for rpc data model types.
// They are used from tests, and just pipe through
// the apidef types to avoid import cycles.
type (
	GroupLoginRequest    = apidef.GroupLoginRequest
	GroupKeySpaceRequest = apidef.GroupKeySpaceRequest
	DefRequest           = apidef.DefRequest
	InboundData          = apidef.InboundData
	KeysValuesPair       = apidef.KeysValuesPair
)
```

```go
// These are health check shims.
type (
	HealthCheckItem     = apidef.HealthCheckItem
	HealthCheckResponse = apidef.HealthCheckResponse
	HealthCheckStatus   = apidef.HealthCheckStatus

	HostDetails = apidef.HostDetails
	NodeData    = apidef.NodeData
	GWStats     = apidef.GWStats
)
```

```go
// These are utility methods without any real data model design around them.
type (
	// ReplaceTykVariables is a request-based template replacement hook.
	// Implemented by gateway.Gateway.
	ReplaceTykVariables interface {
		ReplaceTykVariables(r *http.Request, in string, escape bool) string
	}

	// StripListenPath is the interface implemented by APISpec.StripListenPath.
	StripListenPath interface {
		StripListenPath(string) string
	}

	// StripListenPathFunc is the function signature for StripListenPath.
	StripListenPathFunc func(string) string
)
```

## Consts

```go
// Other.
const (
	Pass      = apidef.Pass
	Warn      = apidef.Warn
	Fail      = apidef.Fail
	System    = apidef.System
	Datastore = apidef.Datastore
)
```

## Vars

```go
var (
	// ErrBucketFull is returned when the amount requested to add exceeds the remaining space in the bucket.
	ErrBucketFull = errors.New("add exceeds free bucket capacity")
)
```

## Function symbols

- `func NewEventMetaDefault (r *http.Request, message string) EventMetaDefault`
- `func NewMergedAPIList (apis ...MergedAPI) *MergedAPIList`
- `func (*MergedAPI) LogFields () logrus.Fields`
- `func (*MergedAPIList) Filter (enabled bool, tags ...string) []MergedAPI`
- `func (*MergedAPIList) SetClassic (defs []*apidef.APIDefinition)`
- `func (*MockUpstreamAuthProvider) Fill (_ *http.Request)`

### NewEventMetaDefault

NewEventMetaDefault creates an instance of model.EventMetaDefault.

```go
func NewEventMetaDefault(r *http.Request, message string) EventMetaDefault
```

### LogFields

Logger returns API detail fields for logging.

```go
func (*MergedAPI) LogFields() logrus.Fields
```

### Filter

Filter, if enabled=true, will filter the internal api definitions by their tags.

```go
func (*MergedAPIList) Filter(enabled bool, tags ...string) []MergedAPI
```

### SetClassic

Set sets the available classic API definitions to the MergedAPIList.

```go
func (*MergedAPIList) SetClassic(defs []*apidef.APIDefinition)
```

### Fill

Fill is a mock implementation to be used in tests.

```go
func (*MockUpstreamAuthProvider) Fill(_ *http.Request)
```

### NewMergedAPIList

```go
func NewMergedAPIList(apis ...MergedAPI) *MergedAPIList
```

# Package ./httputil

```go
import (
	"github.com/TykTechnologies/tyk/internal/httputil"
}
```

## Types

```go
// ConnectionWatcher counts http server connections.
type ConnectionWatcher struct {
	n int64
}
```

```go
// ContextKey is the key type to be used for context interactions.
type ContextKey string
```

## Vars

```go
// CORSHeaders is a list of CORS headers.
var CORSHeaders = []string{
	"Access-Control-Allow-Origin",
	"Access-Control-Expose-Headers",
	"Access-Control-Max-Age",
	"Access-Control-Allow-Credentials",
	"Access-Control-Allow-Methods",
	"Access-Control-Allow-Headers",
}
```

```go
var DumpRequest = httputil.DumpRequest
```

```go
var DumpResponse = httputil.DumpResponse
```

## Function symbols

- `func AuthHeader (username,password string) string`
- `func EntityTooLarge (w http.ResponseWriter, _ *http.Request)`
- `func GetUpstreamAuth (r *http.Request) model.UpstreamAuthProvider`
- `func HasTransferEncoding (req *http.Request) bool`
- `func InternalServerError (w http.ResponseWriter, _ *http.Request)`
- `func IsGrpcStreaming (r *http.Request) bool`
- `func IsMuxTemplate (pattern string) bool`
- `func IsSseStreamingResponse (r *http.Response) bool`
- `func IsStreamingRequest (r *http.Request) bool`
- `func IsStreamingResponse (r *http.Response) bool`
- `func IsUpgrade (req *http.Request) (string, bool)`
- `func LengthRequired (w http.ResponseWriter, _ *http.Request)`
- `func MatchPath (pattern string, endpoint string) (bool, error)`
- `func MatchPaths (pattern string, endpoints []string) (bool, error)`
- `func NewConnectionWatcher () *ConnectionWatcher`
- `func PreparePathRegexp (pattern string, prefix bool, suffix bool) string`
- `func RemoveResponseTransferEncoding (response *http.Response, victim string)`
- `func SetContext (r *http.Request, ctx context.Context)`
- `func SetUpstreamAuth (r *http.Request, auth model.UpstreamAuthProvider)`
- `func StripListenPath (listenPath,urlPath string) string`
- `func TransferEncoding (req *http.Request) string`
- `func ValidatePath (in string) error`
- `func (*ConnectionWatcher) Add (c int64)`
- `func (*ConnectionWatcher) Count () int`
- `func (*ConnectionWatcher) OnStateChange (_ net.Conn, state http.ConnState)`

### AuthHeader

AuthHeader will take username and password and return "Basic " + base64 encoded `username:password` for use in an Authorization header.

```go
func AuthHeader(username, password string) string
```

### EntityTooLarge

EntityTooLarge responds with HTTP 413 Request Entity Too Large. The function is used for a response when blocking requests by size.

```go
func EntityTooLarge(w http.ResponseWriter, _ *http.Request)
```

### GetUpstreamAuth

GetUpstreamAuth returns the header name to be used for upstream authentication.

```go
func GetUpstreamAuth(r *http.Request) model.UpstreamAuthProvider
```

### HasTransferEncoding

HasTransferEncoding returns true if a transfer encoding header is present.

```go
func HasTransferEncoding(req *http.Request) bool
```

### InternalServerError

InternalServerError responds with HTTP 503 Internal Server Error.

```go
func InternalServerError(w http.ResponseWriter, _ *http.Request)
```

### IsGrpcStreaming

IsGrpcStreaming returns true if the request designates gRPC streaming.

```go
func IsGrpcStreaming(r *http.Request) bool
```

### IsMuxTemplate

IsMuxTemplate determines if a pattern is a mux template by counting the number of opening and closing braces.

```go
func IsMuxTemplate(pattern string) bool
```

### IsSseStreamingResponse

IsSseStreamingResponse returns true if the response designates SSE streaming.

```go
func IsSseStreamingResponse(r *http.Response) bool
```

### IsStreamingRequest

IsStreamingRequest returns true if the request designates streaming (gRPC or WebSocket).

```go
func IsStreamingRequest(r *http.Request) bool
```

### IsStreamingResponse

IsStreamingResponse returns true if the response designates streaming (SSE).

```go
func IsStreamingResponse(r *http.Response) bool
```

### IsUpgrade

IsUpgrade checks if the request is an upgrade request and returns the upgrade type.

```go
func IsUpgrade(req *http.Request) (string, bool)
```

### LengthRequired

LengthRequired responds with HTTP 411 Length Required. The function is used in places where Content-Length is required.

```go
func LengthRequired(w http.ResponseWriter, _ *http.Request)
```

### MatchPath

MatchPath matches regexp pattern with request endpoint.

```go
func MatchPath(pattern string, endpoint string) (bool, error)
```

### MatchPaths

MatchPaths matches regexp pattern with multiple request URLs endpoint paths. It will return true if any of them is correctly matched, with no error. If no matches occur, any errors will be retured joined with errors.Join.

```go
func MatchPaths(pattern string, endpoints []string) (bool, error)
```

### NewConnectionWatcher

NewConnectionWatcher returns a new *ConnectionWatcher.

```go
func NewConnectionWatcher() *ConnectionWatcher
```

### PreparePathRegexp

PreparePathRexep will replace mux-style parameters in input with a compatible regular expression. Parameters like `{id}` would be replaced to `([^/]+)`. If the input pattern provides a starting or ending delimiters (`^` or `$`), the pattern is returned. If prefix is true, and pattern starts with /, the returned pattern prefixes a `^` to the regex. No other prefix matches are possible so only `/` to `^/` conversion is considered. If suffix is true, the returned pattern suffixes a `$` to the regex. If both prefix and suffixes are achieved, an explicit match is made.

```go
func PreparePathRegexp(pattern string, prefix bool, suffix bool) string
```

### RemoveResponseTransferEncoding

RemoveResponseTransferEncoding will remove a transfer encoding hint from the response.

```go
func RemoveResponseTransferEncoding(response *http.Response, victim string)
```

### SetContext

SetContext updates the context of a request.

```go
func SetContext(r *http.Request, ctx context.Context)
```

### SetUpstreamAuth

SetUpstreamAuth sets the header name to be used for upstream authentication.

```go
func SetUpstreamAuth(r *http.Request, auth model.UpstreamAuthProvider)
```

### StripListenPath

StripListenPath will strip the listenPath from the passed urlPath. If the listenPath contains mux variables, it will trim away the matching pattern with a regular expression that mux provides.

```go
func StripListenPath(listenPath, urlPath string) string
```

### TransferEncoding

TransferEncoding gets the header value from the request.

```go
func TransferEncoding(req *http.Request) string
```

### ValidatePath

ValidatePath validates if the path is valid. Returns an error.

```go
func ValidatePath(in string) error
```

### Add

Add adds c to the number of active connections.

```go
func (*ConnectionWatcher) Add(c int64)
```

### Count

Count returns the number of connections at the time the call.

```go
func (*ConnectionWatcher) Count() int
```

### OnStateChange

OnStateChange records open connections in response to connection state changes. Set net/http Server.ConnState to this method as value.

```go
func (*ConnectionWatcher) OnStateChange(_ net.Conn, state http.ConnState)
```

# Package ./redis

```go
import (
	"github.com/TykTechnologies/tyk/internal/redis"
}
```

The package redis serves as a refactoring aid. The complete gateway depends on this package, and lists the symbols from the upstream dependency in use.

nolint:revive

## Types

```go
type (
	UniversalClient  = redis.UniversalClient
	UniversalOptions = redis.UniversalOptions
	Pipeliner        = redis.Pipeliner

	Client        = redis.Client
	ClusterClient = redis.ClusterClient

	Z            = redis.Z
	ZRangeBy     = redis.ZRangeBy
	ZRangeArgs   = redis.ZRangeArgs
	Message      = redis.Message
	Subscription = redis.Subscription

	IntCmd         = redis.IntCmd
	StringCmd      = redis.StringCmd
	StringSliceCmd = redis.StringSliceCmd
)
```

## Vars

```go
var (
	NewFailoverClient = redis.NewFailoverClient
	NewClusterClient  = redis.NewClusterClient
	NewClient         = redis.NewClient
	NewClientMock     = redismock.NewClientMock
	NewPool           = goredis.NewPool

	Nil       = redis.Nil
	ErrClosed = redis.ErrClosed
)
```

# Package ./graphql

```go
import (
	"github.com/TykTechnologies/tyk/internal/graphql"
}
```

Package graphql is a generated GoMock package.

## Types

```go
type ExecutionEngineI interface {
	graphql.CustomExecutionEngineV2
	graphql.ExecutionEngineV2Executor
}
```

```go
type GraphStatsExtractionVisitor struct {
	extractor *graphql.Extractor

	gqlRequest *graphql.Request
	schema     *ast.Document
}
```

```go
// MockExecutionEngineI is a mock of ExecutionEngineI interface.
type MockExecutionEngineI struct {
	ctrl     *gomock.Controller
	recorder *MockExecutionEngineIMockRecorder
}
```

```go
// MockExecutionEngineIMockRecorder is the mock recorder for MockExecutionEngineI.
type MockExecutionEngineIMockRecorder struct {
	mock *MockExecutionEngineI
}
```

```go
// OtelGraphqlEngineV2Basic defines a struct that can be used for basic tracing with OTel.
// All execution stages are squashed into one span: GraphqlEngine. The upstream request still
// has its span and GraphqlEngine is its parent span.
type OtelGraphqlEngineV2Basic struct {
	otelGraphqlEngineV2Common
}
```

```go
// OtelGraphqlEngineV2Detailed defines an execution engine that can be used for detailed tracing with OTel.
type OtelGraphqlEngineV2Detailed struct {
	otelGraphqlEngineV2Common
	schema *graphql.Schema
}
```

```go
// TykOtelExecutorI is an interface that inherits ExecutionEngineI and defines Tyk/UDG
// specific methods.
type TykOtelExecutorI interface {
	ExecutionEngineI

	// SetContext sets the current OTel tracer context.
	SetContext(ctx context.Context)
}
```

## Function symbols

- `func NewGraphStatsExtractor () *GraphStatsExtractionVisitor`
- `func NewMockExecutionEngineI (ctrl *gomock.Controller) *MockExecutionEngineI`
- `func NewOtelGraphqlEngineV2Basic (tracerProvider otel.TracerProvider, engine ExecutionEngineI) (*OtelGraphqlEngineV2Basic, error)`
- `func NewOtelGraphqlEngineV2Detailed (tracerProvider otel.TracerProvider, engine ExecutionEngineI, schema *graphql.Schema) (*OtelGraphqlEngineV2Detailed, error)`
- `func PrintOperationType (operationType ast.OperationType) string`
- `func (*GraphStatsExtractionVisitor) AnalyticsOperationTypes () analytics.GraphQLOperations`
- `func (*GraphStatsExtractionVisitor) ExtractStats (rawRequest,response,schema string) (analytics.GraphQLStats, error)`
- `func (*GraphStatsExtractionVisitor) GraphErrors (response []byte) ([]string, error)`
- `func (*MockExecutionEngineI) EXPECT () *MockExecutionEngineIMockRecorder`
- `func (*MockExecutionEngineI) Execute (ctx context.Context, operation *graphql.Request, writer resolve.FlushWriter, options ...graphql.ExecutionOptionsV2) error`
- `func (*MockExecutionEngineI) InputValidation (operation *graphql.Request) error`
- `func (*MockExecutionEngineI) Normalize (operation *graphql.Request) error`
- `func (*MockExecutionEngineI) Plan (postProcessor *postprocess.Processor, operation *graphql.Request, report *operationreport.Report) (plan.Plan, error)`
- `func (*MockExecutionEngineI) Resolve (resolveContext *resolve.Context, planResult plan.Plan, writer resolve.FlushWriter) error`
- `func (*MockExecutionEngineI) Setup (ctx context.Context, postProcessor *postprocess.Processor, resolveContext *resolve.Context, operation *graphql.Request, options ...graphql.ExecutionOptionsV2)`
- `func (*MockExecutionEngineI) Teardown ()`
- `func (*MockExecutionEngineI) ValidateForSchema (operation *graphql.Request) error`
- `func (*otelGraphqlEngineV2Common) SetContext (ctx context.Context)`

### NewMockExecutionEngineI

NewMockExecutionEngineI creates a new mock instance.

```go
func NewMockExecutionEngineI(ctrl *gomock.Controller) *MockExecutionEngineI
```

### NewOtelGraphqlEngineV2Detailed

NewOtelGraphqlEngineV2Detailed creates a new instance of OtelGraphqlEngineV2Detailed. It takes a tracer provider, an execution engine, and a GraphQL schema as parameters. The function returns a pointer to OtelGraphqlEngineV2Detailed and an error if any.

```go
func NewOtelGraphqlEngineV2Detailed(tracerProvider otel.TracerProvider, engine ExecutionEngineI, schema *graphql.Schema) (*OtelGraphqlEngineV2Detailed, error)
```

### EXPECT

EXPECT returns an object that allows the caller to indicate expected use.

```go
func (*MockExecutionEngineI) EXPECT() *MockExecutionEngineIMockRecorder
```

### Execute

Execute mocks base method.

```go
func (*MockExecutionEngineI) Execute(ctx context.Context, operation *graphql.Request, writer resolve.FlushWriter, options ...graphql.ExecutionOptionsV2) error
```

### InputValidation

InputValidation mocks base method.

```go
func (*MockExecutionEngineI) InputValidation(operation *graphql.Request) error
```

### Normalize

Normalize mocks base method.

```go
func (*MockExecutionEngineI) Normalize(operation *graphql.Request) error
```

### Plan

Plan mocks base method.

```go
func (*MockExecutionEngineI) Plan(postProcessor *postprocess.Processor, operation *graphql.Request, report *operationreport.Report) (plan.Plan, error)
```

### Resolve

Resolve mocks base method.

```go
func (*MockExecutionEngineI) Resolve(resolveContext *resolve.Context, planResult plan.Plan, writer resolve.FlushWriter) error
```

### Setup

Setup mocks base method.

```go
func (*MockExecutionEngineI) Setup(ctx context.Context, postProcessor *postprocess.Processor, resolveContext *resolve.Context, operation *graphql.Request, options ...graphql.ExecutionOptionsV2)
```

### Teardown

Teardown mocks base method.

```go
func (*MockExecutionEngineI) Teardown()
```

### ValidateForSchema

ValidateForSchema mocks base method.

```go
func (*MockExecutionEngineI) ValidateForSchema(operation *graphql.Request) error
```

### NewGraphStatsExtractor

```go
func NewGraphStatsExtractor() *GraphStatsExtractionVisitor
```

### NewOtelGraphqlEngineV2Basic

```go
func NewOtelGraphqlEngineV2Basic(tracerProvider otel.TracerProvider, engine ExecutionEngineI) (*OtelGraphqlEngineV2Basic, error)
```

### PrintOperationType

```go
func PrintOperationType(operationType ast.OperationType) string
```

### AnalyticsOperationTypes

```go
func (*GraphStatsExtractionVisitor) AnalyticsOperationTypes() analytics.GraphQLOperations
```

### ExtractStats

```go
func (*GraphStatsExtractionVisitor) ExtractStats(rawRequest, response, schema string) (analytics.GraphQLStats, error)
```

### GraphErrors

```go
func (*GraphStatsExtractionVisitor) GraphErrors(response []byte) ([]string, error)
```

### SetContext

```go
func (*otelGraphqlEngineV2Common) SetContext(ctx context.Context)
```

# Package ./graphengine

```go
import (
	"github.com/TykTechnologies/tyk/internal/graphengine"
}
```

## Types

```go
type ComplexityAccessDefinition struct {
	Limit             ComplexityLimit
	FieldAccessRights []ComplexityFieldAccessDefinition
}
```

```go
type ComplexityChecker interface {
	DepthLimitExceeded(r *http.Request, accessDefinition *ComplexityAccessDefinition) ComplexityFailReason
}
```

```go
type ComplexityFailReason int
```

```go
type ComplexityFieldAccessDefinition struct {
	TypeName  string
	FieldName string
	Limits    ComplexityFieldLimits
}
```

```go
type ComplexityFieldLimits struct {
	MaxQueryDepth int
}
```

```go
type ComplexityLimit struct {
	MaxQueryDepth int
}
```

```go
type ContextRetrieveRequestV1Func func(r *http.Request) *graphql.Request
```

```go
type ContextRetrieveRequestV2Func func(r *http.Request) *graphqlv2.Request
```

```go
type ContextStoreRequestV1Func func(r *http.Request, gqlRequest *graphql.Request)
```

```go
type ContextStoreRequestV2Func func(r *http.Request, gqlRequest *graphqlv2.Request)
```

```go
type Engine interface {
	Version() EngineVersion
	HasSchema() bool
	Cancel()
	ProcessAndStoreGraphQLRequest(w http.ResponseWriter, r *http.Request) (err error, statusCode int)
	ProcessGraphQLComplexity(r *http.Request, accessDefinition *ComplexityAccessDefinition) (err error, statusCode int)
	ProcessGraphQLGranularAccess(w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) (err error, statusCode int)
	HandleReverseProxy(params ReverseProxyParams) (res *http.Response, hijacked bool, err error)
}
```

```go
type EngineV1 struct {
	ExecutionEngine *graphql.ExecutionEngine
	Schema          *graphql.Schema
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client

	logger                    abstractlogger.Logger
	gqlTools                  graphqlGoToolsV1
	graphqlRequestProcessor   GraphQLRequestProcessor
	complexityChecker         ComplexityChecker
	granularAccessChecker     GranularAccessChecker
	reverseProxyPreHandler    ReverseProxyPreHandler
	ctxStoreRequestFunc       func(r *http.Request, gqlRequest *graphql.Request)
	ctxRetrieveRequestFunc    func(r *http.Request) *graphql.Request
	newReusableBodyReadCloser NewReusableBodyReadCloserFunc
}
```

```go
type EngineV1Injections struct {
	PreSendHttpHook           datasource.PreSendHttpHook
	PostReceiveHttpHook       datasource.PostReceiveHttpHook
	ContextStoreRequest       ContextStoreRequestV1Func
	ContextRetrieveRequest    ContextRetrieveRequestV1Func
	NewReusableBodyReadCloser NewReusableBodyReadCloserFunc
}
```

```go
type EngineV1Options struct {
	Logger        *logrus.Logger
	ApiDefinition *apidef.APIDefinition
	Schema        *graphql.Schema
	HttpClient    *http.Client
	Injections    EngineV1Injections
}
```

```go
type EngineV2 struct {
	ExecutionEngine *graphql.ExecutionEngineV2
	Schema          *graphql.Schema
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client
	StreamingClient *http.Client
	OpenTelemetry   *EngineV2OTelConfig

	logger                    abstractlogger.Logger
	gqlTools                  graphqlGoToolsV1
	graphqlRequestProcessor   GraphQLRequestProcessor
	complexityChecker         ComplexityChecker
	granularAccessChecker     GranularAccessChecker
	reverseProxyPreHandler    ReverseProxyPreHandler
	contextCancel             context.CancelFunc
	beforeFetchHook           resolve.BeforeFetchHook
	afterFetchHook            resolve.AfterFetchHook
	ctxStoreRequestFunc       func(r *http.Request, gqlRequest *graphql.Request)
	ctxRetrieveRequestFunc    func(r *http.Request) *graphql.Request
	newReusableBodyReadCloser NewReusableBodyReadCloserFunc
	seekReadCloser            SeekReadCloserFunc
	tykVariableReplacer       TykVariableReplacer
}
```

```go
type EngineV2Injections struct {
	BeforeFetchHook           resolve.BeforeFetchHook
	AfterFetchHook            resolve.AfterFetchHook
	WebsocketOnBeforeStart    graphql.WebsocketBeforeStartHook
	ContextStoreRequest       ContextStoreRequestV1Func
	ContextRetrieveRequest    ContextRetrieveRequestV1Func
	NewReusableBodyReadCloser NewReusableBodyReadCloserFunc
	SeekReadCloser            SeekReadCloserFunc
	TykVariableReplacer       TykVariableReplacer
}
```

```go
type EngineV2OTelConfig struct {
	Enabled        bool
	Config         otel.OpenTelemetry
	TracerProvider otel.TracerProvider
	Executor       graphqlinternal.TykOtelExecutorI
}
```

```go
type EngineV2Options struct {
	Logger          *logrus.Logger
	Schema          *graphql.Schema
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client
	StreamingClient *http.Client
	OpenTelemetry   EngineV2OTelConfig
	Injections      EngineV2Injections
}
```

```go
type EngineV3 struct {
	engine        *graphqlv2.ExecutionEngineV2
	schema        *graphqlv2.Schema
	logger        abstractlogger.Logger
	openTelemetry *EngineV2OTelConfig
	apiDefinition *apidef.APIDefinition

	ctxStoreRequestFunc    ContextStoreRequestV2Func
	ctxRetrieveRequestFunc ContextRetrieveRequestV2Func

	gqlTools                  graphqlGoToolsV2
	graphqlRequestProcessor   GraphQLRequestProcessor
	complexityChecker         ComplexityChecker
	granularAccessChecker     GranularAccessChecker
	reverseProxyPreHandler    ReverseProxyPreHandler
	contextCancel             context.CancelFunc
	newReusableBodyReadCloser NewReusableBodyReadCloserFunc
	seekReadCloser            SeekReadCloserFunc
	tykVariableReplacer       TykVariableReplacer
}
```

```go
type EngineV3Injections struct {
	WebsocketOnBeforeStart    graphqlv2.WebsocketBeforeStartHook
	ContextStoreRequest       ContextStoreRequestV2Func
	ContextRetrieveRequest    ContextRetrieveRequestV2Func
	NewReusableBodyReadCloser NewReusableBodyReadCloserFunc
	SeekReadCloser            SeekReadCloserFunc
	TykVariableReplacer       TykVariableReplacer
}
```

```go
type EngineV3Options struct {
	Logger          *logrus.Logger
	Schema          *graphqlv2.Schema
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client
	StreamingClient *http.Client
	OpenTelemetry   EngineV2OTelConfig
	Injections      EngineV3Injections
}
```

```go
type EngineVersion int
```

```go
type GranularAccessChecker interface {
	CheckGraphQLRequestFieldAllowance(w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) GraphQLGranularAccessResult
}
```

```go
type GranularAccessDefinition struct {
	AllowedTypes         []GranularAccessType
	RestrictedTypes      []GranularAccessType
	DisableIntrospection bool
}
```

```go
type GranularAccessFailReason int
```

```go
type GranularAccessType struct {
	Name   string
	Fields []string
}
```

```go
type GraphQLEngineTransport struct {
	originalTransport         http.RoundTripper
	transportType             GraphQLEngineTransportType
	newReusableBodyReadCloser NewReusableBodyReadCloserFunc
	headersConfig             ReverseProxyHeadersConfig
}
```

```go
type GraphQLEngineTransportType int
```

```go
type GraphQLGranularAccessResult struct {
	FailReason         GranularAccessFailReason
	ValidationError    error
	InternalErr        error
	writeErrorResponse func(w io.Writer, providedErr error) (n int, err error)
}
```

```go
type GraphQLProxyOnlyContext struct {
	context.Context
	forwardedRequest       *http.Request
	upstreamResponse       *http.Response
	ignoreForwardedHeaders map[string]bool
}
```

```go
type GraphQLProxyOnlyContextValues struct {
	forwardedRequest       *http.Request
	upstreamResponse       *http.Response
	ignoreForwardedHeaders map[string]bool
}
```

```go
type GraphQLRequestProcessor interface {
	ProcessRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) (error, int)
}
```

```go
type NewReusableBodyReadCloserFunc func(io.ReadCloser) (io.ReadCloser, error)
```

```go
type ProcessGraphQLComplexityParams struct {
	w http.ResponseWriter
	r *http.Request
}
```

```go
type ProxyOnlyHeadersConfig struct {
	UseImmutableHeaders   bool
	RequestHeadersRewrite map[string]apidef.RequestHeadersRewriteConfig
}
```

```go
type ReverseProxyHeadersConfig struct {
	ProxyOnly ProxyOnlyHeadersConfig
}
```

```go
type ReverseProxyParams struct {
	RoundTripper       http.RoundTripper
	ResponseWriter     http.ResponseWriter
	OutRequest         *http.Request
	WebSocketUpgrader  *websocket.Upgrader
	NeedsEngine        bool
	IsCORSPreflight    bool
	IsWebSocketUpgrade bool
	HeadersConfig      ReverseProxyHeadersConfig
}
```

```go
type ReverseProxyPreHandler interface {
	PreHandle(params ReverseProxyParams) (reverseProxyType ReverseProxyType, err error)
}
```

```go
type ReverseProxyType int
```

```go
type SeekReadCloserFunc func(io.ReadCloser) (io.ReadCloser, error)
```

```go
type TransportModifier func(roundTripper http.RoundTripper, apiDefinition *apidef.APIDefinition) http.RoundTripper
```

```go
type TykVariableReplacer func(r *http.Request, in string, escape bool) string
```

## Consts

```go
const (
	ComplexityFailReasonNone ComplexityFailReason = iota
	ComplexityFailReasonInternalError
	ComplexityFailReasonDepthLimitExceeded
)
```

```go
const (
	GranularAccessFailReasonNone GranularAccessFailReason = iota
	GranularAccessFailReasonInternalError
	GranularAccessFailReasonValidationError
	GranularAccessFailReasonIntrospectionDisabled
)
```

```go
const (
	ReverseProxyTypeNone ReverseProxyType = iota
	ReverseProxyTypeIntrospection
	ReverseProxyTypeWebsocketUpgrade
	ReverseProxyTypeGraphEngine
	ReverseProxyTypePreFlight
)
```

```go
const (
	GraphQLEngineTransportTypeProxyOnly GraphQLEngineTransportType = iota
	GraphQLEngineTransportTypeMultiUpstream
)
```

```go
const (
	EngineVersionUnknown EngineVersion = iota
	EngineVersionV1
	EngineVersionV2
	EngineVersionV3
)
```

```go
const (
	HTTPJSONDataSource   = "HTTPJSONDataSource"
	GraphQLDataSource    = "GraphQLDataSource"
	SchemaDataSource     = "SchemaDataSource"
	TykRESTDataSource    = "TykRESTDataSource"
	TykGraphQLDataSource = "TykGraphQLDataSource"
)
```

## Vars

```go
var (
	ProxyingRequestFailedErr     = errors.New("there was a problem proxying the request")
	errCustomBodyResponse        = errors.New("errCustomBodyResponse")
	GraphQLDepthLimitExceededErr = errors.New("depth limit exceeded")
	ErrIntrospectionDisabled     = errors.New("introspection is disabled")
	ErrUnknownReverseProxyType   = errors.New("unknown reverse proxy type")
)
```

## Function symbols

- `func DetermineGraphQLEngineTransportType (apiDefinition *apidef.APIDefinition) GraphQLEngineTransportType`
- `func GetProxyOnlyContextValue (ctx context.Context) *GraphQLProxyOnlyContextValues`
- `func GetSchemaV1 (engine Engine) (*graphql.Schema, error)`
- `func GetSchemaV2 (engine Engine) (*graphqlv2.Schema, error)`
- `func NewEngineV1 (options EngineV1Options) (*EngineV1, error)`
- `func NewEngineV2 (options EngineV2Options) (*EngineV2, error)`
- `func NewEngineV3 (options EngineV3Options) (*EngineV3, error)`
- `func NewGraphQLEngineTransport (transportType GraphQLEngineTransportType, originalTransport http.RoundTripper, newReusableBodyReadCloser NewReusableBodyReadCloserFunc, headersConfig ReverseProxyHeadersConfig) *GraphQLEngineTransport`
- `func NewGraphQLProxyOnlyContext (ctx context.Context, forwardedRequest *http.Request) *GraphQLProxyOnlyContext`
- `func SetProxyOnlyContextValue (ctx context.Context, req *http.Request) context.Context`
- `func (*EngineV1) Cancel ()`
- `func (*EngineV1) HandleReverseProxy (params ReverseProxyParams) (*http.Response, bool, error)`
- `func (*EngineV1) HasSchema () bool`
- `func (*EngineV1) ProcessAndStoreGraphQLRequest (w http.ResponseWriter, r *http.Request) (error, int)`
- `func (*EngineV1) ProcessGraphQLComplexity (r *http.Request, accessDefinition *ComplexityAccessDefinition) (error, int)`
- `func (*EngineV1) ProcessGraphQLGranularAccess (w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) (error, int)`
- `func (*EngineV1) Version () EngineVersion`
- `func (*EngineV3) ProcessRequest (ctx context.Context, w http.ResponseWriter, r *http.Request) (error, int)`
- `func (*GraphQLEngineTransport) RoundTrip (request *http.Request) (*http.Response, error)`
- `func (*GraphQLProxyOnlyContext) Response () *http.Response`
- `func (*complexityCheckerV1) DepthLimitExceeded (r *http.Request, accessDefinition *ComplexityAccessDefinition) ComplexityFailReason`
- `func (*granularAccessCheckerV1) CheckGraphQLRequestFieldAllowance (w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) GraphQLGranularAccessResult`
- `func (*reverseProxyPreHandlerV1) PreHandle (params ReverseProxyParams) (ReverseProxyType, error)`

### DetermineGraphQLEngineTransportType

```go
func DetermineGraphQLEngineTransportType(apiDefinition *apidef.APIDefinition) GraphQLEngineTransportType
```

### GetProxyOnlyContextValue

```go
func GetProxyOnlyContextValue(ctx context.Context) *GraphQLProxyOnlyContextValues
```

### GetSchemaV1

```go
func GetSchemaV1(engine Engine) (*graphql.Schema, error)
```

### GetSchemaV2

```go
func GetSchemaV2(engine Engine) (*graphqlv2.Schema, error)
```

### NewEngineV1

```go
func NewEngineV1(options EngineV1Options) (*EngineV1, error)
```

### NewEngineV2

```go
func NewEngineV2(options EngineV2Options) (*EngineV2, error)
```

### NewEngineV3

```go
func NewEngineV3(options EngineV3Options) (*EngineV3, error)
```

### NewGraphQLEngineTransport

```go
func NewGraphQLEngineTransport(transportType GraphQLEngineTransportType, originalTransport http.RoundTripper, newReusableBodyReadCloser NewReusableBodyReadCloserFunc, headersConfig ReverseProxyHeadersConfig) *GraphQLEngineTransport
```

### NewGraphQLProxyOnlyContext

```go
func NewGraphQLProxyOnlyContext(ctx context.Context, forwardedRequest *http.Request) *GraphQLProxyOnlyContext
```

### SetProxyOnlyContextValue

```go
func SetProxyOnlyContextValue(ctx context.Context, req *http.Request) context.Context
```

### Cancel

```go
func (*EngineV1) Cancel()
```

### HandleReverseProxy

```go
func (*EngineV1) HandleReverseProxy(params ReverseProxyParams) (*http.Response, bool, error)
```

### HasSchema

```go
func (*EngineV1) HasSchema() bool
```

### ProcessAndStoreGraphQLRequest

```go
func (*EngineV1) ProcessAndStoreGraphQLRequest(w http.ResponseWriter, r *http.Request) (error, int)
```

### ProcessGraphQLComplexity

```go
func (*EngineV1) ProcessGraphQLComplexity(r *http.Request, accessDefinition *ComplexityAccessDefinition) (error, int)
```

### ProcessGraphQLGranularAccess

```go
func (*EngineV1) ProcessGraphQLGranularAccess(w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) (error, int)
```

### Version

```go
func (*EngineV1) Version() EngineVersion
```

### ProcessRequest

```go
func (*EngineV3) ProcessRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) (error, int)
```

### RoundTrip

```go
func (*GraphQLEngineTransport) RoundTrip(request *http.Request) (*http.Response, error)
```

### Response

```go
func (*GraphQLProxyOnlyContext) Response() *http.Response
```

### DepthLimitExceeded

```go
func (*complexityCheckerV1) DepthLimitExceeded(r *http.Request, accessDefinition *ComplexityAccessDefinition) ComplexityFailReason
```

### CheckGraphQLRequestFieldAllowance

```go
func (*granularAccessCheckerV1) CheckGraphQLRequestFieldAllowance(w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) GraphQLGranularAccessResult
```

### PreHandle

```go
func (*reverseProxyPreHandlerV1) PreHandle(params ReverseProxyParams) (ReverseProxyType, error)
```

# Package ./httpctx

```go
import (
	"github.com/TykTechnologies/tyk/internal/httpctx"
}
```

## Types

```go
type Value[T any] struct {
	Key any
}
```

## Function symbols

- `func IsSelfLooping (r *http.Request) bool`
- `func NewValue (key any) *Value[T]`
- `func SetSelfLooping (r *http.Request, value bool)`
- `func (*Value[T]) Get (r *http.Request) T`
- `func (*Value[T]) Set (r *http.Request, val T) *http.Request`

### IsSelfLooping

IsSelfLooping returns true if the request is flagged as self-looping, indicating it originates and targets the same service.

```go
func IsSelfLooping(r *http.Request) bool
```

### SetSelfLooping

SetSelfLooping updates the request context with a boolean value indicating whether the request is in a self-looping state.

```go
func SetSelfLooping(r *http.Request, value bool)
```

### NewValue

```go
func NewValue(key any) *Value[T]
```

### Get

```go
func (*Value[T]) Get(r *http.Request) T
```

### Set

```go
func (*Value[T]) Set(r *http.Request, val T) *http.Request
```

# Package ./httputil/accesslog

```go
import (
	"github.com/TykTechnologies/tyk/internal/httputil/accesslog"
}
```

## Types

```go
// Record is a representation of a transaction log in the Gateway.
type Record struct {
	fields logrus.Fields
}
```

## Function symbols

- `func Filter (in logrus.Fields, allowedFields []string) logrus.Fields`
- `func NewRecord () *Record`
- `func (*Record) Fields (allowedKeys []string) logrus.Fields`
- `func (*Record) WithApiKey (req *http.Request, hashKeys bool, obfuscate func(string) string) *Record`
- `func (*Record) WithRequest (req *http.Request, latency analytics.Latency) *Record`
- `func (*Record) WithResponse (resp *http.Response) *Record`

### Filter

Filter filters the input logrus fields and retains only the allowed fields. The function is case sensitive so keys have to match the case exactly.

```go
func Filter(in logrus.Fields, allowedFields []string) logrus.Fields
```

### NewRecord

NewRecord returns a Record object.

```go
func NewRecord() *Record
```

### Fields

Fields returns a logrus.Fields intended for logging.

```go
func (*Record) Fields(allowedKeys []string) logrus.Fields
```

### WithApiKey

WithApiKey sets the access token from the request under APIKey. The access token is obfuscated, or hashed depending on passed arguments.

```go
func (*Record) WithApiKey(req *http.Request, hashKeys bool, obfuscate func(string) string) *Record
```

### WithRequest

WithRequest fills fields from the http request.

```go
func (*Record) WithRequest(req *http.Request, latency analytics.Latency) *Record
```

### WithResponse

WithResponse fills response details into the log fields.

```go
func (*Record) WithResponse(resp *http.Response) *Record
```

# Package ./memorycache

```go
import (
	"github.com/TykTechnologies/tyk/internal/memorycache"
}
```

## Types

```go
type Bucket struct {
	capacity  uint
	remaining uint
	reset     time.Time
	rate      time.Duration
	mutex     sync.Mutex
}
```

```go
// BucketStorage is a non thread-safe in-memory leaky bucket factory.
type BucketStorage struct {
	buckets *Cache
}
```

```go
// Cache is a synchronised map of items that auto-expire once stale
type Cache struct {
	mutex sync.RWMutex
	ttl   time.Duration
	items map[string]*Item
}
```

```go
// Item represents a record in the cache map.
type Item struct {
	sync.RWMutex
	data    *Bucket
	expires *time.Time
}
```

## Function symbols

- `func New (ctx context.Context) *BucketStorage`
- `func NewCache (ctx context.Context, duration time.Duration) *Cache`
- `func (*Bucket) Add (amount uint) (model.BucketState, error)`
- `func (*Bucket) Capacity () uint`
- `func (*Bucket) Remaining () uint`
- `func (*Bucket) Reset () time.Time`
- `func (*BucketStorage) Create (name string, capacity uint, rate time.Duration) (model.Bucket, error)`
- `func (*Cache) Count () int`
- `func (*Cache) Get (key string) (*Bucket, bool)`
- `func (*Cache) Set (key string, data *Bucket)`

### New

New initializes the in-memory bucket store.

```go
func New(ctx context.Context) *BucketStorage
```

### NewCache

NewCache is a helper to create instance of the Cache struct. The ctx is used to cancel the TTL map cleanup goroutine.

```go
func NewCache(ctx context.Context, duration time.Duration) *Cache
```

### Add

Add to the bucket.

```go
func (*Bucket) Add(amount uint) (model.BucketState, error)
```

### Remaining

Remaining space in the bucket.

```go
func (*Bucket) Remaining() uint
```

### Reset

Reset returns when the bucket will be drained.

```go
func (*Bucket) Reset() time.Time
```

### Create

Create a bucket.

```go
func (*BucketStorage) Create(name string, capacity uint, rate time.Duration) (model.Bucket, error)
```

### Count

Count returns the number of items in the cache (helpful for tracking memory leaks)

```go
func (*Cache) Count() int
```

### Get

Get is a thread-safe way to lookup items Every lookup, also touches the item, hence extending it's life

```go
func (*Cache) Get(key string) (*Bucket, bool)
```

### Set

Set is a thread-safe way to add new items to the map

```go
func (*Cache) Set(key string, data *Bucket)
```

### Capacity

```go
func (*Bucket) Capacity() uint
```

# Package ./middleware

```go
import (
	"github.com/TykTechnologies/tyk/internal/middleware"
}
```

## Consts

```go
// StatusRespond should be returned by a middleware to stop processing
// further middleware from the middleware chain.
const StatusRespond = 666
```

## Function symbols

- `func Enabled (defs ...apidef.MiddlewareDefinition) bool`

### Enabled

Enabled returns whether middlewares are enabled or not.

```go
func Enabled(defs ...apidef.MiddlewareDefinition) bool
```

# Package ./netutil

```go
import (
	"github.com/TykTechnologies/tyk/internal/netutil"
}
```

## Function symbols

- `func GetIpAddress () ([]string, error)`

### GetIpAddress

GetIpAddress returns the list of non-loopback IP address (IPv4 and IPv6) found. Returns error if it fails to get the list of addresses, empty if there's no valid IP addresses.

```go
func GetIpAddress() ([]string, error)
```

# Package ./policy

```go
import (
	"github.com/TykTechnologies/tyk/internal/policy"
}
```

## Types

```go
// RPCDataLoaderMock is a policy-related test utility.
type RPCDataLoaderMock struct {
	ShouldConnect bool
	Policies      []user.Policy
	Apis          []model.MergedAPI
}
```

```go
// Service represents the implementation for apply policies logic.
type Service struct {
	storage model.PolicyProvider
	logger  *logrus.Logger

	// used for validation if not empty
	orgID *string
}
```

```go
// Store is an in-memory policy storage object that implements the
// repository for policy access. We  do not implement concurrency
// protections here. Where order is important, use this.
type Store struct {
	policies []user.Policy
}
```

```go
// StoreMap is same as Store, but doesn't preserve order.
type StoreMap struct {
	policies map[string]user.Policy
}
```

## Vars

```go
var (
	// ErrMixedPartitionAndPerAPIPolicies is the error to return when a mix of per api and partitioned policies are to be applied in a session.
	ErrMixedPartitionAndPerAPIPolicies = errors.New("cannot apply multiple policies when some have per_api set and some are partitioned")
)
```

## Function symbols

- `func MergeAllowedURLs (s1,s2 []user.AccessSpec) []user.AccessSpec`
- `func New (orgID *string, storage model.PolicyProvider, logger *logrus.Logger) *Service`
- `func NewStore (policies []user.Policy) *Store`
- `func NewStoreMap (policies map[string]user.Policy) *StoreMap`
- `func (*RPCDataLoaderMock) Connect () bool`
- `func (*RPCDataLoaderMock) GetApiDefinitions (_ string, tags []string) string`
- `func (*RPCDataLoaderMock) GetPolicies (_ string) string`
- `func (*Service) Apply (session *user.SessionState) error`
- `func (*Service) ApplyEndpointLevelLimits (policyEndpoints user.Endpoints, currEndpoints user.Endpoints) user.Endpoints`
- `func (*Service) ApplyRateLimits (session *user.SessionState, policy user.Policy, apiLimits *user.APILimit)`
- `func (*Service) ClearSession (session *user.SessionState) error`
- `func (*Service) Logger () *logrus.Entry`
- `func (*Store) PolicyByID (id string) (user.Policy, bool)`
- `func (*Store) PolicyCount () int`
- `func (*Store) PolicyIDs () []string`

### MergeAllowedURLs

MergeAllowedURLs will merge s1 and s2 to produce a merged result. It maintains order of keys in s1 and s2 as they are seen. If the result is an empty set, nil is returned.

```go
func MergeAllowedURLs(s1, s2 []user.AccessSpec) []user.AccessSpec
```

### NewStore

NewStore returns a new policy.Store.

```go
func NewStore(policies []user.Policy) *Store
```

### NewStoreMap

NewStoreMap returns a new policy.StoreMap.

```go
func NewStoreMap(policies map[string]user.Policy) *StoreMap
```

### Connect

Connect will return the connection status.

```go
func (*RPCDataLoaderMock) Connect() bool
```

### GetApiDefinitions

GetApiDefinitions returns the internal Apis as a json string.

```go
func (*RPCDataLoaderMock) GetApiDefinitions(_ string, tags []string) string
```

### GetPolicies

GetPolicies returns the internal Policies as a json string.

```go
func (*RPCDataLoaderMock) GetPolicies(_ string) string
```

### Apply

Apply will check if any policies are loaded. If any are, it will overwrite the session state to use the policy values.

```go
func (*Service) Apply(session *user.SessionState) error
```

### ApplyEndpointLevelLimits

ApplyEndpointLevelLimits combines policyEndpoints and currEndpoints and returns the combined value. The returned endpoints would have the highest request rate from policyEndpoints and currEndpoints.

```go
func (*Service) ApplyEndpointLevelLimits(policyEndpoints user.Endpoints, currEndpoints user.Endpoints) user.Endpoints
```

### ApplyRateLimits

ApplyRateLimits will write policy limits to session and apiLimits. The limits get written if either are empty. The limits get written if filled and policyLimits allows a higher request rate.

```go
func (*Service) ApplyRateLimits(session *user.SessionState, policy user.Policy, apiLimits *user.APILimit)
```

### ClearSession

ClearSession clears the quota, rate limit and complexity values so that partitioned policies can apply their values. Otherwise, if the session has already a higher value, an applied policy will not win, and its values will be ignored.

```go
func (*Service) ClearSession(session *user.SessionState) error
```

### Logger

Logger implements a typical logger signature with service context.

```go
func (*Service) Logger() *logrus.Entry
```

### PolicyByID

PolicyByID returns a policy by ID.

```go
func (*Store) PolicyByID(id string) (user.Policy, bool)
```

### PolicyCount

PolicyCount returns the number of policies in the store.

```go
func (*Store) PolicyCount() int
```

### PolicyIDs

PolicyIDs returns a list policy IDs in the store. It will return nil if no policies exist.

```go
func (*Store) PolicyIDs() []string
```

### New

```go
func New(orgID *string, storage model.PolicyProvider, logger *logrus.Logger) *Service
```

# Package ./portal

```go
import (
	"github.com/TykTechnologies/tyk/internal/portal"
}
```

## Types

```go
// App represents the structure of an application from the developer portal
type App struct {
	ID          int    `json:"ID"`
	Name        string `json:"Name"`
	Description string `json:"Description"`
	UserID      int    `json:"UserID"`
	// Assuming other fields based on the provided example
}
```

```go
// AppDetail includes detailed information about an application, including webhooks
type AppDetail struct {
	ID             int `json:"ID"`
	AccessRequests []struct {
		WebhookEventTypes string `json:"WebhookEventTypes"`
		WebhookSecret     string `json:"WebhookSecret"`
		WebhookURL        string `json:"WebhookURL"`
	} `json:"AccessRequests"`
	// Assuming other fields based on the provided example
}
```

```go
// Client is a client application for the portal API
type Client struct {
	Secret  string
	BaseURL string
}
```

```go
// WebhookCredential contains the necessary fields to describe a webhook
type WebhookCredential struct {
	AppID             int
	AppName           string
	WebhookEventTypes string
	WebhookSecret     string
	WebhookURL        string
}
```

## Function symbols

- `func NewClient (baseURL,secret string) *Client`
- `func (*Client) ListWebhookCredentials () ([]WebhookCredential, error)`
- `func (*portalOutput) Close (_ context.Context) error`
- `func (*portalOutput) Connect (_ context.Context) error`
- `func (*portalOutput) Write (_ context.Context, msg *service.Message) error`

### NewClient

NewClient creates a new Client for interacting with the portal API

```go
func NewClient(baseURL, secret string) *Client
```

### ListWebhookCredentials

ListWebhookCredentials retrieves a list of apps and filters out their webhook credentials

```go
func (*Client) ListWebhookCredentials() ([]WebhookCredential, error)
```

### Close

```go
func (*portalOutput) Close(_ context.Context) error
```

### Connect

```go
func (*portalOutput) Connect(_ context.Context) error
```

### Write

```go
func (*portalOutput) Write(_ context.Context, msg *service.Message) error
```

# Package ./rate/limiter

```go
import (
	"github.com/TykTechnologies/tyk/internal/rate/limiter"
}
```

## Types

```go
type Limiter struct {
	redis redis.UniversalClient

	locker limiters.DistLocker
	logger limiters.Logger
	clock  limiters.Clock
}
```

```go
type LimiterFunc func(ctx context.Context, key string, rate float64, per float64) error
```

## Vars

```go
var ErrLimitExhausted = limiters.ErrLimitExhausted
```

## Function symbols

- `func NewLimiter (redis redis.UniversalClient) *Limiter`
- `func (*Limiter) FixedWindow (ctx context.Context, key string, rate float64, per float64) error`
- `func (*Limiter) LeakyBucket (ctx context.Context, key string, rate float64, per float64) error`
- `func (*Limiter) Locker (name string) limiters.DistLocker`
- `func (*Limiter) SlidingWindow (ctx context.Context, key string, rate float64, per float64) error`
- `func (*Limiter) TokenBucket (ctx context.Context, key string, rate float64, per float64) error`

### NewLimiter

NewLimiter creates a new limiter object. It holds the redis client and the default non-distributed locks, logger, and a clock for supporting tests.

```go
func NewLimiter(redis redis.UniversalClient) *Limiter
```

### Locker

Locker will ensure a distributed lock with redis, using redsync for a key. If redis is not in use, fallback is done to use the default locker.

```go
func (*Limiter) Locker(name string) limiters.DistLocker
```

### FixedWindow

```go
func (*Limiter) FixedWindow(ctx context.Context, key string, rate float64, per float64) error
```

### LeakyBucket

```go
func (*Limiter) LeakyBucket(ctx context.Context, key string, rate float64, per float64) error
```

### SlidingWindow

```go
func (*Limiter) SlidingWindow(ctx context.Context, key string, rate float64, per float64) error
```

### TokenBucket

```go
func (*Limiter) TokenBucket(ctx context.Context, key string, rate float64, per float64) error
```

# Package ./rate/model

```go
import (
	"github.com/TykTechnologies/tyk/internal/rate/model"
}
```

## Types

```go
// Allowance is a redis data model type. It's encoded into a redis Hash type.
type Allowance struct {
	// Delay is the minimum time between rate limit changes (in seconds).
	Delay int64 `redis:"delay"`

	// Current holds the current rate limit allowance in effect.
	Current int64 `redis:"current"`

	// NextUpdateAt is the next allowable update time for the allowance.
	NextUpdateAt time.Time `redis:"nextUpdateAt"`
}
```

```go
// AllowanceRepository is the interface for accessing rate limit allowance.
type AllowanceRepository interface {
	// Stringer is implemented to expose repository internal info/summary.
	fmt.Stringer

	// Locker implements a distributed lock.
	Locker(name string) limiters.DistLocker

	// Get will retrieve the allowance from storage.
	Get(ctx context.Context, key string) (*Allowance, error)

	// Set will write the allowance to storage.
	Set(ctx context.Context, key string, allowance *Allowance) error
}
```

```go
type Locker = limiters.DistLocker
```

```go
// RedisClientProvider is a hidden storage API, providing us with a redis.UniversalClient.
type RedisClientProvider interface {
	// Client returns the redis.UniversalClient or an error if not available.
	Client() (redis.UniversalClient, error)
}
```

```go
// SmoothingFn is the signature for a rate limiter decision based on rate.
type SmoothingFn func(ctx context.Context, key string, currentRate int64, maxAllowedRate int64) bool
```

## Function symbols

- `func NewAllowance (delay int64) *Allowance`
- `func NewAllowanceFromMap (in map[string]string) *Allowance`
- `func (*Allowance) Err () error`
- `func (*Allowance) Expired () bool`
- `func (*Allowance) Get () int64`
- `func (*Allowance) GetDelay () time.Duration`
- `func (*Allowance) Map () map[string]any`
- `func (*Allowance) Reset ()`
- `func (*Allowance) Set (allowance int64)`
- `func (*Allowance) Touch ()`
- `func (*Allowance) Valid () bool`

### NewAllowance

NewAllowance creates a new allowance with the update delay (in seconds).

```go
func NewAllowance(delay int64) *Allowance
```

### NewAllowanceFromMap

NewAllowanceFromMap will scan the `in` parameter and convert it to *Allowance.

```go
func NewAllowanceFromMap(in map[string]string) *Allowance
```

### Err

Err returns a validation error for *Allowance.

```go
func (*Allowance) Err() error
```

### Expired

Expired checks if the allowance can be updated based on the configured delay.

```go
func (*Allowance) Expired() bool
```

### Get

Get returns the current allowance.

```go
func (*Allowance) Get() int64
```

### GetDelay

GetDelay returns the delay for rate limit smoothing as a time.Duration.

```go
func (*Allowance) GetDelay() time.Duration
```

### Map

Map will return an allowance as a map.

```go
func (*Allowance) Map() map[string]any
```

### Reset

Reset will clear the allowance.

```go
func (*Allowance) Reset()
```

### Set

Set updates the current allowance to the specified value and sets the next update time based on the configured delay.

```go
func (*Allowance) Set(allowance int64)
```

### Touch

Touch updates the next allowance time to the configured delay.

```go
func (*Allowance) Touch()
```

### Valid

Valid returns false if validation with Err() fails.

```go
func (*Allowance) Valid() bool
```

# Package ./rate

```go
import (
	"github.com/TykTechnologies/tyk/internal/rate"
}
```

## Types

```go
// AllowanceStore implements AllowanceRepository.
type AllowanceStore struct {
	redis redis.UniversalClient

	cacheMu sync.RWMutex
	cache   map[string][]byte

	stats struct {
		set       int64
		setErrors int64

		get       int64
		getCached int64
		getErrors int64

		locker int64
	}
}
```

```go
// SlidingLog implements sliding log storage in redis.
type SlidingLog struct {
	conn     redis.UniversalClient
	pipeline bool

	// PipelineFn is exposed for black box tests in the same package.
	PipelineFn func(context.Context, func(redis.Pipeliner) error) error

	// smoothingFn will evaluate the current rate and must return true if
	// the request should be blocked. It's required.
	smoothingFn SmoothingFn
}
```

```go
// Smoothing implements rate limiter smoothing.
type Smoothing struct {
	allowanceStore AllowanceRepository
}
```

```go
type (
	Allowance           = model.Allowance
	AllowanceRepository = model.AllowanceRepository
	SmoothingFn         = model.SmoothingFn
)
```

## Consts

```go
const (
	// LimiterKeyPrefix serves as a standard prefix for generating rate limit keys.
	LimiterKeyPrefix = "rate-limit-"
)
```

```go
// The following constants enumerate implemented rate limiters.
const (
	LimitLeakyBucket   string = "leaky-bucket"
	LimitTokenBucket   string = "token-bucket"
	LimitFixedWindow   string = "fixed-window"
	LimitSlidingWindow string = "sliding-window"
)
```

## Vars

```go
var (
	// ErrLimitExhausted is returned when the request should be blocked.
	ErrLimitExhausted = limiter.ErrLimitExhausted
)
```

```go
// ErrRedisClientProvider is returned if NewSlidingLog isn't passed a valid RedisClientProvider parameter.
var ErrRedisClientProvider = errors.New("Client doesn't implement RedisClientProvider")
```

```go
var (
	NewAllowance        = model.NewAllowance
	NewAllowanceFromMap = model.NewAllowanceFromMap
)
```

## Function symbols

- `func Limiter (gwConfig *config.Config, redis redis.UniversalClient) limiter.LimiterFunc`
- `func LimiterKey (currentSession *user.SessionState, rateScope string, key string, useCustomKey bool) string`
- `func LimiterKind (c *config.Config) (string, bool)`
- `func NewAllowanceStore (redis redis.UniversalClient) *AllowanceStore`
- `func NewSlidingLog (client interface{}, pipeline bool, smoothingFn SmoothingFn) (*SlidingLog, error)`
- `func NewSlidingLogRedis (conn redis.UniversalClient, pipeline bool, smoothingFn SmoothingFn) *SlidingLog`
- `func NewSmoothing (redis redis.UniversalClient) *Smoothing`
- `func NewStorage (cfg *config.StorageOptionsConf) redis.UniversalClient`
- `func Prefix (params ...string) string`
- `func (*AllowanceStore) Get (ctx context.Context, key string) (*Allowance, error)`
- `func (*AllowanceStore) Locker (key string) limiters.DistLocker`
- `func (*AllowanceStore) Set (ctx context.Context, key string, allowance *Allowance) error`
- `func (*AllowanceStore) String () string`
- `func (*SlidingLog) Do (ctx context.Context, now time.Time, key string, maxAllowedRate int64, per int64) (bool, error)`
- `func (*SlidingLog) ExecPipeline (ctx context.Context, pipeFn func(redis.Pipeliner) error) error`
- `func (*SlidingLog) GetCount (ctx context.Context, now time.Time, keyName string, per int64) (int64, error)`
- `func (*SlidingLog) SetCount (ctx context.Context, now time.Time, keyName string, per int64) (int64, error)`

### Limiter

Limiter returns the appropriate rate limiter as configured by gateway.

```go
func Limiter(gwConfig *config.Config, redis redis.UniversalClient) limiter.LimiterFunc
```

### LimiterKey

LimiterKey returns a redis key name based on passed parameters. The key should be post-fixed if multiple keys are required (sentinel).

```go
func LimiterKey(currentSession *user.SessionState, rateScope string, key string, useCustomKey bool) string
```

### LimiterKind

LimiterKind returns the kind of rate limiter enabled by config. This function is used for release builds.

```go
func LimiterKind(c *config.Config) (string, bool)
```

### NewAllowanceStore

NewAllowanceStore will return a new instance of *AllowanceStore.

```go
func NewAllowanceStore(redis redis.UniversalClient) *AllowanceStore
```

### NewSlidingLog

NewSlidingLog creates a new SlidingLog instance with a storage.Handler. In case the storage is offline, it's expected to return nil and an error to handle.

```go
func NewSlidingLog(client interface{}, pipeline bool, smoothingFn SmoothingFn) (*SlidingLog, error)
```

### NewSlidingLogRedis

NewSlidingLogRedis creates a new SlidingLog instance with a redis.UniversalClient.

```go
func NewSlidingLogRedis(conn redis.UniversalClient, pipeline bool, smoothingFn SmoothingFn) *SlidingLog
```

### NewSmoothing

NewSmoothing will return a new instance of *Smoothing.

```go
func NewSmoothing(redis redis.UniversalClient) *Smoothing
```

### NewStorage

NewStorage provides a redis v9 client for rate limiter use.

```go
func NewStorage(cfg *config.StorageOptionsConf) redis.UniversalClient
```

### Prefix

Prefix is a utility function to generate rate limiter redis key names.

```go
func Prefix(params ...string) string
```

### Get

Get retrieves and decodes an Allowance value from storage.

```go
func (*AllowanceStore) Get(ctx context.Context, key string) (*Allowance, error)
```

### Locker

Locker returns a distributed locker, similar to a mutex.

```go
func (*AllowanceStore) Locker(key string) limiters.DistLocker
```

### Set

Set will write the passed Allowance value to storage.

```go
func (*AllowanceStore) Set(ctx context.Context, key string, allowance *Allowance) error
```

### String

String will return the stats for the AllowanceStore.

```go
func (*AllowanceStore) String() string
```

### Do

Do will return two values, the first indicates if a request should be blocked, and the second returns an error if any occurred. In case an error occurs, the first value will be `true`. If there are issues with storage availability for example, requests will be blocked rather than let through, as no rate limit can be enforced without storage.

```go
func (*SlidingLog) Do(ctx context.Context, now time.Time, key string, maxAllowedRate int64, per int64) (bool, error)
```

### ExecPipeline

ExecPipeline will run a pipeline function in a pipeline or transaction.

```go
func (*SlidingLog) ExecPipeline(ctx context.Context, pipeFn func(redis.Pipeliner) error) error
```

### GetCount

GetCount returns the number of items in the current sliding log window. The sliding log is trimmed removing older items.

```go
func (*SlidingLog) GetCount(ctx context.Context, now time.Time, keyName string, per int64) (int64, error)
```

### SetCount

SetCount returns the number of items in the current sliding log window, before adding a new item. The sliding log is trimmed removing older items, and a `per` seconds expiration is set on the complete log.

```go
func (*SlidingLog) SetCount(ctx context.Context, now time.Time, keyName string, per int64) (int64, error)
```

# Package ./rate/mock

```go
import (
	"github.com/TykTechnologies/tyk/internal/rate/mock"
}
```

## Types

```go
type (
	Allowance = model.Allowance
)
```

```go
type AllowanceStore struct {
	Allowance *Allowance
	Err       error
}
```

```go
type Locker sync.Mutex
```

## Function symbols

- `func (*AllowanceStore) Get (ctx context.Context, key string) (*Allowance, error)`
- `func (*AllowanceStore) Locker (key string) model.Locker`
- `func (*AllowanceStore) Set (ctx context.Context, key string, allowance *Allowance) error`
- `func (*AllowanceStore) String () string`
- `func (*Locker) Lock (ctx context.Context) error`
- `func (*Locker) Unlock (ctx context.Context) error`

### Get

```go
func (*AllowanceStore) Get(ctx context.Context, key string) (*Allowance, error)
```

### Locker

```go
func (*AllowanceStore) Locker(key string) model.Locker
```

### Set

```go
func (*AllowanceStore) Set(ctx context.Context, key string, allowance *Allowance) error
```

### String

```go
func (*AllowanceStore) String() string
```

### Lock

```go
func (*Locker) Lock(ctx context.Context) error
```

### Unlock

```go
func (*Locker) Unlock(ctx context.Context) error
```

# Package ./scheduler

```go
import (
	"github.com/TykTechnologies/tyk/internal/scheduler"
}
```

Package scheduler provides a simple job scheduling utility with support for running periodic tasks and graceful shutdown.

## Types

```go
// Job represents a task that can be scheduled. Each Job has a Name, a Run function
// that performs the task, and an Interval that determines how often the task should run.
type Job struct {
	Name     string
	Run      func() error
	Interval time.Duration
}
```

```go
// Scheduler is responsible for executing Jobs at specified intervals.
type Scheduler struct {
	logger *logrus.Logger

	mustBreak bool
	stop      chan bool
	stopOnce  sync.Once
}
```

## Vars

```go
// Break is an error used to indicate the need to break the scheduler loop.
// It's an internal mechanism for stopping a job's execution within the scheduler.
var Break = errors.New("internal: break scheduler loop")
```

## Function symbols

- `func NewJob (name string, run func() error, interval time.Duration) *Job`
- `func NewScheduler (logger *logrus.Logger) *Scheduler`
- `func (*Scheduler) Close () error`
- `func (*Scheduler) Logger () *logrus.Entry`
- `func (*Scheduler) Start (ctx context.Context, job *Job)`

### NewJob

NewJob creates and returns a new Job with the specified name, task function, and interval.

```go
func NewJob(name string, run func() error, interval time.Duration) *Job
```

### NewScheduler

NewScheduler creates and returns a new Scheduler with the specified logger.

```go
func NewScheduler(logger *logrus.Logger) *Scheduler
```

### Close

Close gracefully stops the execution of any running Jobs in the Scheduler. It is safe to call multiple times and is concurrent-safe.

```go
func (*Scheduler) Close() error
```

### Logger

Logger creates and returns a logrus Entry with the scheduler prefix.

```go
func (*Scheduler) Logger() *logrus.Entry
```

### Start

Start begins the execution of the provided Job within the context of the Scheduler. It schedules the Job's Run function to be called at its specified interval. The job can be stopped via context cancellation, calling Close, or when the job returns the Break error.

```go
func (*Scheduler) Start(ctx context.Context, job *Job)
```

# Package ./service/newrelic

```go
import (
	"github.com/TykTechnologies/tyk/internal/service/newrelic"
}
```

## Types

```go
type Logger struct {
	*logrus.Entry
}
```

```go
type Sink struct {
	relic *newrelic.Application
	health.Sink
}
```

```go
// Type aliases used from newrelic pkg.
type (
	Application  = newrelic.Application
	Transaction  = newrelic.Transaction
	ConfigOption = newrelic.ConfigOption
)
```

## Vars

```go
// Variable aliases used from newrelic pkg.
var (
	NewApplication = newrelic.NewApplication
	FromContext    = newrelic.FromContext

	ConfigLogger                   = newrelic.ConfigLogger
	ConfigEnabled                  = newrelic.ConfigEnabled
	ConfigAppName                  = newrelic.ConfigAppName
	ConfigLicense                  = newrelic.ConfigLicense
	ConfigDistributedTracerEnabled = newrelic.ConfigDistributedTracerEnabled
)
```

## Function symbols

- `func Mount (router *mux.Router, app *Application)`
- `func NewLogger (e *logrus.Entry) *Logger`
- `func NewSink (relic *newrelic.Application) *Sink`
- `func (*Logger) Debug (msg string, c map[string]interface{})`
- `func (*Logger) DebugEnabled () bool`
- `func (*Logger) Error (msg string, c map[string]interface{})`
- `func (*Logger) Info (msg string, c map[string]interface{})`
- `func (*Logger) Warn (msg string, c map[string]interface{})`
- `func (*Sink) EmitComplete (job string, status health.CompletionStatus, nanoseconds int64, kvs map[string]string)`
- `func (*Sink) EmitEvent (job string, event string, kvs map[string]string)`
- `func (*Sink) EmitEventErr (job string, event string, err error, kvs map[string]string)`
- `func (*Sink) EmitGauge (job string, event string, value float64, kvs map[string]string)`
- `func (*Sink) EmitTiming (job string, event string, nanoseconds int64, kvs map[string]string)`

### Mount

Mount adds the nrgorilla middleware to the router. The application is added to the request context. If app is nil, nothing will be done and the function will return.

```go
func Mount(router *mux.Router, app *Application)
```

### NewLogger

```go
func NewLogger(e *logrus.Entry) *Logger
```

### NewSink

```go
func NewSink(relic *newrelic.Application) *Sink
```

### Debug

```go
func (*Logger) Debug(msg string, c map[string]interface{})
```

### DebugEnabled

```go
func (*Logger) DebugEnabled() bool
```

### Error

```go
func (*Logger) Error(msg string, c map[string]interface{})
```

### Info

```go
func (*Logger) Info(msg string, c map[string]interface{})
```

### Warn

```go
func (*Logger) Warn(msg string, c map[string]interface{})
```

### EmitComplete

```go
func (*Sink) EmitComplete(job string, status health.CompletionStatus, nanoseconds int64, kvs map[string]string)
```

### EmitEvent

```go
func (*Sink) EmitEvent(job string, event string, kvs map[string]string)
```

### EmitEventErr

```go
func (*Sink) EmitEventErr(job string, event string, err error, kvs map[string]string)
```

### EmitGauge

```go
func (*Sink) EmitGauge(job string, event string, value float64, kvs map[string]string)
```

### EmitTiming

```go
func (*Sink) EmitTiming(job string, event string, nanoseconds int64, kvs map[string]string)
```
