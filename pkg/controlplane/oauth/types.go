// Package oauth holds the OAuth 2.0 client administration, token storage
// and token issuance logic behind the gateway's /tyk/oauth/* admin API and
// its per-API /oauth/token and /oauth/authorize handlers. The gateway and
// the Dashboard both run this code against the same Redis layout.
package oauth

import (
	"encoding/base64"

	"github.com/lonelycode/osin"

	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/user"
)

// Redis key prefixes, relative to the per-API prefix "oauth-data.<apiID>.".
const (
	PrefixAuth            = "oauth-authorize."
	PrefixClient          = "oauth-clientid."
	PrefixAccess          = "oauth-access."
	PrefixRefresh         = "oauth-refresh."
	PrefixClientset       = "oauth-clientset."
	PrefixClientIndexList = "oauth-client-index."
	PrefixClientTokens    = "oauth-client-tokens."

	// ClientTokensKeyPattern matches every client's token index across APIs.
	ClientTokensKeyPattern = "oauth-data.*oauth-client-tokens.*"
)

// APIPrefix returns the Redis prefix of an API's OAuth data.
func APIPrefix(apiID string) string {
	return "oauth-data." + apiID + "."
}

// ClientStorageID returns the storage key of a client within an API prefix.
func ClientStorageID(clientID string) string {
	return PrefixClient + clientID
}

// Error messages shared with the gateway admin API.
const (
	ErrNotPropagated     = "OAuth client list isn't available or hasn't been propagated yet."
	ErrClientNotFound    = "OAuth client not found"
	ErrClientIDEmpty     = "client_id is required"
	ErrClientSecretEmpty = "client_secret is required"
	ErrClientSecretWrong = "client secret is wrong"
	ErrTokenEmpty        = "token is required"
)

// Config is the gateway configuration the OAuth logic depends on.
type Config struct {
	HashKeys                      bool
	OAuthTokenExpire              int32
	OAuthRefreshExpire            int64
	OAuthTokenExpiredRetainPeriod int32
	OAuthRedirectURISeparator     string
	OAuthErrorStatusCode          int
	// EnableCluster selects the client-set listing instead of the index list.
	EnableCluster bool
	// UseRPC marks a data-plane gateway; deletes then also hit the local store.
	UseRPC bool
}

// OAuthClient is the stored representation of a client.
type OAuthClient struct {
	ClientID          string      `json:"id"`
	ClientSecret      string      `json:"secret"`
	ClientRedirectURI string      `json:"redirecturi"`
	MetaData          interface{} `json:"meta_data,omitempty"`
	PolicyID          string      `json:"policyid"`
	Description       string      `json:"description"`
}

func (oc *OAuthClient) GetId() string            { return oc.ClientID }
func (oc *OAuthClient) GetSecret() string        { return oc.ClientSecret }
func (oc *OAuthClient) GetRedirectUri() string   { return oc.ClientRedirectURI }
func (oc *OAuthClient) GetUserData() interface{} { return oc.MetaData }
func (oc *OAuthClient) GetPolicyID() string      { return oc.PolicyID }
func (oc *OAuthClient) GetDescription() string   { return oc.Description }

// OAuthClientToken is one entry of a client's token index.
//
// swagger:model
type OAuthClientToken struct {
	Token   string `json:"code"`
	Expires int64  `json:"expires"`
}

// ExtendedOsinClientInterface is osin.Client plus a description.
type ExtendedOsinClientInterface interface {
	osin.Client
	GetDescription() string
}

// ExtendedOsinStorageInterface is osin.Storage plus Tyk's client and user
// operations.
type ExtendedOsinStorageInterface interface {
	osin.Storage

	// Create OAuth clients
	SetClient(id string, orgID string, client osin.Client, ignorePrefix bool) error

	// Custom getter to handle prefixing issues in Redis
	GetClientNoPrefix(id string) (osin.Client, error)

	GetClientTokens(id string) ([]OAuthClientToken, error)
	GetPaginatedClientTokens(id string, page int) ([]OAuthClientToken, int, error)

	GetExtendedClient(id string) (ExtendedOsinClientInterface, error)

	// Custom getter to handle prefixing issues in Redis
	GetExtendedClientNoPrefix(id string) (ExtendedOsinClientInterface, error)

	GetClients(filter string, orgID string, ignorePrefix bool) ([]ExtendedOsinClientInterface, error)

	DeleteClient(id string, orgID string, ignorePrefix bool) error

	// GetUser retrieves a Basic Access user token type from the key store
	GetUser(string) (*user.SessionState, error)

	// SetUser updates a Basic Access user token type in the key store
	SetUser(string, *user.SessionState, int64) error
}

// ClientRequest is the outward facing JSON object of a client (the admin
// API's NewClientRequest).
//
// swagger:model NewClientRequest
type ClientRequest struct {
	ClientID          string      `json:"client_id"`
	ClientRedirectURI string      `json:"redirect_uri"`
	APIID             string      `json:"api_id,omitempty"`
	PolicyID          string      `json:"policy_id,omitempty"`
	ClientSecret      string      `json:"secret"`
	MetaData          interface{} `json:"meta_data"`
	Description       string      `json:"description"`
}

func clientRequestFrom(c ExtendedOsinClientInterface) ClientRequest {
	return ClientRequest{
		ClientID:          c.GetId(),
		ClientSecret:      c.GetSecret(),
		ClientRedirectURI: c.GetRedirectUri(),
		PolicyID:          c.GetPolicyID(),
		MetaData:          c.GetUserData(),
		Description:       c.GetDescription(),
	}
}

// PaginationStatus describes a page of client tokens.
type PaginationStatus struct {
	PageNum   int `json:"page_num"`
	PageTotal int `json:"page_total"`
	PageSize  int `json:"page_size"`
}

// PaginatedClientTokens is the paginated token listing payload.
type PaginatedClientTokens struct {
	Pagination PaginationStatus
	Tokens     []OAuthClientToken
}

// NewClientSecret generates a client secret.
func NewClientSecret() string {
	return base64.StdEncoding.EncodeToString([]byte(uuid.New()))
}
