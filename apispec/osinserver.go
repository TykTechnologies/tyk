package apispec

import (
	"github.com/lonelycode/osin"
	"encoding/json"
	"errors"
	"github.com/TykTechnologies/tyk/keygen"
	"github.com/satori/go.uuid"
	"encoding/base64"
	"github.com/TykTechnologies/tyk/session"
)

// TykOsinServer subclasses osin.Server so we can add the SetClient method without wrecking the lbrary
type TykOsinServer struct {
	osin.Server
	Config            *osin.ServerConfig
	Storage           ExtendedOsinStorageInterface
	AuthorizeTokenGen osin.AuthorizeTokenGen
	AccessTokenGen    osin.AccessTokenGen
}

type ExtendedOsinStorageInterface interface {
	// Create OAuth clients
	SetClient(id string, client osin.Client, ignorePrefix bool) error

	// Custom getter to handle prefixing issues in Redis
	GetClientNoPrefix(id string) (osin.Client, error)

	GetClients(filter string, ignorePrefix bool) ([]osin.Client, error)

	DeleteClient(id string, ignorePrefix bool) error

	// Clone the storage if needed. For example, using mgo, you can clone the session with session.Clone
	// to avoid concurrent access problems.
	// This is to avoid cloning the connection at each method access.
	// Can return itself if not a problem.
	Clone() osin.Storage

	// Close the resources the Storate potentially holds (using Clone for example)
	Close()

	// GetClient loads the client by id (client_id)
	GetClient(id string) (osin.Client, error)

	// SaveAuthorize saves authorize data.
	SaveAuthorize(*osin.AuthorizeData) error

	// LoadAuthorize looks up AuthorizeData by a code.
	// Client information MUST be loaded together.
	// Optionally can return error if expired.
	LoadAuthorize(code string) (*osin.AuthorizeData, error)

	// RemoveAuthorize revokes or deletes the authorization code.
	RemoveAuthorize(code string) error

	// SaveAccess writes AccessData.
	// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
	SaveAccess(*osin.AccessData) error

	// LoadAccess retrieves access data by token. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadAccess(token string) (*osin.AccessData, error)

	// RemoveAccess revokes or deletes an AccessData.
	RemoveAccess(token string) error

	// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadRefresh(token string) (*osin.AccessData, error)

	// RemoveRefresh revokes or deletes refresh AccessData.
	RemoveRefresh(token string) error

	// GetUser retrieves a Basic Access user token type from the key store
	GetUser(string) (*session.SessionState, error)

	// SetUser updates a Basic Access user token type in the key store
	SetUser(string, *session.SessionState, int64) error
}


// AccessTokenGenTyk is a modified authorization token generator that uses the same method used to generate tokens for Tyk authHandler
type AccessTokenGenTyk struct{
	KeyGen keygen.DefaultKeyGenerator
	PolicyGen func (policyID, orgID string, enforceOrg bool) (session.SessionState, error)
}

// GenerateAccessToken generates base64-encoded UUID access and refresh tokens
func (a AccessTokenGenTyk) GenerateAccessToken(data *osin.AccessData, generaterefresh bool) (accesstoken, refreshtoken string, err error) {
	log.Info("[OAuth] Generating new token")

	var newSession session.SessionState
	checkPolicy := true
	if data.UserData != nil {
		checkPolicy = false
		err := json.Unmarshal([]byte(data.UserData.(string)), &newSession)
		if err != nil {
			log.Info("[GenerateAccessToken] Couldn't decode SessionState from UserData, checking policy: ", err)
			checkPolicy = true
		}
	}

	if checkPolicy {
		// defined in JWT middleware
		sessionFromPolicy, err := a.PolicyGen(data.Client.GetPolicyID(), "", false)
		if err != nil {
			return "", "", errors.New("Couldn't use policy or key rules to create token, failing")
		}

		newSession = sessionFromPolicy
	}

	accesstoken = a.KeyGen.GenerateAuthKey(newSession.OrgID)

	if generaterefresh {
		u6 := uuid.NewV4()
		refreshtoken = base64.StdEncoding.EncodeToString([]byte(u6.String()))
	}
	return
}