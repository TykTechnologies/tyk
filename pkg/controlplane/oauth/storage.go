package oauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/lonelycode/osin"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/pkg/controlplane/keys"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// SessionFactory is what token issuance needs from the key service.
type SessionFactory interface {
	SessionFromPolicy(policyID, orgID string, enforceOrg bool) (user.SessionState, error)
	ApplyLifetime(sess *user.SessionState, apis ...*keys.APIInfo) int64
	GenerateAuthKey(orgID string) string
}

// Storage implements osin.Storage (plus Tyk's client and user operations)
// over Redis. It is the gateway's RedisOsinStorageInterface with the
// gateway runtime replaced by a config accessor and a SessionFactory.
type Storage struct {
	// store is the API-prefixed store used for clients, codes, access and
	// refresh entries. In a data-plane gateway it is the MDCB-aware store.
	store storage.Handler
	// redisStore is the API-prefixed local Redis store used for the
	// client token index (sorted set).
	redisStore storage.Handler
	// sessions is the apikey- session store.
	sessions keys.SessionStore
	orgID    string
	cfg      func() Config
	keys     SessionFactory
	log      *logrus.Logger
}

var _ ExtendedOsinStorageInterface = (*Storage)(nil)

// NewStorage returns a Storage for one API. store and redisStore are both
// prefixed with APIPrefix(apiID); sessions is the apikey- store.
func NewStorage(store, redisStore storage.Handler, sessions keys.SessionStore, orgID string, cfg func() Config, k SessionFactory, log *logrus.Logger) *Storage {
	if cfg == nil {
		cfg = func() Config { return Config{} }
	}
	if log == nil {
		log = logrus.StandardLogger()
	}
	return &Storage{store: store, redisStore: redisStore, sessions: sessions, orgID: orgID, cfg: cfg, keys: k, log: log}
}

// OrgID returns the org the storage was built for.
func (r *Storage) OrgID() string { return r.orgID }

// Store returns the API-prefixed store.
func (r *Storage) Store() storage.Handler { return r.store }

func (r *Storage) Clone() osin.Storage { return r }

func (r *Storage) Close() {}

// GetClient will retrieve client data
func (r *Storage) GetClient(id string) (osin.Client, error) {
	key := PrefixClient + id

	r.log.Debug("Getting client ID:", id)
	clientJSON, err := r.store.GetKey(key)
	if err != nil {
		r.log.Debugf("Failure retrieving client ID key %q: %v", key, err)
		return nil, err
	}

	client := new(OAuthClient)
	if err := json.Unmarshal([]byte(clientJSON), &client); err != nil {
		r.log.Debug("Couldn't unmarshal OAuth client object: ", err)
	}
	return client, nil
}

// GetClientNoPrefix will retrieve client data, but not assign a prefix - this is an unfortunate hack,
// but we don't want to change the signature in Osin for GetClient to support the odd Redis prefixing
func (r *Storage) GetClientNoPrefix(id string) (osin.Client, error) {
	key := id

	clientJSON, err := r.store.GetKey(key)
	if err != nil {
		r.log.Error("Failure retrieving client ID key: ", err)
		return nil, err
	}

	client := new(OAuthClient)
	if err := json.Unmarshal([]byte(clientJSON), client); err != nil {
		r.log.Error("Couldn't unmarshal OAuth client object: ", err)
	}

	return client, nil
}

func (r *Storage) GetExtendedClient(id string) (ExtendedOsinClientInterface, error) {
	osinClient, err := r.GetClient(id)
	if err != nil {
		r.log.WithError(err).Error("Failure retrieving client ID key")
		return nil, err
	}

	return osinClient.(*OAuthClient), err
}

// GetExtendedClientNoPrefix custom getter to handle prefixing issues in Redis,
func (r *Storage) GetExtendedClientNoPrefix(id string) (ExtendedOsinClientInterface, error) {
	osinClient, err := r.GetClientNoPrefix(id)
	if err != nil {
		r.log.WithError(err).Error("Failure retrieving client ID key")
		return nil, err
	}
	return osinClient.(*OAuthClient), err
}

// GetClients will retrieve a list of clients for a prefix
func (r *Storage) GetClients(filter string, orgID string, ignorePrefix bool) ([]ExtendedOsinClientInterface, error) {
	key := PrefixClient + filter
	if ignorePrefix {
		key = filter
	}

	indexKey := PrefixClientIndexList + orgID

	var clientJSON map[string]string
	if !r.cfg().EnableCluster {
		exists, _ := r.store.Exists(indexKey)
		if exists {
			keys, err := r.store.GetListRange(indexKey, 0, -1)
			if err != nil {
				r.log.Error("Couldn't get OAuth client index list: ", err)
				return nil, err
			}
			keyVals, err := r.store.GetMultiKey(keys)
			if err != nil {
				r.log.Error("Couldn't get OAuth client index list values: ", err)
				return nil, err
			}

			clientJSON = make(map[string]string)
			for i, key := range keys {
				clientJSON[key] = keyVals[i]
			}
		} else {
			clientJSON = r.store.GetKeysAndValuesWithFilter(key)
			for key := range clientJSON {
				r.store.AppendToSet(indexKey, key)
			}
		}
	} else {
		keyForSet := PrefixClientset + PrefixClient // Org ID
		var err error
		if clientJSON, err = r.store.GetSet(keyForSet); err != nil {
			return nil, err
		}
	}

	theseClients := []ExtendedOsinClientInterface{}
	for _, clientJSON := range clientJSON {
		client := new(OAuthClient)
		if err := json.Unmarshal([]byte(clientJSON), &client); err != nil {
			r.log.Error("Couldn't unmarshal OAuth client object: ", err)
			return nil, err
		}
		theseClients = append(theseClients, client)
	}

	return theseClients, nil
}

// GetPaginatedClientTokens returns all tokens associated with the given id.
// It returns the tokens, the total number of pages of the tokens after
// pagination and an error if any
func (r *Storage) GetPaginatedClientTokens(id string, page int) ([]OAuthClientToken, int, error) {
	key := PrefixClientTokens + id

	// use current timestamp as a start score so all expired tokens won't be picked
	nowTs := time.Now().Unix()
	startScore := strconv.FormatInt(nowTs, 10)

	r.log.Info("Getting client tokens sorted list:", key)

	tokens, scores, err := r.store.GetSortedSetRange(key, startScore, "+inf")
	if err != nil {
		return nil, 0, err
	}

	// clean up expired tokens in sorted set (remove all tokens with score up to current timestamp minus retention)
	if retain := r.cfg().OAuthTokenExpiredRetainPeriod; retain > 0 {
		cleanupStartScore := strconv.FormatInt(nowTs-int64(retain), 10)
		go r.store.RemoveSortedSetRange(key, "-inf", cleanupStartScore)
	}

	itemsPerPage := 100

	tokenNumber := len(tokens)

	if tokenNumber == 0 {
		return []OAuthClientToken{}, 0, nil
	}

	startIdx := (page - 1) * itemsPerPage
	endIdx := startIdx + itemsPerPage

	if tokenNumber < startIdx {
		startIdx = tokenNumber
	}

	if tokenNumber < endIdx {
		endIdx = tokenNumber
	}

	totalPages := int(math.Ceil(float64(len(tokens)) / float64(itemsPerPage)))

	tokens = tokens[startIdx:endIdx]

	// convert sorted set data and scores into reply struct
	tokensData := make([]OAuthClientToken, len(tokens))
	for i := range tokens {
		tokensData[i] = OAuthClientToken{
			Token:   tokens[i],
			Expires: int64(scores[i]), // we store expire timestamp as a score
		}
	}

	return tokensData, totalPages, nil
}

func (r *Storage) GetClientTokens(id string) ([]OAuthClientToken, error) {
	key := PrefixClientTokens + id

	// use current timestamp as a start score so all expired tokens won't be picked
	nowTs := time.Now().Unix()
	startScore := strconv.FormatInt(nowTs, 10)

	r.log.Info("Getting client tokens sorted list:", key)

	tokens, scores, err := r.redisStore.GetSortedSetRange(key, startScore, "+inf")
	if err != nil {
		return nil, err
	}

	// clean up expired tokens in sorted set (remove all tokens with score up to current timestamp minus retention)
	if retain := r.cfg().OAuthTokenExpiredRetainPeriod; retain > 0 {
		cleanupStartScore := strconv.FormatInt(nowTs-int64(retain), 10)
		go r.redisStore.RemoveSortedSetRange(key, "-inf", cleanupStartScore)
	}

	if len(tokens) == 0 {
		return []OAuthClientToken{}, nil
	}

	// convert sorted set data and scores into reply struct
	tokensData := make([]OAuthClientToken, len(tokens))
	for i := range tokens {
		tokensData[i] = OAuthClientToken{
			Token:   tokens[i],
			Expires: int64(scores[i]), // we store expire timestamp as a score
		}
	}

	return tokensData, nil
}

// SetClient creates client data
func (r *Storage) SetClient(id string, orgID string, client osin.Client, ignorePrefix bool) error {
	clientDataJSON, err := json.Marshal(client)
	if err != nil {
		r.log.Error("Couldn't marshal client data: ", err)
		return err
	}

	key := PrefixClient + id
	if ignorePrefix {
		key = id
	}

	r.log.Debug("CREATING: ", key)

	err = r.store.SetKey(key, string(clientDataJSON), 0)
	if err != nil {
		r.log.WithError(err).Error("could not save oauth client data")
	}

	keyForSet := PrefixClientset + PrefixClient // Org ID

	indexKey := PrefixClientIndexList + orgID
	//check if the indexKey exists
	exists, err := r.store.Exists(indexKey)
	if err != nil {
		return err
	}
	// if it exists, delete it to avoid duplicity in the client index list
	if exists {
		r.store.RemoveFromList(indexKey, key)
	}
	// append to oauth client index list
	r.store.AppendToSet(indexKey, key)

	// In set, there is no option for update so the existing client should be removed before adding new one.
	set, _ := r.store.GetSet(keyForSet)
	for _, v := range set {
		if strings.Contains(v, client.GetId()) {
			r.store.RemoveFromSet(keyForSet, v)
		}
	}

	r.store.AddToSet(keyForSet, string(clientDataJSON))
	return nil
}

// DeleteClient Removes a client from the system
func (r *Storage) DeleteClient(id string, orgID string, ignorePrefix bool) error {
	key := PrefixClient + id
	if ignorePrefix {
		key = id
	}

	// Get the raw vals:
	clientJSON, err := r.store.GetKey(key)
	keyForSet := PrefixClientset + PrefixClient // Org ID
	if err == nil {
		r.log.Debug("Removing from set")
		r.store.RemoveFromSet(keyForSet, clientJSON)
	}

	r.store.DeleteKey(key)

	indexKey := PrefixClientIndexList + orgID
	// delete from oauth client
	r.store.RemoveFromList(indexKey, key)

	// delete list of tokens for this client
	r.store.DeleteKey(PrefixClientTokens + id)
	if r.cfg().UseRPC {
		r.redisStore.RemoveFromList(indexKey, key)
		r.redisStore.DeleteKey(PrefixClientTokens + id)
		r.redisStore.RemoveFromSet(keyForSet, clientJSON)
	}

	return nil
}

// SaveAuthorize saves authorisation data to Redis
func (r *Storage) SaveAuthorize(authData *osin.AuthorizeData) error {
	authDataJSON, err := json.Marshal(&authData)
	if err != nil {
		return err
	}
	key := PrefixAuth + authData.Code
	r.log.Debug("Saving auth code: ", key)

	_ = r.store.SetKey(key, string(authDataJSON), int64(authData.ExpiresIn))

	return nil
}

// LoadAuthorize loads auth data from redis
func (r *Storage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	key := PrefixAuth + code
	r.log.Debug("Loading auth code: ", key)
	authJSON, err := r.store.GetKey(key)

	if err != nil {
		r.log.Error("Failure retreiving auth code key: ", err)
		return nil, err
	}

	authData := osin.AuthorizeData{Client: new(OAuthClient)}
	if err := json.Unmarshal([]byte(authJSON), &authData); err != nil {
		r.log.Error("Couldn't unmarshal OAuth auth data object (LoadAuthorize): ", err)
		return nil, err
	}

	return &authData, nil
}

// RemoveAuthorize removes authorisation keys from redis
func (r *Storage) RemoveAuthorize(code string) error {
	key := PrefixAuth + code
	r.store.DeleteKey(key)
	return nil
}

// SaveAccess will save a token and it's access data to redis
func (r *Storage) SaveAccess(accessData *osin.AccessData) error {
	cfg := r.cfg()
	authDataJSON, err := json.Marshal(accessData)
	if err != nil {
		return err
	}
	key := PrefixAccess + storage.HashKey(accessData.AccessToken, cfg.HashKeys)
	r.log.Debug("Saving ACCESS key: ", key)

	// Overide default ExpiresIn:
	if oauthTokenExpire := cfg.OAuthTokenExpire; oauthTokenExpire != 0 {
		accessData.ExpiresIn = oauthTokenExpire
	}

	err = r.store.SetKey(key, string(authDataJSON), int64(accessData.ExpiresIn))
	if err != nil {
		r.log.WithError(err).Error("could not save access data")
	}

	// add code to list of tokens for this client
	sortedListKey := PrefixClientTokens + accessData.Client.GetId()
	r.log.Debug("Adding ACCESS key to sorted list: ", sortedListKey)
	r.redisStore.AddToSortedSet(
		sortedListKey,
		storage.HashKey(accessData.AccessToken, cfg.HashKeys),
		float64(accessData.CreatedAt.Unix()+int64(accessData.ExpiresIn)), // set score as token expire timestamp
	)

	// Create a user.SessionState object and register it with the authmanager
	newSession := user.NewSessionState()

	// ------
	checkPolicy := true
	if accessData.UserData != nil {
		checkPolicy = false
		err := json.Unmarshal([]byte(accessData.UserData.(string)), newSession)
		if err != nil {
			r.log.Info("Couldn't decode user.SessionState from UserData, checking policy: ", err)
			checkPolicy = true
		}
	}

	if checkPolicy {
		// defined in JWT middleware
		sessionFromPolicy, err := r.keys.SessionFromPolicy(accessData.Client.GetPolicyID(), "", false)
		if err != nil {
			return errors.New("Couldn't use policy or key rules to create token, failing")
		}

		newSession = &sessionFromPolicy
	}

	// ------

	// Set the client ID for analytics
	newSession.OauthClientID = accessData.Client.GetId()

	// Override timeouts so that we can be in sync with Osin
	newSession.Expires = time.Now().Unix() + int64(accessData.ExpiresIn)

	c, ok := accessData.Client.(*OAuthClient)
	if ok && c.MetaData != nil {
		if newSession.MetaData == nil {
			newSession.MetaData = make(map[string]interface{})
		}

		// Allow session inherit and *override* client values
		for k, v := range c.MetaData.(map[string]interface{}) {
			if _, found := newSession.MetaData[k]; !found {
				newSession.MetaData[k] = v
			}
		}
	}

	sessionLifetime := r.keys.ApplyLifetime(newSession)

	// Use the default session expiry here as this is OAuth
	r.sessions.UpdateSession(accessData.AccessToken, newSession, sessionLifetime, false)

	// Store the refresh token too
	if accessData.RefreshToken != "" {
		accessDataJSON, err := json.Marshal(accessData)
		if err != nil {
			return err
		}
		key := PrefixRefresh + accessData.RefreshToken
		refreshExpire := int64(1209600) // 14 days
		if oauthRefreshExpire := cfg.OAuthRefreshExpire; oauthRefreshExpire != 0 {
			refreshExpire = oauthRefreshExpire
		}
		r.log.Debug("STORING ACCESS DATA: ", string(accessDataJSON))
		err = r.store.SetKey(key, string(accessDataJSON), refreshExpire)
		if err != nil {
			r.log.WithError(err).Error("could not save access data")
		}
		return err
	}

	return nil
}

// LoadAccess will load access data from redis
func (r *Storage) LoadAccess(token string) (*osin.AccessData, error) {
	key := PrefixAccess + storage.HashKey(token, r.cfg().HashKeys)
	r.log.Debug("Loading ACCESS key: ", key)
	accessJSON, err := r.store.GetKey(key)

	if err != nil {
		// Fallback to unhashed value for backward compatibility
		key = PrefixAccess + token
		accessJSON, err = r.store.GetKey(key)

		if err != nil {
			r.log.Error("Failure retreiving access token by key: ", err)
			return nil, err
		}
	}

	accessData := osin.AccessData{Client: new(OAuthClient)}
	if err := json.Unmarshal([]byte(accessJSON), &accessData); err != nil {
		r.log.Error("Couldn't unmarshal OAuth auth data object (LoadAccess): ", err)
		return nil, err
	}

	return &accessData, nil
}

// RemoveAccess will remove access data from Redis
func (r *Storage) RemoveAccess(token string) error {
	access, err := r.LoadAccess(token)
	if err == nil {
		key := PrefixClientTokens + access.Client.GetId()
		//remove from set oauth.client-tokens
		r.log.Info("removing token from oauth client tokens list")
		limit := strconv.FormatFloat(float64(access.ExpireAt().Unix()), 'f', 0, 64)
		r.redisStore.RemoveSortedSetRange(key, limit, limit)
	} else {
		r.log.Warning("Cannot load access token:", token)
	}

	key := PrefixAccess + storage.HashKey(token, r.cfg().HashKeys)
	r.store.DeleteKey(key)
	// remove the access token from central storage too
	r.sessions.RemoveSession(r.orgID, token, false)
	return nil
}

// LoadRefresh will load access data from Redis
func (r *Storage) LoadRefresh(token string) (*osin.AccessData, error) {
	key := PrefixRefresh + token
	r.log.Debug("Loading REFRESH key: ", key)
	accessJSON, err := r.store.GetKey(key)

	if err != nil {
		r.log.Error("Failure retreiving access token by key: ", err)
		return nil, err
	}

	// new interface means having to make this nested... ick.
	accessData := osin.AccessData{Client: new(OAuthClient)}
	if err := json.Unmarshal([]byte(accessJSON), &accessData); err != nil {
		r.log.Error("Couldn't unmarshal OAuth auth data object (LoadRefresh): ", err,
			"; Decoding: ", accessJSON)
		return nil, err
	}

	return &accessData, nil
}

// RemoveRefresh will remove a refresh token from redis
func (r *Storage) RemoveRefresh(token string) error {
	r.log.Debug("is going to revoke refresh token: ", token)
	key := PrefixRefresh + token
	r.store.DeleteKey(key)
	return nil
}

// GetUser loads a basic-auth user session by its raw storage key.
func (r *Storage) GetUser(username string) (*user.SessionState, error) {
	key := username
	r.log.Debug("Loading User key: ", key)
	accessJSON, err := r.store.GetRawKey(key)

	if err != nil {
		r.log.Error("Failure retreiving access token by key: ", err)
		return nil, err
	}

	session := &user.SessionState{}
	if err := json.Unmarshal([]byte(accessJSON), session); err != nil {
		r.log.Error("Couldn't unmarshal OAuth auth data object (LoadRefresh): ", err,
			"; Decoding: ", accessJSON)
		return nil, err
	}

	return session, nil
}

// SetUser writes a basic-auth user session by its raw storage key.
func (r *Storage) SetUser(username string, session *user.SessionState, timeout int64) error {
	key := username
	authDataJSON, err := json.Marshal(session)
	if err != nil {
		return err
	}

	if err := r.store.SetRawKey(key, string(authDataJSON), timeout); err != nil {
		r.log.Error("Failure setting user token by key: ", err)
		return err
	}

	return nil
}

// AccessTokenGen generates access tokens with the same token format as API
// keys, so a token can be looked up as a session.
type AccessTokenGen struct {
	Keys SessionFactory
	Log  *logrus.Logger
}

// GenerateAccessToken generates base64-encoded UUID access and refresh tokens
func (a AccessTokenGen) GenerateAccessToken(data *osin.AccessData, generaterefresh bool) (accesstoken, refreshtoken string, err error) {
	log := a.Log
	if log == nil {
		log = logrus.StandardLogger()
	}
	log.Info("[OAuth] Generating new token")

	var newSession user.SessionState
	checkPolicy := true
	if data.UserData != nil {
		checkPolicy = false
		err := json.Unmarshal([]byte(data.UserData.(string)), &newSession)
		if err != nil {
			log.Info("[GenerateAccessToken] Couldn't decode user.SessionState from UserData, checking policy: ", err)
			checkPolicy = true
		}
	}

	if checkPolicy {
		// defined in JWT middleware
		sessionFromPolicy, err := a.Keys.SessionFromPolicy(data.Client.GetPolicyID(), "", false)
		if err != nil {
			return "", "", errors.New("Couldn't use policy or key rules to create token, failing")
		}

		newSession = sessionFromPolicy.Clone()
	}

	accesstoken = a.Keys.GenerateAuthKey(newSession.OrgID)
	if generaterefresh {
		refreshtoken = base64.StdEncoding.EncodeToString([]byte(uuid.New()))
	}
	return
}

// Server subclasses osin.Server so the extended storage is reachable.
type Server struct {
	osin.Server
	Config            *osin.ServerConfig
	Storage           ExtendedOsinStorageInterface
	AuthorizeTokenGen osin.AuthorizeTokenGen
	AccessTokenGen    osin.AccessTokenGen
}

// NewServer creates an osin server over the extended storage.
func NewServer(config *osin.ServerConfig, storage ExtendedOsinStorageInterface, k SessionFactory, log *logrus.Logger) *Server {
	overrideServer := Server{
		Config:            config,
		Storage:           storage,
		AuthorizeTokenGen: &osin.AuthorizeTokenGenDefault{},
		AccessTokenGen:    AccessTokenGen{Keys: k, Log: log},
	}

	overrideServer.Server.Config = config
	overrideServer.Server.Storage = storage
	overrideServer.Server.AuthorizeTokenGen = overrideServer.AuthorizeTokenGen
	overrideServer.Server.AccessTokenGen = overrideServer.AccessTokenGen

	return &overrideServer
}

// ServerConfigFor builds the osin server config the gateway uses for an
// API: error status, allowed grant and response types, redirect separator.
func ServerConfigFor(api keys.APIInfo, cfg Config) *osin.ServerConfig {
	serverConfig := osin.NewServerConfig()
	if cfg.OAuthErrorStatusCode != 0 {
		serverConfig.ErrorStatusCode = cfg.OAuthErrorStatusCode
	} else {
		serverConfig.ErrorStatusCode = 403
	}
	serverConfig.AllowedAccessTypes = make(osin.AllowedAccessType, 0, len(api.OAuth.AllowedAccessTypes))
	for _, t := range api.OAuth.AllowedAccessTypes {
		serverConfig.AllowedAccessTypes = append(serverConfig.AllowedAccessTypes, osin.AccessRequestType(t))
	}
	serverConfig.AllowedAuthorizeTypes = make(osin.AllowedAuthorizeType, 0, len(api.OAuth.AllowedAuthorizeTypes))
	for _, t := range api.OAuth.AllowedAuthorizeTypes {
		serverConfig.AllowedAuthorizeTypes = append(serverConfig.AllowedAuthorizeTypes, osin.AuthorizeRequestType(t))
	}
	serverConfig.RedirectUriSeparator = cfg.OAuthRedirectURISeparator
	return serverConfig
}
