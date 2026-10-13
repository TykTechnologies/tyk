package oauth

import (
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/lonelycode/osin"
	"github.com/sirupsen/logrus"

	internalerrors "github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/pkg/controlplane/keys"
)

// Resolution tells how a per-API OAuth storage lookup ended.
type Resolution int

const (
	// APINotFound means the API is not loaded / not active.
	APINotFound Resolution = iota
	// NoManager means the API exists but has no OAuth manager yet and the
	// caller did not ask for one to be created.
	NoManager
	// Found means a storage (and manager) is available.
	Found
)

// Resolver returns the OAuth storage and manager of an API. The gateway
// backs it with the per-spec OAuthManager (created lazily when asked); the
// Dashboard builds and caches one per API.
type Resolver interface {
	StorageFor(apiID string, createIfMissing bool) (ExtendedOsinStorageInterface, Resolution)
	ManagerFor(apiID string, createIfMissing bool) (*Manager, Resolution)
}

// PurgeStore is the unprefixed Redis access the lapsed-token purge needs.
type PurgeStore interface {
	Lock(key string, timeout time.Duration) (bool, error)
	ScanKeys(pattern string) ([]string, error)
	RemoveSortedSetRange(keyName, scoreFrom, scoreTo string) error
}

// Deps are the collaborators of the Service.
type Deps struct {
	Resolver  Resolver
	APIs      keys.APIInfoProvider
	Policies  model.PolicyProvider
	NewSecret func() string
	Purge     PurgeStore
	Log       *logrus.Logger
}

// Service implements the /tyk/oauth/* administration operations and token
// issuance entry points.
type Service struct {
	cfg func() Config
	d   Deps
	log *logrus.Logger
}

// New returns a Service.
func New(cfg func() Config, d Deps) *Service {
	if cfg == nil {
		cfg = func() Config { return Config{} }
	}
	if d.Log == nil {
		d.Log = logrus.StandardLogger()
	}
	if d.NewSecret == nil {
		d.NewSecret = NewClientSecret
	}
	return &Service{cfg: cfg, d: d, log: d.Log}
}

func statusErr(code int, msg string) *keys.StatusError {
	return &keys.StatusError{Code: code, Message: msg}
}

// ---------------------------------------------------------------------------
// clients

// CreateClient implements POST /tyk/oauth/clients/create. With APIID set
// the client is stored for that API; otherwise for every OAuth/JWT API in
// the policy's access rights.
func (s *Service) CreateClient(req ClientRequest) (ClientRequest, error) {
	// Allow the client ID to be set
	clientID := req.ClientID
	if clientID == "" {
		clientID = uuid.NewHex()
	}

	// Allow the secret to be set
	secret := req.ClientSecret
	if secret == "" {
		secret = s.d.NewSecret()
	}

	newClient := OAuthClient{
		ClientID:          clientID,
		ClientRedirectURI: req.ClientRedirectURI,
		ClientSecret:      secret,
		PolicyID:          req.PolicyID,
		MetaData:          req.MetaData,
		Description:       req.Description,
	}

	storageID := ClientStorageID(newClient.GetId())
	s.log.WithField("prefix", "api").Debug("Created storage ID: ", storageID)

	if req.APIID != "" {
		// set client only for passed API ID
		api, ok := s.d.APIs.APIByID(req.APIID)
		if !ok {
			s.log.WithFields(logrus.Fields{
				"prefix": "api",
				"apiID":  req.APIID,
				"status": "fail",
				"err":    "API doesn't exist",
			}).Error("Failed to create OAuth client")
			return ClientRequest{}, statusErr(http.StatusBadRequest, "API doesn't exist")
		}

		if !api.UseOAuth2 {
			return ClientRequest{}, statusErr(http.StatusBadRequest, "API is not OAuth2")
		}

		st, res := s.d.Resolver.StorageFor(req.APIID, true)
		if res != Found {
			return ClientRequest{}, statusErr(http.StatusInternalServerError, "Failure in storing client data.")
		}
		if err := st.SetClient(storageID, api.OrgID, &newClient, true); err != nil {
			s.log.WithFields(logrus.Fields{
				"prefix": "api",
				"apiID":  req.APIID,
				"status": "fail",
				"err":    err,
			}).Error("Failed to create OAuth client")
			return ClientRequest{}, statusErr(http.StatusInternalServerError, "Failure in storing client data.")
		}
	} else {
		// set client for all APIs from the given policy
		pol, ok := s.d.Policies.PolicyByID(model.NonScopedLastInsertedPolicyId(newClient.PolicyID))
		if !ok {
			s.log.WithFields(logrus.Fields{
				"prefix":   "api",
				"policyID": newClient.PolicyID,
				"status":   "fail",
				"err":      "Policy doesn't exist",
			}).Error("Failed to create OAuth client")
			return ClientRequest{}, statusErr(http.StatusBadRequest, "Policy doesn't exist")
		}

		oauth2 := false
		// iterate over APIs and set client for each of them
		for apiID := range pol.AccessRights {
			api, ok := s.d.APIs.APIByID(apiID)
			if !ok {
				s.log.WithFields(logrus.Fields{
					"prefix": "api",
					"apiID":  apiID,
					"status": "fail",
					"err":    "API doesn't exist",
				}).Error("Failed to create OAuth client")
				return ClientRequest{}, statusErr(http.StatusBadRequest, "API doesn't exist")
			}
			// set oauth client if it is oauth API
			if api.UseOAuth2 || api.EnableJWT {
				oauth2 = true
				st, res := s.d.Resolver.StorageFor(apiID, true)
				if res != Found {
					return ClientRequest{}, statusErr(http.StatusInternalServerError, "Failure in storing client data.")
				}
				if err := st.SetClient(storageID, api.OrgID, &newClient, true); err != nil {
					s.log.WithFields(logrus.Fields{
						"prefix": "api",
						"apiID":  apiID,
						"status": "fail",
						"err":    err,
					}).Error("Failed to create OAuth client")
					return ClientRequest{}, statusErr(http.StatusInternalServerError, "Failure in storing client data.")
				}
			}
		}

		if !oauth2 {
			return ClientRequest{}, statusErr(http.StatusBadRequest, "API is not OAuth2")
		}
	}

	clientData := clientRequestFrom(&newClient)

	s.log.WithFields(logrus.Fields{
		"prefix":            "api",
		"apiID":             req.APIID,
		"clientID":          clientData.ClientID,
		"clientRedirectURI": clientData.ClientRedirectURI,
		"policyID":          clientData.PolicyID,
		"description":       clientData.Description,
		"status":            "ok",
	}).Info("Created OAuth client")

	return clientData, nil
}

func (s *Service) clientStorage(apiID string, notFoundMsg string, notFoundCode int) (ExtendedOsinStorageInterface, keys.APIInfo, error) {
	api, ok := s.d.APIs.APIByID(apiID)
	if !ok {
		return nil, keys.APIInfo{}, statusErr(notFoundCode, notFoundMsg)
	}
	st, res := s.d.Resolver.StorageFor(apiID, false)
	if res != Found {
		return nil, api, statusErr(http.StatusNotFound, "OAuth Client ID not found")
	}
	return st, api, nil
}

// RotateClientSecret implements PUT /tyk/oauth/clients/{api}/{client}/rotate.
func (s *Service) RotateClientSecret(apiID, clientID string) (ClientRequest, error) {
	st, api, err := s.clientStorage(apiID, "API doesn't exist", http.StatusNotFound)
	if err != nil {
		return ClientRequest{}, err
	}

	storageID := ClientStorageID(clientID)
	client, err := st.GetExtendedClientNoPrefix(storageID)
	if err != nil {
		return ClientRequest{}, statusErr(http.StatusNotFound, "OAuth Client ID not found")
	}

	updatedClient := OAuthClient{
		ClientID:          client.GetId(),
		ClientSecret:      s.d.NewSecret(),
		ClientRedirectURI: client.GetRedirectUri(),
		PolicyID:          client.GetPolicyID(),
		MetaData:          client.GetUserData(),
		Description:       client.GetDescription(),
	}

	if err := st.SetClient(storageID, api.OrgID, &updatedClient, true); err != nil {
		s.log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    err,
		}).Error("Failed to update OAuth client")
		return ClientRequest{}, statusErr(http.StatusInternalServerError, "Failure in storing client data")
	}

	// invalidate tokens if we had a new policy
	InvalidateTokens(client, updatedClient, st, s.log)

	return clientRequestFrom(&updatedClient), nil
}

// UpdateClient implements PUT /tyk/oauth/clients/{api}/{client}.
func (s *Service) UpdateClient(apiID, clientID string, req ClientRequest) (ClientRequest, error) {
	api, ok := s.d.APIs.APIByID(apiID)
	if !ok {
		return ClientRequest{}, statusErr(http.StatusNotFound, "API doesn't exist")
	}

	// check policy
	if req.PolicyID != "" {
		pol, ok := s.d.Policies.PolicyByID(model.NewScopedCustomPolicyId(api.OrgID, req.PolicyID))
		if !ok {
			return ClientRequest{}, statusErr(http.StatusNotFound, "Policy doesn't exist")
		}
		if _, ok := pol.AccessRights[apiID]; !ok {
			return ClientRequest{}, statusErr(http.StatusBadRequest, "Policy access rights doesn't contain API this OAuth client belongs to")
		}
	}

	st, res := s.d.Resolver.StorageFor(apiID, false)
	if res != Found {
		return ClientRequest{}, statusErr(http.StatusNotFound, "OAuth Client ID not found")
	}

	storageID := ClientStorageID(clientID)
	client, err := st.GetExtendedClientNoPrefix(storageID)
	if err != nil {
		return ClientRequest{}, statusErr(http.StatusNotFound, "OAuth Client ID not found")
	}

	updatedClient := OAuthClient{
		ClientID:          client.GetId(),
		ClientSecret:      client.GetSecret(),
		ClientRedirectURI: req.ClientRedirectURI, // update
		PolicyID:          req.PolicyID,          // update
		MetaData:          req.MetaData,          // update
		Description:       req.Description,       // update
	}

	if err := st.SetClient(storageID, api.OrgID, &updatedClient, true); err != nil {
		s.log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    err,
		}).Error("Failed to update OAuth client")
		return ClientRequest{}, statusErr(http.StatusInternalServerError, "Failure in storing client data")
	}

	// invalidate tokens if we had a new policy
	InvalidateTokens(client, updatedClient, st, s.log)

	return clientRequestFrom(&updatedClient), nil
}

// InvalidateTokens removes every token of a client whose policy changed.
func InvalidateTokens(prevClient ExtendedOsinClientInterface, updatedClient OAuthClient, st ExtendedOsinStorageInterface, log *logrus.Logger) {
	if log == nil {
		log = logrus.StandardLogger()
	}
	if prevPolicy := prevClient.GetPolicyID(); prevPolicy != "" && prevPolicy != updatedClient.PolicyID {
		tokenList, err := st.GetClientTokens(updatedClient.ClientID)
		if err != nil {
			log.WithError(err).Warning("Could not get list of tokens for updated OAuth client")
		}

		for _, token := range tokenList {
			if err := st.RemoveAccess(token.Token); err != nil {
				log.WithError(err).Warning("Could not remove token for updated OAuth client policy")
			}
		}
	}
}

// GetClient implements GET /tyk/oauth/clients/{api}/{client}.
func (s *Service) GetClient(apiID, clientID string) (ClientRequest, error) {
	if _, ok := s.d.APIs.APIByID(apiID); !ok {
		s.log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"client": clientID,
			"err":    "not found",
		}).Error("Failed to retrieve OAuth client details")
		return ClientRequest{}, statusErr(http.StatusNotFound, "OAuth Client ID not found")
	}

	st, res := s.d.Resolver.StorageFor(apiID, true)
	if res != Found {
		return ClientRequest{}, statusErr(http.StatusNotFound, "OAuth Client ID not found")
	}

	clientData, err := st.GetExtendedClientNoPrefix(ClientStorageID(clientID))
	if err != nil {
		return ClientRequest{}, statusErr(http.StatusNotFound, "OAuth Client ID not found")
	}

	s.log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  apiID,
		"status": "ok",
		"client": clientID,
	}).Info("Retrieved OAuth client ID")

	return clientRequestFrom(clientData), nil
}

func (s *Service) apiClients(apiID string) ([]ExtendedOsinClientInterface, error) {
	api, ok := s.d.APIs.APIByID(apiID)
	if !ok {
		s.log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    "API not found",
		}).Error("Failed to retrieve OAuth client list.")
		return nil, statusErr(http.StatusNotFound, ErrClientNotFound)
	}

	clientData := []ExtendedOsinClientInterface{}
	if api.UseOAuth2 {
		st, res := s.d.Resolver.StorageFor(apiID, false)
		if res != Found {
			return nil, statusErr(http.StatusNotFound, ErrClientNotFound)
		}
		var err error
		clientData, err = st.GetClients(PrefixClient, api.OrgID, true)
		if err != nil {
			s.log.WithFields(logrus.Fields{
				"prefix": "api",
				"apiID":  apiID,
				"status": "fail",
				"err":    err,
			}).Error("Failed to report OAuth client list")
			return nil, statusErr(http.StatusNotFound, ErrClientNotFound)
		}
	}

	return clientData, nil
}

// ListClients implements GET /tyk/oauth/clients/{api}.
func (s *Service) ListClients(apiID string) ([]ClientRequest, error) {
	clientData, err := s.apiClients(apiID)
	if err != nil {
		return nil, err
	}

	clients := []ClientRequest{}
	for _, c := range clientData {
		clients = append(clients, clientRequestFrom(c))
	}
	s.log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  apiID,
		"status": "ok",
	}).Info("Retrieved OAuth client list")

	return clients, nil
}

// DeleteClient implements DELETE /tyk/oauth/clients/{api}/{client}.
func (s *Service) DeleteClient(apiID, clientID string) (keys.Result, error) {
	if _, ok := s.d.APIs.APIByID(apiID); !ok {
		s.log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"client": clientID,
			"err":    "not found",
		}).Error("Failed to delete OAuth client")
		return keys.Result{}, statusErr(http.StatusNotFound, "OAuth Client ID not found")
	}

	st, res := s.d.Resolver.StorageFor(apiID, false)
	if res != Found {
		return keys.Result{}, statusErr(http.StatusNotFound, "OAuth Client ID not found")
	}

	api, _ := s.d.APIs.APIByID(apiID)
	if err := st.DeleteClient(ClientStorageID(clientID), api.OrgID, true); err != nil {
		return keys.Result{}, statusErr(http.StatusInternalServerError, "Delete failed")
	}

	s.log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  apiID,
		"status": "ok",
		"client": clientID,
	}).Info("Deleted OAuth client")

	return keys.Result{Key: clientID, Status: "ok", Action: "deleted", StoredKey: clientID}, nil
}

// APIsForClient returns the OAuth APIs of the org (all orgs when orgID is
// empty) that hold a client with the given ID.
func (s *Service) APIsForClient(clientID, orgID string) []string {
	apis := []string{}
	var candidates []keys.APIInfo
	if orgID == "" {
		candidates = s.d.APIs.AllAPIs()
	} else {
		candidates = s.d.APIs.APIsForOrg(orgID)
	}

	for _, api := range candidates {
		if !api.UseOAuth2 {
			continue
		}
		clients, err := s.apiClients(api.APIID)
		if err != nil {
			continue
		}
		for _, client := range clients {
			if client.GetId() == clientID {
				apis = append(apis, api.APIID)
			}
		}
	}

	return apis
}

// ClientTokens implements GET /tyk/oauth/clients/{api}/{client}/tokens.
func (s *Service) ClientTokens(apiID, clientID string) ([]OAuthClientToken, error) {
	st, _, err := s.clientStorage(apiID, "OAuth Client ID not found", http.StatusNotFound)
	if err != nil {
		return nil, err
	}
	tokens, err := st.GetClientTokens(clientID)
	if err != nil {
		return nil, statusErr(http.StatusInternalServerError, "Get client tokens failed")
	}
	return tokens, nil
}

// ClientTokensPage implements the paginated form (?page=N) of ClientTokens.
func (s *Service) ClientTokensPage(apiID, clientID string, page int) (PaginatedClientTokens, error) {
	if page <= 0 {
		page = 1
	}
	st, _, err := s.clientStorage(apiID, "OAuth Client ID not found", http.StatusNotFound)
	if err != nil {
		return PaginatedClientTokens{}, err
	}
	tokens, totalPages, err := st.GetPaginatedClientTokens(clientID, page)
	if err != nil {
		return PaginatedClientTokens{}, statusErr(http.StatusInternalServerError, "Get client tokens failed")
	}
	return PaginatedClientTokens{
		Pagination: PaginationStatus{PageSize: 100, PageNum: page, PageTotal: totalPages},
		Tokens:     tokens,
	}, nil
}

// ---------------------------------------------------------------------------
// tokens

const (
	accessTokenHint  = "access_token"
	refreshTokenHint = "refresh_token"
)

// RevokeToken removes an access and/or refresh token from a storage.
func RevokeToken(st ExtendedOsinStorageInterface, token, tokenTypeHint string) {
	switch tokenTypeHint {
	case accessTokenHint:
		st.RemoveAccess(token)
	case refreshTokenHint:
		st.RemoveRefresh(token)
	default:
		st.RemoveAccess(token)
		st.RemoveRefresh(token)
	}
}

// RevokeAllTokens removes every token of a client after checking its
// secret. It returns the HTTP status the gateway reports, the revoked
// access tokens and an error.
func RevokeAllTokens(st ExtendedOsinStorageInterface, clientID, clientSecret string, log *logrus.Logger) (int, []string, error) {
	if log == nil {
		log = logrus.StandardLogger()
	}
	resp := []string{}
	client, err := st.GetClient(clientID)
	log.Debug("Revoke all tokens")
	if err != nil {
		return http.StatusNotFound, resp, errors.New("error getting oauth client")
	}

	if client.GetSecret() != clientSecret {
		return http.StatusUnauthorized, resp, errors.New(ErrClientSecretWrong)
	}

	clientTokens, err := st.GetClientTokens(clientID)
	if err != nil {
		return http.StatusBadRequest, resp, errors.New("cannot retrieve client tokens")
	}

	log.Debug("Tokens found to be revoked:", len(clientTokens))
	for _, token := range clientTokens {
		access, err := st.LoadAccess(token.Token)
		if err == nil {
			resp = append(resp, access.AccessToken)
			st.RemoveAccess(access.AccessToken)
			st.RemoveRefresh(access.RefreshToken)
		} else {
			log.Debug("error loading access:", err.Error())
		}
	}

	return http.StatusOK, resp, nil
}

// RevokeClientToken implements POST /tyk/oauth/revoke across every API of
// the org holding the client.
func (s *Service) RevokeClientToken(orgID, clientID, token, tokenTypeHint string) error {
	if token == "" {
		return statusErr(http.StatusBadRequest, ErrTokenEmpty)
	}
	if clientID == "" {
		return statusErr(http.StatusBadRequest, ErrClientIDEmpty)
	}

	apis := s.APIsForClient(clientID, orgID)
	if len(apis) == 0 {
		return statusErr(http.StatusBadRequest, "oauth client doesn't exist")
	}

	for _, apiID := range apis {
		if st, res := s.d.Resolver.StorageFor(apiID, false); res == Found {
			RevokeToken(st, token, tokenTypeHint)
		}
	}
	return nil
}

// RevokeAllClientTokens implements POST /tyk/oauth/revoke_all across every
// API of the org holding the client; it returns the revoked access tokens
// so the caller can notify other gateways.
func (s *Service) RevokeAllClientTokens(orgID, clientID, clientSecret string) ([]string, error) {
	if clientID == "" {
		return nil, statusErr(http.StatusUnauthorized, ErrClientIDEmpty)
	}
	if clientSecret == "" {
		return nil, statusErr(http.StatusUnauthorized, ErrClientSecretEmpty)
	}

	apis := s.APIsForClient(clientID, orgID)
	if len(apis) == 0 {
		// if api is 0 is because the client wasn't found
		return nil, statusErr(http.StatusNotFound, "oauth client doesn't exist")
	}

	tokens := []string{}
	for _, apiID := range apis {
		if st, res := s.d.Resolver.StorageFor(apiID, false); res == Found {
			_, revoked, _ := RevokeAllTokens(st, clientID, clientSecret, s.log)
			tokens = append(tokens, revoked...)
		}
	}
	return tokens, nil
}

// InvalidateRefresh implements DELETE /tyk/oauth/refresh/{token}?api_id=.
func (s *Service) InvalidateRefresh(apiID, token string) (keys.Result, error) {
	if apiID == "" {
		return keys.Result{}, statusErr(http.StatusBadRequest, "Missing parameter api_id")
	}

	s.log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  apiID,
	}).Debug("Looking for refresh token in API Register")

	if _, ok := s.d.APIs.APIByID(apiID); !ok {
		s.log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    "API not found",
		}).Error("Failed to invalidate refresh token")
		return keys.Result{}, statusErr(http.StatusNotFound, "API for this refresh token not found")
	}

	st, res := s.d.Resolver.StorageFor(apiID, false)
	if res != Found {
		s.log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    "API is not OAuth",
		}).Error("Failed to invalidate refresh token")
		return keys.Result{}, statusErr(http.StatusBadRequest, "OAuth is not enabled on this API")
	}

	if err := st.RemoveRefresh(token); err != nil {
		s.log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    err,
		}).Error("Failed to invalidate refresh token")
		return keys.Result{}, statusErr(http.StatusInternalServerError, "Failed to invalidate refresh token")
	}

	s.log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  apiID,
		"token":  token,
		"status": "ok",
	}).Info("Invalidated refresh token")

	return keys.Result{Key: token, Status: "ok", Action: "deleted", StoredKey: token}, nil
}

// PurgeLapsedTokens removes expired entries from every client token index
// (DELETE /tyk/oauth/tokens?scope=lapsed). It is a no-op unless
// oauth_token_expired_retain_period is set.
func (s *Service) PurgeLapsedTokens() error {
	retain := s.cfg().OAuthTokenExpiredRetainPeriod
	if retain <= 0 {
		return nil
	}
	if s.d.Purge == nil {
		return errors.New("purge store not configured")
	}

	ok, err := s.d.Purge.Lock("oauth-purge-lock", time.Minute)
	if err != nil {
		s.log.WithError(err).Error("error acquiring lock to purge oauth tokens")
		return err
	}

	if !ok {
		s.log.Info("oauth tokens purge lock not acquired, purging in background")
		return nil
	}

	keysToPurge, err := s.d.Purge.ScanKeys(ClientTokensKeyPattern)
	if err != nil {
		s.log.WithError(err).Error("error while scanning for tokens")
		return err
	}

	nowTs := time.Now().Unix()
	// clean up expired tokens in sorted set (remove all tokens with score up to current timestamp minus retention)
	cleanupStartScore := strconv.FormatInt(nowTs-int64(retain), 10)

	var wg sync.WaitGroup
	errs := make(chan error, len(keysToPurge))
	for _, key := range keysToPurge {
		wg.Add(1)
		go func(k string) {
			defer wg.Done()
			if err := s.d.Purge.RemoveSortedSetRange(k, "-inf", cleanupStartScore); err != nil {
				errs <- err
			}
		}(key)
	}

	wg.Wait()
	close(errs)

	combinedErr := &multierror.Error{ErrorFormat: internalerrors.Formatter}
	for err := range errs {
		combinedErr = multierror.Append(combinedErr, err)
	}

	return combinedErr.ErrorOrNil()
}

// ---------------------------------------------------------------------------
// issuance

// Authorize runs the authorize-client flow for apiID: with keyRules (a
// session JSON) it issues a code, or a token for response_type=token.
func (s *Service) Authorize(apiID string, r *http.Request, keyRules string) (*osin.Response, error) {
	m, res := s.d.Resolver.ManagerFor(apiID, true)
	if res != Found || m == nil {
		return nil, statusErr(http.StatusNotFound, "API not found")
	}
	if keyRules == "" {
		s.log.Warning("Authorise request is missing key_rules in params, policy will be required!")
	}
	return m.HandleAuthorisation(r, true, keyRules), nil
}

// Token runs the token endpoint for apiID (client_credentials,
// authorization_code, refresh_token, password).
func (s *Service) Token(apiID string, r *http.Request) (*osin.Response, error) {
	m, res := s.d.Resolver.ManagerFor(apiID, true)
	if res != Found || m == nil {
		return nil, statusErr(http.StatusNotFound, "API not found")
	}
	return m.HandleAccess(r), nil
}
