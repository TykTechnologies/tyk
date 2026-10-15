package keys

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/policy"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// APIInfo is the slice of an API definition the key administration logic
// reads. The gateway fills it from its loaded specs, the Dashboard from its
// database; in both cases only active APIs are reported.
type APIInfo struct {
	APIID string
	OrgID string

	// SessionLifetime is the API-level session_lifetime (seconds).
	SessionLifetime int64
	// SessionLifetimeRespectsKeyExpiration is the API-level flag; the
	// global config flag is OR-ed in by the service.
	SessionLifetimeRespectsKeyExpiration bool
	// DontSetQuotasOnCreate skips the quota reset on key create/update.
	DontSetQuotasOnCreate bool
	// IsMCP reports an MCP proxy (not a synthetic adapter), which constrains
	// which access-right fields are allowed.
	IsMCP bool

	// UseOAuth2 and EnableJWT gate OAuth client administration.
	UseOAuth2 bool
	EnableJWT bool
	// OAuth carries the API's oauth_meta, used to build the OAuth server.
	OAuth OAuthMeta
}

// OAuthMeta mirrors apidef.APIDefinition.Oauth2Meta without the osin
// dependency; the values are osin.AccessRequestType / AuthorizeRequestType.
type OAuthMeta struct {
	AllowedAccessTypes     []string
	AllowedAuthorizeTypes  []string
	AuthorizeLoginRedirect string
}

// APIInfoProvider resolves APIs for the key logic. A false second return
// value means "not loaded / not active", which mirrors the gateway's
// getApiSpec returning nil.
type APIInfoProvider interface {
	APIByID(apiID string) (APIInfo, bool)
	APIsForOrg(orgID string) []APIInfo
	AllAPIs() []APIInfo
}

// SessionStore is the subset of session persistence the service needs.
// *SessionManager satisfies it; the gateway adapts its SessionHandler.
type SessionStore interface {
	Store() storage.Handler
	UpdateSession(keyName string, session *user.SessionState, resetTTLTo int64, hashed bool) error
	RemoveSession(orgID, keyName string, hashed bool) bool
	SessionDetail(orgID, keyName string, hashed bool) (user.SessionState, bool)
	Sessions(filter string) []string
	ResetQuota(keyName string, session *user.SessionState, hashed bool)
}

// Config is the gateway configuration the key administration logic depends
// on. Values must match the gateway(s) sharing the Redis.
type Config struct {
	HashConfig

	BasicAuthHashKeyFunction string
	MinTokenLength           int
	AllowMasterKeys          bool
	EnableHashedKeysListing  bool

	GlobalSessionLifetime                int64
	ForceGlobalSessionLifetime           bool
	SessionLifetimeRespectsKeyExpiration bool
}

// Deps are the collaborators of the Service.
type Deps struct {
	Sessions SessionStore
	APIs     APIInfoProvider
	Policies model.PolicyProvider
	Certs    certs.CertificateManager
	Log      *logrus.Logger
}

// Service implements the key administration operations behind the
// gateway's /tyk/keys endpoints.
type Service struct {
	cfg func() Config
	d   Deps
	log *logrus.Logger
}

// New returns a Service. cfg is called on every operation so a caller with
// live configuration sees updates.
func New(cfg func() Config, d Deps) *Service {
	if cfg == nil {
		cfg = func() Config { return Config{} }
	}
	if d.Log == nil {
		d.Log = logrus.StandardLogger()
	}
	return &Service{cfg: cfg, d: d, log: d.Log}
}

// Config returns the current configuration.
func (s *Service) Config() Config { return s.cfg() }

// StatusError carries the HTTP status and message the gateway admin API
// returns for a failed operation, so every caller renders identical errors.
type StatusError struct {
	Code    int
	Message string
}

func (e *StatusError) Error() string { return e.Message }

func statusErr(code int, msg string) *StatusError { return &StatusError{Code: code, Message: msg} }

// Result is the success payload of a key write (apiModifyKeySuccess).
type Result struct {
	Key     string `json:"key"`
	Status  string `json:"status"`
	Action  string `json:"action"`
	KeyHash string `json:"key_hash,omitempty"`

	// StoredKey is the key name the session was written under. It equals
	// Key except for hashed basic-auth creates, where Key is blanked in
	// the response.
	StoredKey string `json:"-"`
}

// WriteOptions parameterise CreateOrUpdate.
type WriteOptions struct {
	// IsPut selects update semantics (PUT) instead of create (POST).
	IsPut bool
	// IsHashed means keyName is a key hash.
	IsHashed bool
	// SuppressReset preserves quota and rate-limit counters (suppress_reset=1).
	SuppressReset bool
}

// ---------------------------------------------------------------------------
// shared helpers

func (s *Service) generateToken(orgID, keyID string, customHashKeyFunction ...string) string {
	hashKeyFunction := s.cfg().HashKeyFunction
	if len(customHashKeyFunction) > 0 {
		hashKeyFunction = customHashKeyFunction[0]
	}
	return GenerateToken(hashKeyFunction, orgID, keyID, s.log)
}

// GenerateAuthKey returns a fresh token for the org.
func (s *Service) GenerateAuthKey(orgID string) string {
	return s.generateToken(orgID, "")
}

// GenerateHMACSecret returns a random HMAC secret.
func GenerateHMACSecret() string {
	return base64.StdEncoding.EncodeToString([]byte(uuid.NewHex()))
}

// KeyNameForUsername converts a basic-auth username into the key name the
// session is stored under, unless username actions are disabled.
func (s *Service) KeyNameForUsername(orgID, username string) string {
	if s.cfg().DisableKeyActionsByUsername {
		return username
	}
	return s.generateToken(orgID, username)
}

// ApplyPolicies applies the session's policies, scoped to orgID when given.
func (s *Service) ApplyPolicies(session *user.SessionState, orgID *string) error {
	return policy.New(orgID, s.d.Policies, s.log).Apply(session)
}

func (s *Service) applyPoliciesForAPI(session *user.SessionState, api *APIInfo) error {
	var orgID *string
	if api != nil {
		orgID = &api.OrgID
	}
	return s.ApplyPolicies(session, orgID)
}

// ApplyLifetime returns the TTL for the session: the largest lifetime over
// the APIs in its access rights (or over apis when it has none), -1 to
// persist forever, 0 when no API is known.
func (s *Service) ApplyLifetime(sess *user.SessionState, apis ...*APIInfo) int64 {
	cfg := s.cfg()
	var lifetime int64

	if len(sess.AccessRights) > 0 {
		apis = s.apisFromAccessRights(sess)
	}

	for _, api := range apis {
		if api == nil {
			continue
		}
		respects := cfg.SessionLifetimeRespectsKeyExpiration || api.SessionLifetimeRespectsKeyExpiration
		sessionLifeTime := sess.Lifetime(respects, api.SessionLifetime, cfg.ForceGlobalSessionLifetime, cfg.GlobalSessionLifetime)
		// -1 means "never delete" (persist forever), which is the maximum possible lifetime
		if sessionLifeTime == -1 {
			return -1
		}
		if sessionLifeTime > lifetime {
			lifetime = sessionLifeTime
		}
	}

	return lifetime
}

func (s *Service) apisFromAccessRights(sess *user.SessionState) []*APIInfo {
	var apis []*APIInfo
	if sess != nil && len(sess.AccessRights) > 0 {
		for apiID := range sess.AccessRights {
			if api, ok := s.d.APIs.APIByID(apiID); ok {
				a := api
				apis = append(apis, &a)
			}
		}
	}
	return apis
}

func (s *Service) checkAndApplyTrialPeriod(keyName string, newSession *user.SessionState, isHashed bool) {
	// Check the policies to see if we are forcing an expiry on the key
	for _, polID := range newSession.PolicyIDs() {
		pol, ok := s.d.Policies.PolicyByID(model.NewScopedCustomPolicyId(newSession.OrgID, polID))
		if !ok {
			continue
		}
		// Are we forcing an expiry?
		if pol.KeyExpiresIn > 0 {
			// We are, does the key exist?
			_, found := s.d.Sessions.SessionDetail(newSession.OrgID, keyName, isHashed)
			if !found {
				// this is a new key, lets expire it
				newSession.Expires = time.Now().Unix() + pol.KeyExpiresIn
			}
		}

		if pol.PostExpiryAction != "" {
			newSession.PostExpiryAction = pol.PostExpiryAction
		}
		if pol.PostExpiryGracePeriod != 0 {
			newSession.PostExpiryGracePeriod = pol.PostExpiryGracePeriod
		}
	}
}

func (s *Service) applyPoliciesAndSave(keyName string, session *user.SessionState, api *APIInfo, isHashed bool) error {
	if err := s.applyPoliciesForAPI(session, api); err != nil {
		return err
	}
	lifetime := s.ApplyLifetime(session, api)
	return s.d.Sessions.UpdateSession(keyName, session, lifetime, isHashed)
}

// ResetAPILimits clears per-API limits that are set but zero-valued.
func ResetAPILimits(accessRights map[string]user.AccessDefinition) {
	for apiID := range accessRights {
		if access := accessRights[apiID]; !access.Limit.IsEmpty() && access.Limit == (user.APILimit{}) {
			access.Limit = user.APILimit{}
			accessRights[apiID] = access
		}
	}
}

// BasicAuthHashAlgo returns the configured basic-auth password hash, or
// bcrypt when unset or invalid.
func (s *Service) BasicAuthHashAlgo() string {
	algo := s.cfg().BasicAuthHashKeyFunction
	if ok := user.IsHashType(algo); !ok {
		return string(user.HashBCrypt)
	}
	return algo
}

// SetBasicAuthSessionPassword hashes the session's basic-auth password in
// place with the configured algorithm.
func (s *Service) SetBasicAuthSessionPassword(session *user.SessionState) {
	basicAuthHashAlgo := s.BasicAuthHashAlgo()

	if basicAuthHashAlgo == string(user.HashBCrypt) {
		session.BasicAuthData.Hash = user.HashBCrypt
		hashedPassBytes, err := bcrypt.GenerateFromPassword([]byte(session.BasicAuthData.Password), 10)
		if err != nil {
			s.log.WithError(err).Error("Could not hash password, setting to plaintext")
			session.BasicAuthData.Hash = user.HashPlainText
			return
		}

		session.BasicAuthData.Password = string(hashedPassBytes)
		return
	}

	session.BasicAuthData.Password = storage.HashStr(session.BasicAuthData.Password, basicAuthHashAlgo)
	session.BasicAuthData.Hash = user.HashType(basicAuthHashAlgo)
}

// doAddOrUpdate resets quota, applies the trial period, applies policies
// and saves the key once per access right (or once per known API for
// master keys), exactly as the gateway does.
func (s *Service) doAddOrUpdate(keyName string, newSession *user.SessionState, dontReset bool, isHashed bool) error {
	// field last_updated plays an important role in in-mem rate limiter
	// so update last_updated to current timestamp only if suppress_reset wasn't set to 1
	if !dontReset {
		newSession.LastUpdated = fmt.Sprint(time.Now().Unix())
	}

	logger := s.log.WithFields(logrus.Fields{
		"prefix":      "api",
		"key":         ObfuscateKey(keyName, s.cfg().EnableKeyLogging),
		"org_id":      newSession.OrgID,
		"expires":     newSession.Expires,
		"api_id":      "--",
		"user_id":     "system",
		"user_ip":     "--",
		"path":        "--",
		"server_name": "system",
	})

	if len(newSession.AccessRights) > 0 {
		// reset API-level limit to empty APILimit if any has a zero-value
		ResetAPILimits(newSession.AccessRights)

		// We have a specific list of access rules, only add / update those
		for apiID := range newSession.AccessRights {
			var api *APIInfo
			if a, ok := s.d.APIs.APIByID(apiID); ok {
				api = &a
			} else {
				logger.WithField("api_id", apiID).Warn("Can't find active API, storing anyway")
			}

			if api != nil {
				s.checkAndApplyTrialPeriod(keyName, newSession, isHashed)
			}

			// Lets reset keys if they are edited by admin
			if api == nil || !api.DontSetQuotasOnCreate {
				// Reset quota by default
				if !dontReset {
					s.d.Sessions.ResetQuota(keyName, newSession, isHashed)
					newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
				}
			}

			// apply policies (if any) and save key
			if err := s.applyPoliciesAndSave(keyName, newSession, api, isHashed); err != nil {
				return err
			}
		}
	} else {
		// nothing defined, add key to ALL
		if !s.cfg().AllowMasterKeys {
			logger.Error("Master keys disallowed in configuration, key not added.")
			return fmt.Errorf("Master keys not allowed")
		}
		logger.Warning("No API Access Rights set, adding key to ALL.")

		for _, api := range s.d.APIs.AllAPIs() {
			api := api
			if !dontReset {
				s.d.Sessions.ResetQuota(keyName, newSession, isHashed)
				newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
			}
			s.checkAndApplyTrialPeriod(keyName, newSession, isHashed)
			// apply policies (if any) and save key
			if err := s.applyPoliciesAndSave(keyName, newSession, &api, isHashed); err != nil {
				return err
			}
		}
	}

	logger.Info("Key added or updated.")
	return nil
}

// errTimeout is returned by List when the context expires.
var errTimeout = statusErr(http.StatusGatewayTimeout, "Request timeout while processing keys")

func ctxErr(ctx context.Context) error {
	if ctx.Err() != nil {
		return errTimeout
	}
	return nil
}

// nonScopedPolicyID resolves a policy by custom ID without org scope
// (backward-compatible lookup used by the hashed-key policy update).
func nonScopedPolicyID(id string) model.PolicyID {
	return model.NonScopedLastInsertedPolicyId(id)
}

// AddOrUpdate writes an already validated session under keyName, applying
// quota reset, trial period and policies per access right. It is the
// write step shared by Create, CreateOrUpdate and the JSVM key API.
func (s *Service) AddOrUpdate(keyName string, session *user.SessionState, suppressReset bool, isHashed bool) error {
	return s.doAddOrUpdate(keyName, session, suppressReset, isHashed)
}

// GenerateToken builds a token for orgID and keyID with the configured
// hash function (the gateway's generateToken).
func (s *Service) GenerateToken(orgID, keyID string) string {
	return s.generateToken(orgID, keyID)
}

// LifetimeFor returns the session TTL for one API, ignoring the session's
// access rights (used by the OAuth password flow and the JWT middleware).
func (s *Service) LifetimeFor(sess *user.SessionState, api *APIInfo) int64 {
	cfg := s.cfg()
	if api == nil {
		return sess.Lifetime(cfg.SessionLifetimeRespectsKeyExpiration, 0, cfg.ForceGlobalSessionLifetime, cfg.GlobalSessionLifetime)
	}
	respects := cfg.SessionLifetimeRespectsKeyExpiration || api.SessionLifetimeRespectsKeyExpiration
	return sess.Lifetime(respects, api.SessionLifetime, cfg.ForceGlobalSessionLifetime, cfg.GlobalSessionLifetime)
}

// SessionFromPolicy builds a session from a policy (the JWT middleware's
// generateSessionFromPolicy). With enforceOrg the policy must belong to
// orgID; otherwise the policy's org is used.
func (s *Service) SessionFromPolicy(policyID, orgID string, enforceOrg bool) (user.SessionState, error) {
	var polID model.PolicyID
	if enforceOrg {
		polID = model.NewScopedCustomPolicyId(orgID, policyID)
	} else {
		polID = model.NonScopedLastInsertedPolicyId(policyID)
	}

	pol, ok := s.d.Policies.PolicyByID(polID)
	session := user.SessionState{}

	if !ok {
		return session.Clone(), errors.New("Policy not found")
	}
	// Check ownership, policy org owner must be the same as API,
	// otherwise you could overwrite a session key with a policy from a different org!
	if enforceOrg {
		if pol.OrgID != orgID {
			s.log.Error("Attempting to apply policy from different organisation to key, skipping")
			return session.Clone(), errors.New("Key not authorized: no matching policy")
		}
	} else {
		// Org isn't enforced, so lets use the policy baseline
		orgID = pol.OrgID
	}

	session.SetPolicies(policyID)
	session.OrgID = orgID
	session.Allowance = pol.Rate // legacy, kept so output is consistent
	session.Rate = pol.Rate
	session.Per = pol.Per
	session.ThrottleInterval = pol.ThrottleInterval
	session.ThrottleRetryLimit = pol.ThrottleRetryLimit
	session.MaxQueryDepth = pol.MaxQueryDepth
	session.QuotaMax = pol.QuotaMax
	session.QuotaRenewalRate = pol.QuotaRenewalRate
	session.AccessRights = make(map[string]user.AccessDefinition)
	for apiID, access := range pol.AccessRights {
		session.AccessRights[apiID] = access
	}
	session.HMACEnabled = pol.HMACEnabled
	session.EnableHTTPSignatureValidation = pol.EnableHTTPSignatureValidation
	session.IsInactive = pol.IsInactive
	session.Tags = pol.Tags

	if pol.KeyExpiresIn > 0 {
		session.Expires = time.Now().Unix() + pol.KeyExpiresIn
	}

	session.PostExpiryAction = pol.PostExpiryAction
	session.PostExpiryGracePeriod = pol.PostExpiryGracePeriod

	return session.Clone(), nil
}
