package keys

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// OrgKeyPrefix is the Redis prefix of organisation sessions. The store
// itself never hashes key names (orgkey.<orgID>), but the SessionManager
// built over it must carry the global HashConfig, because quota counters
// for orgs are addressed as quota-<HashKey(orgID, hash_keys)>.
const OrgKeyPrefix = "orgkey."

// OrgStoreResolver returns the session store for an org's session. The
// boolean mirrors the gateway's getSpecForOrg: false means no API is loaded
// at all, in which case writes fall back to the default org store (unless
// suppressed) and reads report the org as not found.
type OrgStoreResolver interface {
	OrgSessions(orgID string) (SessionStore, bool)
}

// OrgConfig is the configuration the org-key operations depend on.
type OrgConfig struct {
	HashKeys               bool
	SupressDefaultOrgStore bool
}

// OrgDeps are the collaborators of OrgService.
type OrgDeps struct {
	Resolver OrgStoreResolver
	// Default is the fallback org store used by writes when no API is loaded.
	Default SessionStore
	// Quota is the store the gateway calls DefaultQuotaStore; quota resets
	// remove the org's quota key through it as well.
	Quota SessionStore
	Log   *logrus.Logger
}

// OrgService implements the /tyk/org/keys operations.
type OrgService struct {
	cfg func() OrgConfig
	d   OrgDeps
	log *logrus.Logger
}

// NewOrgService returns an OrgService.
func NewOrgService(cfg func() OrgConfig, d OrgDeps) *OrgService {
	if cfg == nil {
		cfg = func() OrgConfig { return OrgConfig{} }
	}
	if d.Log == nil {
		d.Log = logrus.StandardLogger()
	}
	return &OrgService{cfg: cfg, d: d, log: d.Log}
}

// StaticOrgStores is an OrgStoreResolver over one store, reporting
// "found" when the provider has at least one API loaded (any org), which
// is what the gateway's getSpecForOrg fallback amounts to.
type StaticOrgStores struct {
	Store SessionStore
	APIs  APIInfoProvider
}

// OrgSessions implements OrgStoreResolver.
func (s StaticOrgStores) OrgSessions(string) (SessionStore, bool) {
	if s.APIs == nil || len(s.APIs.AllAPIs()) == 0 {
		return s.Store, false
	}
	return s.Store, true
}

// OrgResult is the payload of an org-key write.
type OrgResult struct {
	Result
	// Found reports whether an API was loaded for the org (the gateway uses
	// it to flag the spec as having an org session).
	Found bool `json:"-"`
}

// Set implements POST/PUT /tyk/org/keys/{orgID}.
func (s *OrgService) Set(orgID string, newSession *user.SessionState, isPut, resetQuota bool) (OrgResult, error) {
	cfg := s.cfg()
	store, found := s.d.Resolver.OrgSessions(orgID)
	if !found {
		s.log.Warning("Couldn't find org session store in active API list")
		if cfg.SupressDefaultOrgStore {
			return OrgResult{}, statusErr(http.StatusNotFound, "No such organisation found in Active API list")
		}
		store = s.d.Default
	}

	if resetQuota {
		store.ResetQuota(orgID, newSession, false)
		newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
		rawKey := QuotaKeyPrefix + storage.HashKey(orgID, cfg.HashKeys)

		// manage quotas separately
		s.d.Quota.RemoveSession(orgID, rawKey, false)
	}

	newSession.LastUpdated = strconv.Itoa(int(time.Now().Unix()))
	if err := store.UpdateSession(orgID, newSession, 0, false); err != nil {
		return OrgResult{}, statusErr(http.StatusInternalServerError, "Error writing to key store "+err.Error())
	}

	s.log.WithFields(logrus.Fields{
		"prefix": "api",
		"org":    orgID,
		"status": "ok",
	}).Info("New organization key added or updated.")

	action := "modified"
	if !isPut {
		action = "added"
	}
	return OrgResult{Result: Result{Key: orgID, Status: "ok", Action: action, StoredKey: orgID}, Found: found}, nil
}

// Get implements GET /tyk/org/keys/{orgID}.
func (s *OrgService) Get(orgID string) (user.SessionState, error) {
	store, found := s.d.Resolver.OrgSessions(orgID)
	if !found {
		return user.SessionState{}, statusErr(http.StatusNotFound, "Org not found")
	}

	session, ok := store.SessionDetail(orgID, orgID, false)
	if !ok {
		s.log.WithFields(logrus.Fields{
			"prefix": "api",
			"org":    orgID,
			"status": "fail",
			"err":    "not found",
		}).Error("Failed retrieval of record for ORG ID.")
		return user.SessionState{}, statusErr(http.StatusNotFound, "Org not found")
	}
	s.log.WithFields(logrus.Fields{
		"prefix": "api",
		"org":    orgID,
		"status": "ok",
	}).Info("Retrieved record for ORG ID.")
	return session.Clone(), nil
}

// List implements GET /tyk/org/keys/.
func (s *OrgService) List(filter string) ([]string, error) {
	store, found := s.d.Resolver.OrgSessions("")
	if !found {
		return nil, statusErr(http.StatusNotFound, "ORG not found")
	}

	sessions := store.Sessions(filter)
	fixed := make([]string, 0)
	for _, k := range sessions {
		if !strings.HasPrefix(k, QuotaKeyPrefix) && !strings.HasPrefix(k, RateLimitKeyPrefix) {
			fixed = append(fixed, k)
		}
	}
	return fixed, nil
}

// Delete implements DELETE /tyk/org/keys/{orgID}.
func (s *OrgService) Delete(orgID string) (OrgResult, error) {
	store, found := s.d.Resolver.OrgSessions(orgID)
	if !found {
		s.log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    orgID,
			"status": "fail",
			"err":    "not found",
		}).Error("Failed to delete org key.")
		return OrgResult{}, statusErr(http.StatusNotFound, "Org not found")
	}

	if !store.RemoveSession(orgID, orgID, false) {
		return OrgResult{}, statusErr(http.StatusBadRequest, "Failed to remove the key")
	}

	s.log.WithFields(logrus.Fields{
		"prefix": "api",
		"key":    orgID,
		"status": "ok",
	}).Info("Org key deleted.")

	return OrgResult{Result: Result{Key: orgID, Status: "ok", Action: "deleted", StoredKey: orgID}, Found: true}, nil
}
