package keys

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/redis"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// Key listing worker-pool sizing; averaged through profiling and benchmarking.
const (
	KeyListingWorkerCountCap      = 350
	KeyListingWorkerEntriesPerKey = 100
)

// Create implements POST /tyk/keys/create: a new token is generated for the
// session's org, policies are applied and the key is written once per
// access right.
func (s *Service) Create(newSession *user.SessionState) (Result, error) {
	cfg := s.cfg()

	newKey := s.GenerateAuthKey(newSession.OrgID)
	if newSession.HMACEnabled {
		newSession.HmacSecret = GenerateHMACSecret()
	}

	if newSession.Certificate != "" {
		newKey = s.generateToken(newSession.OrgID, newSession.Certificate)
		if _, ok := s.d.Sessions.SessionDetail(newSession.OrgID, newKey, false); ok {
			return Result{}, statusErr(http.StatusInternalServerError, "Failed to create key - Key with given certificate already found:"+newKey)
		}
	}

	if err := s.ValidateMtlsStaticCertificateBindings(newSession.MtlsStaticCertificateBindings, newSession.OrgID); err != nil {
		return Result{}, statusErr(http.StatusBadRequest, err.Error())
	}

	if err := ValidateAccessConditions(newSession.AccessRights); err != nil {
		s.log.Error(err)
		return Result{}, statusErr(http.StatusBadRequest, err.Error())
	}

	newSession.LastUpdated = strconv.Itoa(int(time.Now().Unix()))
	newSession.DateCreated = time.Now()

	if err := s.ApplyPolicies(newSession, nil); err != nil {
		return Result{}, statusErr(http.StatusInternalServerError, "Failed to create key - "+err.Error())
	}

	if len(newSession.AccessRights) > 0 {
		// reset API-level limit to nil if any has a zero-value
		ResetAPILimits(newSession.AccessRights)
		for apiID := range newSession.AccessRights {
			var api *APIInfo
			if a, ok := s.d.APIs.APIByID(apiID); ok {
				api = &a
				s.checkAndApplyTrialPeriod(newKey, newSession, false)
			}

			if api == nil || !api.DontSetQuotasOnCreate {
				// Reset quota by default
				newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
				s.d.Sessions.ResetQuota(newKey, newSession, false)
			}

			// apply policies (if any) and save key
			if err := s.applyPoliciesAndSave(newKey, newSession, api, false); err != nil {
				return Result{}, statusErr(http.StatusInternalServerError, "Failed to create key - "+err.Error())
			}
		}
	} else {
		if !cfg.AllowMasterKeys {
			s.log.WithFields(logrus.Fields{
				"prefix":      "api",
				"status":      "error",
				"err":         "master keys disabled",
				"org_id":      newSession.OrgID,
				"api_id":      "--",
				"user_id":     "system",
				"path":        "--",
				"server_name": "system",
			}).Error("Master keys disallowed in configuration, key not added.")
			return Result{}, statusErr(http.StatusBadRequest, "Failed to create key, keys must have at least one Access Rights record set.")
		}

		// nothing defined, add key to ALL
		s.log.WithFields(logrus.Fields{
			"prefix":      "api",
			"status":      "warning",
			"org_id":      newSession.OrgID,
			"api_id":      "--",
			"user_id":     "system",
			"path":        "--",
			"server_name": "system",
		}).Warning("No API Access Rights set on key session, adding key to all APIs.")

		for _, api := range s.d.APIs.AllAPIs() {
			api := api
			s.checkAndApplyTrialPeriod(newKey, newSession, false)
			if !api.DontSetQuotasOnCreate {
				// Reset quota by default
				s.d.Sessions.ResetQuota(newKey, newSession, false)
				newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
			}
			if err := s.applyPoliciesAndSave(newKey, newSession, &api, false); err != nil {
				return Result{}, statusErr(http.StatusInternalServerError, "Failed to create key - "+err.Error())
			}
		}
	}

	res := Result{Action: "added", Key: newKey, Status: "ok", StoredKey: newKey}
	if cfg.HashKeys {
		res.KeyHash = storage.HashKey(newKey, cfg.HashKeys)
	}

	s.log.WithFields(logrus.Fields{
		"prefix":      "api",
		"key":         ObfuscateKey(newKey, cfg.EnableKeyLogging),
		"status":      "ok",
		"api_id":      "--",
		"org_id":      newSession.OrgID,
		"user_id":     "system",
		"path":        "--",
		"server_name": "system",
	}).Info("Generated new key: (", ObfuscateKey(newKey, cfg.EnableKeyLogging), ")")

	return res, nil
}

// CreateOrUpdate implements POST and PUT /tyk/keys/{keyName}. For POST,
// keyName is the custom key ID (may be empty) or basic-auth username; for
// PUT it is the existing key, hash or username-derived key name.
func (s *Service) CreateOrUpdate(keyName string, newSession *user.SessionState, opts WriteOptions) (Result, error) {
	cfg := s.cfg()

	if err := s.ValidateMCPFieldsInAccessRights(newSession.AccessRights); err != nil {
		s.log.Error(err)
		return Result{}, statusErr(http.StatusBadRequest, err.Error())
	}

	if err := s.ValidateNonMCPFieldsOnMCPProxy(newSession.AccessRights); err != nil {
		s.log.Error(err)
		return Result{}, statusErr(http.StatusBadRequest, err.Error())
	}

	if err := ValidateAccessConditions(newSession.AccessRights); err != nil {
		s.log.Error(err)
		return Result{}, statusErr(http.StatusBadRequest, err.Error())
	}

	_ = s.ApplyPolicies(newSession, nil)

	// get original session in case of update and preserve fields that SHOULD NOT be updated
	originalKey := user.SessionState{}
	if opts.IsPut {
		key, found := s.d.Sessions.SessionDetail(newSession.OrgID, keyName, opts.IsHashed)
		keyName = key.KeyID
		if !found {
			s.log.Error("Could not find key when updating")
			return Result{}, statusErr(http.StatusNotFound, "Key is not found")
		}
		originalKey = key.Clone()

		if newSession.Certificate != originalKey.Certificate {
			if newSession.Certificate == "" {
				s.log.Error("Key must contain a certificate")
				return Result{}, statusErr(http.StatusBadRequest, "Key cannot be used without a certificate")
			}

			// check that the certificate exists in the system
			if s.d.Certs == nil {
				return Result{}, statusErr(http.StatusBadRequest, "Key must be used with an existent certificate")
			}
			if _, err := s.d.Certs.GetRaw(newSession.Certificate); err != nil {
				s.log.Error("Key must contain an existing certificate")
				return Result{}, statusErr(http.StatusBadRequest, "Key must be used with an existent certificate")
			}
		}

		// preserve the creation date
		newSession.DateCreated = originalKey.DateCreated

		// don't change fields related to quota and rate limiting if was passed as "suppress_reset=1"
		if opts.SuppressReset {
			// on session level
			newSession.QuotaRenews = originalKey.QuotaRenews
			newSession.LastUpdated = originalKey.LastUpdated

			// on ACL API limit level
			for apiID, access := range originalKey.AccessRights {
				if access.Limit.IsEmpty() {
					continue
				}
				if newAccess, ok := newSession.AccessRights[apiID]; ok && !newAccess.Limit.IsEmpty() {
					newAccess.Limit.QuotaRenews = access.Limit.QuotaRenews
					newSession.AccessRights[apiID] = newAccess
				}
			}
		}
	} else {
		// POST path (create). Reject a user-supplied custom key ID that would
		// be unreachable at auth time (the auth middleware rejects keys
		// shorter than min_token_length). Empty keyName is fine: a UUID
		// envelope of safe length is generated below.
		minLen := EffectiveMinTokenLength(cfg.MinTokenLength)
		if keyName != "" && len(keyName) < minLen {
			return Result{}, statusErr(http.StatusBadRequest, fmt.Sprintf(
				"custom key ID length %d is less than min_token_length (%d); "+
					"the key would be unreachable at auth time. Use an ID of at least min_token_length characters, "+
					"or lower min_token_length in the gateway configuration.",
				len(keyName), minLen,
			))
		}
		newSession.DateCreated = time.Now()
		keyName = s.generateToken(newSession.OrgID, keyName)
	}

	// set the original expiry if the content in payload is a past time
	if time.Now().After(time.Unix(newSession.Expires, 0)) && newSession.Expires > 1 {
		newSession.Expires = originalKey.Expires
	}

	// Validate mtls_static_certificate_bindings: all for POST, only new ones for PUT
	certsToValidate := NewCertIDs(originalKey.MtlsStaticCertificateBindings, newSession.MtlsStaticCertificateBindings)
	if err := s.ValidateMtlsStaticCertificateBindings(certsToValidate, newSession.OrgID); err != nil {
		s.log.Error("Invalid certificate in mtls_static_certificate_bindings: ", err)
		return Result{}, statusErr(http.StatusBadRequest, err.Error())
	}

	if newSession.IsBasicAuth() {
		if !opts.IsPut {
			// It's a create, so lets hash the password
			s.SetBasicAuthSessionPassword(newSession)
		} else if originalKey.BasicAuthData.Password != newSession.BasicAuthData.Password {
			// passwords dont match assume it's new, lets hash it
			s.log.Debug("Changing password")
			s.SetBasicAuthSessionPassword(newSession)
		}
	} else if originalKey.IsBasicAuth() {
		// preserve basic auth data
		newSession.BasicAuthData.Hash = originalKey.BasicAuthData.Hash
		newSession.BasicAuthData.Password = originalKey.BasicAuthData.Password
	}

	if !opts.IsPut || storage.TokenOrg(keyName) != "" {
		// use new key format if key gets created or updating key with new format
		if err := s.doAddOrUpdate(keyName, newSession, opts.SuppressReset, opts.IsHashed); err != nil {
			return Result{}, statusErr(http.StatusInternalServerError, "Failed to create key, ensure security settings are correct.")
		}
	} else {
		newFormatKey := s.generateToken(newSession.OrgID, keyName)
		// search as a custom key
		if _, err := s.d.Sessions.Store().GetKey(newFormatKey); err == nil {
			// update new format key for custom keys, as it was found then its a customKey
			keyName = newFormatKey
		}

		if err := s.doAddOrUpdate(keyName, newSession, opts.SuppressReset, opts.IsHashed); err != nil {
			return Result{}, statusErr(http.StatusInternalServerError, "Failed to create key, ensure security settings are correct.")
		}
	}

	res := Result{Key: keyName, Status: "ok", Action: "modified", StoredKey: keyName}
	if !opts.IsPut {
		res.Action = "added"
	}

	// add key hash for newly created key
	if cfg.HashKeys && !opts.IsPut {
		if newSession.IsBasicAuth() {
			res.Key = ""
		}
		if opts.IsHashed {
			res.KeyHash = keyName
		} else {
			res.KeyHash = storage.HashKey(keyName, cfg.HashKeys)
		}
	}

	return res, nil
}

// Detail implements GET /tyk/keys/{key}: the stored session with policies
// applied and remaining quota filled in from the quota counters.
func (s *Service) Detail(sessionKey, apiID, orgID string, byHash bool) (user.SessionState, error) {
	cfg := s.cfg()
	if byHash && !cfg.HashKeys {
		return user.SessionState{}, statusErr(http.StatusBadRequest, "Key requested by hash but key hashing is not enabled")
	}

	var api *APIInfo
	if a, ok := s.d.APIs.APIByID(apiID); ok {
		api = &a
		orgID = a.OrgID
	}

	session, ok := s.d.Sessions.SessionDetail(orgID, sessionKey, byHash)
	sessionKey = session.KeyID
	if !ok {
		return user.SessionState{}, statusErr(http.StatusNotFound, "Key not found")
	}

	_ = s.applyPoliciesForAPI(&session, api)

	store := s.d.Sessions.Store()
	if session.QuotaMax != -1 {
		quotaKey := QuotaKeyPrefix + storage.HashKey(sessionKey, cfg.HashKeys)
		if byHash {
			quotaKey = QuotaKeyPrefix + sessionKey
		}

		if usedQuota, err := store.GetRawKey(quotaKey); err == nil || errors.Is(err, redis.Nil) {
			qInt, _ := strconv.Atoi(usedQuota)
			remaining := session.QuotaMax - int64(qInt)

			if remaining < 0 {
				session.QuotaRemaining = 0
			} else {
				session.QuotaRemaining = remaining
			}
		} else {
			s.log.WithError(err).WithFields(logrus.Fields{
				"prefix": "api",
				"key":    ObfuscateKey(quotaKey, cfg.EnableKeyLogging),
				"status": "ok",
			}).Info("Can't retrieve key quota")
		}
	}

	// populate remaining quota for API limits (if any)
	for id, access := range session.AccessRights {
		if access.Limit.IsEmpty() || access.Limit.QuotaMax == -1 || access.Limit.QuotaMax == 0 {
			continue
		}

		quotaScope := ""
		if access.AllowanceScope != "" {
			quotaScope = access.AllowanceScope + "-"
		}

		limQuotaKey := QuotaKeyPrefix + quotaScope + storage.HashKey(sessionKey, cfg.HashKeys)
		if byHash {
			limQuotaKey = QuotaKeyPrefix + quotaScope + sessionKey
		}

		if usedQuota, err := store.GetRawKey(limQuotaKey); err == nil {
			qInt, _ := strconv.Atoi(usedQuota)
			remaining := access.Limit.QuotaMax - int64(qInt)

			if remaining < 0 {
				access.Limit.QuotaRemaining = 0
			} else {
				access.Limit.QuotaRemaining = remaining
			}
			session.AccessRights[id] = access
		} else {
			access.Limit.QuotaRemaining = access.Limit.QuotaMax
			session.AccessRights[id] = access

			s.log.WithFields(logrus.Fields{
				"prefix": "api",
				"apiID":  id,
				"key":    ObfuscateKey(sessionKey, cfg.EnableKeyLogging),
				"error":  err,
			}).Info("Can't retrieve api limit quota")
		}
	}

	// If it's a basic auth key and a valid Base64 string, use it as the key ID:
	if session.IsBasicAuth() {
		if storage.TokenOrg(sessionKey) != "" {
			session.KeyID = sessionKey
		}
		session.BasicAuthData.Password = ""
	}

	s.log.WithFields(logrus.Fields{
		"prefix": "api",
		"key":    ObfuscateKey(sessionKey, cfg.EnableKeyLogging),
		"status": "ok",
	}).Info("Retrieved key detail.")

	return session.Clone(), nil
}

// List implements GET /tyk/keys/: key names matching filter, optionally
// narrowed to keys granting apiID.
func (s *Service) List(ctx context.Context, filter string, apiID string, hashed bool) ([]string, error) {
	keys := s.allSessionKeys(filter)

	if apiID == "" {
		validSessions := make([]string, 0, len(keys))
		for _, k := range keys {
			if !strings.HasPrefix(k, QuotaKeyPrefix) && !strings.HasPrefix(k, RateLimitKeyPrefix) {
				validSessions = append(validSessions, k)
			}
		}
		return validSessions, nil
	}

	validSessions, err := s.filterKeysByAPIID(ctx, keys, filter, apiID, hashed)
	if err != nil {
		s.log.WithError(err).Warn("Request timeout while processing keys")
		return nil, errTimeout
	}

	sort.Strings(validSessions)

	s.log.WithFields(logrus.Fields{
		"prefix": "api",
		"status": "ok",
		"count":  len(validSessions),
	}).Info("Retrieved key list.")

	return validSessions, nil
}

// allSessionKeys returns the raw keys matching filter, including the
// legacy base64 org-filter form.
func (s *Service) allSessionKeys(filter string) []string {
	keys := s.d.Sessions.Sessions(filter)
	if filter != "" {
		filterB64 := base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(fmt.Sprintf(`{"org":"%s"`, filter)))
		filterB64 = filterB64[0 : len(filterB64)-2]
		keys = append(keys, s.d.Sessions.Sessions(filterB64)...)
	}
	return keys
}

func (s *Service) filterKeysByAPIID(ctx context.Context, keys []string, filter, apiID string, hashed bool) ([]string, error) {
	numKeys := len(keys)
	keyListingWorkerCount := min(int(4+math.Sqrt(float64(numKeys))), KeyListingWorkerCountCap)
	keyListingBufferSize := keyListingWorkerCount * KeyListingWorkerEntriesPerKey

	jobs := make(chan string, keyListingBufferSize)
	validSessions := make([]string, 0)
	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(keyListingWorkerCount)
	for w := 0; w < keyListingWorkerCount; w++ {
		go func() {
			defer wg.Done()
			localMatches := make([]string, 0)

			for {
				select {
				case <-ctx.Done():
					return
				case keyName, ok := <-jobs:
					if !ok {
						if len(localMatches) > 0 {
							mu.Lock()
							validSessions = append(validSessions, localMatches...)
							mu.Unlock()
						}
						return
					}

					if s.keyHasAccess(filter, keyName, apiID, hashed) {
						localMatches = append(localMatches, keyName)
					}
				}
			}
		}()
	}

	go s.feedKeyListingWorkers(ctx, keys, jobs)

	wg.Wait()

	if err := ctxErr(ctx); err != nil {
		return nil, err
	}

	return validSessions, nil
}

func (s *Service) keyHasAccess(filter, keyName, apiID string, hashed bool) bool {
	session, found := s.d.Sessions.SessionDetail(filter, keyName, hashed)
	if !found {
		return false
	}

	if _, ok := session.AccessRights[apiID]; ok {
		return true
	}

	if len(session.AccessRights) == 0 && s.cfg().AllowMasterKeys {
		return true
	}

	return false
}

func (s *Service) feedKeyListingWorkers(ctx context.Context, keys []string, jobs chan<- string) {
	defer close(jobs)
	for _, k := range keys {
		if strings.HasPrefix(k, QuotaKeyPrefix) || strings.HasPrefix(k, RateLimitKeyPrefix) {
			continue
		}

		select {
		case <-ctx.Done():
			return
		case jobs <- k:
		}
	}
}

// Delete implements DELETE /tyk/keys/{key} for raw keys. A nil Result with
// a nil error means the key was removed across all APIs (apiID == "-1"),
// which the gateway reports with an empty body.
func (s *Service) Delete(keyName, orgID, apiID string, resetQuota bool) (*Result, error) {
	cfg := s.cfg()
	session, ok := s.d.Sessions.SessionDetail(orgID, keyName, false)
	if !ok {
		return nil, statusErr(http.StatusNotFound, "There is no such key found")
	}
	keyName = session.KeyID

	if resetQuota {
		s.d.Sessions.ResetQuota(keyName, &session, false)
	}

	logger := s.log.WithFields(logrus.Fields{
		"prefix": "api",
		"key":    ObfuscateKey(keyName, cfg.EnableKeyLogging),
	})

	if apiID == "-1" {
		// Go through ALL managed API's and delete the key
		if !s.d.Sessions.RemoveSession(orgID, keyName, false) {
			logger.WithField("status", "fail").Error("Failed to remove the key")
			return nil, statusErr(http.StatusBadRequest, "Failed to remove the key")
		}
		logger.WithField("status", "ok").Info("Deleted key across all APIs.")
		return nil, nil
	}

	if !s.d.Sessions.RemoveSession(orgID, keyName, false) {
		logger.WithField("status", "fail").Error("Failed to remove the key")
		return nil, statusErr(http.StatusBadRequest, "Failed to remove the key")
	}

	logger.WithField("status", "ok").Info("Deleted key.")

	return &Result{Key: keyName, Status: "ok", Action: "deleted"}, nil
}

// DeleteHashed implements DELETE /tyk/keys/{hash}?hashed=true.
func (s *Service) DeleteHashed(keyName, orgID, apiID string, resetQuota bool) (*Result, error) {
	session, ok := s.d.Sessions.SessionDetail(orgID, keyName, true)
	keyName = session.KeyID
	if !ok {
		return nil, statusErr(http.StatusNotFound, "There is no such key found")
	}

	if apiID == "-1" {
		// Go through ALL managed API's and delete the key
		if !s.d.Sessions.RemoveSession(orgID, keyName, true) {
			return nil, statusErr(http.StatusBadRequest, "Failed to remove the key")
		}
		return nil, nil
	}

	if !s.d.Sessions.RemoveSession(orgID, keyName, true) {
		return nil, statusErr(http.StatusBadRequest, "Failed to remove the key")
	}

	if resetQuota {
		s.d.Sessions.ResetQuota(keyName, &session, true)
	}

	return &Result{Key: keyName, Status: "ok", Action: "deleted"}, nil
}

// Preview implements POST /tyk/keys/preview: the session with policies
// applied, without persisting anything.
func (s *Service) Preview(newSession *user.SessionState) *user.SessionState {
	newSession.LastUpdated = strconv.Itoa(int(time.Now().Unix()))
	newSession.DateCreated = time.Now()
	_ = s.ApplyPolicies(newSession, nil)
	return newSession
}

// ApplyPolicyIDs implements POST /tyk/keys/policy/{hash}: replaces the
// policies of a key addressed by hash.
func (s *Service) ApplyPolicyIDs(keyHash string, applyPolicies []string) (Result, error) {
	var orgID string

	if len(applyPolicies) != 0 {
		if pol, ok := s.d.Policies.PolicyByID(nonScopedPolicyID(applyPolicies[0])); ok {
			orgID = pol.OrgID
		}
	}

	sess, ok := s.d.Sessions.SessionDetail(orgID, keyHash, true)
	keyHash = sess.KeyID
	if !ok {
		s.log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    keyHash,
			"status": "fail",
		}).Error("Failed to update hashed key.")

		return Result{}, statusErr(http.StatusNotFound, "Key not found")
	}

	// Set the policy
	sess.LastUpdated = strconv.Itoa(int(time.Now().Unix()))
	sess.SetPolicies(applyPolicies...)

	if err := s.d.Sessions.UpdateSession(keyHash, &sess, 0, true); err != nil {
		s.log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    keyHash,
			"status": "fail",
			"err":    err,
		}).Error("Failed to update hashed key.")

		return Result{}, statusErr(http.StatusInternalServerError, "Could not write key data")
	}

	return Result{Key: keyHash, Status: "ok", Action: "updated"}, nil
}
