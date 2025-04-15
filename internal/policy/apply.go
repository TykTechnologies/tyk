package policy

import (
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/user"
)

var (
	// ErrMixedPartitionAndPerAPIPolicies is the error to return when a mix of per api and partitioned policies are to be applied in a session.
	ErrMixedPartitionAndPerAPIPolicies = errors.New("cannot apply multiple policies when some have per_api set and some are partitioned")
)

// Service represents the implementation for apply policies logic.
type Service struct {
	storage model.PolicyProvider
	logger  *logrus.Logger

	// used for validation if not empty
	orgID *string
}

func New(orgID *string, storage model.PolicyProvider, logger *logrus.Logger) *Service {
	return &Service{
		orgID:   orgID,
		storage: storage,
		logger:  logger,
	}
}

// ClearSession clears the quota, rate limit and complexity values so that partitioned policies can apply their values.
// Otherwise, if the session has already a higher value, an applied policy will not win, and its values will be ignored.
func (t *Service) ClearSession(session *user.SessionState) error {
	policies := session.PolicyIDs()

	for _, polID := range policies {
		policy, ok := t.storage.PolicyByID(polID)
		if !ok {
			return fmt.Errorf("policy not found: %s", polID)
		}

		all := !(policy.Partitions.Quota || policy.Partitions.RateLimit || policy.Partitions.Acl || policy.Partitions.Complexity)

		if policy.Partitions.Quota || all {
			session.QuotaMax = 0
			session.QuotaRemaining = 0
		}

		if policy.Partitions.RateLimit || all {
			session.Rate = 0
			session.Per = 0
			session.Smoothing = nil
			session.ThrottleRetryLimit = 0
			session.ThrottleInterval = 0
		}

		if policy.Partitions.Complexity || all {
			session.MaxQueryDepth = 0
		}
	}

	return nil
}

type applyStatus struct {
	didQuota      map[string]bool
	didRateLimit  map[string]bool
	didAcl        map[string]bool
	didComplexity map[string]bool
	didPerAPI     bool
	didPartition  bool
}

// Apply will check if any policies are loaded. If any are, it
// will overwrite the session state to use the policy values.
func (t *Service) Apply(session *user.SessionState) error {
	rights := make(map[string]user.AccessDefinition)
	tags := make(map[string]bool)
	if session.MetaData == nil {
		session.MetaData = make(map[string]interface{})
	}

	if err := t.ClearSession(session); err != nil {
		t.logger.WithError(err).Warn("error clearing session")
	}

	applyState := applyStatus{
		didQuota:      make(map[string]bool),
		didRateLimit:  make(map[string]bool),
		didAcl:        make(map[string]bool),
		didComplexity: make(map[string]bool),
	}

	var (
		err       error
		policyIDs []string
	)

	storage := t.storage

	customPolicies, err := session.GetCustomPolicies()
	if err != nil {
		policyIDs = session.PolicyIDs()
	} else {
		storage = NewStore(customPolicies)
		policyIDs = storage.PolicyIDs()
	}

	for _, polID := range policyIDs {
		policy, ok := storage.PolicyByID(polID)
		if !ok {
			err := fmt.Errorf("policy not found: %q", polID)
			t.Logger().Error(err)
			if len(policyIDs) > 1 {
				continue
			}

			return err
		}
		// Check ownership, policy org owner must be the same as API,
		// otherwise you could overwrite a session key with a policy from a different org!
		if t.orgID != nil && policy.OrgID != *t.orgID {
			err := errors.New("attempting to apply policy from different organisation to key, skipping")
			t.Logger().Error(err)
			return err
		}

		if policy.Partitions.PerAPI && policy.Partitions.Enabled() {
			err := fmt.Errorf("cannot apply policy %s which has per_api and any of partitions set", policy.ID)
			t.logger.Error(err)
			return err
		}

		if policy.Partitions.PerAPI {
			if err := t.applyPerAPI(policy, session, rights, &applyState); err != nil {
				return err
			}
		} else {
			if err := t.applyPartitions(policy, session, rights, &applyState); err != nil {
				return err
			}
		}

		session.IsInactive = session.IsInactive || policy.IsInactive

		for _, tag := range policy.Tags {
			tags[tag] = true
		}

		for k, v := range policy.MetaData {
			session.MetaData[k] = v
		}

		if policy.LastUpdated > session.LastUpdated {
			session.LastUpdated = policy.LastUpdated
		}
	}

	for _, tag := range session.Tags {
		tags[tag] = true
	}

	// set tags
	session.Tags = []string{}
	for tag := range tags {
		session.Tags = appendIfMissing(session.Tags, tag)
	}

	if len(policyIDs) == 0 {
		for apiID, accessRight := range session.AccessRights {
			// check if the api in the session has per api limit
			if !accessRight.Limit.IsEmpty() {
				accessRight.AllowanceScope = apiID
				session.AccessRights[apiID] = accessRight
			}
		}
	}

	distinctACL := make(map[string]bool)

	for _, v := range rights {
		if v.Limit.SetBy != "" {
			distinctACL[v.Limit.SetBy] = true
		}
	}

	// If some APIs had only ACL partitions, inherit rest from session level
	for k, v := range rights {
		if !applyState.didAcl[k] {
			delete(rights, k)
			continue
		}

		if !applyState.didRateLimit[k] {
			v.Limit.Rate = session.Rate
			v.Limit.Per = session.Per
			v.Limit.Smoothing = session.Smoothing
			v.Limit.ThrottleInterval = session.ThrottleInterval
			v.Limit.ThrottleRetryLimit = session.ThrottleRetryLimit
			v.Endpoints = nil
		}

		if !applyState.didComplexity[k] {
			v.Limit.MaxQueryDepth = session.MaxQueryDepth
		}

		if !applyState.didQuota[k] {
			v.Limit.QuotaMax = session.QuotaMax
			v.Limit.QuotaRenewalRate = session.QuotaRenewalRate
			v.Limit.QuotaRenews = session.QuotaRenews
		}

		// If multime ACL
		if len(distinctACL) > 1 {
			if v.AllowanceScope == "" && v.Limit.SetBy != "" {
				v.AllowanceScope = v.Limit.SetBy
			}
		}

		v.Limit.SetBy = ""

		rights[k] = v
	}

	// If we have policies defining rules for one single API, update session root vars (legacy)
	t.updateSessionRootVars(session, rights, applyState)

	// Override session ACL if at least one policy define it
	if len(applyState.didAcl) > 0 {
		session.AccessRights = rights
	}

	if len(rights) == 0 && policyIDs != nil {
		return errors.New("key has no valid policies to be applied")
	}

	return nil
}

// Logger implements a typical logger signature with service context.
func (t *Service) Logger() *logrus.Entry {
	return logrus.NewEntry(t.logger)
}

// ApplyRateLimits will write policy limits to session and apiLimits.
// The limits get written if either are empty.
// The limits get written if filled and policyLimits allows a higher request rate.
func (t *Service) ApplyRateLimits(session *user.SessionState, policy user.Policy, apiLimits *user.APILimit) {
	policyLimits := policy.APILimit()
	if t.emptyRateLimit(policyLimits) {
		return
	}

	// duration is time between requests, e.g.:
	//
	// apiLimits: 500ms for 2 requests / second
	// policyLimits: 100ms for 10 requests / second
	//
	// if apiLimits > policyLimits (500ms > 100ms) then
	// we apply the higher rate from the policy.
	//
	// the policy-defined rate limits are enforced as
	// a minimum possible api rate limit setting,
	// raising apiLimits.

	if t.emptyRateLimit(*apiLimits) || apiLimits.Duration() > policyLimits.Duration() {
		apiLimits.Rate = policyLimits.Rate
		apiLimits.Per = policyLimits.Per
		apiLimits.Smoothing = policyLimits.Smoothing
	}

	// sessionLimits, similar to apiLimits, get policy
	// rate applied if the policy allows more requests.
	sessionLimits := session.APILimit()
	if t.emptyRateLimit(sessionLimits) || sessionLimits.Duration() > policyLimits.Duration() {
		session.Rate = policyLimits.Rate
		session.Per = policyLimits.Per
		session.Smoothing = policyLimits.Smoothing
	}
}

func (t *Service) emptyRateLimit(m user.APILimit) bool {
	return m.Rate == 0 || m.Per == 0
}

func (t *Service) applyPerAPI(policy user.Policy, session *user.SessionState, rights map[string]user.AccessDefinition,
	applyState *applyStatus) error {

	if applyState.didPartition {
		t.logger.Error(ErrMixedPartitionAndPerAPIPolicies)
		return ErrMixedPartitionAndPerAPIPolicies
	}

	for apiID, accessRights := range policy.AccessRights {
		idForScope := apiID
		// check if we don't have limit on API level specified when policy was created
		if accessRights.Limit.IsEmpty() {
			// limit was not specified on API level so we will populate it from policy
			idForScope = policy.ID
			accessRights.Limit = policy.APILimit()
		}
		accessRights.AllowanceScope = idForScope
		accessRights.Limit.SetBy = idForScope

		// respect current quota renews (on API limit level)
		if r, ok := session.AccessRights[apiID]; ok && !r.Limit.IsEmpty() {
			accessRights.Limit.QuotaRenews = r.Limit.QuotaRenews
		}

		if r, ok := session.AccessRights[apiID]; ok {
			// If GQL introspection is disabled, keep that configuration.
			if r.DisableIntrospection {
				accessRights.DisableIntrospection = r.DisableIntrospection
			}
		}

		if currAD, ok := rights[apiID]; ok {
			accessRights = t.applyAPILevelLimits(accessRights, currAD)
		}

		// overwrite session access right for this API
		rights[apiID] = accessRights

		// identify that limit for that API is set (to allow set it only once)
		applyState.didAcl[apiID] = true
		applyState.didQuota[apiID] = true
		applyState.didRateLimit[apiID] = true
		applyState.didComplexity[apiID] = true
	}

	if len(policy.AccessRights) > 0 {
		applyState.didPerAPI = true
	}

	return nil
}

func (t *Service) applyPartitions(policy user.Policy, session *user.SessionState, rights map[string]user.AccessDefinition,
	applyState *applyStatus) error {

	usePartitions := policy.Partitions.Enabled()

	if usePartitions && applyState.didPerAPI {
		t.logger.Error(ErrMixedPartitionAndPerAPIPolicies)
		return ErrMixedPartitionAndPerAPIPolicies
	}

	// Ensure `rights` is filled with known APIs to ensure that
	// a policy with acl rights gets honored even if not first.
	for k := range policy.AccessRights {
		if _, ok := rights[k]; ok {
			continue
		}
		rights[k] = user.AccessDefinition{}
	}

	for k, v := range policy.AccessRights {
		// Use rights[k], which holds previously seen/merged policy access rights.
		ar := rights[k]

		if !usePartitions || policy.Partitions.Acl {
			applyState.didAcl[k] = true

			// Merge ACLs for the same API
			if r, ok := rights[k]; ok {
				// If GQL introspection is disabled, keep that configuration.
				if v.DisableIntrospection {
					r.DisableIntrospection = v.DisableIntrospection
				}
				r.Versions = appendIfMissing(rights[k].Versions, v.Versions...)

				r.AllowedURLs = MergeAllowedURLs(r.AllowedURLs, v.AllowedURLs)

				// When two or more non-empty policies are applied, only the
				// fields restricted by all policies are in the resulting policy.
				// A merge of `[a b]` and `[b c]` becomes `[b]`, as `b` is
				// restricted by both of the policies.
				if len(r.RestrictedTypes) == 0 {
					r.RestrictedTypes = v.RestrictedTypes
				} else {
					typeMap := make(map[string]int)
					for i, rt := range r.RestrictedTypes {
						typeMap[rt.Name] = i
					}

					for _, t := range v.RestrictedTypes {
						if existingIndex, exists := typeMap[t.Name]; exists {
							// Type exists in both policies - intersect fields
							r.RestrictedTypes[existingIndex].Fields = intersection(r.RestrictedTypes[existingIndex].Fields, t.Fields)
						} else {
							// Type only exists in new policy - add it
							r.RestrictedTypes = append(r.RestrictedTypes, t)
						}
					}
				}

				// When two or more non-empty policies are applied, the fields allowed
				// are merged in the resulting policy. For an example, `[a b]` and `[b c]`,
				// results in a polict that allows `[a b c]`.
				if len(r.AllowedTypes) == 0 {
					r.AllowedTypes = v.AllowedTypes
				} else {
					for _, t := range v.AllowedTypes {
						for ri, rt := range r.AllowedTypes {
							if t.Name == rt.Name {
								r.AllowedTypes[ri].Fields = appendIfMissing(rt.Fields, t.Fields...)
							}
						}
					}
				}

				mergeFieldLimits := func(res *user.FieldLimits, new user.FieldLimits) {
					if greaterThanInt(new.MaxQueryDepth, res.MaxQueryDepth) {
						res.MaxQueryDepth = new.MaxQueryDepth
					}
				}

				if len(r.FieldAccessRights) == 0 {
					r.FieldAccessRights = v.FieldAccessRights
				} else {
					for _, far := range v.FieldAccessRights {
						exists := false
						for i, rfar := range r.FieldAccessRights {
							if far.TypeName == rfar.TypeName && far.FieldName == rfar.FieldName {
								exists = true
								mergeFieldLimits(&r.FieldAccessRights[i].Limits, far.Limits)
							}
						}

						if !exists {
							r.FieldAccessRights = append(r.FieldAccessRights, far)
						}
					}
				}

				ar = r
			}

			ar.Limit.SetBy = policy.ID
		}

		if !usePartitions || policy.Partitions.Quota {
			applyState.didQuota[k] = true

			if greaterThanInt64(policy.QuotaMax, ar.Limit.QuotaMax) {
				ar.Limit.QuotaMax = policy.QuotaMax
				if greaterThanInt64(policy.QuotaMax, session.QuotaMax) {
					session.QuotaMax = policy.QuotaMax
				}
			}

			if policy.QuotaRenewalRate > ar.Limit.QuotaRenewalRate {
				ar.Limit.QuotaRenewalRate = policy.QuotaRenewalRate
				if policy.QuotaRenewalRate > session.QuotaRenewalRate {
					session.QuotaRenewalRate = policy.QuotaRenewalRate
				}
			}
		}

		if !usePartitions || policy.Partitions.RateLimit {
			applyState.didRateLimit[k] = true

			t.ApplyRateLimits(session, policy, &ar.Limit)

			if rightsAR, ok := rights[k]; ok {
				ar.Endpoints = t.ApplyEndpointLevelLimits(v.Endpoints, rightsAR.Endpoints)
			}

			if policy.ThrottleRetryLimit > ar.Limit.ThrottleRetryLimit {
				ar.Limit.ThrottleRetryLimit = policy.ThrottleRetryLimit
				if policy.ThrottleRetryLimit > session.ThrottleRetryLimit {
					session.ThrottleRetryLimit = policy.ThrottleRetryLimit
				}
			}

			if policy.ThrottleInterval > ar.Limit.ThrottleInterval {
				ar.Limit.ThrottleInterval = policy.ThrottleInterval
				if policy.ThrottleInterval > session.ThrottleInterval {
					session.ThrottleInterval = policy.ThrottleInterval
				}
			}
		}

		if !usePartitions || policy.Partitions.Complexity {
			applyState.didComplexity[k] = true

			if greaterThanInt(policy.MaxQueryDepth, ar.Limit.MaxQueryDepth) {
				ar.Limit.MaxQueryDepth = policy.MaxQueryDepth
				if greaterThanInt(policy.MaxQueryDepth, session.MaxQueryDepth) {
					session.MaxQueryDepth = policy.MaxQueryDepth
				}
			}
		}

		// Respect existing QuotaRenews
		if r, ok := session.AccessRights[k]; ok && !r.Limit.IsEmpty() {
			ar.Limit.QuotaRenews = r.Limit.QuotaRenews
		}

		rights[k] = ar
	}

	// Master policy case
	if len(policy.AccessRights) == 0 {
		if !usePartitions || policy.Partitions.RateLimit {
			session.Rate = policy.Rate
			session.Per = policy.Per
			session.Smoothing = policy.Smoothing
			session.ThrottleInterval = policy.ThrottleInterval
			session.ThrottleRetryLimit = policy.ThrottleRetryLimit
		}

		if !usePartitions || policy.Partitions.Complexity {
			session.MaxQueryDepth = policy.MaxQueryDepth
		}

		if !usePartitions || policy.Partitions.Quota {
			session.QuotaMax = policy.QuotaMax
			session.QuotaRenewalRate = policy.QuotaRenewalRate
		}
	}

	if !session.HMACEnabled {
		session.HMACEnabled = policy.HMACEnabled
	}

	if !session.EnableHTTPSignatureValidation {
		session.EnableHTTPSignatureValidation = policy.EnableHTTPSignatureValidation
	}

	applyState.didPartition = usePartitions

	return nil
}

func (t *Service) updateSessionRootVars(session *user.SessionState, rights map[string]user.AccessDefinition, applyState applyStatus) {
	if len(applyState.didQuota) == 1 && len(applyState.didRateLimit) == 1 && len(applyState.didComplexity) == 1 {
		for _, v := range rights {
			if len(applyState.didRateLimit) == 1 {
				session.Rate = v.Limit.Rate
				session.Per = v.Limit.Per
				session.Smoothing = v.Limit.Smoothing
			}

			if len(applyState.didQuota) == 1 {
				session.QuotaMax = v.Limit.QuotaMax
				session.QuotaRenews = v.Limit.QuotaRenews
				session.QuotaRenewalRate = v.Limit.QuotaRenewalRate
			}

			if len(applyState.didComplexity) == 1 {
				session.MaxQueryDepth = v.Limit.MaxQueryDepth
			}
		}
	}
}

func (t *Service) applyAPILevelLimits(policyAD user.AccessDefinition, currAD user.AccessDefinition) user.AccessDefinition {
	var updated bool
	if policyAD.Limit.Duration() > currAD.Limit.Duration() {
		policyAD.Limit.Per = currAD.Limit.Per
		policyAD.Limit.Rate = currAD.Limit.Rate
		policyAD.Limit.Smoothing = currAD.Limit.Smoothing
		updated = true
	}

	if currAD.Limit.QuotaMax != policyAD.Limit.QuotaMax && greaterThanInt64(currAD.Limit.QuotaMax, policyAD.Limit.QuotaMax) {
		policyAD.Limit.QuotaMax = currAD.Limit.QuotaMax
		updated = true
	}

	if greaterThanInt64(currAD.Limit.QuotaRenewalRate, policyAD.Limit.QuotaRenewalRate) {
		policyAD.Limit.QuotaRenewalRate = currAD.Limit.QuotaRenewalRate
	}

	if policyAD.Limit.QuotaMax == -1 {
		policyAD.Limit.QuotaRenewalRate = 0
	}

	if updated {
		policyAD.Limit.SetBy = currAD.Limit.SetBy
		policyAD.AllowanceScope = currAD.AllowanceScope
	}

	policyAD.Endpoints = t.ApplyEndpointLevelLimits(policyAD.Endpoints, currAD.Endpoints)

	return policyAD
}

// ApplyEndpointLevelLimits combines policyEndpoints and currEndpoints and returns the combined value.
// The returned endpoints would have the highest request rate from policyEndpoints and currEndpoints.
func (t *Service) ApplyEndpointLevelLimits(policyEndpoints user.Endpoints, currEndpoints user.Endpoints) user.Endpoints {
	currEPMap := currEndpoints.Map()
	if len(currEPMap) == 0 {
		return policyEndpoints
	}

	result := policyEndpoints.Map()
	if len(result) == 0 {
		return currEPMap.Endpoints()
	}

	for currEP, currRL := range currEPMap {
		policyRL, ok := result[currEP]
		if !ok {
			// merge missing endpoints
			result[currEP] = currRL
			continue
		}

		policyDur, currDur := policyRL.Duration(), currRL.Duration()
		if policyDur > currDur {
			result[currEP] = currRL
			continue
		}

		// when duration is equal, use higher rate and per
		// eg. when 10 per 60 and 5 per 30 comes in
		// Duration would be 6s each, in such a case higher rate of 10 per 60 would be picked up.
		if policyDur == currDur && currRL.Rate > policyRL.Rate {
			result[currEP] = currRL
		}
	}

	return result.Endpoints()
}
