package policy

import (
	"errors"
	"fmt"

	"github.com/samber/lo"
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

	for _, polID := range t.policyIds(session) {
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

// apiId is the key used throughout Apply for anything tracked per API.
// It is the same value as user.AccessDefinition.APIID and the key of
// user.Policy.AccessRights / user.SessionState.AccessRights.
type apiId = string

// rightsByAPI is the working map Apply builds from the session's policies,
// keyed by apiId. Aliased so it can be assigned straight to
// user.SessionState.AccessRights, which has the same underlying type.
type rightsByAPI = map[apiId]user.AccessDefinition

// tagName is a session/policy tag. Apply collects tags into a set before
// writing them back to the session.
type tagName = string

// appliedPartitions records, for one API, which policy partitions have
// already been written into the working `rights` map while iterating over
// the session's policies. It does not remember which policy did it, only
// that some policy did. A non-partitioned policy sets all four at once.
type appliedPartitions struct {
	// acl is set when a policy granted access to this API (access rights,
	// allowed URLs, versions, GraphQL/MCP type restrictions). Without it
	// the API is dropped from `rights` at the end of Apply, so the key's
	// own access list stays untouched.
	acl bool

	// rateLimit is set when a policy wrote request rate limits for this
	// API: Rate, Per, Smoothing, Throttle* and per-endpoint rate limits
	// (Endpoints, JSONRPCMethods, MCPPrimitives).
	rateLimit bool

	// quota is set when a policy wrote QuotaMax and QuotaRenewalRate for
	// this API.
	quota bool

	// complexity is set when a policy wrote GraphQL MaxQueryDepth for this
	// API.
	complexity bool
}

// mark applies fn to the appliedPartitions entry of api, creating the entry
// if it does not exist yet. Use it only where a partition is being set; plain
// reads must go through byAPI[api] so that they never create entries.
func (r *applyRun) mark(api apiId, fn func(p *appliedPartitions)) {
	p := r.byAPI[api]
	fn(&p)
	r.byAPI[api] = p
}

// partitionCounts says, for each partition, how many APIs had it applied.
type partitionCounts struct {
	acl, rateLimit, quota, complexity int
}

// counts tallies byAPI in one pass. It replaces the old `len(didX)` checks:
// those maps only ever received `true`, so their length was the number of
// APIs with that partition applied.
func (r *applyRun) counts() partitionCounts {
	var c partitionCounts
	for _, p := range r.byAPI {
		if p.acl {
			c.acl++
		}
		if p.rateLimit {
			c.rateLimit++
		}
		if p.quota {
			c.quota++
		}
		if p.complexity {
			c.complexity++
		}
	}
	return c
}

// applyRun is one execution of Apply for one session. It owns the working
// state that the individual steps read and write, so those steps take no
// parameters beyond what varies per call. It has no reference back to
// Service; Service only builds it (newApplyRun) and drives it.
type applyRun struct {
	// orgID, when set, must match every applied policy's OrgID.
	orgID *string
	// logger receives the same errors Apply always logged.
	logger *logrus.Logger

	// session is the session being (re)computed, modified in place.
	session *user.SessionState

	// rights is the working access-rights map built from the policies. At
	// the end it either replaces session.AccessRights or is discarded.
	rights rightsByAPI
	// tags collects tags from policies and the session; written back once.
	tags map[tagName]bool
	// byAPI holds, per API, which partitions some policy has already
	// applied. An API absent from the map has had nothing applied yet.
	byAPI map[apiId]appliedPartitions

	// didPerAPI is set once a per_api policy has been applied; didPartition
	// once a partitioned policy has. Mixing the two kinds in one session is
	// an error, and these two flags are how it is detected.
	didPerAPI    bool
	didPartition bool
}

// newApplyRun prepares the working state for one Apply on session.
func (t *Service) newApplyRun(session *user.SessionState) *applyRun {
	return &applyRun{
		orgID:   t.orgID,
		logger:  t.logger,
		session: session,
		rights:  make(rightsByAPI),
		tags:    make(map[tagName]bool),
		byAPI:   make(map[apiId]appliedPartitions),
	}
}

// Apply will check if any policies are loaded. If any are, it
// will overwrite the session state to use the policy values.
func (t *Service) Apply(session *user.SessionState) error {
	run := t.newApplyRun(session)

	if session.MetaData == nil {
		session.MetaData = make(map[string]interface{})
	}

	if err := t.ClearSession(session); err != nil {
		t.logger.WithError(err).Warn("error clearing session")
	}

	var (
		policyIDs []model.PolicyID
	)

	storage := t.storage
	if customPolicies, err := session.GetCustomPolicies(); err == nil {
		storage = NewStore(customPolicies)
		policyIDs = storage.PolicyIDs()
	} else {
		policyIDs = t.policyIds(session)
	}

	// Only the status of policies applied to a key should determine the validity of the key.
	// If no policies are applied, preserve the session's own IsInactive state.
	sessionInactiveState := session.IsInactive
	hasPolicies := len(policyIDs) > 0
	if hasPolicies {
		sessionInactiveState = false
	}

	var appliedPoliciesCount int

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
		appliedPoliciesCount++
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
			if err := run.applyPerAPI(policy); err != nil {
				return err
			}
		} else {
			if err := run.applyPartitions(policy); err != nil {
				return err
			}
		}

		sessionInactiveState = sessionInactiveState || policy.IsInactive

		run.mergePolicyMetadata(policy)
	}

	session.IsInactive = sessionInactiveState

	run.writeSessionTags()

	if len(policyIDs) == 0 {
		run.scopeKeyLevelLimits()
	}

	run.finaliseRights()

	if appliedPoliciesCount == 0 && policyIDs != nil {
		return errors.New("key has no valid policies to be applied")
	}

	return nil
}

// Logger implements a typical logger signature with service context.
func (t *Service) Logger() *logrus.Entry {
	return logrus.NewEntry(t.logger)
}

// The exported Service methods below are thin wrappers kept for the package
// tests, which live in package policy_test and cannot see applyRun. The
// logic lives on applyRun; these helpers use no run state.

// ApplyRateLimits see applyRun.applyRateLimits.
func (t *Service) ApplyRateLimits(session *user.SessionState, policy user.Policy, apiLimits *user.APILimit) {
	(&applyRun{}).applyRateLimits(session, policy, apiLimits)
}

// ApplyEndpointLevelLimits see applyRun.applyEndpointLevelLimits.
func (t *Service) ApplyEndpointLevelLimits(policyEndpoints user.Endpoints, currEndpoints user.Endpoints) user.Endpoints {
	return (&applyRun{}).applyEndpointLevelLimits(policyEndpoints, currEndpoints)
}

// ApplyJSONRPCMethodLimits see applyRun.applyJSONRPCMethodLimits.
func (t *Service) ApplyJSONRPCMethodLimits(policy, current []user.JSONRPCMethodLimit) []user.JSONRPCMethodLimit {
	return (&applyRun{}).applyJSONRPCMethodLimits(policy, current)
}

// ApplyMCPPrimitiveLimits see applyRun.applyMCPPrimitiveLimits.
func (t *Service) ApplyMCPPrimitiveLimits(policy, current []user.MCPPrimitiveLimit) []user.MCPPrimitiveLimit {
	return (&applyRun{}).applyMCPPrimitiveLimits(policy, current)
}

// applyRateLimits will write policy limits to session and apiLimits.
// The limits get written if either are empty.
// The limits get written if filled and policyLimits allows a higher request rate.
func (r *applyRun) applyRateLimits(session *user.SessionState, policy user.Policy, apiLimits *user.APILimit) {
	policyLimits := policy.APILimit()
	if r.emptyRateLimit(policyLimits) {
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

	if r.emptyRateLimit(*apiLimits) || apiLimits.Duration() > policyLimits.Duration() {
		apiLimits.Rate = policyLimits.Rate
		apiLimits.Per = policyLimits.Per
		apiLimits.Smoothing = policyLimits.Smoothing
	}

	// sessionLimits, similar to apiLimits, get policy
	// rate applied if the policy allows more requests.
	sessionLimits := session.APILimit()
	if r.emptyRateLimit(sessionLimits) || sessionLimits.Duration() > policyLimits.Duration() {
		session.Rate = policyLimits.Rate
		session.Per = policyLimits.Per
		session.Smoothing = policyLimits.Smoothing
	}
}

func (r *applyRun) emptyRateLimit(m user.APILimit) bool {
	return m.Rate == 0 || m.Per == 0
}

func (r *applyRun) applyPerAPI(policy user.Policy) error {
	session, rights := r.session, r.rights

	if r.didPartition {
		r.logger.Error(ErrMixedPartitionAndPerAPIPolicies)
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
			accessRights = r.applyAPILevelLimits(accessRights, currAD)
		}

		// overwrite session access right for this API
		rights[apiID] = accessRights

		// identify that limit for that API is set (to allow set it only once)
		r.mark(apiID, func(p *appliedPartitions) {
			p.acl = true
			p.quota = true
			p.rateLimit = true
			p.complexity = true
		})
	}

	if len(policy.AccessRights) > 0 {
		r.didPerAPI = true
	}

	return nil
}

func (t *Service) policyIds(session *user.SessionState) []model.PolicyID {
	if ids := session.PolicyIDs(); ids == nil {
		return nil
	}

	orgID := session.OrgID
	if orgID == "" && t.orgID != nil {
		// Use the API spec's organization ID if the session's organization ID is empty
		orgID = *t.orgID
	}

	return lo.Map(session.PolicyIDs(), func(item string, _ int) model.PolicyID {
		return model.NewScopedCustomPolicyId(orgID, item)
	})
}

func (r *applyRun) applyPartitions(policy user.Policy) error {
	session, rights := r.session, r.rights

	usePartitions := policy.Partitions.Enabled()

	if usePartitions && r.didPerAPI {
		r.logger.Error(ErrMixedPartitionAndPerAPIPolicies)
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
			r.mark(k, func(p *appliedPartitions) { p.acl = true })

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
					// Create a map to track which types have been processed
					processedTypes := make(map[string]bool)

					for _, t := range v.RestrictedTypes {
						typeFound := false
						for ri, rt := range r.RestrictedTypes {
							if t.Name == rt.Name {
								// Merge fields for existing types
								r.RestrictedTypes[ri].Fields = appendIfMissing(rt.Fields, t.Fields...)
								typeFound = true
								processedTypes[t.Name] = true
								break
							}
						}
						// Add new types that don't exist in destination
						if !typeFound {
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
					// Create a map to track which types have been processed
					processedTypes := make(map[string]bool)

					for _, t := range v.AllowedTypes {
						typeFound := false
						for ri, rt := range r.AllowedTypes {
							if t.Name == rt.Name {
								// Merge fields for existing types
								r.AllowedTypes[ri].Fields = appendIfMissing(rt.Fields, t.Fields...)
								typeFound = true
								processedTypes[t.Name] = true
								break
							}
						}
						// Add new types that don't exist in destination
						if !typeFound {
							r.AllowedTypes = append(r.AllowedTypes, t)
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

				r.JSONRPCMethodsAccessRights = mergeACLRules(r.JSONRPCMethodsAccessRights, v.JSONRPCMethodsAccessRights)
				r.MCPAccessRights.Tools = mergeACLRules(r.MCPAccessRights.Tools, v.MCPAccessRights.Tools)
				r.MCPAccessRights.Resources = mergeACLRules(r.MCPAccessRights.Resources, v.MCPAccessRights.Resources)
				r.MCPAccessRights.Prompts = mergeACLRules(r.MCPAccessRights.Prompts, v.MCPAccessRights.Prompts)

				ar = r
			}

			ar.Limit.SetBy = policy.ID
		}

		if !usePartitions || policy.Partitions.Quota {
			r.mark(k, func(p *appliedPartitions) { p.quota = true })

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
			r.mark(k, func(p *appliedPartitions) { p.rateLimit = true })

			r.applyRateLimits(session, policy, &ar.Limit)

			if rightsAR, ok := rights[k]; ok {
				ar.Endpoints = r.applyEndpointLevelLimits(v.Endpoints, rightsAR.Endpoints)
				ar.JSONRPCMethods = r.applyJSONRPCMethodLimits(v.JSONRPCMethods, rightsAR.JSONRPCMethods)
				ar.MCPPrimitives = r.applyMCPPrimitiveLimits(v.MCPPrimitives, rightsAR.MCPPrimitives)
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
			r.mark(k, func(p *appliedPartitions) { p.complexity = true })

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

	r.didPartition = usePartitions

	return nil
}

// mergePolicyMetadata copies the non-limit, non-ACL parts of a policy into
// the session: tags (collected into the set, written back later), metadata
// (policy wins on key clash), the newest LastUpdated, and post-expiry
// settings when the policy defines them.
func (r *applyRun) mergePolicyMetadata(policy user.Policy) {
	session, tags := r.session, r.tags

	for _, tag := range policy.Tags {
		tags[tag] = true
	}

	for k, v := range policy.MetaData {
		session.MetaData[k] = v
	}

	if policy.LastUpdated > session.LastUpdated {
		session.LastUpdated = policy.LastUpdated
	}

	if policy.PostExpiryAction != "" {
		session.PostExpiryAction = policy.PostExpiryAction
	}
	if policy.PostExpiryGracePeriod != 0 {
		session.PostExpiryGracePeriod = policy.PostExpiryGracePeriod
	}
}

// writeSessionTags merges the session's own tags into the set collected from
// policies and writes the result back. Map iteration order is random, so the
// order of session.Tags is not stable between calls; this is long-standing
// behaviour.
func (r *applyRun) writeSessionTags() {
	session, tags := r.session, r.tags

	for _, tag := range session.Tags {
		tags[tag] = true
	}

	session.Tags = []string{}
	for tag := range tags {
		session.Tags = appendIfMissing(session.Tags, tag)
	}
}

// scopeKeyLevelLimits handles a key with no policies at all: every access
// right that carries its own limit gets AllowanceScope set to its API ID, so
// rate limiting and quotas are counted per API rather than per key.
func (r *applyRun) scopeKeyLevelLimits() {
	session := r.session

	for apiID, accessRight := range session.AccessRights {
		if !accessRight.Limit.IsEmpty() {
			accessRight.AllowanceScope = apiID
			session.AccessRights[apiID] = accessRight
		}
	}
}

// finaliseRights turns the working `rights` map into the session's access
// rights. Every API in it falls into one of two cases:
//
//   - no policy granted ACL for it: the API must not become a session entry
//     (its ACL would be empty), so push the computed limits into the key's
//     own entry, if any, and drop it from `rights`;
//   - some policy granted ACL for it: it will replace the session entry, so
//     fill the partitions no policy applied from the session root.
//
// Afterwards the legacy session-root limits are updated and, if any policy
// granted ACL, `rights` replaces session.AccessRights wholesale.
func (r *applyRun) finaliseRights() {
	session, rights := r.session, r.rights

	multipleACL := r.limitsFromMultiplePolicies()

	for k, v := range rights {
		applied := r.byAPI[k]

		if !applied.acl {
			r.updateExistingAccessRightLimits(k, v, applied)
			delete(rights, k)
			continue
		}

		rights[k] = r.inheritUnappliedFromSessionRoot(v, applied, multipleACL)
	}

	counts := r.counts()

	// If we have policies defining rules for one single API, update session root vars (legacy)
	r.updateSessionRootVars(counts)

	// Override session ACL if at least one policy define it
	if counts.acl > 0 {
		session.AccessRights = rights
	}
}

// limitsFromMultiplePolicies reports whether the limits in rights were set by at
// least two different policies (Limit.SetBy holds the policy ID). It stops
// as soon as a second distinct policy is seen.
func (r *applyRun) limitsFromMultiplePolicies() bool {
	first := ""
	for _, v := range r.rights {
		setBy := v.Limit.SetBy
		if setBy == "" {
			continue
		}
		if first == "" {
			first = setBy
			continue
		}
		if setBy != first {
			return true
		}
	}
	return false
}

// updateExistingAccessRightLimits copies the limits computed in `computed`
// into the session's own access right for api, but only for the partitions
// some policy actually applied. The session entry's ACL (AllowedURLs,
// Versions, GraphQL/MCP restrictions) is left untouched. If the key has no
// access right for api, nothing happens: a policy without ACL cannot grant
// access to a new API.
func (r *applyRun) updateExistingAccessRightLimits(api apiId, computed user.AccessDefinition, applied appliedPartitions) {
	session := r.session

	existing, ok := session.AccessRights[api]
	if !ok {
		return
	}

	if applied.rateLimit {
		existing.Limit.Rate = computed.Limit.Rate
		existing.Limit.Per = computed.Limit.Per
		existing.Limit.Smoothing = computed.Limit.Smoothing
		existing.Limit.ThrottleInterval = computed.Limit.ThrottleInterval
		existing.Limit.ThrottleRetryLimit = computed.Limit.ThrottleRetryLimit
		existing.Endpoints = computed.Endpoints
	}

	if applied.quota {
		existing.Limit.QuotaMax = computed.Limit.QuotaMax
		existing.Limit.QuotaRenewalRate = computed.Limit.QuotaRenewalRate
		existing.Limit.QuotaRenews = computed.Limit.QuotaRenews
	}

	if applied.complexity {
		existing.Limit.MaxQueryDepth = computed.Limit.MaxQueryDepth
	}

	// `existing` is a copy; write it back.
	session.AccessRights[api] = existing
}

// inheritUnappliedFromSessionRoot returns ar with every partition no policy
// applied filled from the session root values, ready to become the
// session's access right for that API. When more than one policy set ACLs,
// the AllowanceScope is pinned to the policy that set the limit so that
// quotas and rate limits are counted per policy.
func (r *applyRun) inheritUnappliedFromSessionRoot(ar user.AccessDefinition, applied appliedPartitions, multipleACL bool) user.AccessDefinition {
	session := r.session

	if !applied.rateLimit {
		ar.Limit.Rate = session.Rate
		ar.Limit.Per = session.Per
		ar.Limit.Smoothing = session.Smoothing
		ar.Limit.ThrottleInterval = session.ThrottleInterval
		ar.Limit.ThrottleRetryLimit = session.ThrottleRetryLimit
		ar.Endpoints = nil
	}

	if !applied.complexity {
		ar.Limit.MaxQueryDepth = session.MaxQueryDepth
	}

	if !applied.quota {
		ar.Limit.QuotaMax = session.QuotaMax
		ar.Limit.QuotaRenewalRate = session.QuotaRenewalRate
		ar.Limit.QuotaRenews = session.QuotaRenews
	}

	if multipleACL && ar.AllowanceScope == "" && ar.Limit.SetBy != "" {
		ar.AllowanceScope = ar.Limit.SetBy
	}

	ar.Limit.SetBy = ""

	return ar
}

func (r *applyRun) updateSessionRootVars(c partitionCounts) {
	session, rights := r.session, r.rights

	// Only when exactly one API received all three partitions. This has been
	// an AND since the check was introduced (2019, #2462); a rate-limit-only
	// policy for a single API deliberately does not touch the session root.
	if c.quota != 1 || c.rateLimit != 1 || c.complexity != 1 {
		return
	}

	for _, v := range rights {
		session.Rate = v.Limit.Rate
		session.Per = v.Limit.Per
		session.Smoothing = v.Limit.Smoothing

		session.QuotaMax = v.Limit.QuotaMax
		session.QuotaRenews = v.Limit.QuotaRenews
		session.QuotaRenewalRate = v.Limit.QuotaRenewalRate

		session.MaxQueryDepth = v.Limit.MaxQueryDepth
	}
}

func (r *applyRun) applyAPILevelLimits(policyAD user.AccessDefinition, currAD user.AccessDefinition) user.AccessDefinition {
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

	policyAD.Endpoints = r.applyEndpointLevelLimits(policyAD.Endpoints, currAD.Endpoints)
	policyAD.JSONRPCMethods = r.applyJSONRPCMethodLimits(policyAD.JSONRPCMethods, currAD.JSONRPCMethods)
	policyAD.MCPPrimitives = r.applyMCPPrimitiveLimits(policyAD.MCPPrimitives, currAD.MCPPrimitives)

	return policyAD
}

// applyEndpointLevelLimits combines policyEndpoints and currEndpoints and returns the combined value.
// The returned endpoints would have the highest request rate from policyEndpoints and currEndpoints.
func (r *applyRun) applyEndpointLevelLimits(policyEndpoints user.Endpoints, currEndpoints user.Endpoints) user.Endpoints {
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

// mergeACLRules merges two AccessControlRules using union semantics, consistent
// with how AllowedURLs are merged across policies: both Allowed and Blocked lists
// are unioned. If src is empty (not configured), dst is returned unchanged.
func mergeACLRules(dst, src user.AccessControlRules) user.AccessControlRules {
	if src.IsEmpty() {
		return dst
	}
	if dst.IsEmpty() {
		return src
	}
	return user.AccessControlRules{
		Allowed: appendIfMissing(dst.Allowed, src.Allowed...),
		Blocked: appendIfMissing(dst.Blocked, src.Blocked...),
	}
}

// applyJSONRPCMethodLimits merges per-method rate limits: higher rate (lower duration) wins,
// matching the semantics of applyEndpointLevelLimits.
func (r *applyRun) applyJSONRPCMethodLimits(policy, current []user.JSONRPCMethodLimit) []user.JSONRPCMethodLimit {
	if len(current) == 0 {
		return policy
	}
	if len(policy) == 0 {
		return current
	}

	result := make(map[string]user.JSONRPCMethodLimit)
	for _, m := range current {
		result[m.Name] = m
	}
	for _, m := range policy {
		curr, ok := result[m.Name]
		if !ok {
			result[m.Name] = m
			continue
		}
		if m.Limit.Duration() < curr.Limit.Duration() || curr.Limit.Duration() == 0 {
			result[m.Name] = m
		}
	}

	out := make([]user.JSONRPCMethodLimit, 0, len(result))
	for _, m := range result {
		out = append(out, m)
	}
	return out
}

// applyMCPPrimitiveLimits merges per-primitive rate limits keyed on type+name:
// higher rate (lower duration) wins, matching applyEndpointLevelLimits semantics.
func (r *applyRun) applyMCPPrimitiveLimits(policy, current []user.MCPPrimitiveLimit) []user.MCPPrimitiveLimit {
	if len(current) == 0 {
		return policy
	}
	if len(policy) == 0 {
		return current
	}

	type key struct{ typ, name string }

	result := make(map[key]user.MCPPrimitiveLimit)
	for _, p := range current {
		result[key{p.Type, p.Name}] = p
	}
	for _, p := range policy {
		k := key{p.Type, p.Name}
		curr, ok := result[k]
		if !ok {
			result[k] = p
			continue
		}
		if p.Limit.Duration() < curr.Limit.Duration() || curr.Limit.Duration() == 0 {
			result[k] = p
		}
	}

	out := make([]user.MCPPrimitiveLimit, 0, len(result))
	for _, p := range result {
		out = append(out, p)
	}
	return out
}
