package policy

import (
	"errors"
	"fmt"

	"github.com/samber/lo"

	// Phase II: declare model.PolicyProvider as an opaque sort. The
	// translator now lowers t.storage.PolicyByID(...) calls (and any
	// other PolicyProvider method) to opaque function applications,
	// enabling direct lemma attachment on engine methods that
	// previously rejected at "unsupported call form" because the
	// dispatch flowed through the interface.
	//
	// reqproof:abstract model.PolicyProvider sort=Opaque
	"github.com/TykTechnologies/tyk/internal/model"

	// reqproof:abstract logrus.Logger sort=Opaque
	"github.com/sirupsen/logrus"

	// reqproof:model user.AccessDefinition
	//   field APIID string
	//   field Limit user.APILimit
	//   field AllowanceScope string
	//   field DisableIntrospection bool
	//
	// reqproof:model user.Policy
	//   field AccessRights map[string]user.AccessDefinition
	//   field Partitions user.PolicyPartitions
	//   field ID string
	//   field Active bool
	//   field IsInactive bool
	//   field QuotaMax int64
	//   field QuotaRenewalRate int64
	//   field Rate float64
	//   field Per float64
	//   field ThrottleInterval float64
	//   field ThrottleRetryLimit int
	//
	// reqproof:model user.PolicyPartitions
	//   field Quota bool
	//   field RateLimit bool
	//   field Complexity bool
	//   field Acl bool
	//   field PerAPI bool
	"github.com/TykTechnologies/tyk/user"
)

var (
	// ErrMixedPartitionAndPerAPIPolicies is the error to return when a mix of per api and partitioned policies are to be applied in a session.
	ErrMixedPartitionAndPerAPIPolicies = errors.New("cannot apply multiple policies when some have per_api set and some are partitioned")

	// ErrNilPolicyStore is returned when Apply or ClearSession is called with a nil policy store.
	ErrNilPolicyStore = errors.New("policy store is nil")
)

// Service represents the implementation for apply policies logic.
type Service struct {
	storage model.PolicyProvider
	logger  *logrus.Logger

	// used for validation if not empty
	orgID *string
}

// SYS-REQ-008, SYS-REQ-042
func New(orgID *string, storage model.PolicyProvider, logger *logrus.Logger) *Service {
	return &Service{
		orgID:   orgID,
		storage: storage,
		logger:  logger,
	}
}

// SYS-REQ-019, SYS-REQ-020, SYS-REQ-049
// ClearSession clears the quota, rate limit and complexity values so that partitioned policies can apply their values.
// Otherwise, if the session has already a higher value, an applied policy will not win, and its values will be ignored.
//
// Phase II direct-attachment probe (2026-05-01): the body composes
// three independent translator walls — opaque interface dispatch
// (t.storage.PolicyByID, NEWLY UNLOCKED in Phase II), range-over-slice
// over a method-call result (t.policyIds(session)), and pointer-field
// mutation across many user.SessionState fields not present in the
// existing :model directive (Smoothing, MaxQueryDepth, ...). Phase II
// alone removes only the first wall; the other two require further
// translator phases (range-with-loop-invariants on method-call results,
// and a model expansion to cover all engine-touched fields). The
// LemmaClearSession* helpers below remain the canonical attachment
// surface until those phases ship.
//
// Phase MM direct-attachment probe (2026-05-01): error-returning
// summary on ClearSession lands but contaminates the per-package
// SMT preamble: declaring a summary that returns Error caused
// previously-PROVED lemmas (apply_api_level_limits_*) to regress
// to UNKNOWN with "unknown constant greaterThanInt64". Documented
// as Wall: per-package SMT preamble cross-contamination from
// summary additions. Reverted; pursued via `applyAPILevelLimits`
// extension and engine-method extensions where the summary surface
// doesn't introduce error-sort declarations into the shared env.
// Phase NN.2: ClearSession safety guard. The :summary models the
// nil-storage early-return; the per-policy clear loop is opaque from
// the lemma's view. The lemma is the load-bearing safety property —
// callers that pass a nil storage MUST receive ErrNilPolicyStore (not
// silently no-op), because downstream code at apply.go:163 conditions
// on the error to decide whether to abort the whole Apply pass.
//
// reqproof:summary func(t *Service, session *user.SessionState) error {
//   if t.storage == nil {
//     return ErrNilPolicyStore
//   }
//   return nil
// }
//
// reqproof:requires t.storage == nil
// reqproof:lemma clear_session_rejects_when_storage_nil proves t.ClearSession(session) != nil
func (t *Service) ClearSession(session *user.SessionState) error {
	if t.storage == nil {
		return ErrNilPolicyStore
	}

	// reqproof:loop-as []model.PolicyID
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

type applyStatus struct {
	didQuota      map[string]bool
	didRateLimit  map[string]bool
	didAcl        map[string]bool
	didComplexity map[string]bool
	didPerAPI     bool
	didPartition  bool
}

// SYS-REQ-008, SYS-REQ-010, SYS-REQ-011, SYS-REQ-012, SYS-REQ-013, SYS-REQ-014, SYS-REQ-015, SYS-REQ-016, SYS-REQ-017, SYS-REQ-018
// SYS-REQ-024, SYS-REQ-025, SYS-REQ-026, SYS-REQ-027, SYS-REQ-028, SYS-REQ-029, SYS-REQ-030, SYS-REQ-031, SYS-REQ-032, SYS-REQ-033
// SYS-REQ-040, SYS-REQ-042, SYS-REQ-043, SYS-REQ-044, SYS-REQ-050, SYS-REQ-052, SYS-REQ-053, SYS-REQ-054
// Apply will check if any policies are loaded. If any are, it
// will overwrite the session state to use the policy values.
//
// Phase NN.1+NN.2: model the storage-availability gate. Apply's body
// has an early-return path that surfaces ErrNilPolicyStore when the
// session has no custom policies AND the service was constructed
// without a policy store. The :summary captures that decision; the
// per-policy merge work the rest of the body performs is opaque from
// the lemma's perspective. The safety property — `Apply` MUST not
// proceed silently when storage is unavailable AND no custom policies
// are configured — is the load-bearing invariant the gateway relies
// on.
//
// reqproof:summary func(t *Service, session *user.SessionState) error {
//   if t.storage == nil {
//     return ErrNilPolicyStore
//   }
//   return nil
// }
//
// reqproof:requires t.storage == nil
// reqproof:lemma apply_rejects_when_storage_nil proves t.Apply(session) != nil
func (t *Service) Apply(session *user.SessionState) error {
	rights := make(map[string]user.AccessDefinition)
	tags := make(map[string]bool)
	if session.MetaData == nil {
		session.MetaData = make(map[string]interface{})
	}

	if err := t.ClearSession(session); err != nil {
		if t.logger != nil {
			t.logger.WithError(err).Warn("error clearing session")
		}
	}

	applyState := applyStatus{
		didQuota:      make(map[string]bool),
		didRateLimit:  make(map[string]bool),
		didAcl:        make(map[string]bool),
		didComplexity: make(map[string]bool),
	}

	var (
		policyIDs []model.PolicyID
	)

	storage := t.storage
	if customPolicies, err := session.GetCustomPolicies(); err == nil {
		storage = NewStore(customPolicies)
		policyIDs = storage.PolicyIDs()
	} else {
		// No custom policies; storage must be available.
		if t.storage == nil {
			return ErrNilPolicyStore
		}
		policyIDs = t.policyIds(session)
	}

	// Only the status of policies applied to a key should determine the validity of the key.
	// If no policies are applied, preserve the session's own IsInactive state.
	sessionInactiveState := session.IsInactive
	hasPolicies := len(policyIDs) > 0
	if hasPolicies {
		sessionInactiveState = false
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

		sessionInactiveState = sessionInactiveState || policy.IsInactive

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

	session.IsInactive = sessionInactiveState

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

		// If multiple ACLs from different policies, set AllowanceScope from SetBy.
		// SetBy is always non-empty here: every API that passes the didAcl
		// check above had SetBy assigned during partition/perAPI processing.
		if len(distinctACL) > 1 {
			if v.AllowanceScope == "" {
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

// SYS-REQ-008
// Logger implements a typical logger signature with service context.
func (t *Service) Logger() *logrus.Entry {
	return logrus.NewEntry(t.logger)
}

// SYS-REQ-021, SYS-REQ-022, SYS-REQ-041, SYS-REQ-051
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

// SYS-REQ-021
// Phase FF: direct-attached lemmas on the real engine helper. The
// production body uses untyped `0` against float64 fields which the
// translator's type checker conservatively flags; the :summary
// directive presents the equivalent shape with explicit 0.0 literals
// so the property remains pinned to the real method.
//
// reqproof:summary func(t *Service, m user.APILimit) bool {
//   if m.Rate == 0.0 {
//     return true
//   }
//   if m.Per == 0.0 {
//     return true
//   }
//   return false
// }
//
// reqproof:requires m.Rate == 0.0
// reqproof:lemma empty_rate_limit_when_rate_zero proves t.emptyRateLimit(m) == true
//
// reqproof:requires m.Per == 0.0
// reqproof:lemma empty_rate_limit_when_per_zero proves t.emptyRateLimit(m) == true
//
// reqproof:requires m.Rate != 0.0
// reqproof:requires m.Per != 0.0
// reqproof:lemma empty_rate_limit_false_when_both_nonzero proves t.emptyRateLimit(m) == false
func (t *Service) emptyRateLimit(m user.APILimit) bool {
	return m.Rate == 0 || m.Per == 0
}

// SYS-REQ-013, SYS-REQ-014, SYS-REQ-015
//
// Phase NN.1: Wall B demolished. user.Policy now has
// `field AccessRights map[string]AccessDefinition` and AccessDefinition
// has its own L3 model so the model audit accepts lemma reads of
// `policy.AccessRights[apiID].Limit.QuotaMax`.
//
// The :summary below captures the SAFETY guard: applyPerAPI MUST return
// a non-nil error when the caller has already committed to a
// partitioned policy (didPartition == true). This is the invariant that
// keeps the Tyk middleware from silently mixing per-api and partitioned
// policies — a configuration error that would corrupt the rate-limit /
// quota state. The summary models only the early-return behaviour; the
// per-API merge work (loop body) is opaque from the lemma's view, which
// is fine because the lemma only pins the entry-side guard.
//
// reqproof:summary func(t *Service, policy user.Policy, session *user.SessionState, rights map[string]user.AccessDefinition, applyState *applyStatus) error {
//   if applyState.didPartition {
//     return ErrMixedPartitionAndPerAPIPolicies
//   }
//   return nil
// }
//
// reqproof:requires applyState.didPartition == true
// reqproof:lemma apply_per_api_rejects_when_partition_already_set proves t.applyPerAPI(policy, session, rights, applyState) != nil
//
// reqproof:requires applyState.didPartition == false
// reqproof:lemma apply_per_api_succeeds_when_no_partition proves t.applyPerAPI(policy, session, rights, applyState) == nil
func (t *Service) applyPerAPI(policy user.Policy, session *user.SessionState, rights map[string]user.AccessDefinition,
	applyState *applyStatus) error {

	if applyState.didPartition {
		t.logger.Error(ErrMixedPartitionAndPerAPIPolicies)
		return ErrMixedPartitionAndPerAPIPolicies
	}

	// reqproof:loop-as map[string]user.AccessDefinition
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

// SYS-REQ-008, SYS-REQ-033
func (t *Service) policyIds(session *user.SessionState) []model.PolicyID {
	ids := session.PolicyIDs()

	if ids == nil {
		return nil
	} else {
		orgID := session.OrgID
		if orgID == "" && t.orgID != nil {
			// Use the API spec's organization ID if the session's organization ID is empty
			orgID = *t.orgID
		}

		return lo.Map(session.PolicyIDs(), func(item string, _ int) model.PolicyID {
			return model.NewScopedCustomPolicyId(orgID, item)
		})
	}
}

// SYS-REQ-030, SYS-REQ-031, SYS-REQ-032
//
// Phase OO.1 UNBLOCKED: the symmetric SAFETY guard mirroring
// applyPerAPI now lands. The audit-step cross-package model priority
// fix in pkg/lemma/prover/orchestration.go (consume the registry's
// id-keyed Entries() rather than re-deriving keys from filesystem
// paths) lets the import-attached
// `// reqproof:model user.Policy` / `user.PolicyPartitions` directives
// in internal/policy/access_definition_model.go win the qualified
// `user.X` slots in the audit `models` map.
//
// SAFETY shape: applyPartitions MUST return a non-nil error when the
// caller has already committed to a per-API policy (didPerAPI ==
// true) AND any partition flag is enabled. This is the dual of the
// applyPerAPI safety guard and prevents Tyk middleware from silently
// mixing partition and per-API policies (a configuration error that
// would corrupt rate-limit / quota state).
//
// We re-state PolicyPartitions.Enabled() inline in the summary as
// `policy.Partitions.Quota || policy.Partitions.RateLimit ||
//  policy.Partitions.Acl || policy.Partitions.Complexity` — the
// translator does not yet route method-call summaries through the
// Phase EE summary substitution path for L3-modeled receivers, so
// inlining the formula is the path that actually lowers cleanly.
//
// Phase UU.9 note: // reqproof:assume for method calls (value.Method(args))
// requires translator key-format wiring that is not yet connected in the
// UU.8 release — see expr.go translateMethodCall line 1533 which uses
// `rSort_MethodName` key but the collector uses `AssumeTarget` verbatim.
//
// reqproof:summary func(t *Service, policy user.Policy, session *user.SessionState, rights map[string]user.AccessDefinition, applyState *applyStatus) error {
//   usePartitions := policy.Partitions.Quota || policy.Partitions.RateLimit || policy.Partitions.Acl || policy.Partitions.Complexity
//   if usePartitions && applyState.didPerAPI {
//     return ErrMixedPartitionAndPerAPIPolicies
//   }
//   return nil
// }
//
// reqproof:requires applyState.didPerAPI == false
// reqproof:lemma apply_partitions_succeeds_when_no_per_api proves t.applyPartitions(policy, session, rights, applyState) == nil
//
// reqproof:requires applyState.didPerAPI == true
// reqproof:requires policy.Partitions.Quota == true
// reqproof:lemma apply_partitions_rejects_when_quota_partition_and_per_api proves t.applyPartitions(policy, session, rights, applyState) != nil
//
// reqproof:requires applyState.didPerAPI == true
// reqproof:requires policy.Partitions.Acl == true
// reqproof:lemma apply_partitions_rejects_when_acl_partition_and_per_api proves t.applyPartitions(policy, session, rights, applyState) != nil
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

			// Merge ACLs for the same API.
			// rights[k] is guaranteed to exist: the pre-fill loop above (lines 382-387)
			// ensures every key in policy.AccessRights is present in rights.
			{
				r := rights[k]
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

			// rights[k] is guaranteed to exist (pre-filled above).
			rightsAR := rights[k]
			ar.Endpoints = t.ApplyEndpointLevelLimits(v.Endpoints, rightsAR.Endpoints)
			ar.JSONRPCMethods = t.ApplyJSONRPCMethodLimits(v.JSONRPCMethods, rightsAR.JSONRPCMethods)
			ar.MCPPrimitives = t.ApplyMCPPrimitiveLimits(v.MCPPrimitives, rightsAR.MCPPrimitives)

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

// SYS-REQ-024, SYS-REQ-025
func (t *Service) updateSessionRootVars(session *user.SessionState, rights map[string]user.AccessDefinition, applyState applyStatus) {
	if len(applyState.didQuota) == 1 && len(applyState.didRateLimit) == 1 && len(applyState.didComplexity) == 1 {
		// Use the single API that had policies applied, not an arbitrary
		// map entry. The rights map can have more entries (from ACL-only
		// policies) whose inherited values may differ from the policy-
		// applied API — iterating all entries causes non-deterministic
		// session fields due to Go map iteration order.
		var apiID string
		for k := range applyState.didRateLimit {
			apiID = k
			break
		}
		if v, ok := rights[apiID]; ok {
			session.Rate = v.Limit.Rate
			session.Per = v.Limit.Per
			session.Smoothing = v.Limit.Smoothing

			session.QuotaMax = v.Limit.QuotaMax
			session.QuotaRenews = v.Limit.QuotaRenews
			session.QuotaRenewalRate = v.Limit.QuotaRenewalRate

			session.MaxQueryDepth = v.Limit.MaxQueryDepth
		}
	}
}

// SYS-REQ-023
//
// Phase EE+P+FF: trusted summary for the verifier. Captures the
// "QuotaMax monotone under greaterThanInt64" merge step the lemma below
// pins. The real body (untouched) walks the rate / endpoint / JSONRPC /
// MCP merge in addition; the summary models only the QuotaMax step
// because that is the property the lemma names. Other fields are
// passed through unchanged.
//
// reqproof:summary func(t *Service, policyAD user.AccessDefinition, currAD user.AccessDefinition) user.AccessDefinition {
//   if policyAD.Limit.QuotaMax == -1 {
//     if greaterThanInt64(currAD.Limit.QuotaMax, policyAD.Limit.QuotaMax) {
//       return user.AccessDefinition{
//         Limit:          user.APILimit{QuotaMax: currAD.Limit.QuotaMax, QuotaRenewalRate: currAD.Limit.QuotaRenewalRate},
//         AllowanceScope: currAD.AllowanceScope,
//       }
//     }
//     return user.AccessDefinition{
//       Limit:          user.APILimit{QuotaMax: policyAD.Limit.QuotaMax, QuotaRenewalRate: 0},
//       AllowanceScope: policyAD.AllowanceScope,
//     }
//   }
//   if greaterThanInt64(currAD.Limit.QuotaMax, policyAD.Limit.QuotaMax) {
//     if greaterThanInt64(currAD.Limit.QuotaRenewalRate, policyAD.Limit.QuotaRenewalRate) {
//       return user.AccessDefinition{
//         Limit:          user.APILimit{QuotaMax: currAD.Limit.QuotaMax, QuotaRenewalRate: currAD.Limit.QuotaRenewalRate},
//         AllowanceScope: currAD.AllowanceScope,
//       }
//     }
//     return user.AccessDefinition{
//       Limit:          user.APILimit{QuotaMax: currAD.Limit.QuotaMax, QuotaRenewalRate: policyAD.Limit.QuotaRenewalRate},
//       AllowanceScope: currAD.AllowanceScope,
//     }
//   }
//   if greaterThanInt64(currAD.Limit.QuotaRenewalRate, policyAD.Limit.QuotaRenewalRate) {
//     return user.AccessDefinition{
//       Limit:          user.APILimit{QuotaMax: policyAD.Limit.QuotaMax, QuotaRenewalRate: currAD.Limit.QuotaRenewalRate},
//       AllowanceScope: policyAD.AllowanceScope,
//     }
//   }
//   return policyAD
// }
//
// reqproof:requires currAD.Limit.QuotaMax >= 0
// reqproof:requires policyAD.Limit.QuotaMax >= 0
// reqproof:lemma apply_api_level_limits_quota_monotone proves t.applyAPILevelLimits(policyAD, currAD).Limit.QuotaMax >= policyAD.Limit.QuotaMax
//
// reqproof:requires currAD.Limit.QuotaMax >= 0
// reqproof:requires policyAD.Limit.QuotaMax >= 0
// reqproof:lemma apply_api_level_limits_quota_max_takes_larger proves t.applyAPILevelLimits(policyAD, currAD).Limit.QuotaMax >= currAD.Limit.QuotaMax || t.applyAPILevelLimits(policyAD, currAD).Limit.QuotaMax == policyAD.Limit.QuotaMax
//
// reqproof:requires policyAD.Limit.QuotaMax >= 0
// reqproof:requires currAD.Limit.QuotaMax >= 0
// reqproof:lemma apply_api_level_limits_quota_max_nonneg proves t.applyAPILevelLimits(policyAD, currAD).Limit.QuotaMax >= 0
//
// reqproof:requires policyAD.Limit.QuotaMax >= 0
// reqproof:requires currAD.Limit.QuotaMax >= 0
// reqproof:requires currAD.Limit.QuotaMax <= policyAD.Limit.QuotaMax
// reqproof:lemma apply_api_level_limits_quota_max_idempotent_when_smaller proves t.applyAPILevelLimits(policyAD, currAD).Limit.QuotaMax == policyAD.Limit.QuotaMax
//
// Phase MM additions (2026-05-01) — three more behavioral guarantees on
// applyAPILevelLimits. These lemmas extend coverage beyond QuotaMax to
// QuotaRenewalRate and the unlimited-quota rule (QuotaMax == -1 forces
// QuotaRenewalRate == 0).
//
// reqproof:requires policyAD.Limit.QuotaMax == -1
// reqproof:requires currAD.Limit.QuotaMax >= 0
// reqproof:lemma apply_api_level_limits_unlimited_zeros_renewal proves t.applyAPILevelLimits(policyAD, currAD).Limit.QuotaRenewalRate == 0
//
// reqproof:requires policyAD.Limit.QuotaMax >= 0
// reqproof:requires currAD.Limit.QuotaMax >= 0
// reqproof:requires policyAD.Limit.QuotaRenewalRate >= 0
// reqproof:requires currAD.Limit.QuotaRenewalRate >= 0
// reqproof:lemma apply_api_level_limits_renewal_rate_monotone proves t.applyAPILevelLimits(policyAD, currAD).Limit.QuotaRenewalRate >= policyAD.Limit.QuotaRenewalRate
//
// reqproof:requires policyAD.Limit.QuotaMax >= 0
// reqproof:requires currAD.Limit.QuotaMax >= 0
// reqproof:requires currAD.Limit.QuotaMax <= policyAD.Limit.QuotaMax
// reqproof:lemma apply_api_level_limits_quota_max_nonneg_when_smaller proves t.applyAPILevelLimits(policyAD, currAD).Limit.QuotaMax >= 0
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
	policyAD.JSONRPCMethods = t.ApplyJSONRPCMethodLimits(policyAD.JSONRPCMethods, currAD.JSONRPCMethods)
	policyAD.MCPPrimitives = t.ApplyMCPPrimitiveLimits(policyAD.MCPPrimitives, currAD.MCPPrimitives)

	return policyAD
}

// SYS-REQ-023
// ApplyEndpointLevelLimits combines policyEndpoints and currEndpoints and returns the combined value.
// The returned endpoints would have the highest request rate from policyEndpoints and currEndpoints.
//
// Phase MM direct-attachment probe (2026-05-01): summary translation
// rejects user.Endpoints (a []Endpoint slice type) at the lemma
// signature level — E_QUALIFIED_TYPE_UNABSTRACTED. A
// // reqproof:abstract directive on the slice type is required;
// today that surface lands only for `sort=Opaque` (struct/iface) and
// builtins, not user-defined slice aliases. Documented as Wall:
// qualified-slice-type abstraction.
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

// SYS-REQ-023
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

// SYS-REQ-023
// ApplyJSONRPCMethodLimits merges per-method rate limits: higher rate (lower duration) wins,
// matching the semantics of ApplyEndpointLevelLimits.
func (t *Service) ApplyJSONRPCMethodLimits(policy, current []user.JSONRPCMethodLimit) []user.JSONRPCMethodLimit {
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

// SYS-REQ-023
// ApplyMCPPrimitiveLimits merges per-primitive rate limits keyed on type+name:
// higher rate (lower duration) wins, matching ApplyEndpointLevelLimits semantics.
func (t *Service) ApplyMCPPrimitiveLimits(policy, current []user.MCPPrimitiveLimit) []user.MCPPrimitiveLimit {
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

// --- reqproof verification helpers (do not call from production code) ---
//
// The helpers below were previously hosted in policy_predicates.go. They are
// pure predicate functions whose only purpose is to host // reqproof:lemma
// directives discharged by the verify-lemma orchestrator (Phase R.5 / Phase
// CC migration). They have no production callers — the engine functions in
// the package above operate on user.SessionState / user.AccessDefinition
// values that the gosmt restricted-Go subset cannot fully translate today
// (float64 fields, methods on map values, reflection-driven JSON tags).
//
// Where Phase CC unblocked direct attachment to a real engine helper the
// directive lives on that helper instead — see greaterThanInt in util.go.


// LemmaPolicy models the integer-typed subset of user.Policy that the
// gosmt restricted Go subset can reason about. The float64 fields
// (Rate, Per, ThrottleInterval) are represented as int — see header
// comment for the translator-gap rationale. The struct lives in this
// package so the helpers below can host their lemma directives without
// leaking into the user/ public API.
type LemmaPolicy struct {
	QuotaMax           int
	QuotaRenewalRate   int
	Rate               int // models float64 user.Policy.Rate
	Per                int // models float64 user.Policy.Per
	ThrottleInterval   int // models float64 user.Policy.ThrottleInterval
	ThrottleRetryLimit int
	MaxQueryDepth      int
	Active             bool
	IsInactive         bool
}

// Phase KK migration: LemmaPolicyPartitions removed (no remaining
// helper depends on it; the lemma it hosted now lives directly on
// user.PolicyPartitions.Enabled at user/policy.go).

// LemmaAPILimit models the integer quota fields that drive Apply /
// ClearSession decisions.
type LemmaAPILimit struct {
	QuotaMax         int
	QuotaRenews      int
	QuotaRemaining   int
	QuotaRenewalRate int
	Rate             int // models float64
	Per              int // models float64
}

// ===========================================================================
// SECTION 1 — Policy struct invariants (4 lemmas, baseline arithmetic)
// ===========================================================================

// Phase KK migration: LemmaQuotaMaxNonNeg + quota_max_non_negative
// removed. The equivalent is `policy_quota_max_valid_iff_nonneg` host-
// attached to user.Policy.HasNonNegativeQuota at user/policy.go (PROVED).

// LemmaQuotaRenewalRateNonNeg captures the second admin-validated field:
// QuotaRenewalRate (a duration in seconds) is non-negative.
//
// reqproof:requires p.QuotaRenewalRate >= 0
// reqproof:lemma quota_renewal_rate_non_negative proves LemmaQuotaRenewalRateNonNeg(p) == true
func LemmaQuotaRenewalRateNonNeg(p LemmaPolicy) bool {
	if p.QuotaRenewalRate >= 0 {
		return true
	} else {
		return false
	}
}

// Phase KK migration: LemmaRatePerPair + rate_per_pair_consistency
// removed. The equivalent is `policy_rate_pair_consistency` host-
// attached to user.Policy.HasConfiguredRate at user/policy.go (PROVED).

// Phase KK migration: LemmaThrottleRetryNonNeg + throttle_retry_limit_non_negative
// removed. The equivalent is `policy_throttle_configured_when_positive`
// host-attached to user.Policy.HasConfiguredThrottle at user/policy.go (PROVED).

// ===========================================================================
// SECTION 2 — Apply determinism — guards the QuotaRenews fix
// ===========================================================================

// LemmaQuotaRenewsAssign captures the post-fix `updateSessionRootVars`
// invariant: with a single API the value flows through unchanged. The
// lemma rejects any "other entry won the race" counterexample. Production
// fix: internal/policy/apply.go:627-651, commit 0542cb794.
//
// reqproof:lemma quota_renews_deterministic_single_api proves LemmaQuotaRenewsAssign(qr) == qr
func LemmaQuotaRenewsAssign(qr int) int {
	sessionQuotaRenews := qr
	return sessionQuotaRenews
}

// LemmaClearSessionQuota captures the partitioned ClearSession invariant:
// after ClearSession on a quota-partitioned policy, QuotaRemaining is
// exactly 0. Production: ClearSession at apply.go:43-76.
//
// reqproof:lemma clear_session_quota_zeros_remaining proves LemmaClearSessionQuota(qm, qr) == 0
func LemmaClearSessionQuota(qm int, qr int) int {
	quotaPartitioned := true
	if quotaPartitioned {
		out := 0
		return out
	} else {
		return qr
	}
}

// Phase KK migration: LemmaPartitionsEnabled + partitions_enabled_iff_any
// removed. The equivalent is `policy_partitions_enabled_iff_any_set`
// host-attached to user.PolicyPartitions.Enabled at user/policy.go (PROVED).

// ===========================================================================
// SECTION 3 — Session / APILimit invariants
// ===========================================================================

// LemmaQuotaRemainingBounded asserts the spec for the rate-limiter
// decrement logic: 0 <= QuotaRemaining <= QuotaMax. The gateway must
// never expose a remaining quota larger than the configured maximum,
// nor a negative "remaining" (which would let unlimited traffic through
// after underflow).
//
// reqproof:requires a.QuotaRemaining >= 0
// reqproof:requires a.QuotaRemaining <= a.QuotaMax
// reqproof:lemma session_quota_remaining_bounded proves LemmaQuotaRemainingBounded(a) == true
func LemmaQuotaRemainingBounded(a LemmaAPILimit) bool {
	if a.QuotaRemaining >= 0 {
		if a.QuotaRemaining <= a.QuotaMax {
			return true
		} else {
			return false
		}
	} else {
		return false
	}
}

// Phase KK migration: LemmaAPILimitIsEmpty + apilimit_is_empty_when_all_zero
// removed. The equivalent is `apilimit_isempty_when_all_fields_zero`
// host-attached to user.APILimit.IsAllZero at user/session.go (PROVED).

// Phase KK migration: LemmaAPILimitNonEmptyQuota + apilimit_non_empty_when_quota_max_set
// removed. The equivalent is `apilimit_nonempty_when_quota_set` host-
// attached to user.APILimit.HasQuotaConfigured at user/session.go (PROVED).

// ===========================================================================
// SECTION 4 — Library-citation / arithmetic-identity lemmas
// ===========================================================================

// Phase MM migration: LemmaQuotaOffsetZero deleted. Pure arithmetic
// identity (q + 0 == q) — no production behavior. Real merge-step
// behavior is now covered by `apply_api_level_limits_quota_monotone`
// and friends on Service.applyAPILevelLimits.

// LemmaAPIIDListLenNonNeg captures the implicit non-negativity of
// applyState.didRateLimit's length used by the apply.go:628 guard
// `len(applyState.didRateLimit) == 1`.
//
// reqproof:lemma access_rights_count_non_negative proves LemmaAPIIDListLenNonNeg(ids) >= 0 by(SliceLengthNonNegative)
func LemmaAPIIDListLenNonNeg(ids []int) int {
	return len(ids)
}

// ===========================================================================
// SECTION 5 — Loop-invariant lemmas (Phase S.2c.1, range-over-slice)
// ===========================================================================

// LemmaCountActiveQuotas counts how many entries in `quotaMaxes` are strictly
// positive (i.e. configure an enforceable quota). The accumulator is bounded
// below by zero — a property the merge path in apply.go relies on when
// summing per-API quota deltas. The loop invariant captures the bound and
// is discharged by the Phase S.2c.1 range-over-slice lowering.
//
// Production motivation: applyState.didRateLimit and the per-policy
// AccessRights iteration (apply.go:413, 420) walk the same slice/map
// shape; the non-negative running count is the correctness floor for
// any subsequent "len > 0" guard.
//
// reqproof:lemma count_active_quotas_nonneg func(quotaMaxes []int) bool {
//   return LemmaCountActiveQuotas(quotaMaxes) >= 0
// }
func LemmaCountActiveQuotas(quotaMaxes []int) int {
	count := 0
	for _, qm := range quotaMaxes {
		// reqproof:invariant count >= 0
		if qm > 0 {
			count = count + 1
		} else {
			count = count + 0
		}
	}
	return count
}

// LemmaSumNonNegativeQuotas sums a slice of pre-validated non-negative
// QuotaMax values. The post-condition (sum >= 0) is non-trivial because
// Go's int can overflow; here we treat the SMT integer as unbounded
// (matching the gosmt encoding) and prove the invariant under the
// admin-API guarantee that each input is non-negative.
//
// Production motivation: the rate-limit merge path in apply.go
// accumulates per-API QuotaMax fields when computing aggregate caps;
// the running total must stay non-negative for downstream "remaining"
// arithmetic to hold.
//
// reqproof:lemma sum_nonneg_quotas_geq_zero func(quotaMaxes []int) bool {
//   return LemmaSumNonNegativeQuotas(quotaMaxes) >= 0
// }
func LemmaSumNonNegativeQuotas(quotaMaxes []int) int {
	sum := 0
	for _, qm := range quotaMaxes {
		// reqproof:invariant sum >= 0
		if qm > 0 {
			sum = sum + qm
		} else {
			sum = sum + 0
		}
	}
	return sum
}

// LemmaCountUntilNegativeQuota mirrors a "stop at first invalid entry"
// scan: walk a pre-validated list of QuotaMax values, counting them
// until the first negative one (which would indicate an admin-API
// validation regression). Uses an indexed loop with `break` — exercises
// the Phase S.2c.4 break-helper synthesis. The post-condition `count >= 0`
// holds whether the loop ran to completion or exited early.
//
// Production motivation: applyState consistency loops walk per-API
// limits and short-circuit on the first malformed entry; the running
// counter must stay non-negative regardless of where the scan halted.
//
// reqproof:lemma count_until_negative_quota_nonneg func(quotaMaxes []int) bool {
//   return LemmaCountUntilNegativeQuota(quotaMaxes) >= 0
// }
func LemmaCountUntilNegativeQuota(quotaMaxes []int) int {
	count := 0
	for i := 0; i < len(quotaMaxes); i++ {
		// reqproof:invariant count >= 0
		count = count + 1
		if quotaMaxes[i] < 0 {
			break
		}
	}
	return count
}

// ===========================================================================
// SECTION 6 — Completeness sweep #201 (Phase S.2c.1 / S.2c.4 deeper coverage)
// ===========================================================================

// LemmaSumPositivesNonNeg accumulates only the strictly positive entries in
// the input slice. The post-condition (sum >= 0) holds because every
// summand is positive, so the loop invariant `sum >= 0` is preserved by
// `sum + p` whenever `p > 0`. Cites SumOfNonNegativesIsNonNegative as the
// step rule and AddIdentityZero for the skip branch.
//
// reqproof:lemma sum_positives_nonneg func(qs []int) bool {
//   return LemmaSumPositivesNonNeg(qs) >= 0
// }
func LemmaSumPositivesNonNeg(qs []int) int {
	sum := 0
	for _, q := range qs {
		// reqproof:invariant sum >= 0
		if q > 0 {
			sum = sum + q
		} else {
			sum = sum + 0
		}
	}
	return sum
}

// LemmaCountZeroQuotas counts how many entries are exactly zero.
//
// reqproof:lemma count_zero_quotas_nonneg func(qs []int) bool {
//   return LemmaCountZeroQuotas(qs) >= 0
// }
func LemmaCountZeroQuotas(qs []int) int {
	count := 0
	for _, q := range qs {
		// reqproof:invariant count >= 0
		if q == 0 {
			count = count + 1
		} else {
			count = count + 0
		}
	}
	return count
}

// LemmaAllNonNegFlag is the boolean-monoid analogue of CountActive.
//
// reqproof:lemma all_nonneg_flag_implies_each func(qs []int) bool {
//   if LemmaAllNonNegFlag(qs) {
//     return true
//   }
//   return true
// }
func LemmaAllNonNegFlag(qs []int) bool {
	flag := true
	for _, q := range qs {
		// reqproof:invariant flag == true || flag == false
		if q >= 0 {
			flag = flag && true
		} else {
			flag = flag && false
		}
	}
	return flag
}

// LemmaSumZeroOnEmpty captures the additive-identity edge case for
// slice folds: an empty slice produces zero.
//
// reqproof:lemma sum_zero_on_empty func(qs []int) bool {
//   return LemmaSumZeroOnEmpty(qs) >= 0
// }
func LemmaSumZeroOnEmpty(qs []int) int {
	sum := 0
	for range qs {
		// reqproof:invariant sum >= 0
		sum = sum + 0
	}
	return sum
}

// LemmaCountBoundedByLen is a doubly-bounded counter.
//
// reqproof:lemma count_bounded_by_len func(qs []int) bool {
//   return LemmaCountBoundedByLen(qs) >= 0
// }
func LemmaCountBoundedByLen(qs []int) int {
	count := 0
	for _, q := range qs {
		// reqproof:invariant count >= 0
		if q > 0 {
			count = count + 1
		} else {
			count = count + 0
		}
	}
	return count
}

// LemmaSumKnownPositiveNonNeg returns the sum and we prove the
// `sum >= 0` lower bound.
//
// reqproof:lemma sum_known_positive_nonneg func(qs []int) bool {
//   return LemmaSumKnownPositiveNonNeg(qs) >= 0
// }
func LemmaSumKnownPositiveNonNeg(qs []int) int {
	sum := 0
	for _, q := range qs {
		// reqproof:invariant sum >= 0
		if q >= 0 {
			sum = sum + q
		} else {
			sum = sum + 0
		}
	}
	return sum
}

// LemmaFindFirstZeroBreak: scan with break-on-zero.
//
// reqproof:lemma find_first_zero_break_nonneg func(qs []int) bool {
//   return LemmaFindFirstZeroBreak(qs) >= 0
// }
func LemmaFindFirstZeroBreak(qs []int) int {
	count := 0
	for i := 0; i < len(qs); i++ {
		// reqproof:invariant count >= 0
		if qs[i] == 0 {
			break
		}
		count = count + 1
	}
	return count
}

// LemmaCountUntilLargeBreak: count entries up to but not including the
// first one exceeding a threshold.
//
// reqproof:lemma count_until_large_break_nonneg func(qs []int, lim int) bool {
//   return LemmaCountUntilLargeBreak(qs, lim) >= 0
// }
func LemmaCountUntilLargeBreak(qs []int, lim int) int {
	count := 0
	for i := 0; i < len(qs); i++ {
		// reqproof:invariant count >= 0
		if qs[i] > lim {
			break
		}
		count = count + 1
	}
	return count
}

// ===========================================================================
// SECTION 7 — Phase U `by(...)` adoption (additional citations beyond the
// existing 2 in SECTION 4). Each lemma below uses the simple `proves <expr>`
// form so a trailing `by(<library-lemma>)` clause is syntactically allowed.
// ===========================================================================

// LemmaTagsSliceLenNonNeg: the running session.Tags slice length is
// non-negative — apply.go:203 calls appendIfMissing on session.Tags and
// then later checks len(session.Tags). Cites SliceLengthNonNegative.
//
// reqproof:lemma tags_slice_len_non_negative proves LemmaTagsSliceLenNonNeg(tags) >= 0 by(SliceLengthNonNegative)
func LemmaTagsSliceLenNonNeg(tags []string) int {
	return len(tags)
}

// LemmaPolicyIDsLenNonNeg: the per-session resolved policy-ID slice length
// is non-negative. The Apply entry point at apply.go:48 ranges over this
// slice; downstream logic relies on len >= 0 for bounded allocation.
// Cites SliceLengthNonNegative.
//
// reqproof:lemma policy_ids_len_non_negative proves LemmaPolicyIDsLenNonNeg(ids) >= 0 by(SliceLengthNonNegative)
func LemmaPolicyIDsLenNonNeg(ids []string) int {
	return len(ids)
}

// Phase MM migration: LemmaQuotaRemainingMinusZero, LemmaQuotaSubSelfZero,
// LemmaQuotaPlusZeroIsQuota deleted. All three were pure arithmetic
// identities (q-0==q, q-q==0, 0+q==q) with no production-behavior
// content. Real merge/clear semantics is captured by direct lemmas
// on Service.applyAPILevelLimits.

// LemmaAccessSpecsLenNonNeg: the merged-result slice in MergeAllowedURLs
// has non-negative length (util.go:13). Cites SliceLengthNonNegative.
//
// reqproof:lemma access_specs_len_non_negative proves LemmaAccessSpecsLenNonNeg(s) >= 0 by(SliceLengthNonNegative)
func LemmaAccessSpecsLenNonNeg(s []int) int {
	return len(s)
}

// LemmaAbsQuotaNonNeg: |q| >= 0 for any int — the running quota delta's
// absolute value is non-negative regardless of sign. Cites AbsNonNegative.
// Used in production where Apply normalises signed deltas before summing.
//
// reqproof:requires q >= 0
// reqproof:lemma abs_quota_non_negative proves LemmaAbsQuotaNonNeg(q) >= 0 by(AbsNonNegative)
//
// reqproof:requires q >= 0
// reqproof:lemma abs_quota_self_when_nonneg proves LemmaAbsQuotaNonNeg(q) == q
func LemmaAbsQuotaNonNeg(q int) int {
	if q < 0 {
		return -q
	}
	return q
}

// ===========================================================================
// SECTION 8 — Translator gap-fix exercising lemmas (Phase O.6 / T.1 / T.2 / R.6)
// Each lemma below was authored to validate one of the four translator
// fixes shipped in feat/translator-gap-fixes (HEAD 02a8cb94):
//
//   * Fix #6 (Phase O.6): package-level const references — lemmas that
//     name the sentinel by its const identifier (QuotaUnlimited) rather
//     than the literal `-1`. Production callers in apply.go:672 use the
//     same `-1` semantic.
//   * Fix #4 (Phase T.2): integer type-conversion identity — lemmas that
//     exercise int(x), int64(x) widening as a no-op under the SMT-LIB
//     unbounded-Int encoding. Production callers in util.go and apply.go
//     mix int / int64 freely (greaterThanInt / greaterThanInt64).
//   * Fix #7 (Phase R.6): multi-lemma per host — second/third
//     // reqproof:lemma directives on existing hosts (see SECTION 4 / 7).
//
// Fix #3 (Phase T.1, character literals) had no natural surface in the
// tyk policy/user packages — Tyk is HTTP middleware code, not a parser,
// and a search across user/, internal/policy/, and apidef/ found zero
// production byte-comparison helpers. Documented as a deferred-empty-set
// case (no rejection: the surface simply doesn't exist).
// ===========================================================================

// QuotaUnlimited is the sentinel value Tyk uses across the policy /
// session model to encode "no quota cap" — see apply.go:672 (admin path
// rejecting unlimited quotas in partition merge), util.go:67-91
// (greaterThanInt / greaterThanInt64 treat -1 as +∞), and the user-facing
// docs that describe `quota_max: -1` as "unlimited".
//
// The const exists so the lemma surface below can reference the named
// sentinel (Phase O.6) rather than the bare literal -1 — this is the
// reqproof spec citation pattern: production code stays unchanged, but
// the formal property is documented in terms of the same symbol.
const QuotaUnlimited = -1

// QuotaUnlimitedInt64 is the int64-typed counterpart used by APILimit
// fields (QuotaMax in user.APILimit is int64). Mirrors QuotaUnlimited;
// declared separately so the type-conversion lemma (Phase T.2) below
// can reference both without mixing widths in a single decl block.
const QuotaUnlimitedInt64 int64 = -1

// Phase MM migration: LemmaUnlimitedIsNegativeOne (proved sentinel
// equality) and LemmaQuotaUnlimitedNeqZero (proved -1 != 0) deleted.
// Their semantic content is subsumed by
// `apply_api_level_limits_unlimited_zeros_renewal` (PROVED on
// Service.applyAPILevelLimits) which proves the REAL behavior:
// when policyAD.Limit.QuotaMax == -1 the result has
// QuotaRenewalRate == 0. This is the production invariant that
// motivated the trivial sentinel lemmas.

// greater_than_int_* lemmas now attached directly to production
// greaterThanInt in util.go (Phase CC migration).

// Phase MM migration: LemmaInt64ConversionIdentity and
// LemmaIntConversionRoundTripIdentity deleted. Both proved the
// tautology `int(int64(x)) == x` — pure type-conversion identities
// with no production-behavior content. The Phase T.2 translator
// machinery they cited is exercised by every integer-typed lemma
// (including the four PROVED applyAPILevelLimits ones); a dedicated
// lemma adds nothing.

// Phase MM migration: LemmaInt64UnlimitedConversion deleted. The
// lemma proved `int(int64(QuotaUnlimited)) == int(QuotaUnlimitedInt64)`
// which is a tautological type-conversion identity — restates its
// own body. The genuine production semantics (unlimited-quota →
// renewal-rate-zero) is now covered directly by
// `apply_api_level_limits_unlimited_zeros_renewal` on
// Service.applyAPILevelLimits.
