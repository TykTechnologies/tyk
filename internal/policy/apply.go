package policy

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/user"
)

// Repository is a storage encapsulating policy retrieval.
// Gateway implements this object to decouple this package.
type Repository interface {
	PolicyCount() int
	PolicyIDs() []string
	PolicyByID(string) (user.Policy, bool)
}

type Service struct {
	storage Repository
	logger  *logrus.Logger
}

func New(storage Repository, logger *logrus.Logger) *Service {
	return &Service{
		storage: storage,
		logger:  logger,
	}
}

// ClearSession clears the quota, rate limit and complexity values so that partitioned policies can apply their values.
// Otherwise, if the session has already a higher value, an applied policy will not win, and its values will be ignored.
func (t *Service) ClearSession(session *user.SessionState) {
	policies := session.PolicyIDs()
	for _, polID := range policies {
		policy, ok := t.storage.PolicyByID(polID)
		if !ok {
			continue
		}

		all := !(policy.Partitions.Quota || policy.Partitions.RateLimit || policy.Partitions.Acl || policy.Partitions.Complexity)

		if policy.Partitions.Quota || all {
			session.QuotaMax = 0
			session.QuotaRemaining = 0
		}

		if policy.Partitions.RateLimit || all {
			session.Rate = 0
			session.Per = 0
			session.ThrottleRetryLimit = 0
			session.ThrottleInterval = 0
		}

		if policy.Partitions.Complexity || all {
			session.MaxQueryDepth = 0
		}
	}
}

// ApplyPolicies will check if any policies are loaded. If any are, it
// will overwrite the session state to use the policy values.
func (t *Service) Apply(session *user.SessionState) error {
	rights := make(map[string]user.AccessDefinition)
	tags := make(map[string]bool)
	if session.MetaData == nil {
		session.MetaData = make(map[string]interface{})
	}

	t.ClearSession(session)

	didQuota, didRateLimit, didACL, didComplexity := make(map[string]bool), make(map[string]bool), make(map[string]bool), make(map[string]bool)

	var (
		err       error
		policyIDs []string
	)

	storage := t.storage
	customPolicies, err := session.CustomPolicies()
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

		/*if t.Spec != nil && policy.OrgID != t.Spec.OrgID {
			err := fmt.Errorf("attempting to apply policy from different organisation to key, skipping")
			t.Logger().Error(err)
			return err
		}*/

		if policy.Partitions.PerAPI &&
			(policy.Partitions.Quota || policy.Partitions.RateLimit || policy.Partitions.Acl || policy.Partitions.Complexity) {
			err := fmt.Errorf("cannot apply policy %s which has per_api and any of partitions set", policy.ID)
			t.logger.Error(err)
			return err
		}

		if policy.Partitions.PerAPI {
			for apiID, accessRights := range policy.AccessRights {
				// new logic when you can specify quota or rate in more than one policy but for different APIs
				if didQuota[apiID] || didRateLimit[apiID] || didACL[apiID] || didComplexity[apiID] { // no other partitions allowed
					err := fmt.Errorf("cannot apply multiple policies when some have per_api set and some are partitioned")
					t.logger.Error(err)
					return err
				}

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

				// overwrite session access right for this API
				rights[apiID] = accessRights

				// identify that limit for that API is set (to allow set it only once)
				didACL[apiID] = true
				didQuota[apiID] = true
				didRateLimit[apiID] = true
				didComplexity[apiID] = true
			}
		} else {
			usePartitions := policy.Partitions.Quota || policy.Partitions.RateLimit || policy.Partitions.Acl || policy.Partitions.Complexity

			for k, v := range policy.AccessRights {
				ar := v

				if !usePartitions || policy.Partitions.Acl {
					didACL[k] = true

					ar.AllowedURLs = copyAllowedURLs(v.AllowedURLs)

					// Merge ACLs for the same API
					if r, ok := rights[k]; ok {
						// If GQL introspection is disabled, keep that configuration.
						if v.DisableIntrospection {
							r.DisableIntrospection = v.DisableIntrospection
						}
						r.Versions = appendIfMissing(rights[k].Versions, v.Versions...)

						for _, u := range v.AllowedURLs {
							found := false
							for ai, au := range r.AllowedURLs {
								if u.URL == au.URL {
									found = true
									r.AllowedURLs[ai].Methods = appendIfMissing(au.Methods, u.Methods...)
								}
							}

							if !found {
								r.AllowedURLs = append(r.AllowedURLs, v.AllowedURLs...)
							}
						}

						for _, t := range v.RestrictedTypes {
							for ri, rt := range r.RestrictedTypes {
								if t.Name == rt.Name {
									r.RestrictedTypes[ri].Fields = intersection(rt.Fields, t.Fields)
								}
							}
						}

						for _, t := range v.AllowedTypes {
							for ri, rt := range r.AllowedTypes {
								if t.Name == rt.Name {
									r.AllowedTypes[ri].Fields = intersection(rt.Fields, t.Fields)
								}
							}
						}

						mergeFieldLimits := func(res *user.FieldLimits, new user.FieldLimits) {
							if greaterThanInt(new.MaxQueryDepth, res.MaxQueryDepth) {
								res.MaxQueryDepth = new.MaxQueryDepth
							}
						}

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

						ar = r
					}

					ar.Limit.SetBy = policy.ID
				}

				if !usePartitions || policy.Partitions.Quota {
					didQuota[k] = true
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
					didRateLimit[k] = true

					apiLimits := ar.Limit
					policyLimits := policy.APILimit()
					sessionLimits := session.APILimit()

					// Update Rate, Per and Smoothing
					if apiLimits.Less(policyLimits) {
						ar.Limit.Rate = policyLimits.Rate
						ar.Limit.Per = policyLimits.Per
						ar.Limit.Smoothing = policyLimits.Smoothing

						if sessionLimits.Less(policyLimits) {
							session.Rate = policyLimits.Rate
							session.Per = policyLimits.Per
							session.Smoothing = policyLimits.Smoothing
						}
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
					didComplexity[k] = true

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
		if !didACL[k] {
			delete(rights, k)
			continue
		}

		if !didRateLimit[k] {
			v.Limit.Rate = session.Rate
			v.Limit.Per = session.Per
			v.Limit.Smoothing = session.Smoothing
			v.Limit.ThrottleInterval = session.ThrottleInterval
			v.Limit.ThrottleRetryLimit = session.ThrottleRetryLimit
		}

		if !didComplexity[k] {
			v.Limit.MaxQueryDepth = session.MaxQueryDepth
		}

		if !didQuota[k] {
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
	if len(didQuota) == 1 && len(didRateLimit) == 1 && len(didComplexity) == 1 {
		for _, v := range rights {
			if len(didRateLimit) == 1 {
				session.Rate = v.Limit.Rate
				session.Per = v.Limit.Per
				session.Smoothing = v.Limit.Smoothing
			}

			if len(didQuota) == 1 {
				session.QuotaMax = v.Limit.QuotaMax
				session.QuotaRenews = v.Limit.QuotaRenews
				session.QuotaRenewalRate = v.Limit.QuotaRenewalRate
			}

			if len(didComplexity) == 1 {
				session.MaxQueryDepth = v.Limit.MaxQueryDepth
			}
		}
	}

	// Override session ACL if at least one policy define it
	if len(didACL) > 0 {
		session.AccessRights = rights
	}

	return nil
}

func (t *Service) Logger() *logrus.Logger {
	return t.logger
}
