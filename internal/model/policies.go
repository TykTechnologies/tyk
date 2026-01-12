package model

import (
	"sync"

	"github.com/TykTechnologies/tyk/user"
	"github.com/samber/lo"
	"golang.org/x/exp/maps"
)

type (
	// Policies
	// set of policies loaded into memory
	Policies interface {
		PolicyProvider
		Load(...user.Policy)
		AsSlice() []user.Policy
		DeleteById(PolicyID) bool
	}

	PolicySetOpt func(*policySet)

	policySet struct {
		mu                sync.RWMutex
		policies          map[PolicyDbId]user.Policy
		policiesCustomKey map[customKey]user.Policy
		onCollision       CollisionCb
		onBrokenPolicy    BrokenPolicyCb
	}
	CollisionCb    func(oldEntry, newEntry *user.Policy)
	BrokenPolicyCb func(*user.Policy)

	customKey struct {
		orgId string
		id    string
	}
)

var (
	_ Policies = new(policySet)
)

func NewPolicies(opts ...PolicySetOpt) Policies {
	var set = &policySet{
		policies:          make(map[PolicyDbId]user.Policy),
		policiesCustomKey: make(map[customKey]user.Policy),
		onCollision:       collisionNoop,
		onBrokenPolicy:    brokenPolicyNoop,
	}

	for _, apply := range opts {
		apply(set)
	}

	return set
}

func WithCollisionCb(cb CollisionCb) PolicySetOpt {
	return func(s *policySet) {
		s.onCollision = cb
	}
}

func (p *policySet) PolicyCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.policies)
}

func (p *policySet) AsSlice() []user.Policy {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return maps.Values(p.policies)
}

func (p *policySet) PolicyIDs() []PolicyID {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return lo.Map(maps.Keys(p.policies), func(pol PolicyDbId, _ int) PolicyID {
		return pol
	})
}

func (p *policySet) PolicyByID(id PolicyID) (user.Policy, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	switch id := id.(type) {
	case AnyPolicyId:
		if policy, ok := p.policiesCustomKey[id.customKey()]; ok {
			return policy, true
		}

		// fallback strategy
		dbId := PolicyDbId(id.id)

		if !dbId.objectID().Valid() {
			return user.Policy{}, false
		}

		if policy, ok := p.policies[dbId]; ok && policy.OrgID == id.orgId {
			return policy, true
		}

		return user.Policy{}, false
	case PolicyDbId:
		policy, ok := p.policies[id]
		return policy, ok

	default:
		panic("expected unreachable")
	}
}

func (p *policySet) DeleteById(id PolicyID) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	switch id := id.(type) {
	case PolicyDbId:
		pol, ok := p.policies[id]

		if ok {
			delete(p.policies, id)
			delete(p.policiesCustomKey, newCustomKey(&pol))
		}

		return ok
	case AnyPolicyId:
		pol, ok := p.policiesCustomKey[id.customKey()]

		if ok {
			delete(p.policiesCustomKey, id.customKey())
			delete(p.policies, PolicyDbId(pol.MID))
		}

		return ok
	default:
		panic("expected unreachable")
	}
}

func (p *policySet) Load(policies ...user.Policy) {
	for _, pol := range policies {
		p.loadOne(&pol)
	}
}

func (p *policySet) loadOne(pol *user.Policy) {
	if !EnsurePolicyId(pol) {
		p.onBrokenPolicy(pol)
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.policies[PolicyDbId(pol.MID)] = *pol

	key := newCustomKey(pol)
	if oldPol, ok := p.policiesCustomKey[key]; ok {
		if oldPol.MID != pol.MID {
			p.onCollision(&oldPol, pol)
		}
	}

	p.policiesCustomKey[key] = *pol
}

func collisionNoop(_, _ *user.Policy) {}

func brokenPolicyNoop(_ *user.Policy) {}

func newCustomKey(pol *user.Policy) customKey {
	return customKey{
		orgId: pol.OrgID,
		id:    pol.MID.Hex(),
	}
}

// EnsurePolicyId ensures ID field exists
// should be removed after migrate
func EnsurePolicyId(policy *user.Policy) bool {
	if policy == nil {
		return false
	}

	if policy.ID != "" {
		return true
	}

	if !policy.MID.Valid() {
		return false
	}

	policy.ID = policy.MID.Hex()
	return true
}
