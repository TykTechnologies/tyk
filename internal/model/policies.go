package model

import (
	"sync"

	"github.com/TykTechnologies/tyk/user"
	"golang.org/x/exp/maps"
)

type (
	// Policies
	// set of policies loaded into memory
	Policies interface {
		PolicyProvider
		Load(...user.Policy)
		AsSlice() []user.Policy
		DeleteById(id string) bool
	}

	PolicySetOpt func(*policySet)

	policySet struct {
		mu                sync.RWMutex
		policies          map[string]user.Policy
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

func NewPolicies(opts ...PolicySetOpt) Policies {
	var set = &policySet{
		onCollision:    collisionNoop,
		onBrokenPolicy: brokenPolicyNoop,
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

func (p *policySet) PolicyIDs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return maps.Keys(p.policies)
}

func (p *policySet) PolicyByID(id string) (user.Policy, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	policy, ok := p.policies[id]
	return policy, ok
}

func (p *policySet) DeleteById(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	policy, ok := p.policies[id]

	if !ok {
		return false
	}

	delete(p.policies, id)
	delete(p.policiesCustomKey, newCustomKey(&policy))

	return true
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

	p.policies[pol.ID] = *pol
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
