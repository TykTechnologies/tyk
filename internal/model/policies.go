package model

import (
	"sync"

	persistentmodel "github.com/TykTechnologies/storage/persistent/model"
	"github.com/TykTechnologies/tyk/pkg/errpack"
	"github.com/TykTechnologies/tyk/user"
	"github.com/samber/lo"
	"golang.org/x/exp/maps"
)

var (
	_ PolicyProvider = new(Policies)

	// ErrPolicyNotFound unable to find policy with given id
	ErrPolicyNotFound = errpack.New("policy not found", errpack.WithType(errpack.TypeNotFound))

	// ErrAmbiguousState represents error when org_id is required to determinate policy
	ErrAmbiguousState = errpack.New("ambiguous state", errpack.WithType(errpack.TypeNotFound))

	// ErrUnreachable represents unreachable case
	ErrUnreachable = errpack.New("unreachable", errpack.WithType(errpack.BrokenInvariant))
)

type (
	PolicySetOpt func(*Policies)

	Policies struct {
		mu                sync.RWMutex
		policies          map[persistentmodel.ObjectID]user.Policy
		policiesCustomKey map[customKey]map[orgId]user.Policy
		onCollision       CollisionCb
		onBrokenPolicy    BrokenPolicyCb
		once              sync.Once
	}

	CollisionCb    func(oldEntry, newEntry *user.Policy)
	BrokenPolicyCb func(*user.Policy)

	customKey string
	orgId     string
)

func (p *Policies) init() {
	p.once.Do(func() {
		p.policies = make(map[persistentmodel.ObjectID]user.Policy)
		p.policiesCustomKey = make(map[customKey]map[orgId]user.Policy)
		p.onCollision = collisionNoop
		p.onBrokenPolicy = brokenPolicyNoop
	})
}

func NewPolicies(opts ...PolicySetOpt) *Policies {
	var set Policies
	set.init()

	for _, apply := range opts {
		apply(&set)
	}

	return &set
}

func WithCollisionCb(cb CollisionCb) PolicySetOpt {
	return func(s *Policies) {
		s.onCollision = cb
	}
}

func (p *Policies) PolicyCount() int {
	p.init()
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.policies)
}

func (p *Policies) AsSlice() []user.Policy {
	p.init()
	p.mu.RLock()
	defer p.mu.RUnlock()
	return maps.Values(p.policies)
}

func (p *Policies) PolicyIDs() []PolicyID {
	p.init()
	p.mu.RLock()
	defer p.mu.RUnlock()

	return lo.Map(maps.Keys(p.policies), func(oid persistentmodel.ObjectID, _ int) PolicyID {
		return NonScopedPolicyId(oid.Hex())
	})
}

func (p *Policies) PolicyByID(id PolicyID) (user.Policy, bool) {
	p.init()
	p.mu.RLock()
	defer p.mu.RUnlock()

	if pol, err := p.policyByIdExtended(id); err == nil {
		return pol, true
	}

	return user.Policy{}, false
}

func (p *Policies) PolicyByIdExtended(id PolicyID) (user.Policy, error) {
	p.init()
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.policyByIdExtended(id)
}

func (p *Policies) policyByIdExtended(id PolicyID) (user.Policy, error) {
	switch id := id.(type) {
	case ScopedPolicyId:
		polMap, ok := p.policiesCustomKey[id.customKey()]
		if !ok {
			return user.Policy{}, ErrPolicyNotFound
		}

		if pol, ok := polMap[orgId(id.orgId)]; ok {
			return pol, nil
		}

		// fallback strategy
		dbId := persistentmodel.ObjectID(id.id)
		if !dbId.Valid() {
			return user.Policy{}, ErrPolicyNotFound
		}

		if policy, ok := p.policies[dbId]; ok && policy.OrgID == id.orgId {
			return policy, nil
		}

		return user.Policy{}, ErrPolicyNotFound

	case NonScopedPolicyId:
		ckSet, ok := p.policiesCustomKey[customKey(id)]
		switch {
		case !ok:
			if pol, ok := p.policies[persistentmodel.ObjectID(id)]; ok {
				return pol, nil
			}

			return user.Policy{}, ErrPolicyNotFound
		case len(ckSet) == 0:
			return user.Policy{}, ErrUnreachable
		case len(ckSet) == 1:
			return lo.FirstOrEmpty(maps.Values(ckSet)), nil
		default:
			return user.Policy{}, ErrAmbiguousState
		}
	default:
		return user.Policy{}, ErrUnreachable
	}
}

func (p *Policies) DeleteById(id PolicyID) bool {
	pol, err := p.PolicyByIdExtended(id)
	if err != nil {
		return false
	}

	p.unloadOne(&pol)
	return true
}

func (p *Policies) Load(policies ...user.Policy) {
	for _, pol := range policies {
		p.loadOne(&pol)
	}
}

func (p *Policies) unloadOne(pol *user.Policy) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.policies, pol.MID)
	ckSet, ok := p.policiesCustomKey[customKey(pol.ID)]

	if !ok {
		return
	}

	delete(ckSet, orgId(pol.OrgID))

	if len(ckSet) == 0 {
		delete(p.policiesCustomKey, customKey(pol.ID))
	}
}

func (p *Policies) loadOne(pol *user.Policy) {
	if !EnsurePolicyId(pol) {
		p.onBrokenPolicy(pol)
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.policies[pol.MID] = *pol
	key := customKey(pol.ID)

	set, ok := p.policiesCustomKey[key]
	if !ok {
		set = make(map[orgId]user.Policy)
	}

	if existent, ok := set[orgId(pol.OrgID)]; ok && existent.ID != pol.ID {
		p.onCollision(&existent, pol)
	}

	set[orgId(pol.OrgID)] = *pol
	p.policiesCustomKey[key] = set
}

func collisionNoop(_, _ *user.Policy) {}

func brokenPolicyNoop(_ *user.Policy) {}

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
