package model

import (
	"fmt"
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
		// Bad old approach. better to get rid of it, because of it provide UB
		// It's left here just for backward compatibility
		policiesCustomKeyToObjectID map[customKey]persistentmodel.ObjectID
		onCollision                 CollisionCb
		onBrokenPolicy              BrokenPolicyCb
		onMultiTenantCollision      MultiTenantCollisionCb
		once                        sync.Once
	}

	CollisionCb            func(oldEntry, newEntry *user.Policy)
	BrokenPolicyCb         func(*user.Policy)
	MultiTenantCollisionCb func(customId string, dbIds []persistentmodel.ObjectID)

	customKey string
	orgId     string
)

func (p *Policies) init() {
	p.once.Do(func() {
		p.reset()
		p.initDefaultCallbacks()
	})
}

func (p *Policies) initDefaultCallbacks() {
	p.onCollision = collisionNoop
	p.onBrokenPolicy = brokenPolicyNoop
	p.onMultiTenantCollision = multiTenantCollisionNoop
}

func (p *Policies) reset() {
	p.policies = make(map[persistentmodel.ObjectID]user.Policy)
	p.policiesCustomKey = make(map[customKey]map[orgId]user.Policy)
	p.policiesCustomKeyToObjectID = make(map[customKey]persistentmodel.ObjectID)
}

func NewPolicies(opts ...PolicySetOpt) *Policies {
	var set Policies
	set.init()

	for _, apply := range opts {
		apply(&set)
	}

	return &set
}

func WithCombined(opts ...PolicySetOpt) PolicySetOpt {
	return func(s *Policies) {
		for _, apply := range opts {
			apply(s)
		}
	}
}

func WithCollisionCb(cb CollisionCb) PolicySetOpt {
	return func(s *Policies) {
		s.onCollision = cb
	}
}

func WithLoadFail(cb BrokenPolicyCb) PolicySetOpt {
	return func(s *Policies) {
		s.onBrokenPolicy = cb
	}
}

func WithCollisionMultiTenant(cb MultiTenantCollisionCb) PolicySetOpt {
	return func(s *Policies) {
		s.onMultiTenantCollision = cb
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

	return lo.MapToSlice(p.policies, func(_ persistentmodel.ObjectID, pol user.Policy) PolicyID {
		return NewScopedCustomPolicyId(pol.OrgID, pol.ID)
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

func (p *Policies) DeleteById(id PolicyID) bool {
	p.init()
	pol, err := p.PolicyByIdExtended(id)
	if err != nil {
		return false
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.unloadOne(&pol)
	return true
}

func (p *Policies) Load(policies ...user.Policy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reset()

	for _, pol := range policies {
		p.loadOne(&pol)
	}

	p.emitMultiTenancyCollisions()

}

func (p *Policies) emitMultiTenancyCollisions() {
	for id, set := range p.policiesCustomKey {
		if len(set) == 1 {
			continue
		}

		p.onMultiTenantCollision(
			string(id),
			lo.Map(lo.Values(set), func(item user.Policy, _ int) persistentmodel.ObjectID {
				return item.MID
			}),
		)
	}
}

func (p *Policies) policyByIdExtended(id PolicyID) (user.Policy, error) {
	switch id := id.(type) {
	case ScopedCustomPolicyId:
		polMap, ok := p.policiesCustomKey[id.customKey()]
		if !ok {
			return user.Policy{}, ErrPolicyNotFound
		}

		if pol, ok := polMap[orgId(id.orgId)]; ok {
			return pol, nil
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
			return user.Policy{}, fmt.Errorf(
				"more than one policct with id %s was found: %w",
				id, ErrAmbiguousState,
			)
		}
	case NonScopedLastInsertedPolicyId:
		oid, ok := p.policiesCustomKeyToObjectID[customKey(id)]

		if !ok {
			return user.Policy{}, ErrPolicyNotFound
		}

		pol, ok := p.policies[oid]

		if !ok {
			return user.Policy{}, ErrPolicyNotFound
		}

		return pol, nil

	default:
		return user.Policy{}, ErrUnreachable
	}
}

func (p *Policies) unloadOne(pol *user.Policy) {
	delete(p.policies, pol.MID)
	ckSet, ok := p.policiesCustomKey[customKey(pol.ID)]

	if !ok {
		return
	}

	delete(ckSet, orgId(pol.OrgID))

	if len(ckSet) == 0 {
		delete(p.policiesCustomKey, customKey(pol.ID))
	}

	delete(p.policiesCustomKeyToObjectID, customKey(pol.ID))
}

func (p *Policies) loadOne(pol *user.Policy) {
	if !EnsurePolicyId(pol) {
		p.onBrokenPolicy(pol)
		return
	}

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
	p.policiesCustomKeyToObjectID[customKey(pol.ID)] = pol.MID
}

func collisionNoop(_, _ *user.Policy) {}

func brokenPolicyNoop(_ *user.Policy) {}

func multiTenantCollisionNoop(_ string, _ []persistentmodel.ObjectID) {}

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
