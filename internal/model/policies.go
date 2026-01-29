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

	// ErrUnreachable represents unreachable case
	ErrUnreachable = errpack.New("unreachable", errpack.WithType(errpack.BrokenInvariant))
)

type (
	PolicySetOpt func(*Policies)

	Policies struct {
		policySet
		callbacks
		mu   sync.RWMutex
		once sync.Once
	}
	BrokenPolicyCb      func(*user.Policy)
	InternalCollisionCb func(_ string, ids []persistentmodel.ObjectID)

	customKey       string
	scopedCustomKey struct {
		id  string
		org string
	}

	callbacks struct {
		onBrokenPolicy      BrokenPolicyCb
		onInternalCollision InternalCollisionCb
	}

	policySet struct {
		callbacks
		policiesScoped map[scopedCustomKey]user.Policy
		policies       map[customKey]user.Policy
	}

	policyCollisions struct {
		data map[customKey]map[persistentmodel.ObjectID]struct{}
		once sync.Once
	}
)

func (p *Policies) init() {
	p.once.Do(func() {
		p.initDefaultCallbacks()
		p.policySet = newPolicySet(0, p.callbacks)
	})
}

func (p *Policies) initDefaultCallbacks() {
	p.onBrokenPolicy = brokenPolicyNoop
	p.onInternalCollision = internalCollisionCb
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

// WithLoadFail sets callback for invalid policies.
// Callback will be called when found invalid policy to load.
func WithLoadFail(cb BrokenPolicyCb) PolicySetOpt {
	return func(s *Policies) {
		s.onBrokenPolicy = cb
	}
}

func WithInternalCollision(cb InternalCollisionCb) PolicySetOpt {
	return func(s *Policies) {
		s.onInternalCollision = cb
	}
}

func (p *Policies) PolicyCount() int {
	p.init()
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.policiesScoped)
}

func (p *Policies) AsSlice() []user.Policy {
	p.init()
	p.mu.RLock()
	defer p.mu.RUnlock()
	return maps.Values(p.policiesScoped)
}

func (p *Policies) PolicyIDs() []PolicyID {
	p.init()
	p.mu.RLock()
	defer p.mu.RUnlock()

	return lo.MapToSlice(p.policiesScoped, func(_ scopedCustomKey, pol user.Policy) PolicyID {
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

func (p *Policies) Add(policies ...user.Policy) {
	p.init()
	p.mu.Lock()
	defer p.mu.Unlock()

	var collision policyCollisions

	for _, pol := range policies {
		p.loadOne(&pol, &collision)
	}

	collision.Emit(p.onInternalCollision)
}

func (p *Policies) Reload(policies ...user.Policy) {
	p.init()

	set := newPolicySet(len(policies), p.callbacks)
	var collision policyCollisions

	for _, pol := range policies {
		set.loadOne(&pol, &collision)
	}

	collision.Emit(p.onInternalCollision)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.policySet = set
}

func (p *Policies) policyByIdExtended(id PolicyID) (user.Policy, error) {
	switch id := id.(type) {
	case ScopedCustomPolicyId:
		if pol, ok := p.policiesScoped[scopedCustomKey{id: id.id, org: id.orgId}]; ok {
			return pol, nil
		}

		return user.Policy{}, ErrPolicyNotFound
	case NonScopedLastInsertedPolicyId:
		pol, ok := p.policies[customKey(id)]

		if !ok {
			return user.Policy{}, ErrPolicyNotFound
		}

		return pol, nil

	default:
		return user.Policy{}, ErrUnreachable
	}
}

func brokenPolicyNoop(_ *user.Policy) {}

func internalCollisionCb(_ string, _ []persistentmodel.ObjectID) {}

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

func newPolicySet(
	capacity int,
	callbacksSet callbacks,
) policySet {
	return policySet{
		callbacks:      callbacksSet,
		policies:       make(map[customKey]user.Policy, capacity),
		policiesScoped: make(map[scopedCustomKey]user.Policy, capacity),
	}
}

func (p *policySet) loadOne(
	pol *user.Policy,
	collisions *policyCollisions,
) {
	if !EnsurePolicyId(pol) {
		p.onBrokenPolicy(pol)
		return
	}

	sck := scopedCustomKey{id: pol.ID, org: pol.OrgID}
	ck := customKey(pol.ID)
	if old, ok := p.policiesScoped[sck]; ok && old.MID != pol.MID {
		collisions.Add(ck, old.MID)
		collisions.Add(ck, pol.MID)
	}

	p.policiesScoped[sck] = *pol
	p.policies[ck] = *pol
}

func (p *policySet) unloadOne(pol *user.Policy) {
	delete(p.policiesScoped, scopedCustomKey{id: pol.ID, org: pol.OrgID})
	delete(p.policies, customKey(pol.ID))
}

func (pc *policyCollisions) init() {
	pc.once.Do(func() {
		pc.data = make(map[customKey]map[persistentmodel.ObjectID]struct{})
	})
}

func (pc *policyCollisions) Emit(emitter InternalCollisionCb) {
	pc.init()

	for key, dbIdsSet := range pc.data {
		emitter(string(key), maps.Keys(dbIdsSet))
	}
}

func (pc *policyCollisions) Add(key customKey, dbId persistentmodel.ObjectID) {
	pc.init()

	set, ok := pc.data[key]
	if !ok {
		set = make(map[persistentmodel.ObjectID]struct{})
	}

	set[dbId] = struct{}{}
	pc.data[key] = set
}
