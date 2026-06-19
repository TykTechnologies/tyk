package mock

import (
	"context"

	"github.com/TykTechnologies/tyk/internal/rate/model"
)

type AllowanceStore struct {
	Allowance   *Allowance
	Allowances  []*Allowance
	Err         error
	GetErr      error
	GetErrs     []error
	SetErr      error
	LockErr     error
	GetCalls    int
	SetCalls    int
	LockerCalls int
}

func (m *AllowanceStore) Get(ctx context.Context, key string) (*Allowance, error) {
	m.GetCalls++
	if m.Err != nil {
		return nil, m.Err
	}
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	if len(m.GetErrs) > 0 {
		err := m.GetErrs[0]
		m.GetErrs = m.GetErrs[1:]
		if err != nil {
			return nil, err
		}
	}
	if len(m.Allowances) > 0 {
		allowance := m.Allowances[0]
		m.Allowances = m.Allowances[1:]
		return allowance, nil
	}
	return m.Allowance, nil
}

func (m *AllowanceStore) Set(ctx context.Context, key string, allowance *Allowance) error {
	m.SetCalls++
	if m.Err != nil {
		return m.Err
	}
	if m.SetErr != nil {
		return m.SetErr
	}
	m.Allowance = allowance
	return nil
}

func (m *AllowanceStore) Locker(key string) model.Locker {
	m.LockerCalls++
	return &Locker{Err: m.LockErr}
}

func (m *AllowanceStore) String() string {
	return "mock"
}

var _ model.AllowanceRepository = &AllowanceStore{}
