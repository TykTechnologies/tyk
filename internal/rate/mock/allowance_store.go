package mock

import (
	"context"

	"github.com/TykTechnologies/tyk/internal/rate/model"
)

type AllowanceStore struct {
	Allowance *Allowance
	Err       error
}

func (m *AllowanceStore) Get(ctx context.Context, key string) (*Allowance, error) {
	return m.Allowance, m.Err
}

func (m *AllowanceStore) Set(ctx context.Context, key string, allowance *Allowance) error {
	m.Allowance = allowance
	return m.Err
}

func (m *AllowanceStore) Locker(key string) model.Locker {
	return &Locker{}
}

func (m *AllowanceStore) String() string {
	return "mock"
}

var _ model.AllowanceRepository = &AllowanceStore{}
