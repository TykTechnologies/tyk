package healthcheck

import (
	"context"
)

// FakeCheck is provided for tests. It returns whatever name and
// error you pass to the object.
type FakeCheck struct {
	name string
	err  error
}

// NewFakeCheck creates a new instance of FakeCheck.
func NewFakeCheck(name string, err error) FakeCheck {
	return FakeCheck{
		name: name,
		err:  err,
	}
}

// Name returns the name of the check.
func (f FakeCheck) Name() string {
	return f.name
}

// Result returns the result of the check.
func (f FakeCheck) Result(_ context.Context) error {
	return f.err
}
