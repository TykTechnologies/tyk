package result_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/TykTechnologies/tyk/internal/result"
)

type ResultTestSuite struct {
	suite.Suite
	errSample error
}

func (s *ResultTestSuite) SetupTest() {
	s.errSample = errors.New("something went wrong")
}

func TestResultTestSuite(t *testing.T) {
	suite.Run(t, new(ResultTestSuite))
}

func (s *ResultTestSuite) TestNew() {
	s.Run("Given a value and a nil error", func() {
		// When constructing via New
		res := result.New(100, nil)

		// Then it behaves as a successful Result
		s.True(res.IsOk())
		s.False(res.IsError())

		val, err := res.Get()
		s.NoError(err)
		s.Equal(100, val)
	})

	s.Run("Given a zero value and a non-nil error", func() {
		// When constructing via New
		res := result.New(0, s.errSample)

		// Then it behaves as a failed Result
		s.False(res.IsOk())
		s.True(res.IsError())

		val, err := res.Get()
		s.ErrorIs(err, s.errSample)
		s.Zero(val)
	})
}

func (s *ResultTestSuite) TestOk() {
	s.Run("Given an Ok Result created with a value", func() {
		// When initializing an Ok result
		res := result.Ok("gopher")

		// Then status flags should indicate success
		s.True(res.IsOk())
		s.False(res.IsError())

		// And value should be accessible directly
		s.Equal("gopher", res.MustGet())
	})
}

func (s *ResultTestSuite) TestMustErr() {
	s.Run("Given a valid error instance", func() {
		// When creating an Err result
		res := result.MustErr[string](s.errSample)

		// Then status flags should indicate failure
		s.False(res.IsOk())
		s.True(res.IsError())

		// And retrieving value with MustGet should panic
		s.PanicsWithValue(s.errSample, func() {
			_ = res.MustGet()
		})
	})

	s.Run("Given a nil error passed to Err constructor", func() {
		// Then it must immediately panic to prevent inconsistent state
		s.PanicsWithValue(result.ErrNilError, func() {
			_ = result.MustErr[int](nil)
		})
	})
}

func (s *ResultTestSuite) TestErr() {
	s.Run("Given a valid error instance", func() {
		// When creating an Err result
		res := result.Err[string](s.errSample)

		// Then status flags should indicate failure
		s.False(res.IsOk())
		s.True(res.IsError())

		// And retrieving value with MustGet should panic
		s.PanicsWithValue(s.errSample, func() {
			_ = res.MustGet()
		})
	})

	s.Run("Given a nil error passed to Err constructor", func() {
		res := result.Err[int](nil)
		s.Assert().True(res.IsError())
		s.Assert().ErrorIs(res.Err(), result.ErrNilError)
	})
}

func (s *ResultTestSuite) TestGetOr() {
	s.Run("Given a successful Result", func() {
		res := result.Ok("actual value")

		// When calling GetOr with a fallback value
		val := res.GetOr("fallback")

		// Then the original value must be returned
		s.Equal("actual value", val)
	})

	s.Run("Given a failed Result", func() {
		res := result.Err[string](s.errSample)

		// When calling GetOr with a fallback value
		val := res.GetOr("fallback")

		// Then the fallback value must be returned
		s.Equal("fallback", val)
	})
}

func (s *ResultTestSuite) TestErrMethod() {
	s.Run("Given a failed Result", func() {
		res := result.Err[int](s.errSample)

		// When retrieving the error details
		err := res.Err()

		// Then error and flag should reflect the failure state
		s.ErrorIs(err, s.errSample)
	})

	s.Run("Given a successful Result", func() {
		res := result.Ok(42)

		// When retrieving the error details
		err := res.Err()
		s.NoError(err)
	})
}

func (s *ResultTestSuite) TestValueReceiverDirectInvocations() {
	s.Run("Given functions returning Result by value", func() {
		// When chaining calls directly on unaddressable return values
		val := result.Ok(2026).MustGet()
		fallback := result.Err[int](s.errSample).GetOr(999)

		// Then operations succeed without intermediate addressable variables
		s.Equal(2026, val)
		s.Equal(999, fallback)
	})
}
