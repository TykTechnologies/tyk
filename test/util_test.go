package test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCI(t *testing.T) {
	t.Parallel()

	envVar := os.Getenv("CI")
	if envVar != "" {
		assert.True(t, CI())
	} else {
		assert.False(t, CI())
	}
}

func TestSkipping(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		title string
		run   func(func(...interface{}))
	}{
		{
			"flaky tests",
			func(skip func(...interface{})) {
				Flaky(t, func() (bool, func(...interface{})) {
					// ci=true, skip= test replacement of t.Skip
					return true, skip
				})
			},
		},
		{
			"racy tests",
			func(skip func(...interface{})) {
				Racy(t, func() (bool, func(...interface{})) {
					// ci=true, skip= test replacement of t.Skip
					return true, skip
				})
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()

			skipped := false
			skip := func(...interface{}) {
				skipped = true
			}

			tc.run(skip)

			assert.True(t, skipped)
		})
	}
}
