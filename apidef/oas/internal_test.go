package oas

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestInternal_Fill(t *testing.T) {
	var (
		enabled  = apidef.InternalMeta{Disabled: false}
		disabled = apidef.InternalMeta{Disabled: true}

		wantEnabled  = Internal{Enabled: true}
		wantDisabled = Internal{Enabled: false}
	)

	var got Internal

	got = Internal{}
	got.Fill(enabled)
	assert.Equal(t, wantEnabled, got)

	got = Internal{}
	got.Fill(disabled)
	assert.Equal(t, wantDisabled, got)
}

func TestInternal_ExtractTo(t *testing.T) {
	var (
		wantEnabled  = apidef.InternalMeta{Disabled: false}
		wantDisabled = apidef.InternalMeta{Disabled: true}

		enabled  = Internal{Enabled: true}
		disabled = Internal{Enabled: false}
	)

	var got apidef.InternalMeta

	got = apidef.InternalMeta{}
	enabled.ExtractTo(&got)
	assert.Equal(t, wantEnabled, got)

	got = apidef.InternalMeta{}
	disabled.ExtractTo(&got)
	assert.Equal(t, wantDisabled, got)
}
