package oas

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestTrackEndpoint_Fill(t *testing.T) {
	var (
		enabled  = apidef.TrackEndpointMeta{Disabled: false}
		disabled = apidef.TrackEndpointMeta{Disabled: true}

		wantEnabled  = TrackEndpoint{Enabled: true}
		wantDisabled = TrackEndpoint{Enabled: false}
	)

	var got TrackEndpoint

	got = TrackEndpoint{}
	got.Fill(enabled)
	assert.Equal(t, wantEnabled, got)

	got = TrackEndpoint{}
	got.Fill(disabled)
	assert.Equal(t, wantDisabled, got)
}

func TestTrackEndpoint_ExtractTo(t *testing.T) {
	var (
		wantEnabled  = apidef.TrackEndpointMeta{Disabled: false}
		wantDisabled = apidef.TrackEndpointMeta{Disabled: true}

		enabled  = TrackEndpoint{Enabled: true}
		disabled = TrackEndpoint{Enabled: false}
	)

	var got apidef.TrackEndpointMeta

	got = apidef.TrackEndpointMeta{}
	enabled.ExtractTo(&got)
	assert.Equal(t, wantEnabled, got)

	got = apidef.TrackEndpointMeta{}
	disabled.ExtractTo(&got)
	assert.Equal(t, wantDisabled, got)
}
