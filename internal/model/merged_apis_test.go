package model_test

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/model"
)

// Verifies: SYS-REQ-080 [boundary]
// SYS-REQ-080:nominal:nominal
// SYS-REQ-080:boundary:nominal
// SYS-REQ-080:determinism:nominal
// MCDC SYS-REQ-080: api_list_requested=T, api_list_result_returned=F => FALSE
// MCDC SYS-REQ-080: api_list_requested=T, api_list_result_returned=T => TRUE
func TestMergedAPIList_Filter(t *testing.T) {
	untagged := model.MergedAPI{APIDefinition: &apidef.APIDefinition{APIID: "untagged"}}
	disabled := model.MergedAPI{APIDefinition: &apidef.APIDefinition{APIID: "disabled", Tags: []string{"team-a"}, TagsDisabled: true}}
	matchingOAS := &oas.OAS{}
	matching := model.MergedAPI{APIDefinition: &apidef.APIDefinition{APIID: "matching", Tags: []string{"team-a"}}, OAS: matchingOAS}
	other := model.MergedAPI{APIDefinition: &apidef.APIDefinition{APIID: "other", Tags: []string{"team-b"}}}
	list := model.NewMergedAPIList(untagged, disabled, matching, other)

	t.Run("construction preserves order", func(t *testing.T) {
		require.Equal(t, []string{"untagged", "disabled", "matching", "other"}, []string{
			list.Message[0].APIID,
			list.Message[1].APIID,
			list.Message[2].APIID,
			list.Message[3].APIID,
		})
		require.Same(t, matchingOAS, list.Message[2].OAS)
	})

	t.Run("log fields expose stable API details", func(t *testing.T) {
		api := model.MergedAPI{APIDefinition: &apidef.APIDefinition{
			APIID: "api-log",
			OrgID: "org1",
			Name:  "Orders",
			Proxy: apidef.ProxyConfig{ListenPath: "/orders/"},
		}}

		require.Equal(t, logrus.Fields{
			"api_id": "api-log",
			"org_id": "org1",
			"name":   "Orders",
			"path":   "/orders/",
		}, api.LogFields())
	})

	t.Run("set classic appends definitions", func(t *testing.T) {
		classic := model.NewMergedAPIList()
		classic.SetClassic([]*apidef.APIDefinition{
			{APIID: "classic-1"},
			{APIID: "classic-2"},
		})

		require.Equal(t, []string{"classic-1", "classic-2"}, []string{
			classic.Message[0].APIID,
			classic.Message[1].APIID,
		})
	})

	t.Run("disabled filtering returns all APIs", func(t *testing.T) {
		got := list.Filter(false, "team-a")
		require.Len(t, got, 4)
		require.Equal(t, "untagged", got[0].APIID)
		require.Equal(t, "disabled", got[1].APIID)
		require.Equal(t, "matching", got[2].APIID)
		require.Equal(t, "other", got[3].APIID)
	})

	t.Run("enabled filtering with no tags returns nil", func(t *testing.T) {
		require.Nil(t, list.Filter(true))
	})

	t.Run("enabled filtering skips disabled and non matching tags", func(t *testing.T) {
		got := list.Filter(true, "team-a")
		require.Len(t, got, 1)
		require.Equal(t, "matching", got[0].APIID)
		require.Same(t, matchingOAS, got[0].OAS)
	})

	t.Run("enabled filtering returns no APIs when no tag matches", func(t *testing.T) {
		require.Empty(t, list.Filter(true, "missing"))
	})
}
