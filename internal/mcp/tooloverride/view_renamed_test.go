package tooloverride

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

func TestView_RenamedAway(t *testing.T) {
	t.Parallel()

	view := compileView(t,
		rename("create_issue", "open_issue", ""),
		rename("remove_repo", "delete_repo", ""),
		rename("update_repo", "remove_repo", ""),
		annotate("merge_branch", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
	)

	for _, tc := range []struct {
		name        string
		exposed     string
		renamedAway bool
	}{
		{name: "create_issue", exposed: "open_issue", renamedAway: true},
		{name: "update_repo", exposed: "remove_repo", renamedAway: true},
		{name: "remove_repo", renamedAway: false},
		{name: "open_issue", renamedAway: false},
		{name: "merge_branch", renamedAway: false},
		{name: "list_issues", renamedAway: false},
	} {
		exposed, renamedAway := view.RenamedAway(tc.name)
		assert.Equal(t, tc.renamedAway, renamedAway, tc.name)
		assert.Equal(t, tc.exposed, exposed, tc.name)
	}

	var nilView *View
	_, renamedAway := nilView.RenamedAway("create_issue")
	assert.False(t, renamedAway)
}

func TestView_NameTakenBy(t *testing.T) {
	t.Parallel()

	view := compileView(t,
		rename("create_issue", "open_issue", ""),
		// Swap.
		rename("delete_repo", "remove_repo", ""),
		rename("remove_repo", "delete_repo", ""),
		// Chain: archive_repo -> hide_repo -> drop_repo.
		rename("archive_repo", "hide_repo", ""),
		rename("hide_repo", "drop_repo", ""),
		annotate("merge_branch", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
	)

	for _, tc := range []struct {
		name   string
		source string
		taken  bool
	}{
		{name: "delete_repo", source: "remove_repo", taken: true},
		{name: "remove_repo", source: "delete_repo", taken: true},
		{name: "hide_repo", source: "archive_repo", taken: true},
		{name: "archive_repo", taken: false},
		{name: "drop_repo", taken: false},
		{name: "open_issue", taken: false},
		{name: "create_issue", taken: false},
		{name: "merge_branch", taken: false},
		{name: "list_issues", taken: false},
	} {
		source, taken := view.NameTakenBy(tc.name)
		assert.Equal(t, tc.taken, taken, tc.name)
		assert.Equal(t, tc.source, source, tc.name)
	}

	var nilView *View
	_, taken := nilView.NameTakenBy("delete_repo")
	assert.False(t, taken)
}
