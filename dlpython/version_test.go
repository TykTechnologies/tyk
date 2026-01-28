package python

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionSelection(t *testing.T) {
	assert.Equal(t, "3.5", selectLatestVersion([]string{"2.0", "3.5"}))
	assert.Equal(t, "3.8", selectLatestVersion([]string{"3.5", "3.8"}))
	assert.Equal(t, "3.10", selectLatestVersion([]string{"3.9", "3.10"}))
	assert.Equal(t, "3.11", selectLatestVersion([]string{"3.9", "3.11"}))
	assert.Equal(t, "3.12", selectLatestVersion([]string{"3.11", "3.12"}))
}
