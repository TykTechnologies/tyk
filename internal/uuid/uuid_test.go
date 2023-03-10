package uuid_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/uuid"
)

func TestUUID(t *testing.T) {
	id := uuid.New()

	assert.NotEmpty(t, id)
	assert.True(t, uuid.Valid(id))
}
