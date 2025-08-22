package certcheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBatch(t *testing.T) {
	batch := NewBatch()
	assert.Equal(t, 0, batch.Size())

	firstCert := CertInfo{ID: "first"}
	secondCert := CertInfo{ID: "second"}

	batch.Append(firstCert)
	batch.Append(secondCert)
	batch.Append(firstCert)
	assert.Equal(t, 2, batch.Size())

	copiedBatch := batch.CopyAndClear()
	assert.Equal(t, 2, len(copiedBatch))
	assert.Equal(t, firstCert.ID, copiedBatch[0].ID)
	assert.Equal(t, secondCert.ID, copiedBatch[1].ID)
	assert.Equal(t, 0, batch.Size())

}
