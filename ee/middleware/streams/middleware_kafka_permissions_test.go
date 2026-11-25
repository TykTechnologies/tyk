package streams

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/user"
)

func TestHasKafkaControlPermission(t *testing.T) {
	tests := []struct {
		name     string
		session  *user.SessionState
		required string
		allowed  bool
	}{
		{name: "missing session", required: "kafka:ack"},
		{name: "missing metadata", session: &user.SessionState{}, required: "kafka:ack"},
		{name: "exact string", session: &user.SessionState{MetaData: map[string]interface{}{kafkaPermissionsMetadataKey: "kafka:ack"}}, required: "kafka:ack", allowed: true},
		{name: "wrong permission", session: &user.SessionState{MetaData: map[string]interface{}{kafkaPermissionsMetadataKey: []string{"kafka:ack"}}}, required: "kafka:offset-reset"},
		{name: "string slice", session: &user.SessionState{MetaData: map[string]interface{}{kafkaPermissionsMetadataKey: []string{"other", "kafka:offset-reset"}}}, required: "kafka:offset-reset", allowed: true},
		{name: "decoded json slice", session: &user.SessionState{MetaData: map[string]interface{}{kafkaPermissionsMetadataKey: []interface{}{"kafka:ack"}}}, required: "kafka:ack", allowed: true},
		{name: "wildcard", session: &user.SessionState{MetaData: map[string]interface{}{kafkaPermissionsMetadataKey: "kafka:*"}}, required: "kafka:offset-reset", allowed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.allowed, hasKafkaControlPermission(test.session, test.required))
		})
	}
}
