package kafka

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKafkaSecurityMechanisms(t *testing.T) {
	all, err := kafkaSecurityMechanisms("")
	require.NoError(t, err)
	require.Equal(t, []string{"PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"}, all)

	selected, err := kafkaSecurityMechanisms(" SCRAM-SHA-256 ")
	require.NoError(t, err)
	require.Equal(t, []string{"SCRAM-SHA-256"}, selected)

	selected, err = kafkaSecurityMechanisms("scram-sha-256")
	require.Error(t, err)
	require.Nil(t, selected)
}
