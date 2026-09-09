//go:build ee || dev

package gateway

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseKVFactories_EnterpriseEditionProvidesAggregator(t *testing.T) {
	require.NotNil(t, enterpriseKVFactories(),
		"the enterprise-edition build must return a non-nil factory map")
}
