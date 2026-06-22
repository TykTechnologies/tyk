//go:build !ee && !dev

package gateway

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseKVFactories_CommunityEditionHasNone(t *testing.T) {
	require.Nil(t, enterpriseKVFactories(),
		"the community-edition build must provide no enterprise KV factories")
}
