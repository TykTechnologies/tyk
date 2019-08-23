package gateway

import (
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"
	cache "github.com/pmylund/go-cache"
)

type mockStore struct {
	SessionHandler
}

var sess = user.SessionState{
	OrgID:       "TestBaseMiddleware_OrgSessionExpiry",
	DataExpires: 110,
}

func (mockStore) SessionDetail(keyName string, hashed bool) (user.SessionState, bool) {
	return sess, true
}

func TestBaseMiddleware_OrgSessionExpiry(t *testing.T) {
	m := BaseMiddleware{
		Spec: &APISpec{
			GlobalConfig: config.Config{
				EnforceOrgDataAge: true,
			},
			OrgSessionManager: mockStore{},
		},
		logger: mainLog,
	}
	v := int64(100)
	ExpiryCache.Set(sess.OrgID, v, cache.DefaultExpiration)

	got := m.OrgSessionExpiry(sess.OrgID)
	if got != v {
		t.Errorf("expected %d got %d", v, got)
	}
	ExpiryCache.Delete(sess.OrgID)
	got = m.OrgSessionExpiry(sess.OrgID)
	if got != sess.DataExpires {
		t.Errorf("expected %d got %d", sess.DataExpires, got)
	}
}
