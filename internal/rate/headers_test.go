package rate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_HeaderSender(t *testing.T) {
	t.Run("NewSender", func(t *testing.T) {
		t.Run("create quota sender", func(t *testing.T) {
			s := NewSender("")
			assert.IsType(t, &quotaSender{}, s)

			s = NewSender("dummy data")
			assert.IsType(t, &quotaSender{}, s)

			s = NewSender("quotas")
			assert.IsType(t, &quotaSender{}, s)
		})

		t.Run("create rate limit sender", func(t *testing.T) {
			s := NewSender("rate_limits")
			assert.IsType(t, &rateLimitSender{}, s)
		})
	})

	// todo: add cover
	//t.Run("SendQuotas", func(t *testing.T) {
	//	s := &quotaSender{}
	//	s.SendQuotas(nil, nil, "")
	//})
}
