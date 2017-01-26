package redeo

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Client", func() {
	var subject *Client

	BeforeEach(func() {
		subject = NewClient(&mockConn{Port: 10001})
	})

	It("should generate IDs", func() {
		a, b := NewClient(&mockConn{}), NewClient(&mockConn{})
		Expect(b.ID() - 1).To(Equal(a.ID()))
	})

	It("should generate info string", func() {
		subject.id = 12
		Expect(subject.String()).To(Equal(`id=12 addr=1.2.3.4:10001 age=0 idle=0 cmd=`))
	})

})
