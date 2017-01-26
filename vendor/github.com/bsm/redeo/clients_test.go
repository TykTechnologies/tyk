package redeo

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("clients", func() {
	var subject *clients

	BeforeEach(func() {
		subject = newClientRegistry()
	})

	It("should put clients", func() {
		subject.Put(NewClient(&mockConn{}))
		Expect(subject.Len()).To(Equal(1))
		Expect(subject.All()).To(HaveLen(1))
	})

	It("should close clients", func() {
		conn := &mockConn{}
		client := NewClient(conn)
		subject.Put(client)
		Expect(subject.m).To(HaveLen(1))

		err := subject.Close(client.id)
		Expect(err).NotTo(HaveOccurred())
		Expect(conn.closed).To(BeTrue())
		Expect(subject.m).To(BeEmpty())

		err = subject.Close(9999)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should clear clients", func() {
		conn := &mockConn{}
		subject.Put(NewClient(conn))
		Expect(subject.m).To(HaveLen(1))

		err := subject.Clear()
		Expect(err).NotTo(HaveOccurred())
		Expect(conn.closed).To(BeTrue())
		Expect(subject.m).To(BeEmpty())
	})

})
