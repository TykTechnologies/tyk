package info

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PlainString", func() {
	It("should generate strings", func() {
		var v Value = PlainString("x")
		Expect(v.String()).To(Equal("x"))
	})
})

var _ = Describe("PlainInt", func() {
	It("should generate strings", func() {
		var v Value = PlainInt(12)
		Expect(v.String()).To(Equal("12"))
	})
})

var _ = Describe("Callback", func() {
	It("should generate strings", func() {
		var v Value = Callback(func() string { return "x" })
		Expect(v.String()).To(Equal("x"))
	})
})

var _ = Describe("Counter", func() {
	var subject *Counter

	BeforeEach(func() {
		subject = NewCounter()
	})

	It("should have accessors", func() {
		Expect(subject.Inc(3)).To(Equal(int64(3)))
		Expect(subject.Inc(24)).To(Equal(int64(27)))
		Expect(subject.Value()).To(Equal(int64(27)))
		Expect(subject.Inc(-17)).To(Equal(int64(10)))
		Expect(subject.Value()).To(Equal(int64(10)))
		subject.Set(21)
		Expect(subject.Value()).To(Equal(int64(21)))
	})

	It("should generate strings", func() {
		var v Value = subject
		Expect(v.String()).To(Equal("0"))
	})
})
