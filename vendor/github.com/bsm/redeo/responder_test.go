package redeo

import (
	"bytes"
	"io/ioutil"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Responder", func() {
	var subject *Responder
	var out bytes.Buffer

	BeforeEach(func() {
		out = bytes.Buffer{}
		subject = NewResponder(&out)
	})

	It("should mark as failed when a write fails", func() {
		subject = NewResponder(&badWriter{})
		subject.WriteOK()
		Expect(subject.Flush()).To(HaveOccurred())
	})

	It("should write inline strings", func() {
		subject.WriteInlineString("HELLO")
		Expect(subject.Flush()).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal("+HELLO\r\n"))
	})

	It("should write strings", func() {
		subject.WriteString("HELLO")
		Expect(subject.Flush()).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal("$5\r\nHELLO\r\n"))
	})

	It("should write string slices", func() {
		subject.WriteStringBulk([]string{"A", "", "CD"})
		Expect(subject.Flush()).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal("*3\r\n$1\r\nA\r\n$0\r\n\r\n$2\r\nCD\r\n"))
	})

	It("should write plain bytes", func() {
		subject.WriteBytes([]byte("HELLO"))
		Expect(subject.Flush()).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal("$5\r\nHELLO\r\n"))
	})

	It("should write byte slices", func() {
		subject.WriteBulk([][]byte{{'A'}, nil, {'C', 'D'}})
		Expect(subject.Flush()).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal("*3\r\n$1\r\nA\r\n$-1\r\n$2\r\nCD\r\n"))
	})

	It("should write ints", func() {
		subject.WriteInt(345)
		subject.WriteZero()
		subject.WriteOne()
		Expect(subject.Flush()).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal(":345\r\n:0\r\n:1\r\n"))
	})

	It("should write error strings", func() {
		subject.WriteErrorString("ERR some error")
		Expect(subject.Flush()).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal("-ERR some error\r\n"))
	})

	It("should write errors", func() {
		subject.WriteError(ErrInvalidRequest)
		Expect(subject.Flush()).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal("-ERR invalid request\r\n"))
	})

	It("should write OK", func() {
		subject.WriteOK()
		Expect(subject.Flush()).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal("+OK\r\n"))
	})

	It("should write nils", func() {
		subject.WriteNil()
		Expect(subject.Flush()).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal("$-1\r\n"))
	})

	It("should write bulk lens", func() {
		subject.WriteBulkLen(4)
		Expect(subject.Flush()).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal("*4\r\n"))
	})

	It("should stream data", func() {
		subject.WriteN(strings.NewReader("HELLO STREAM"), 9)
		Expect(subject.Flush()).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal("$9\r\nHELLO STR\r\n"))
	})

	It("should stream data with prefix and suffix", func() {
		subject.WriteNil()
		subject.WriteN(strings.NewReader("ECHOX"), 4)
		subject.WriteOK()
		Expect(subject.Flush()).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal("$-1\r\n$4\r\nECHO\r\n+OK\r\n"))
	})

})

func BenchmarkResponder_WriteOK(b *testing.B) {
	r := NewResponder(ioutil.Discard)
	for i := 0; i < b.N; i++ {
		r.WriteOK()
	}
	r.Flush()
}

func BenchmarkResponder_WriteNil(b *testing.B) {
	r := NewResponder(ioutil.Discard)
	for i := 0; i < b.N; i++ {
		r.WriteNil()
	}
	r.Flush()
}

func BenchmarkResponder_WriteInlineString(b *testing.B) {
	r := NewResponder(ioutil.Discard)
	s := strings.Repeat("x", 64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.WriteInlineString(s)
	}
	r.Flush()
}

func BenchmarkResponder_WriteString(b *testing.B) {
	r := NewResponder(ioutil.Discard)
	s := strings.Repeat("x", 64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.WriteString(s)
	}
	r.Flush()
}

func BenchmarkResponder_WriteBytes(b *testing.B) {
	r := NewResponder(ioutil.Discard)
	p := bytes.Repeat([]byte{'x'}, 64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.WriteBytes(p)
	}
	r.Flush()
}

func BenchmarkResponder_WriteStringBulks(b *testing.B) {
	r := NewResponder(ioutil.Discard)
	s := strings.Repeat("x", 64)
	t := []string{s, s, s, s, s}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.WriteStringBulk(t)
	}
	r.Flush()
}

func BenchmarkResponder_WriteBulk(b *testing.B) {
	r := NewResponder(ioutil.Discard)
	p := bytes.Repeat([]byte{'x'}, 64)
	t := [][]byte{p, nil, p, p, p}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.WriteBulk(t)
	}
	r.Flush()
}

func BenchmarkResponder_WriteInt(b *testing.B) {
	r := NewResponder(ioutil.Discard)
	for i := 0; i < b.N; i++ {
		r.WriteInt(98765)
	}
	r.Flush()
}
