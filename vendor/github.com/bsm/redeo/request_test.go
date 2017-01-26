package redeo

import (
	"bufio"
	"io"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Request", func() {
	var successCases = []struct {
		r Request
		m string
		d string
	}{
		{Request{Name: "ping"}, "PiNg\r\n", "inline ping"},
		{Request{Name: "ping", Args: []string{}}, "*1\r\n$4\r\nPiNg\r\n", "bulk ping"},
		{Request{Name: "get", Args: []string{"Xy"}}, "*2\r\n$3\r\nGET\r\n$2\r\nXy\r\n", "get"},
		{Request{Name: "set", Args: []string{"k\r\ney", "va\r\nl"}}, "*3\r\n$3\r\nSET\r\n$5\r\nk\r\ney\r\n$5\r\nva\r\nl\r\n", "set"},
	}

	var failureCases = []struct {
		e error
		m string
		d string
	}{
		{io.EOF, "", "blank"},
		{io.EOF, "\r\n", "blank with CRLF"},
		{ErrInvalidRequest, "*x\r\n", "no bulk length"},
		{ErrInvalidRequest, "*1\r\nping\r\n", "no argument length"},
		{io.EOF, "*2\r\n$3\r\nget\r\n", "truncated message"},
		{ErrInvalidRequest, "*2\r\n$x\r\nget\r\n", "missing argument len"},
		{io.EOF, "*2\r\n$3\r\nge", "truncated argument"},
		{ErrInvalidRequest, "*2\n$3\nget\n$1\nx\n", "wrong line breaks"},
	}

	It("should parse successfully, consuming the full message", func() {
		for _, c := range successCases {
			rd := bufio.NewReader(strings.NewReader(c.m))
			req, err := ParseRequest(rd)
			Expect(err).To(BeNil(), c.d)
			Expect(req).To(BeEquivalentTo(&c.r), c.d)

			more, err := rd.Peek(1)
			Expect(more).To(HaveLen(0))
			Expect(err).To(Equal(io.EOF))
		}
	})

	It("should have client information", func() {
		cln := &Client{}
		req := &Request{client: cln}
		Expect(req.Client()).To(Equal(cln))
	})

	It("should parse chunks", func() {
		val := strings.Repeat("x", 1024)
		bio := bufio.NewReader(mockFD{s: "*3\r\n$3\r\nset\r\n$1\r\nx\r\n$1024\r\n" + val + "\r\n"})
		req, err := ParseRequest(bio)
		Expect(err).NotTo(HaveOccurred())
		Expect(req).NotTo(BeNil())
		Expect(req.Args).To(HaveLen(2))
		Expect(req.Args[1]).To(HaveLen(1024))
		Expect(req.Args[1][1020:]).To(Equal("xxxx"))
	})

	It("should support pipelining", func() {
		msg := ""
		for _, c := range successCases {
			msg = msg + c.m
		}
		rdr := bufio.NewReader(strings.NewReader(msg))

		for _, c := range successCases {
			req, err := ParseRequest(rdr)
			Expect(err).To(BeNil(), c.d)
			Expect(req).To(BeEquivalentTo(&c.r), c.d)
		}
	})

	It("should fail on invalid inputs", func() {
		for _, c := range failureCases {
			req, err := ParseRequest(bufio.NewReader(strings.NewReader(c.m)))
			Expect(req).To(BeNil(), c.d)
			Expect(err).To(Equal(c.e), c.d)
		}
	})

})

func BenchmarkParseRequest_Inline(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseRequest(bufio.NewReader(strings.NewReader("ping\r\n")))
	}
}

func BenchmarkParseRequest_Bulk(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseRequest(bufio.NewReader(strings.NewReader("*2\r\n$3\r\nget\r\n$1\r\nx\r\n")))
	}
}

// MOCKS

type mockFD struct {
	s   string
	pos int
}

func (r mockFD) Read(buf []byte) (int, error) {
	n := len(r.s) - r.pos
	if n > 100 {
		n = 100
	}

	copy(buf, r.s[r.pos:r.pos+n])
	r.pos += n
	return n, nil
}
