package redeo

import (
	"bytes"
	"io"
	"net"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Server", func() {
	var subject *Server

	var pong = func(out *Responder, _ *Request) error {
		out.WriteInlineString("PONG")
		return nil
	}

	var blank = func(out *Responder, _ *Request) error {
		return nil
	}

	var failing = func(out *Responder, _ *Request) error {
		return io.EOF
	}

	var echo = func(out *Responder, req *Request) error {
		if len(req.Args) != 1 {
			return WrongNumberOfArgs(req.Name)
		}
		out.WriteString(req.Args[0])
		return nil
	}

	BeforeEach(func() {
		subject = NewServer(nil)
	})

	It("should fallback on default config", func() {
		Expect(subject.config).To(Equal(DefaultConfig))
	})

	It("should listen/serve/close", func() {
		subject.HandleFunc("pInG", pong)

		// Listen to connections
		ec := make(chan error, 1)
		go func() {
			ec <- subject.ListenAndServe()
		}()

		// Connect client
		var clnt net.Conn
		Eventually(func() (err error) {
			clnt, err = net.Dial("tcp", "127.0.0.1:9736")
			return err
		}).ShouldNot(HaveOccurred())
		defer clnt.Close()

		// Ping
		pong := make([]byte, 10)
		_, err := clnt.Write([]byte("PING\r\n"))
		Expect(err).NotTo(HaveOccurred())
		n, err := clnt.Read(pong)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(pong[:n])).To(Equal("+PONG\r\n"))

		// Close
		err = subject.Close()
		Expect(err).NotTo(HaveOccurred())

		// Expect to exit
		err = <-ec
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("closed"))

		// Ping again
		_, err = clnt.Write([]byte("PING\r\n"))
		Expect(err).NotTo(HaveOccurred())
		_, err = clnt.Read(pong)
		Expect(err).To(Equal(io.EOF))
	})

	It("should register handlers", func() {
		subject.HandleFunc("pInG", pong)
		Expect(subject.commands).To(HaveLen(1))
		Expect(subject.commands).To(HaveKey("ping"))
	})

	Describe("request handling", func() {

		It("should apply requests", func() {
			subject.HandleFunc("echo", echo)

			client := NewClient(&mockConn{})

			w := &bytes.Buffer{}
			ok := subject.apply(&Request{Name: "echo", client: client}, w)
			Expect(ok).To(BeTrue())
			Expect(w.String()).To(Equal("-ERR wrong number of arguments for 'echo' command\r\n"))

			w = &bytes.Buffer{}
			ok = subject.apply(&Request{Name: "echo", Args: []string{"SAY HI!"}}, w)
			Expect(ok).To(BeTrue())
			Expect(w.String()).To(Equal("$7\r\nSAY HI!\r\n"))

			w = &bytes.Buffer{}
			ok = subject.apply(&Request{Name: "echo", Args: []string{strings.Repeat("x", 100000)}}, w)
			Expect(ok).To(BeTrue())
			Expect(w.Len()).To(Equal(100011))
			Expect(w.String()[:9]).To(Equal("$100000\r\n"))

			Expect(client.lastCommand).To(Equal("echo"))
			Expect(subject.Info().TotalCommands()).To(Equal(int64(3)))
		})

		It("should write errors if they occur", func() {
			subject.HandleFunc("failing", failing)

			w := &bytes.Buffer{}
			ok := subject.apply(&Request{Name: "failing"}, w)
			Expect(ok).To(BeTrue())
			Expect(w.String()).To(Equal("-ERR EOF\r\n"))
		})

		It("should auto-respond with OK when nothing written", func() {
			subject.HandleFunc("blank", blank)

			w := &bytes.Buffer{}
			ok := subject.apply(&Request{Name: "blank"}, w)
			Expect(ok).To(BeTrue())
			Expect(w.String()).To(Equal("+OK\r\n"))
		})

		It("should return false on write failures", func() {
			subject.HandleFunc("blank", blank)

			w := &badWriter{}
			ok := subject.apply(&Request{Name: "blank"}, w)
			Expect(ok).To(BeFalse())
			Expect(w.String()).To(Equal("+OK\r\n"))
		})

	})
})
