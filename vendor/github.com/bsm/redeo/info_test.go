package redeo

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ServerInfo", func() {
	var subject *ServerInfo

	BeforeEach(func() {
		a, b, c := NewClient(&mockConn{Port: 10001}), NewClient(&mockConn{Port: 10002}), NewClient(&mockConn{Port: 10004})
		a.trackCommand("get")
		b.trackCommand("set")
		c.trackCommand("info")

		clients := newClientRegistry()
		clients.Put(a)
		clients.Put(b)
		clients.Put(c)

		subject = newServerInfo(&Config{
			Addr:   "127.0.0.1:9736",
			Socket: "/tmp/redeo.sock",
		}, clients)
		for i := 0; i < 5; i++ {
			subject.onConnect()
		}
		for i := 0; i < 12; i++ {
			subject.onCommand()
		}
	})

	It("should generate info string", func() {
		str := subject.String()
		Expect(str).To(ContainSubstring("# Server\n"))
		Expect(str).To(MatchRegexp(`process_id:\d+\n`))
		Expect(str).To(ContainSubstring("tcp_port:9736\nunix_socket:/tmp/redeo.sock\n"))
		Expect(str).To(MatchRegexp(`uptime_in_seconds:\d+\n`))
		Expect(str).To(MatchRegexp(`uptime_in_days:\d+\n`))

		Expect(str).To(ContainSubstring("# Clients\nconnected_clients:3\n"))
		Expect(str).To(ContainSubstring("# Stats\ntotal_connections_received:5\ntotal_commands_processed:12\n"))
	})

	It("should retrieve a list of clients", func() {
		Expect(subject.Clients()).To(HaveLen(3))
	})

	It("should generate client string", func() {
		str := subject.ClientsString()
		Expect(str).To(MatchRegexp(`id=\d+ addr=1\.2\.3\.4\:10001 age=\d+ idle=\d+ cmd=get`))
		Expect(str).To(MatchRegexp(`id=\d+ addr=1\.2\.3\.4\:10002 age=\d+ idle=\d+ cmd=set`))
		Expect(str).To(MatchRegexp(`id=\d+ addr=1\.2\.3\.4\:10004 age=\d+ idle=\d+ cmd=info`))
	})

})
