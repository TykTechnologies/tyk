package certcheck

import (
	"crypto/tls"
)

type CertInfo struct {
	Certificate      *tls.Certificate
	ID               string
	CommonName       string
	HoursUntilExpiry int
	IsExpired        bool
	IsExpiringSoon   bool
}
