package main

import (
	"github.com/facebookgo/pidfile"
	"os"
)

type AuditHostDetails struct {
	Hostname string
	PID      int
}

var HostDetails AuditHostDetails

func GetHostDetails() {
	var pfErr error
	HostDetails.PID, pfErr = pidfile.Read()
	if pfErr != nil {
		log.Error("Failed ot get host pid: ", pfErr)
	}

	var hErr error
	HostDetails.Hostname, hErr = os.Hostname()
	if hErr != nil {
		log.Error("Failed ot get hostname: ", hErr)
	}
}
