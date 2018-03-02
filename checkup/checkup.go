package checkup

import (
	"runtime"
	"syscall"

	logger "github.com/TykTechnologies/tyk/log"
)

var log = logger.Get()

const (
	minCPU             = 2
	minFileDescriptors = 80000
)

func CheckFileDescriptors() {

	rlimit := &syscall.Rlimit{}
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, rlimit)
	if err == nil && rlimit.Cur < minFileDescriptors {
		log.Warningf("File descriptor limit %d too low for production use. Min %d recommended.\n"+
			"\tThis could have a significant negative impact on performance.\n"+
			"\tPlease refer to https://tyk.io/docs/deploy-tyk-premise-production/#file-handles for further guidance.", rlimit.Cur, minFileDescriptors)
	}
}

func CheckCpus() {

	cpus := runtime.NumCPU()
	if cpus < minCPU {
		log.Warningf("Num CPUs %d too low for production use. Min %d recommended.\n"+
			"\tThis could have a significant negative impact on performance.\n"+
			"\tPlease refer to https://tyk.io/docs/deploy-tyk-premise-production/#use-the-right-hardware for further guidance.", cpus, minCPU)
	}
}
