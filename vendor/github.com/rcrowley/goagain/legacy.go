package goagain

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// Block this goroutine awaiting signals.  Signals are handled as they
// are by Nginx and Unicorn: <http://unicorn.bogomips.org/SIGNALS.html>.
func AwaitSignals(l net.Listener) (err error) {
	_, err = Wait(l)
	return
}

// Convert and validate the GOAGAIN_FD, GOAGAIN_NAME, and GOAGAIN_PPID
// environment variables.  If all three are present and in order, this
// is a child process that may pick up where the parent left off.
func GetEnvs() (l net.Listener, ppid int, err error) {
	if _, err = fmt.Sscan(os.Getenv("GOAGAIN_PPID"), &ppid); nil != err {
		return
	}
	l, err = Listener()
	return
}

// Send SIGQUIT to the given ppid in order to complete the handoff to the
// child process.
func KillParent(ppid int) error {
	return syscall.Kill(ppid, syscall.SIGQUIT)
}
