package again

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strings"
	"sync"
	"syscall"
)

type strategy int

var OnForkHook func()

const (
	// The Single-exec strategy: parent forks child to exec with an inherited
	// net.Listener; child kills parent and becomes a child of init(8).
	Single strategy = iota

	// The Double-exec strategy: parent forks child to exec (first) with an
	// inherited net.Listener; child signals parent to exec (second); parent
	// kills child.
	Double
)

// Don't make the caller import syscall.
const (
	SIGINT  = syscall.SIGINT
	SIGQUIT = syscall.SIGQUIT
	SIGTERM = syscall.SIGTERM
	SIGUSR2 = syscall.SIGUSR2
)

var (
	// OnSIGHUP is the function called when the server receives a SIGHUP
	// signal. The normal use case for SIGHUP is to reload the
	// configuration.
	OnSIGHUP func(l net.Listener) error

	// OnSIGUSR1 is the function called when the server receives a
	// SIGUSR1 signal. The normal use case for SIGUSR1 is to repon the
	// log files.
	OnSIGUSR1 func(l net.Listener) error

	// The strategy to use; Single by default.
	Strategy strategy = Single
)

type Service struct {
	Name       string
	FdName     string
	Descriptor uintptr
	Listener   net.Listener
	Hooks      Hooks
}

type Hooks struct {
	OnSIGHUP  func(l net.Listener) error
	OnSIGUSR1 func(l net.Listener) error
}

type Again struct {
	services *sync.Map
}

func New() *Again {
	return &Again{
		services: &sync.Map{},
	}
}

func (a *Again) Env() (m map[string]string, err error) {
	var fds []string
	var names []string
	var fdNames []string
	a.services.Range(func(k, value interface{}) bool {
		s := value.(*Service)
		names = append(names, s.Name)
		v := reflect.ValueOf(s.Listener).Elem().FieldByName("fd").Elem()
		fdField := v.FieldByName("sysfd")

		if !fdField.IsValid() {
			fdField = v.FieldByName("pfd").FieldByName("Sysfd")
		}

		if !fdField.IsValid() {
			err = fmt.Errorf("Not supported by current Go version")
			return false
		}
		fd := uintptr(fdField.Int())
		s.Descriptor = fd
		_, _, e1 := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, 0)
		if 0 != e1 {
			err = e1
			return false
		}
		fds = append(fds, fmt.Sprint(fd))
		fdNames = append(fdNames, ListerName(s.Listener))
		return true
	})
	if err != nil {
		return
	}
	return map[string]string{
		"GOAGAIN_FD":           strings.Join(fds, ","),
		"GOAGAIN_SERVICE_NAME": strings.Join(names, ","),
		"GOAGAIN_NAME":         strings.Join(fdNames, ","),
	}, nil
}

func ListerName(l net.Listener) string {
	addr := l.Addr()
	return fmt.Sprintf("%s:%s->", addr.Network(), addr.String())
}

func (a *Again) Range(fn func(*Service)) {
	a.services.Range(func(k, v interface{}) bool {
		s := v.(*Service)
		fn(s)
		return true
	})
}

func (a *Again) Listen(name string, ls net.Listener) {
	a.services.Store(name, &Service{
		Name:     name,
		Listener: ls,
	})
}

// Re-exec this same image without dropping the net.Listener.
func Exec(a *Again) error {
	var pid int
	fmt.Sscan(os.Getenv("GOAGAIN_PID"), &pid)
	if syscall.Getppid() == pid {
		return fmt.Errorf("goagain.Exec called by a child process")
	}
	argv0, err := lookPath()
	if nil != err {
		return err
	}
	if err := setEnvs(a); nil != err {
		return err
	}
	if err := os.Setenv(
		"GOAGAIN_SIGNAL",
		fmt.Sprintf("%d", syscall.SIGQUIT),
	); nil != err {
		return err
	}
	log.Println("re-executing", argv0)
	return syscall.Exec(argv0, os.Args, os.Environ())
}

// Fork and exec this same image without dropping the net.Listener.
func ForkExec(a *Again) error {
	argv0, err := lookPath()
	if nil != err {
		return err
	}
	wd, err := os.Getwd()
	if nil != err {
		return err
	}
	err = setEnvs(a)
	if nil != err {
		return err
	}
	if err := os.Setenv("GOAGAIN_PID", ""); nil != err {
		return err
	}
	if err := os.Setenv(
		"GOAGAIN_PPID",
		fmt.Sprint(syscall.Getpid()),
	); nil != err {
		return err
	}
	var sig syscall.Signal
	if Double == Strategy {
		sig = syscall.SIGUSR2
	} else {
		sig = syscall.SIGQUIT
	}
	if err := os.Setenv("GOAGAIN_SIGNAL", fmt.Sprintf("%d", sig)); nil != err {
		return err
	}

	files := []*os.File{
		os.Stdin, os.Stdout, os.Stderr,
	}
	a.Range(func(s *Service) {
		files = append(files, os.NewFile(
			s.Descriptor,
			ListerName(s.Listener),
		))
	})
	p, err := os.StartProcess(argv0, os.Args, &os.ProcAttr{
		Dir:   wd,
		Env:   os.Environ(),
		Files: files,
		Sys:   &syscall.SysProcAttr{},
	})
	if nil != err {
		return err
	}
	log.Println("spawned child", p.Pid)
	if err = os.Setenv("GOAGAIN_PID", fmt.Sprint(p.Pid)); nil != err {
		return err
	}
	return nil
}

// Test whether an error is equivalent to net.errClosing as returned by
// Accept during a graceful exit.
func IsErrClosing(err error) bool {
	if opErr, ok := err.(*net.OpError); ok {
		err = opErr.Err
	}
	return "use of closed network connection" == err.Error()
}

// Kill process specified in the environment with the signal specified in the
// environment; default to SIGQUIT.
func Kill() error {
	var (
		pid int
		sig syscall.Signal
	)
	_, err := fmt.Sscan(os.Getenv("GOAGAIN_PID"), &pid)
	if io.EOF == err {
		_, err = fmt.Sscan(os.Getenv("GOAGAIN_PPID"), &pid)
	}
	if nil != err {
		return err
	}
	if _, err := fmt.Sscan(os.Getenv("GOAGAIN_SIGNAL"), &sig); nil != err {
		sig = syscall.SIGQUIT
	}
	if syscall.SIGQUIT == sig && Double == Strategy {
		go syscall.Wait4(pid, nil, 0, nil)
	}
	log.Println("sending signal", sig, "to process", pid)
	return syscall.Kill(pid, sig)
}

func Listener(forkHook func()) (*Again, error) {
	OnForkHook = forkHook
	a := &Again{services: &sync.Map{}}
	fds := strings.Split(os.Getenv("GOAGAIN_FD"), ",")
	names := strings.Split(os.Getenv("GOAGAIN_SERVICE_NAME"), ",")
	fdNames := strings.Split(os.Getenv("GOAGAIN_NAME"), ",")
	if !((len(fds) == len(names)) && (len(fds) == len(fdNames))) {
		return nil, errors.New(("again: names/fds mismatch"))
	}
	for k, f := range fds {
		var s Service
		_, err := fmt.Sscan(f, &s.Descriptor)
		if err != nil {
			return nil, err
		}
		s.Name = names[k]
		s.FdName = fdNames[k]
		l, err := net.FileListener(os.NewFile(s.Descriptor, s.FdName))
		if err != nil {
			return nil, err
		}
		s.Listener = l
		switch l.(type) {
		case *net.TCPListener, *net.UnixListener:
		default:
			return nil, fmt.Errorf(
				"file descriptor is %T not *net.TCPListener or *net.UnixListener",
				l,
			)
		}
		if err = syscall.Close(int(s.Descriptor)); nil != err {
			return nil, err
		}
		fmt.Println("=> ", s.Name, s.FdName)
		a.services.Store(s.Name, &s)
	}
	return a, nil
}

func Wait(a *Again) (syscall.Signal, error) {
	ch := make(chan os.Signal, 2)
	signal.Notify(
		ch,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGQUIT,
		syscall.SIGTERM,
		syscall.SIGUSR1,
		syscall.SIGUSR2,
	)
	forked := false
	for {
		sig := <-ch
		log.Println(sig.String())
		switch sig {

		// SIGHUP should reload configuration.
		case syscall.SIGHUP:
			a.Range(func(s *Service) {
				if s.Hooks.OnSIGHUP != nil {
					if err := s.Hooks.OnSIGHUP(s.Listener); err != nil {
						log.Println("OnSIGHUP:", err)
					}
				}
			})

		// SIGINT should exit.
		case syscall.SIGINT:
			return syscall.SIGINT, nil

		// SIGQUIT should exit gracefully.
		case syscall.SIGQUIT:
			return syscall.SIGQUIT, nil

		// SIGTERM should exit.
		case syscall.SIGTERM:
			return syscall.SIGTERM, nil

		// SIGUSR1 should reopen logs.
		case syscall.SIGUSR1:
			a.Range(func(s *Service) {
				if s.Hooks.OnSIGHUP != nil {
					if err := s.Hooks.OnSIGUSR1(s.Listener); err != nil {
						log.Println("OnSIGUSR1:", err)
					}
				}
			})

		// SIGUSR2 forks and re-execs the first time it is received and execs
		// without forking from then on.
		case syscall.SIGUSR2:
			OnForkHook()
			if forked {
				return syscall.SIGUSR2, nil
			}
			forked = true
			if err := ForkExec(a); nil != err {
				return syscall.SIGUSR2, err
			}

		}
	}
}

func lookPath() (argv0 string, err error) {
	argv0, err = exec.LookPath(os.Args[0])
	if nil != err {
		return
	}
	if _, err = os.Stat(argv0); nil != err {
		return
	}
	return
}

func setEnvs(a *Again) error {
	e, err := a.Env()
	if err != nil {
		return err
	}
	for k, v := range e {
		os.Setenv(k, v)
	}
	return nil
}
