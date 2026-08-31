package log

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --------------------------------------------------------------------------
// TT-7099 blocking-issue regression tests.
//
// Each test encodes the CORRECT/expected behaviour and currently FAILS
// against the code on this branch - that failure is the proof the issue
// is real. Once the corresponding bug is fixed, the test should pass.
// --------------------------------------------------------------------------

// Issue #1 (log/logger.go:59): inside the ExitFunc closure installed by
// New(), "lgr.ExitFunc(code)" is promoted straight back to the embedded
// *logrus.Logger's ExitFunc field - i.e. the very same closure - so
// EVERY Fatal/Fatalf/Fatalln call recurses into itself forever and
// crashes the process with "fatal error: stack overflow" instead of
// exiting cleanly. Reproduced via a subprocess because the crash is an
// unrecoverable runtime fatal error, not a panic the parent test could
// recover from directly.
func TestIssue1_FatalMustExitCleanly_NotStackOverflow(t *testing.T) {
	const marker = "TT7099-FATAL-MESSAGE"

	if os.Getenv("TT7099_FATAL_SUBPROCESS") == "1" {
		lgr := Build(func(b *Builder) {
			b.AddSink(NewSink(os.Stderr, &logrus.TextFormatter{DisableColors: true}, AcceptorAllowAll))
		})
		lgr.WithField("prefix", "main").Fatal(marker)
		os.Stderr.WriteString("UNREACHABLE: Fatal returned control instead of exiting\n")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestIssue1_FatalMustExitCleanly_NotStackOverflow$", "-test.v")
	cmd.Env = append(os.Environ(), "TT7099_FATAL_SUBPROCESS=1")

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	require.NoError(t, cmd.Start())

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
		output := out.String()

		if strings.Contains(output, "stack overflow") {
			t.Fatalf("BUG CONFIRMED (blocking issue #1): calling Fatal() recursed into "+
				"itself and crashed the process with a stack overflow instead of exiting "+
				"cleanly via OsExit. log/logger.go:59 should call lgr.OsExit(code), not "+
				"lgr.ExitFunc(code) (the same closure, promoted from the embedded "+
				"logrus.Logger).\n--- subprocess output (%d bytes) ---\n%s",
				len(output), truncateForTestOutput(output, 2000))
		}

		assert.Contains(t, output, marker, "expected the Fatal message to reach the sink before exit")
	case <-time.After(20 * time.Second):
		t.Fatal("subprocess did not terminate within 20s (unexpected hang)")
	}
}

func truncateForTestOutput(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}

// Issue #2 (log/logger.go, invokeOnce.MustOnce): calling Fatal from
// *inside* the Setup() callback deadlocks the process. MustOnce locks
// setupOnce.mu, sets the "executed" flag, then runs the callback while
// still holding the lock; Fatal's ExitFunc closure re-enters
// setupOnce.Do(...), which tries to lock the same, non-reentrant mutex
// from the same goroutine. This is directly reachable via
// gateway/server.go's setupLogger(), which calls mainLog.Fatalf() for
// an invalid log level while running inside log.Setup(gw.setupLogger).
func TestIssue2_FatalDuringSetupMustNotDeadlock(t *testing.T) {
	lgr := New()
	lgr.OsExit = func(int) {} // don't actually exit the test binary

	done := make(chan struct{})
	go func() {
		lgr.Setup(func(b *Builder) {
			// mirrors gateway/server.go:1555's mainLog.Fatalf call site
			lgr.WithField("prefix", "main").Fatal("invalid log level")
			b.AddSink(NewSink(io.Discard, &logrus.TextFormatter{}, AcceptorAllowAll))
		})
		close(done)
	}()

	select {
	case <-done:
		// Setup returned - no deadlock.
	case <-time.After(5 * time.Second):
		t.Fatal("BUG CONFIRMED (blocking issue #2): Logger.Setup() deadlocked when its " +
			"callback called Fatal(). invokeOnce.MustOnce holds setupOnce.mu across the " +
			"whole callback, and Fatal's ExitFunc closure re-enters setupOnce.Do(...), " +
			"locking the same non-reentrant mutex from the same goroutine.")
	}
}

// Issue #3 (gateway/server.go:1549 + log/builder.go's AddSinkSplitByLevel):
// the ticket requires info/debug on stdout and warn/error on stderr.
// setupLogger calls AddSinkSplitByLevel(logrus.ErrorLevel, ...), which
// routes WARN to stdout alongside info/debug - only error/fatal/panic
// actually reach stderr.
func TestIssue3_WarnMustBeRoutedToStderr_NotStdout(t *testing.T) {
	origStdout, origStderr := os.Stdout, os.Stderr
	stdoutR, stdoutW, err := os.Pipe()
	require.NoError(t, err)
	stderrR, stderrW, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = stdoutW
	os.Stderr = stderrW
	t.Cleanup(func() {
		os.Stdout = origStdout
		os.Stderr = origStderr
	})

	lgr := Build(func(b *Builder) {
		// exact call made by gateway/server.go's setupLogger()
		b.AddSinkSplitByLevel(logrus.ErrorLevel, &logrus.TextFormatter{DisableColors: true})
		b.WithLevel(logrus.TraceLevel)
	})

	lgr.Warn("warn-message")
	lgr.Info("info-message")
	lgr.Error("error-message")

	stdoutW.Close()
	stderrW.Close()

	stdoutBytes, _ := io.ReadAll(stdoutR)
	stderrBytes, _ := io.ReadAll(stderrR)
	stdoutStr, stderrStr := string(stdoutBytes), string(stderrBytes)

	assert.Contains(t, stdoutStr, "info-message", "info should be on stdout")
	assert.Contains(t, stderrStr, "error-message", "error should be on stderr")

	if strings.Contains(stdoutStr, "warn-message") {
		t.Errorf("BUG CONFIRMED (blocking issue #3): warn-level log was written to stdout, "+
			"not stderr. gateway/server.go:1549 calls AddSinkSplitByLevel(logrus.ErrorLevel, ...), "+
			"which only sends error/fatal/panic to stderr - warn ends up bucketed with info/debug "+
			"on stdout.\nstdout contents: %q\nstderr contents: %q", stdoutStr, stderrStr)
	}
	assert.Contains(t, stderrStr, "warn-message", "TT-7099 requires warn on stderr, not stdout")
}

// Issue #4 (log/builder.go's discardLogger + gateway/server.go:1553-1560):
// when LogLevel/TYK_LOGLEVEL/TYK_GW_LOGLEVEL all resolve to "", setupLogger
// never calls builder.WithLevel(...), so the logger keeps the level it was
// constructed with in New() - logrus.TraceLevel - instead of the documented
// default of "info" (see config.Config.LogLevel's doc comment).
func TestIssue4_DefaultLevelWithoutExplicitConfigMustBeInfo(t *testing.T) {
	lgr := Build(func(b *Builder) {
		// mirrors gateway/server.go: logLevel == "" -> WithLevel is never called
		b.AddSink(NewSink(io.Discard, &logrus.TextFormatter{}, AcceptorAllowAll))
	})

	if lgr.GetLevel() != logrus.InfoLevel {
		t.Errorf("BUG CONFIRMED (blocking issue #4): with no explicit level configured, "+
			"the logger defaults to %s instead of the documented default of %s. New() sets "+
			"the inner logger to TraceLevel for pre-setup buffering, and Builder.discardLogger "+
			"only overrides the level when WithLevel was called - otherwise it keeps whatever "+
			"level was already set.", lgr.GetLevel(), logrus.InfoLevel)
	}
}
