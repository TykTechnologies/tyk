package gateway

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/policy"
	"github.com/TykTechnologies/tyk/user"
)

const (
	runSessionCacheRaceReproEnv   = "TYK_RUN_SESSION_CACHE_RACE_REPRO"
	childSessionCacheRaceReproEnv = "TYK_SESSION_CACHE_RACE_REPRO_CHILD"
)

func TestOnDemandReproduceSessionCacheAccessRightsConcurrentMapCrash(t *testing.T) {
	if os.Getenv(runSessionCacheRaceReproEnv) != "1" {
		t.Skipf("set %s=1 to run this on-demand crash reproducer", runSessionCacheRaceReproEnv)
	}

	if os.Getenv(childSessionCacheRaceReproEnv) == "1" {
		runSessionCacheAccessRightsRaceReproChild(t)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOnDemandReproduceSessionCacheAccessRightsConcurrentMapCrash$", "-test.v")
	cmd.Env = append(os.Environ(), childSessionCacheRaceReproEnv+"=1")

	output, err := cmd.CombinedOutput()
	require.Error(t, err, "child test process should abort with the Go runtime map-concurrency fatal")
	require.NoError(t, ctx.Err(), "child test process timed out instead of reproducing the map-concurrency fatal")

	out := string(output)
	require.Contains(t, out, "fatal error: concurrent map")
	require.Contains(t, out, "github.com/TykTechnologies/tyk/user.SessionState.Clone")

	t.Logf("reproduced runtime crash in child process:\n%s", sessionCacheRaceReproExcerpt(out))
}

func runSessionCacheAccessRightsRaceReproChild(t *testing.T) {
	t.Helper()

	runtime.GOMAXPROCS(max(runtime.GOMAXPROCS(0), 4))

	session := user.SessionState{
		Rate:         1000000,
		Per:          60,
		QuotaMax:     -1,
		OrgID:        "default",
		AccessRights: make(map[string]user.AccessDefinition, 50000),
	}
	for i := 0; i < 50000; i++ {
		apiID := "api-" + strconv.Itoa(i)
		session.AccessRights[apiID] = user.AccessDefinition{
			APIID:    apiID,
			Versions: []string{"Default"},
			Limit: user.APILimit{
				RateLimit: user.RateLimit{
					Rate: 1000,
					Per:  60,
				},
			},
		}
	}

	// This shallow copy mirrors the old SessionCache.Set(cacheKey, session, ...)
	// behavior: the cached value and request-local value share AccessRights.
	cachedSession := session

	done := make(chan struct{})
	for i := 0; i < runtime.GOMAXPROCS(0); i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					_ = cachedSession.Clone()
				}
			}
		}()
	}

	apply := policy.New(nil, nil, logrus.New())
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			close(done)
			t.Fatal("race reproducer did not trigger the runtime map-concurrency fatal")
		default:
			require.NoError(t, apply.Apply(&session))
		}
	}
}

func sessionCacheRaceReproExcerpt(output string) string {
	var excerpt []string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "fatal error:") ||
			strings.Contains(line, "user.SessionState.Clone") ||
			strings.Contains(line, "internal/policy.(*Service).Apply") {

			excerpt = append(excerpt, line)
		}
		if len(excerpt) == 8 {
			break
		}
	}
	return strings.Join(excerpt, "\n")
}
