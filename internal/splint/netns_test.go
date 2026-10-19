package splint

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// Primary seam: the update cycle's network-namespace targeting,
// observed at the same firewall-driver boundary as cycle_test.go — one
// stub driver per target namespace. Which namespace installs what and
// when: one fetch-compile serves every namespace, an unreachable
// namespace is warned and skipped while the others still install, the
// per-namespace installed state lets quiet cycles skip the reinstall
// independently per namespace, and reset on exit tolerates vanished
// namespaces.

// newTestNamespaces wires the seam over one stub driver per namespace
// path ("" is the current namespace).
func newTestNamespaces(t *testing.T, srv *docServer, paths ...string) (*Updater, []*Stub, *logCapture) {
	t.Helper()
	fetcher, err := NewFetcher(srv.URL)
	if err != nil {
		t.Fatalf("NewFetcher: %v", err)
	}
	var stubs []*Stub
	var namespaces []Namespace
	for _, path := range paths {
		s := &Stub{}
		stubs = append(stubs, s)
		namespaces = append(namespaces, Namespace{Path: path, Driver: s})
	}
	logs := &logCapture{}
	u, err := NewForNamespaces(fetcher, namespaces, defaultPolicy(), DefaultInterval, zerolog.New(logs))
	if err != nil {
		t.Fatalf("NewForNamespaces: %v", err)
	}
	return u, stubs, logs
}

// unreachable is the driver error a vanished namespace surfaces: its
// nsfs handle cannot be opened (internal/splint/nft wraps open
// failures exactly so).
func unreachable(path string) error {
	return fmt.Errorf("%w: open %s: no such file or directory", ErrUnreachable, path)
}

// TestUpdateCycleInstallsIntoEveryTargetNamespace: one fetch-compile
// cycle serves all targets — the same ban rules install into every
// namespace, and the report endpoint is fetched exactly once.
func TestUpdateCycleInstallsIntoEveryTargetNamespace(t *testing.T) {
	srv := newDocServer(t)
	srv.serve(http.StatusOK, canonicalDoc(t))
	u, stubs, _ := newTestNamespaces(t, srv, "/var/run/netns/a", "/var/run/netns/b")

	if _, err := u.Update(context.Background()); err != nil {
		t.Fatalf("Update: %v", err)
	}
	for _, stub := range stubs {
		assertInstalls(t, stub, []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
	}
	if got := srv.Hits(); got != 1 {
		t.Errorf("report endpoint fetched %d times, want 1 (one fetch-compile serves every namespace)", got)
	}
}

// TestUpdateCycleSkipsAnUnreachableNamespace: a namespace whose handle
// is gone is warned and skipped for the cycle while the other
// namespaces still install — one dead container cannot halt
// enforcement everywhere — and a real install failure stays loud after
// the others have installed.
func TestUpdateCycleSkipsAnUnreachableNamespace(t *testing.T) {
	t.Run("an unreachable namespace is warned and skipped while the others still install", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stubs, logs := newTestNamespaces(t, srv, "/gone", "/alive")
		stubs[0].InstallErr = unreachable("/gone")

		if _, err := u.Update(context.Background()); err != nil {
			t.Fatalf("Update: %v", err)
		}
		assertInstalls(t, stubs[0], nil)
		assertInstalls(t, stubs[1], []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
		logText := logs.String()
		if !strings.Contains(logText, "namespace unreachable") || !strings.Contains(logText, "/gone") {
			t.Errorf("the skipped namespace is not warned about: %s", logText)
		}
	})

	t.Run("a refused install fails the cycle after the other namespaces install", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stubs, _ := newTestNamespaces(t, srv, "/broken", "/alive")
		stubs[0].InstallErr = errors.New("netlink: permission denied")

		if _, err := u.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "install") {
			t.Fatalf("Update error = %v, want a loud install failure", err)
		}
		assertInstalls(t, stubs[0], nil)
		assertInstalls(t, stubs[1], []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
	})
}

// TestUpdateCycleSkipsUnchangedRulesPerNamespace: the
// skip-if-unchanged state is per namespace — a quiet cycle reinstalls
// nothing anywhere, a changed ruleset reinstalls everywhere, and a
// namespace that comes back installs even while the unchanged ones
// skip. (The installed-state slot holds the compiled ruleset for now;
// ticket 06 fills it with the rolling hash.)
func TestUpdateCycleSkipsUnchangedRulesPerNamespace(t *testing.T) {
	t.Run("an unchanged ruleset is not reinstalled into any namespace", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stubs, logs := newTestNamespaces(t, srv, "/a", "/b")

		if _, err := u.Update(context.Background()); err != nil {
			t.Fatalf("first Update: %v", err)
		}
		if _, err := u.Update(context.Background()); err != nil {
			t.Fatalf("second Update: %v", err)
		}
		assertInstalls(t, stubs[0], []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
		assertInstalls(t, stubs[1], []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
		if n := strings.Count(logs.String(), "ban rules unchanged"); n != 2 {
			t.Errorf("logged %d unchanged skips, want 2 (one per namespace): %s", n, logs.String())
		}
	})

	t.Run("a changed ruleset reinstalls into every namespace", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		srv.serve(http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
			record(t, doc, 0)["target"] = "198.51.100.9/32"
		}))
		u, stubs, _ := newTestNamespaces(t, srv, "/a", "/b")

		if _, err := u.Update(context.Background()); err != nil {
			t.Fatalf("first Update: %v", err)
		}
		if _, err := u.Update(context.Background()); err != nil {
			t.Fatalf("second Update: %v", err)
		}
		for _, stub := range stubs {
			calls := stub.InstallCalls()
			if len(calls) != 2 {
				t.Fatalf("installed %d rulesets, want 2", len(calls))
			}
			if !equalRules(calls[1], []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "198.51.100.9/32")}) {
				t.Errorf("second installed ruleset = %v, want the changed rules", calls[1])
			}
		}
	})

	t.Run("the installed state follows each namespace", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stubs, _ := newTestNamespaces(t, srv, "/a", "/b")
		stubs[1].InstallErr = unreachable("/b")

		if _, err := u.Update(context.Background()); err != nil {
			t.Fatalf("first Update: %v", err)
		}
		// /b comes back with the very same document: /a is unchanged
		// and skips, /b has no installed state yet and installs.
		stubs[1].InstallErr = nil
		if _, err := u.Update(context.Background()); err != nil {
			t.Fatalf("second Update: %v", err)
		}
		assertInstalls(t, stubs[0], []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
		assertInstalls(t, stubs[1], []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
	})
}

// TestRunResetToleratesVanishedNamespaces: reset on exit tolerates
// namespaces that vanished meanwhile — the clean exit stays clean —
// while a real reset failure is still loud after every namespace has
// been tried.
func TestRunResetToleratesVanishedNamespaces(t *testing.T) {
	t.Run("a vanished namespace at reset does not spoil the clean exit", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stubs, logs := newTestNamespaces(t, srv, "/alive", "/gone")
		stubs[1].ResetErr = unreachable("/gone")
		ticks := make(chan time.Time)
		u.ticks = ticks
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		runDone := make(chan error, 1)
		go func() { runDone <- u.Run(ctx) }()

		sendTick(t, ticks, runDone) // proves the startup test install succeeded
		cancel()
		if err := <-runDone; err != nil {
			t.Fatalf("Run: %v", err)
		}
		if stubs[0].ResetCalls() != 1 {
			t.Errorf("alive namespace reset %d times, want 1", stubs[0].ResetCalls())
		}
		if !strings.Contains(logs.String(), "namespace unreachable") {
			t.Errorf("the vanished namespace is not warned about at reset: %s", logs.String())
		}
	})

	t.Run("a real reset failure still fails the exit", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stubs, _ := newTestNamespaces(t, srv, "/alive", "/broken")
		stubs[1].ResetErr = errors.New("netlink: permission denied")
		ticks := make(chan time.Time)
		u.ticks = ticks
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		runDone := make(chan error, 1)
		go func() { runDone <- u.Run(ctx) }()

		sendTick(t, ticks, runDone)
		cancel()
		err := <-runDone
		if err == nil || !strings.Contains(err.Error(), "reset") {
			t.Fatalf("Run error = %v, want a loud reset failure", err)
		}
		if stubs[0].ResetCalls() != 1 {
			t.Errorf("alive namespace reset %d times, want 1 (every namespace is tried before the exit fails)", stubs[0].ResetCalls())
		}
	})
}

// TestNewForNamespacesValidatesTheNamespaceList: the constructor's one
// validation, a failing and a passing case.
func TestNewForNamespacesValidatesTheNamespaceList(t *testing.T) {
	srv := newDocServer(t)
	fetcher, err := NewFetcher(srv.URL)
	if err != nil {
		t.Fatalf("NewFetcher: %v", err)
	}
	log := zerolog.New(&logCapture{})

	t.Run("an empty namespace list is rejected", func(t *testing.T) {
		_, err := NewForNamespaces(fetcher, nil, defaultPolicy(), DefaultInterval, log)
		if err == nil || !strings.Contains(err.Error(), "namespaces: at least one required") {
			t.Fatalf("NewForNamespaces error = %v, want the empty-list rejection", err)
		}
	})

	t.Run("a namespace list is accepted", func(t *testing.T) {
		u, err := NewForNamespaces(fetcher, []Namespace{{Path: "/a", Driver: &Stub{}}}, defaultPolicy(), DefaultInterval, log)
		if err != nil {
			t.Fatalf("NewForNamespaces: %v", err)
		}
		if u == nil {
			t.Fatal("NewForNamespaces returned a nil updater")
		}
	})
}
