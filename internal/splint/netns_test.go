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

	"github.com/HT4w5/bandage/internal/firewall"
	"github.com/HT4w5/bandage/internal/firewall/firewalltest"
)

// Primary seam: the update cycle's network-namespace targeting,
// observed at the same firewall-driver boundary as cycle_test.go — one
// stub driver per target namespace. Which namespace installs what and
// when: one fetch-compile serves every namespace, an unreachable
// namespace is warned and skipped while the others still install, each
// namespace's outcome is logged on its own, and reset on exit tolerates
// vanished namespaces.

// newTestNamespaces wires the seam over one stub driver per namespace
// path ("" is the current namespace).
func newTestNamespaces(t *testing.T, srv *docServer, paths ...string) (*Updater, []*firewalltest.Stub, *logCapture) {
	t.Helper()
	fetcher, err := NewFetcher(srv.URL)
	if err != nil {
		t.Fatalf("NewFetcher: %v", err)
	}
	var stubs []*firewalltest.Stub
	var namespaces []Namespace
	for _, path := range paths {
		s := &firewalltest.Stub{}
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
// nsfs handle cannot be opened (internal/firewall/nft wraps open
// failures exactly so).
func unreachable(path string) error {
	return fmt.Errorf("%w: open %s: no such file or directory", firewall.ErrUnreachable, path)
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
		assertApplies(t, stub, []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
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
		stubs[0].ApplyErr = unreachable("/gone")

		if _, err := u.Update(context.Background()); err != nil {
			t.Fatalf("Update: %v", err)
		}
		assertApplies(t, stubs[0], nil)
		assertApplies(t, stubs[1], []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
		logText := logs.String()
		if !strings.Contains(logText, "namespace unreachable") || !strings.Contains(logText, "/gone") {
			t.Errorf("the skipped namespace is not warned about: %s", logText)
		}
	})

	t.Run("a refused install fails the cycle after the other namespaces install", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stubs, _ := newTestNamespaces(t, srv, "/broken", "/alive")
		stubs[0].ApplyErr = errors.New("netlink: permission denied")

		if _, err := u.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "install") {
			t.Fatalf("Update error = %v, want a loud install failure", err)
		}
		assertApplies(t, stubs[0], nil)
		assertApplies(t, stubs[1], []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
	})
}

// TestUpdateCycleReportsEachNamespacesOutcome: skip-if-unchanged is
// each driver's own (the skip state follows the driver instance), and
// the engine logs every target's report independently — one
// namespace's unchanged-skip never silences another's install, and a
// namespace that failed is handed the ruleset again next cycle.
func TestUpdateCycleReportsEachNamespacesOutcome(t *testing.T) {
	t.Run("one namespace's skip does not change another's install", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stubs, logs := newTestNamespaces(t, srv, "/a", "/b")
		// /a's driver reports the unchanged ruleset; /b's installs.
		stubs[0].Skip = true

		if _, err := u.Update(context.Background()); err != nil {
			t.Fatalf("Update: %v", err)
		}
		rules := []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")}
		assertApplies(t, stubs[0], rules)
		assertApplies(t, stubs[1], rules)
		logText := logs.String()
		if !strings.Contains(logText, "ban rules unchanged") || !strings.Contains(logText, "/a") {
			t.Errorf("the skipped namespace is not logged: %s", logText)
		}
		if !strings.Contains(logText, "installed ban rules") || !strings.Contains(logText, "/b") {
			t.Errorf("the installing namespace is not logged: %s", logText)
		}
	})

	t.Run("a namespace that comes back is handed the ruleset again", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stubs, _ := newTestNamespaces(t, srv, "/a", "/b")
		stubs[1].ApplyErr = unreachable("/b")

		if _, err := u.Update(context.Background()); err != nil {
			t.Fatalf("first Update: %v", err)
		}
		// /b comes back with the very same document: the engine hands
		// both drivers the ruleset again — its own skip state is each
		// driver's to keep.
		stubs[1].ApplyErr = nil
		if _, err := u.Update(context.Background()); err != nil {
			t.Fatalf("second Update: %v", err)
		}
		rules := []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")}
		if n := len(stubs[0].ApplyCalls()); n != 2 {
			t.Errorf("/a's driver was handed %d rulesets, want 2 (every cycle, every namespace)", n)
		}
		if calls := stubs[1].ApplyCalls(); len(calls) != 1 {
			t.Errorf("/b's driver was handed %d rulesets, want 1 (the cycle after it came back)", len(calls))
		} else if !equalRules(calls[0], rules) {
			t.Errorf("/b's ruleset = %v, want %v", calls[0], rules)
		}
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
		u, err := NewForNamespaces(fetcher, []Namespace{{Path: "/a", Driver: &firewalltest.Stub{}}}, defaultPolicy(), DefaultInterval, log)
		if err != nil {
			t.Fatalf("NewForNamespaces: %v", err)
		}
		if u == nil {
			t.Fatal("NewForNamespaces returned a nil updater")
		}
	})
}
