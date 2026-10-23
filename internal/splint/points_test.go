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

// Primary seam: the update cycle's enforcement-point fan-out,
// observed at the same firewall-driver boundary as cycle_test.go — one
// stub driver per enforcement point. Which point installs what and
// when: one fetch-compile serves every point, an unreachable point is
// warned and skipped while the others still install, each point's
// outcome is logged on its own, and reset on exit tolerates vanished
// points.

// newTestPoints wires the seam over one stub driver per enforcement
// point label (the labels are opaque to the engine — the nftables
// factory labels its points with their nsfs paths).
func newTestPoints(t *testing.T, srv *docServer, labels ...string) (*Updater, []*firewalltest.Stub, *logCapture) {
	t.Helper()
	fetcher, err := NewFetcher(srv.URL)
	if err != nil {
		t.Fatalf("NewFetcher: %v", err)
	}
	var stubs []*firewalltest.Stub
	var points []firewall.Point
	for _, label := range labels {
		s := &firewalltest.Stub{}
		stubs = append(stubs, s)
		points = append(points, firewall.Point{Label: label, Driver: s})
	}
	logs := &logCapture{}
	u, err := New(fetcher, points, defaultPolicy(), DefaultInterval, zerolog.New(logs))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return u, stubs, logs
}

// unreachable is the driver error a vanished enforcement point
// surfaces: its handle cannot be opened (internal/firewall/nft wraps
// open failures exactly so).
func unreachable(point string) error {
	return fmt.Errorf("%w: open %s: no such file or directory", firewall.ErrUnreachable, point)
}

// TestUpdateCycleInstallsAtEveryEnforcementPoint: one fetch-compile
// cycle serves all points — the same ban rules install at every
// enforcement point, and the report endpoint is fetched exactly once.
func TestUpdateCycleInstallsAtEveryEnforcementPoint(t *testing.T) {
	srv := newDocServer(t)
	srv.serve(http.StatusOK, canonicalDoc(t))
	u, stubs, _ := newTestPoints(t, srv, "/var/run/netns/a", "/var/run/netns/b")

	if _, err := u.Update(context.Background()); err != nil {
		t.Fatalf("Update: %v", err)
	}
	for _, stub := range stubs {
		assertApplies(t, stub, []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
	}
	if got := srv.Hits(); got != 1 {
		t.Errorf("report endpoint fetched %d times, want 1 (one fetch-compile serves every enforcement point)", got)
	}
}

// TestUpdateCycleSkipsAnUnreachablePoint: a point whose handle is gone
// is warned and skipped for the cycle while the other points still
// install — one dead container cannot halt enforcement everywhere —
// and a real install failure stays loud after the others have
// installed.
func TestUpdateCycleSkipsAnUnreachablePoint(t *testing.T) {
	t.Run("an unreachable point is warned and skipped while the others still install", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stubs, logs := newTestPoints(t, srv, "/gone", "/alive")
		stubs[0].ApplyErr = unreachable("/gone")

		if _, err := u.Update(context.Background()); err != nil {
			t.Fatalf("Update: %v", err)
		}
		assertApplies(t, stubs[0], nil)
		assertApplies(t, stubs[1], []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
		logText := logs.String()
		if !strings.Contains(logText, "enforcement point unreachable") || !strings.Contains(logText, "/gone") {
			t.Errorf("the skipped point is not warned about: %s", logText)
		}
	})

	t.Run("a refused install fails the cycle after the other points install", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stubs, _ := newTestPoints(t, srv, "/broken", "/alive")
		stubs[0].ApplyErr = errors.New("netlink: permission denied")

		if _, err := u.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "install") {
			t.Fatalf("Update error = %v, want a loud install failure", err)
		}
		assertApplies(t, stubs[0], nil)
		assertApplies(t, stubs[1], []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
	})
}

// TestUpdateCycleReportsEachPointsOutcome: skip-if-unchanged is each
// driver's own (the skip state follows the driver instance), and the
// engine logs every point's report independently — one point's
// unchanged-skip never silences another's install, and a point that
// failed is handed the ruleset again next cycle.
func TestUpdateCycleReportsEachPointsOutcome(t *testing.T) {
	t.Run("one point's skip does not change another's install", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stubs, logs := newTestPoints(t, srv, "/a", "/b")
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
			t.Errorf("the skipped point is not logged: %s", logText)
		}
		if !strings.Contains(logText, "installed ban rules") || !strings.Contains(logText, "/b") {
			t.Errorf("the installing point is not logged: %s", logText)
		}
	})

	t.Run("a point that comes back is handed the ruleset again", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stubs, _ := newTestPoints(t, srv, "/a", "/b")
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
			t.Errorf("/a's driver was handed %d rulesets, want 2 (every cycle, every point)", n)
		}
		if calls := stubs[1].ApplyCalls(); len(calls) != 1 {
			t.Errorf("/b's driver was handed %d rulesets, want 1 (the cycle after it came back)", len(calls))
		} else if !equalRules(calls[0], rules) {
			t.Errorf("/b's ruleset = %v, want %v", calls[0], rules)
		}
	})
}

// TestRunResetToleratesVanishedPoints: reset on exit tolerates points
// that vanished meanwhile — the clean exit stays clean — while a real
// reset failure is still loud after every point has been tried.
func TestRunResetToleratesVanishedPoints(t *testing.T) {
	t.Run("a vanished point at reset does not spoil the clean exit", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stubs, logs := newTestPoints(t, srv, "/alive", "/gone")
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
			t.Errorf("alive point reset %d times, want 1", stubs[0].ResetCalls())
		}
		if !strings.Contains(logs.String(), "enforcement point unreachable") {
			t.Errorf("the vanished point is not warned about at reset: %s", logs.String())
		}
	})

	t.Run("a real reset failure still fails the exit", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stubs, _ := newTestPoints(t, srv, "/alive", "/broken")
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
			t.Errorf("alive point reset %d times, want 1 (every point is tried before the exit fails)", stubs[0].ResetCalls())
		}
	})
}

// TestNewValidatesThePointList: the constructor's one validation, a
// failing and a passing case.
func TestNewValidatesThePointList(t *testing.T) {
	srv := newDocServer(t)
	fetcher, err := NewFetcher(srv.URL)
	if err != nil {
		t.Fatalf("NewFetcher: %v", err)
	}
	log := zerolog.New(&logCapture{})

	t.Run("an empty enforcement-point list is rejected", func(t *testing.T) {
		_, err := New(fetcher, nil, defaultPolicy(), DefaultInterval, log)
		if err == nil || !strings.Contains(err.Error(), "enforcement points: at least one required") {
			t.Fatalf("New error = %v, want the empty-list rejection", err)
		}
	})

	t.Run("an enforcement-point list is accepted", func(t *testing.T) {
		u, err := New(fetcher, []firewall.Point{{Label: "/a", Driver: &firewalltest.Stub{}}}, defaultPolicy(), DefaultInterval, log)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if u == nil {
			t.Fatal("New returned a nil updater")
		}
	})
}
