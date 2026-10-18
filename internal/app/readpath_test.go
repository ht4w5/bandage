package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/report"
	"github.com/HT4w5/bandage/internal/infra/persistence/sqlite"
)

// Reads and writes never wait on each other at the assembled daemon
// seam (ADR 0009): a report query served during an in-flight report
// write does not wait for it, and the write does not wait for the
// query — observable end to end through GET /reports and the pipeline,
// never inside the store. The wedges follow workerpool_test.go's
// blockingStore prior art (a real sqlite repository behind a gated
// seam); the connection-level split they rely on is pinned by the
// report repository's own contract tests in the sqlite package.

// gatedListStore wedges every List it is armed for on entry so a
// served query stays in flight while the write path runs; upserts pass
// straight through to the real repository. The daemon's startup
// live-report rebuild is a List of its own and passes through before
// the test arms the wedge. (The write-side wedge is
// workerpool_test.go's blockingStore; both share its storeGate.)
type gatedListStore struct {
	*sqlite.ReportRepository
	storeGate
	mu    sync.Mutex
	armed bool
}

// arm wedges subsequent List calls; before it, they pass through.
func (g *gatedListStore) arm() {
	g.mu.Lock()
	g.armed = true
	g.mu.Unlock()
}

func (g *gatedListStore) List(ctx context.Context, q report.Query) ([]bandage.Report, error) {
	g.mu.Lock()
	armed := g.armed
	g.mu.Unlock()
	if !armed {
		return g.ReportRepository.List(ctx, q)
	}
	g.enter()
	return g.ReportRepository.List(ctx, q)
}

// fetchReports issues GET /reports off the test goroutine and hands
// back the outcome: the in-test helpers fail inline and must not run
// from a goroutine.
func fetchReports(addr string) (int, reportDoc, error) {
	resp, err := apiClient.Get("http://" + addr + "/reports")
	if err != nil {
		return 0, reportDoc{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, reportDoc{}, err
	}
	var doc reportDoc
	if len(body) > 0 {
		if err := json.Unmarshal(body, &doc); err != nil {
			return 0, reportDoc{}, err
		}
	}
	return resp.StatusCode, doc, nil
}

// queryResult is the async GET outcome handed back to the test
// goroutine.
type queryResult struct {
	status int
	doc    reportDoc
	err    error
}

// waitQuery returns the async GET outcome (guard timeout only — never a
// sleep).
func waitQuery(t *testing.T, res <-chan queryResult) (int, reportDoc) {
	t.Helper()
	select {
	case r := <-res:
		if r.err != nil {
			t.Fatalf("GET /reports: %v", r.err)
		}
		return r.status, r.doc
	case <-time.After(5 * time.Second):
		t.Fatal("GET /reports waited for the store")
	}
	return 0, reportDoc{}
}

// A report query served during an in-flight report write does not wait
// for it: GET /reports answers while the write is still in flight and
// before it has landed (spec: API reads run on separate connections).
func TestQueryDuringInflightWriteDoesNotWait(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	dbPath := filepath.Join(t.TempDir(), "reports.db")
	inner, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	store := &blockingStore{
		ReportRepository: inner,
		storeGate:        newStoreGate(),
	}
	t.Cleanup(store.release)
	d := startTestDaemonCfg(t, clock, "unixgram", dbPath, bandwidthRules, nil, withStore(store))

	// The second event overflows and its report write wedges in flight.
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/releases/24.04.iso", 200, 6000))
	d.waitProcessed(t, 1)
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/releases/24.04.iso", 200, 6000))
	waitEntered(t, &store.storeGate, 1)

	res := make(chan queryResult, 1)
	go func() {
		status, doc, err := fetchReports(d.apiAddr())
		res <- queryResult{status, doc, err}
	}()
	if status, doc := waitQuery(t, res); status != http.StatusOK {
		t.Errorf("GET /reports status = %d, want 200", status)
	} else if len(doc.Reports) != 0 {
		t.Errorf("query during the in-flight write saw %d reports, want 0 (the write has not landed)", len(doc.Reports))
	}

	// Once released, the write lands and the report is served.
	store.release()
	d.waitProcessed(t, 2)
	if doc := d.getReports(t, nil); len(doc.Reports) != 1 {
		t.Fatalf("reports after the write landed = %+v, want 1", doc.Reports)
	}
}

// A report write does not wait for an in-flight query: the Trigger's
// upsert lands while a GET /reports is still being served (spec: API
// reads run on separate connections).
func TestWriteDuringInflightQueryDoesNotWait(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	dbPath := filepath.Join(t.TempDir(), "reports.db")
	inner, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	store := &gatedListStore{
		ReportRepository: inner,
		storeGate:        newStoreGate(),
	}
	t.Cleanup(store.release)
	d := startTestDaemonCfg(t, clock, "unixgram", dbPath, bandwidthRules, nil, withStore(store))

	// The query is in flight inside the store and stays there.
	store.arm()
	res := make(chan queryResult, 1)
	go func() {
		status, doc, err := fetchReports(d.apiAddr())
		res <- queryResult{status, doc, err}
	}()
	waitEntered(t, &store.storeGate, 1)

	// The write path runs to completion regardless: two events overflow
	// and the report lands while the query is still in flight.
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/releases/24.04.iso", 200, 6000))
	d.waitProcessed(t, 1)
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/releases/24.04.iso", 200, 6000))
	d.waitProcessed(t, 2)
	got, err := store.ReportRepository.List(context.Background(), report.Query{Now: clock.Now()})
	if err != nil {
		t.Fatalf("List during the in-flight query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("reports during the in-flight query = %+v, want the landed write", got)
	}

	// Released, the query completes on its own time.
	store.release()
	if status, _ := waitQuery(t, res); status != http.StatusOK {
		t.Errorf("GET /reports status = %d, want 200", status)
	}
}
