// Package httpapi serves the report list over HTTP: GET /reports (the
// version-0 report document) and GET /ping. Nothing else is exposed and
// there is no URL version prefix; the API never writes reports.
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/report"
)

// ReportSource is the read port the API consumes (report.Repository,
// narrowed beside its consumer).
type ReportSource interface {
	List(ctx context.Context, q report.Query) ([]bandage.Report, error)
}

// Server is the HTTP API handler.
type Server struct {
	reports ReportSource
	now     func() time.Time
	mux     *http.ServeMux
}

func New(reports ReportSource, now func() time.Time) *Server {
	s := &Server{reports: reports, now: now, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /reports", s.handleReports)
	s.mux.HandleFunc("GET /ping", s.handlePing)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// document is the version-0 report document.
type document struct {
	Version     int              `json:"version"`
	GeneratedAt string           `json:"generated_at"`
	Reports     []bandage.Report `json:"reports"`
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	reports, err := s.reports.List(r.Context(), report.Query{
		Rule:   r.URL.Query().Get("rule"),
		Target: r.URL.Query().Get("target"),
		Now:    now,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if reports == nil {
		reports = []bandage.Report{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(document{
		Version:     0,
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Reports:     reports,
	})
}

func (s *Server) handlePing(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte("pong"))
}
