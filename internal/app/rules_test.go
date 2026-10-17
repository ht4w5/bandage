package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// The rules file (format version 0) and its load-time validation: this is
// the -check validation surface, so every rule gets a failing and a
// passing case.
const validRules = `
version: 0

chains:
  - name: download-abuse
    rules:
      - id: sustained-iso-egress
        filter: any
        tracker:
          track: bandwidth
          leak: 1MB
          volume: 100GB
          target_prefix: {ipv4: 24, ipv6: 64}
        actions:
          - report:
              reason: iso-egress-overflow
              ttl: 7d

  - name: api
    rules:
      - id: bursty-api
        tracker:
          track: rate
          leak: 10
          volume: 100
        actions:
          - report:
              reason: api-rate-overflow
              ttl: 24h
`

func TestParseRulesValid(t *testing.T) {
	chains, err := ParseRules([]byte(validRules))
	if err != nil {
		t.Fatalf("ParseRules error: %v", err)
	}
	if len(chains) != 2 {
		t.Fatalf("chains = %d, want 2", len(chains))
	}

	iso := chains[0].Rules[0]
	if iso.ID != "sustained-iso-egress" {
		t.Errorf("rule id = %q", iso.ID)
	}
	if !iso.Filter.Match(&bandage.Event{}) {
		t.Error("filter does not match every event")
	}
	if iso.Tracker == nil {
		t.Fatal("tracker = nil")
	}
	if iso.Tracker.Kind != bandage.TrackBandwidth {
		t.Errorf("tracker kind = %q, want bandwidth", iso.Tracker.Kind)
	}
	if iso.Tracker.Leak != 1e6 || iso.Tracker.Volume != 1e11 {
		t.Errorf("tracker leak/volume = %v/%v, want 1e6/1e11", iso.Tracker.Leak, iso.Tracker.Volume)
	}
	if iso.Tracker.TTL != 1e5*time.Second {
		t.Errorf("tracker TTL = %v, want %v", iso.Tracker.TTL, 1e5*time.Second)
	}
	if iso.Tracker.TargetPrefix != (bandage.TargetPrefix{IPv4: 24, IPv6: 64}) {
		t.Errorf("tracker target_prefix = %+v, want {24 64}", iso.Tracker.TargetPrefix)
	}
	if len(iso.Actions) != 1 || iso.Actions[0].Report == nil {
		t.Fatalf("actions = %+v, want one report action", iso.Actions)
	}
	if iso.Actions[0].Report.Reason != "iso-egress-overflow" || iso.Actions[0].Report.TTL != 168*time.Hour {
		t.Errorf("report action = %+v", iso.Actions[0].Report)
	}

	api := chains[1].Rules[0]
	if api.Tracker == nil || api.Tracker.Kind != bandage.TrackRate {
		t.Fatalf("api tracker = %+v, want rate", api.Tracker)
	}
	if api.Tracker.Leak != 10 || api.Tracker.Volume != 100 {
		t.Errorf("api tracker leak/volume = %v/%v, want 10/100", api.Tracker.Leak, api.Tracker.Volume)
	}
	if api.Tracker.TTL != 10*time.Second {
		t.Errorf("api tracker TTL = %v, want 10s", api.Tracker.TTL)
	}
	if api.Tracker.TargetPrefix != bandage.DefaultTargetPrefix {
		t.Errorf("tracker target_prefix = %+v, want default %+v", api.Tracker.TargetPrefix, bandage.DefaultTargetPrefix)
	}
}

// target_prefix defaults to {32, 64} and each family defaults
// independently when only the other is declared (PLAN §1).
func TestParseRulesTargetPrefixDefaults(t *testing.T) {
	tests := []struct {
		name  string
		extra string
		want  bandage.TargetPrefix
	}{
		{"omitted defaults to {32, 64}", "", bandage.DefaultTargetPrefix},
		{"ipv4 only defaults ipv6", "target_prefix: {ipv4: 24}\n", bandage.TargetPrefix{IPv4: 24, IPv6: 64}},
		{"ipv6 only defaults ipv4", "target_prefix: {ipv6: 48}\n", bandage.TargetPrefix{IPv4: 32, IPv6: 48}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker:\n          track: rate\n          leak: 1\n          volume: 2\n          " + tt.extra
			chains, err := ParseRules([]byte(yaml))
			if err != nil {
				t.Fatalf("ParseRules error: %v", err)
			}
			if got := chains[0].Rules[0].Tracker.TargetPrefix; got != tt.want {
				t.Errorf("target_prefix = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseRulesValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		// The four checklist validations: failing and passing cases.
		{
			name: "duplicate rule ids rejected",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: dupe
        tracker: {track: rate, leak: 1, volume: 2}
        actions: [{report: {reason: x, ttl: 1h}}]
  - name: b
    rules:
      - id: dupe
        tracker: {track: rate, leak: 1, volume: 2}
        actions: [{report: {reason: x, ttl: 1h}}]
`,
			wantErr: "duplicate rule id",
		},
		{
			name: "unique rule ids accepted",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: one
        tracker: {track: rate, leak: 1, volume: 2}
        actions: [{report: {reason: x, ttl: 1h}}]
      - id: two
        tracker: {track: rate, leak: 1, volume: 2}
        actions: [{report: {reason: x, ttl: 1h}}]
`,
		},
		{
			name: "report without tracker rejected",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        actions: [{report: {reason: x, ttl: 1h}}]
`,
			wantErr: "report requires a tracker",
		},
		{
			name: "report with tracker accepted",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        tracker: {track: rate, leak: 1, volume: 2}
        actions: [{report: {reason: x, ttl: 1h}}]
`,
		},
		{
			name: "bad reason slug rejected",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        tracker: {track: rate, leak: 1, volume: 2}
        actions: [{report: {reason: Not A Slug, ttl: 1h}}]
`,
			wantErr: "reason",
		},
		{
			name: "reason leading dash rejected",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        tracker: {track: rate, leak: 1, volume: 2}
        actions: [{report: {reason: -x, ttl: 1h}}]
`,
			wantErr: "reason",
		},
		{
			name: "good reason slug accepted",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        tracker: {track: rate, leak: 1, volume: 2}
        actions: [{report: {reason: iso-egress_overflow9, ttl: 1h}}]
`,
		},
		{
			name: "zero ttl rejected",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        tracker: {track: rate, leak: 1, volume: 2}
        actions: [{report: {reason: x, ttl: 0s}}]
`,
			wantErr: "ttl",
		},
		{
			name: "negative ttl rejected",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        tracker: {track: rate, leak: 1, volume: 2}
        actions: [{report: {reason: x, ttl: -1h}}]
`,
			wantErr: "ttl",
		},
		{
			name: "missing ttl rejected",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        tracker: {track: rate, leak: 1, volume: 2}
        actions: [{report: {reason: x}}]
`,
			wantErr: "ttl",
		},
		{
			name: "malformed ttl rejected",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        tracker: {track: rate, leak: 1, volume: 2}
        actions: [{report: {reason: x, ttl: banana}}]
`,
			wantErr: "ttl",
		},
		{
			name: "positive ttl accepted",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        tracker: {track: rate, leak: 1, volume: 2}
        actions: [{report: {reason: x, ttl: 30m}}]
`,
		},

		// Document shape.
		{name: "missing version", yaml: "chains: []\n", wantErr: "version"},
		{name: "unsupported version", yaml: "version: 1\nchains: []\n", wantErr: "version"},
		{name: "missing chains", yaml: "version: 0\n", wantErr: "chain"},
		{name: "empty chains", yaml: "version: 0\nchains: []\n", wantErr: "chain"},
		{name: "chain without name", yaml: "version: 0\nchains:\n  - rules: [{id: r}]\n", wantErr: "name"},
		{name: "chain without rules", yaml: "version: 0\nchains:\n  - name: a\n", wantErr: "rule"},
		{name: "rule without id", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - filter: any\n", wantErr: "id"},
		{name: "unknown key at top level", yaml: "version: 0\nchainz: []\n", wantErr: "chainz"},
		{name: "unknown key in rule", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        buckets: []\n", wantErr: "buckets"},
		{name: "unknown key in tracker", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2, ttl: 5}\n", wantErr: "ttl"},

		// Filter.
		{name: "omitted filter defaults to any", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2}\n"},
		{name: "explicit any filter", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        filter: any\n        tracker: {track: rate, leak: 1, volume: 2}\n"},
		{
			name:    "filter beyond any rejected",
			yaml:    "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        filter: 'src 10.0.0.0/8'\n        tracker: {track: rate, leak: 1, volume: 2}\n",
			wantErr: "unsupported filter expression",
		},

		// Tracker parsing and validation.
		{name: "missing track", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {leak: 1, volume: 2}\n", wantErr: "track"},
		{name: "unknown tracker kind", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: freq, leak: 1, volume: 2}\n", wantErr: "unknown tracker kind"},
		{name: "replay not supported yet", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: replay, leak: 0.1, volume: 2}\n", wantErr: "not supported yet"},
		{name: "missing leak", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, volume: 2}\n", wantErr: "tracker.leak"},
		{name: "missing volume", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1}\n", wantErr: "tracker.volume"},
		{name: "zero volume", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 0}\n", wantErr: "tracker.volume"},
		{name: "negative leak", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: -1, volume: 2}\n", wantErr: "tracker.leak"},
		{name: "rate leak with byte unit", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1MB, volume: 2}\n", wantErr: "tracker.leak"},
		{name: "rate volume with byte unit", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 1MB}\n", wantErr: "tracker.volume"},
		{name: "bandwidth quantities accepted", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: bandwidth, leak: 1MB/s, volume: 100GB}\n        actions: [{report: {reason: x, ttl: 7d}}]\n"},
		{name: "bandwidth zero leak accepted", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: bandwidth, leak: 0, volume: 1KB}\n"},
		{name: "bad quantity names rule and field", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: my-rule\n        tracker: {track: bandwidth, leak: 1, volume: 1q}\n", wantErr: `rule "my-rule": tracker.volume`},
		{name: "volume block rejected for now", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker:\n          track: bandwidth\n          leak: 1\n          volume: {method: constant, value: 5}\n", wantErr: "tracker.volume"},

		// Target aggregation (target_prefix).
		{name: "target prefix boundary values accepted", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2, target_prefix: {ipv4: 32, ipv6: 64}}\n"},
		{name: "zero target prefix accepted", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2, target_prefix: {ipv4: 0, ipv6: 0}}\n"},
		{name: "target prefix ipv4 above 32 rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2, target_prefix: {ipv4: 33, ipv6: 64}}\n", wantErr: "target_prefix.ipv4"},
		{name: "target prefix ipv4 negative rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2, target_prefix: {ipv4: -1}}\n", wantErr: "target_prefix.ipv4"},
		{name: "target prefix ipv6 finer than 64 rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2, target_prefix: {ipv6: 65}}\n", wantErr: "target_prefix.ipv6"},
		{name: "target prefix ipv6 negative rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2, target_prefix: {ipv6: -2}}\n", wantErr: "target_prefix.ipv6"},
		{name: "bad target prefix names rule and field", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: my-rule\n        tracker: {track: rate, leak: 1, volume: 2, target_prefix: {ipv6: 65}}\n", wantErr: `rule "my-rule": tracker.target_prefix.ipv6`},

		// Actions.
		{name: "unknown action rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2}\n        actions: [{ban: 15m}]\n", wantErr: "unknown action"},
		{name: "goto not supported yet", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{goto: b}]\n", wantErr: "not supported yet"},
		{name: "stop not supported yet", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [stop]\n", wantErr: "not supported yet"},
		{name: "report without reason", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2}\n        actions: [{report: {ttl: 1h}}]\n", wantErr: "reason"},
		{name: "report with unknown key", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2}\n        actions: [{report: {reason: x, ttl: 1h, ban: 15m}}]\n", wantErr: "ban"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRules([]byte(tt.yaml))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ParseRules error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ParseRules succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestCheckPrintsValidatedPlan(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bandage.yml")
	rulesPath := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(cfgPath, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, []byte(validRules), 0o600); err != nil {
		t.Fatal(err)
	}

	plan, err := Check(cfgPath, rulesPath)
	if err != nil {
		t.Fatalf("Check error: %v", err)
	}
	for _, want := range []string{
		"ingest syslog/nginx unixgram /run/bandage/log.sock",
		"db sqlite /var/lib/bandage/reports.db",
		"api 127.0.0.1:8080",
		"cache max_entries 65536",
		"chain download-abuse",
		"rule sustained-iso-egress",
		"filter: any",
		"tracker: bandwidth leak=1000000 volume=100000000000 ttl=27h46m40s",
		"action report reason=iso-egress-overflow ttl=168h0m0s",
		"chain api",
		"rule bursty-api",
		"tracker: rate leak=10 volume=100 ttl=10s",
		"action report reason=api-rate-overflow ttl=24h0m0s",
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("plan does not contain %q:\n%s", want, plan)
		}
	}
}

func TestCheckFailsOnBadRules(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bandage.yml")
	rulesPath := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(cfgPath, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(cfgPath, rulesPath); err == nil {
		t.Fatal("Check succeeded, want error")
	}
}

func TestLoadRulesFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yml")
	if err := os.WriteFile(path, []byte(validRules), 0o600); err != nil {
		t.Fatal(err)
	}
	chains, err := LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules error: %v", err)
	}
	if len(chains) != 2 {
		t.Errorf("chains = %d, want 2", len(chains))
	}
}
