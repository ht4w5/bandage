package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HT4w5/bandage/internal/bandage"
	"github.com/HT4w5/bandage/internal/identity"
)

// Rules file (format version 0) and its load-time validation: every rule
// gets a failing and a passing case.
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
              penalty: limit-bandwidth
              rate: 1MB

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
              penalty: limit-req-rate
              rate: 200
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
	if p := iso.Actions[0].Report.Penalty; p.Action != bandage.PenaltyLimitBandwidth || p.Rate == nil || *p.Rate != 1000000 {
		t.Errorf("report penalty = %+v, want limit-bandwidth rate 1000000", p)
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

// TestParseRulesTargetPrefixDefaults: target_prefix defaults to {32, 64} and
// each family defaults independently when only the other is declared.
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
        actions: [{report: {reason: x, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
  - name: b
    rules:
      - id: dupe
        tracker: {track: rate, leak: 1, volume: 2}
        actions: [{report: {reason: x, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
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
        actions: [{report: {reason: x, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
      - id: two
        tracker: {track: rate, leak: 1, volume: 2}
        actions: [{report: {reason: x, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
`,
		},
		{
			name: "report without tracker accepted (tracker-less tripwire)",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        actions: [{report: {reason: x, ttl: 1h, penalty: drop}}]
`,
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
        actions: [{report: {reason: x, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
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
        actions: [{report: {reason: Not A Slug, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
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
        actions: [{report: {reason: -x, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
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
        actions: [{report: {reason: iso-egress_overflow9, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
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
        actions: [{report: {reason: x, ttl: 0s, penalty: limit-req-rate, rate: 200}}]
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
        actions: [{report: {reason: x, ttl: -1h, penalty: limit-req-rate, rate: 200}}]
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
        actions: [{report: {reason: x, penalty: limit-req-rate, rate: 200}}]
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
        actions: [{report: {reason: x, ttl: banana, penalty: limit-req-rate, rate: 200}}]
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
        actions: [{report: {reason: x, ttl: 30m, penalty: limit-req-rate, rate: 200}}]
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
			name: "filter expression accepted",
			yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        filter: 'src 10.0.0.0/8'\n        tracker: {track: rate, leak: 1, volume: 2}\n",
		},

		// Tracker parsing and validation.
		{name: "missing track", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {leak: 1, volume: 2}\n", wantErr: "track"},
		{name: "unknown tracker kind", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: freq, leak: 1, volume: 2}\n", wantErr: "unknown tracker kind"},
		{name: "missing leak", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, volume: 2}\n", wantErr: "tracker.leak"},
		{name: "missing volume", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1}\n", wantErr: "tracker.volume"},
		{name: "zero volume", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 0}\n", wantErr: "tracker.volume"},
		{name: "negative leak", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: -1, volume: 2}\n", wantErr: "tracker.leak"},
		{name: "rate leak with byte unit", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1MB, volume: 2}\n", wantErr: "tracker.leak"},
		{name: "rate volume with byte unit", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 1MB}\n", wantErr: "tracker.volume"},
		{name: "bandwidth quantities accepted", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: bandwidth, leak: 1MB/s, volume: 100GB}\n        actions: [{report: {reason: x, ttl: 7d, penalty: limit-bandwidth, rate: 1MB}}]\n"},
		{name: "bandwidth zero leak accepted", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: bandwidth, leak: 0, volume: 1KB}\n"},
		{name: "bad quantity names rule and field", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: my-rule\n        tracker: {track: bandwidth, leak: 1, volume: 1q}\n", wantErr: `rule "my-rule": tracker.volume`},
		{name: "volume method on bandwidth rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker:\n          track: bandwidth\n          leak: 1\n          volume: {method: constant, value: 5}\n", wantErr: "volume methods are replay-only"},

		// Target aggregation (target_prefix).
		{name: "target prefix boundary values accepted", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2, target_prefix: {ipv4: 32, ipv6: 64}}\n"},
		{name: "zero target prefix accepted", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2, target_prefix: {ipv4: 0, ipv6: 0}}\n"},
		{name: "target prefix ipv4 above 32 rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2, target_prefix: {ipv4: 33, ipv6: 64}}\n", wantErr: "target_prefix.ipv4"},
		{name: "target prefix ipv4 negative rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2, target_prefix: {ipv4: -1}}\n", wantErr: "target_prefix.ipv4"},
		{name: "target prefix ipv6 finer than 64 rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2, target_prefix: {ipv6: 65}}\n", wantErr: "target_prefix.ipv6"},
		{name: "target prefix ipv6 negative rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2, target_prefix: {ipv6: -2}}\n", wantErr: "target_prefix.ipv6"},
		{name: "bad target prefix names rule and field", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: my-rule\n        tracker: {track: rate, leak: 1, volume: 2, target_prefix: {ipv6: 65}}\n", wantErr: `rule "my-rule": tracker.target_prefix.ipv6`},

		// Actions (report, log, goto, jump, stop) and their YAML shapes.
		{name: "unknown action rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2}\n        actions: [{ban: 15m}]\n", wantErr: "unknown action"},
		{name: "stop accepted", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [stop]\n"},
		{
			name: "goto accepted and resolves target",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        actions: [{goto: b}]
  - name: b
    rules:
      - id: s
        actions: [stop]
`,
		},
		{
			name: "jump accepted and resolves forward target",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        actions: [{jump: later}]
  - name: later
    rules:
      - id: s
        actions: [stop]
`,
		},
		{name: "log accepted", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{log: \"debug,ROUTE:\"}]\n"},
		{name: "routing and logging actions without tracker accepted", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{log: \"info,seen\"}, {goto: b}]\n  - name: b\n    rules:\n      - id: s\n        actions: [stop]\n"},
		{name: "stop with options rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{stop: true}]\n", wantErr: "stop"},
		{name: "goto as scalar without options rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [goto]\n", wantErr: "goto"},
		{name: "goto without target rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{goto: \"\"}]\n", wantErr: "goto"},
		{name: "goto mapping target rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{goto: {chain: b}}]\n", wantErr: "goto"},
		{name: "jump without target rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{jump: null}]\n", wantErr: "jump"},
		{name: "log non-string rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{log: [debug, x]}]\n", wantErr: "level,message"},
		{name: "log wrong arg count rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{log: debug}]\n", wantErr: "level,message"},
		{name: "log bad level rejected", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{log: \"verbose,x\"}]\n", wantErr: "level"},

		// The goto/jump chain graph: unique chain names, resolvable
		// targets, acyclic (a DAG; shared target chains are allowed).
		{
			name: "duplicate chain names rejected",
			yaml: `
version: 0
chains:
  - name: dup
    rules:
      - id: r
        actions: [stop]
  - name: dup
    rules:
      - id: s
        actions: [stop]
`,
			wantErr: "duplicate chain name",
		},
		{
			name: "goto dangling target rejected",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        actions: [{goto: nowhere}]
`,
			wantErr: "nonexistent chain",
		},
		{
			name: "jump dangling target rejected",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        actions: [{jump: nowhere}]
`,
			wantErr: "nonexistent chain",
		},
		{
			name: "goto self cycle rejected",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        actions: [{goto: a}]
`,
			wantErr: "cycle",
		},
		{
			name: "goto jump cycle rejected",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        actions: [{jump: b}]
  - name: b
    rules:
      - id: s
        actions: [{goto: a}]
`,
			wantErr: "cycle",
		},
		{
			name: "jump self cycle rejected",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        actions: [{jump: a}]
`,
			wantErr: "cycle",
		},
		{
			name: "shared target chain accepted as a DAG",
			yaml: `
version: 0
chains:
  - name: one
    rules:
      - id: r
        actions: [{goto: shared}]
  - name: two
    rules:
      - id: s
        actions: [{jump: shared}]
  - name: shared
    rules:
      - id: t
        actions: [{goto: sink}]
  - name: sink
    rules:
      - id: u
        actions: [stop]
`,
		},

		{name: "report without reason", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2}\n        actions: [{report: {ttl: 1h, penalty: limit-req-rate, rate: 200}}]\n", wantErr: "reason"},
		{name: "report with unknown key", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2}\n        actions: [{report: {reason: x, ttl: 1h, ban: 15m, penalty: limit-req-rate, rate: 200}}]\n", wantErr: "ban"},

		// Penalty (required, closed vocabulary): failing and passing
		// cases; the per-value passing cases are generated below from
		// the domain's single vocabulary source.
		{name: "report without penalty", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{report: {reason: x, ttl: 1h}}]\n", wantErr: "penalty"},
		{name: "unknown penalty", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{report: {reason: x, ttl: 1h, penalty: ban}}]\n", wantErr: "unknown penalty"},

		// Rate on a penalty: limits only (failing and passing cases).
		{name: "rate with drop", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{report: {reason: x, ttl: 1h, penalty: drop, rate: 200}}]\n", wantErr: "not allowed"},
		{name: "rate with reject", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{report: {reason: x, ttl: 1h, penalty: reject, rate: 200}}]\n", wantErr: "not allowed"},
		{name: "limit-pkt-rate without rate", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{report: {reason: x, ttl: 1h, penalty: limit-pkt-rate}}]\n", wantErr: "rate: required"},
		{name: "limit-bandwidth without rate", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{report: {reason: x, ttl: 1h, penalty: limit-bandwidth}}]\n", wantErr: "rate: required"},
		{name: "limit-req-rate without rate", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{report: {reason: x, ttl: 1h, penalty: limit-req-rate}}]\n", wantErr: "rate: required"},
		{name: "zero rate", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{report: {reason: x, ttl: 1h, penalty: limit-req-rate, rate: 0}}]\n", wantErr: "must be positive"},
		{name: "fractional rate", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{report: {reason: x, ttl: 1h, penalty: limit-req-rate, rate: 1.5}}]\n", wantErr: "whole number"},
		{name: "rate with bad unit", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{report: {reason: x, ttl: 1h, penalty: limit-bandwidth, rate: 1q}}]\n", wantErr: "invalid quantity"},
		{name: "rate out of int64 range", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{report: {reason: x, ttl: 1h, penalty: limit-bandwidth, rate: 9999P}}]\n", wantErr: "out of range"},
		{name: "plain count rate accepted", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{report: {reason: x, ttl: 1h, penalty: limit-req-rate, rate: 200}}]\n"},
		{name: "decimal human size rate accepted", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{report: {reason: x, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]\n"},
		{name: "fractional human size rate accepted", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{report: {reason: x, ttl: 1h, penalty: limit-bandwidth, rate: 1.5MB}}]\n"},
		{name: "per-second rate suffix accepted", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{report: {reason: x, ttl: 1h, penalty: limit-bandwidth, rate: 1MB/s}}]\n"},

		// Well-formedness only (ADR 0010): no tracker/penalty or
		// reason/penalty coherence checks.
		{name: "penalty not checked against tracker kind", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker: {track: rate, leak: 1, volume: 2}\n        actions: [{report: {reason: x, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]\n"},
		{name: "penalty not checked against tracker presence", yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{report: {reason: x, ttl: 1h, penalty: limit-req-rate, rate: 200}}]\n"},
		{
			name: "shared reason with different penalties accepted",
			yaml: `
version: 0
chains:
  - name: a
    rules:
      - id: tripwire
        actions: [{report: {reason: shared, ttl: 1h, penalty: drop}}]
      - id: flood
        tracker: {track: rate, leak: 1, volume: 2}
        actions: [{report: {reason: shared, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
`,
		},
	}

	// One accepted case per closed vocabulary value (the passing side
	// of "penalty must be one of the five"), generated from the domain's
	// single source (bandage.PenaltyActions) so the list cannot drift
	// from the enum. A limit penalty carries a rate.
	for _, action := range bandage.PenaltyActions {
		rate := ""
		if action.IsLimit() {
			rate = ", rate: 200"
		}
		tests = append(tests, struct {
			name    string
			yaml    string
			wantErr string
		}{
			name: "penalty " + string(action) + " accepted",
			yaml: "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        actions: [{report: {reason: x, ttl: 1h, penalty: " + string(action) + rate + "}}]\n",
		})
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

// TestPlanBannerFollowsThePassedBuild: the plan banner carries the
// header of the build the caller passed — the command constructs the
// per-name build; the plan never names the program itself.
func TestPlanBannerFollowsThePassedBuild(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bandage.yml")
	rulesPath := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(cfgPath, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, []byte(validRules), 0o600); err != nil {
		t.Fatal(err)
	}

	build := identity.For("bandage-canary")
	plan, err := Test(cfgPath, rulesPath, build)
	if err != nil {
		t.Fatalf("Test error: %v", err)
	}
	if !strings.HasPrefix(plan, build.Header()+"\n") {
		t.Errorf("plan does not open with the passed build's header %q:\n%s", build.Header(), plan)
	}
}

func TestPrintsValidatedPlan(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bandage.yml")
	rulesPath := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(cfgPath, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, []byte(validRules), 0o600); err != nil {
		t.Fatal(err)
	}

	build := identity.For("bandage")
	plan, err := Test(cfgPath, rulesPath, build)
	if err != nil {
		t.Fatalf("Test error: %v", err)
	}
	// The --test plan output opens with the build identity header,
	// byte for byte.
	if !strings.HasPrefix(plan, build.Header()+"\n") {
		t.Errorf("plan does not open with the identity header %q:\n%s", build.Header(), plan)
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
		"action report reason=iso-egress-overflow ttl=168h0m0s penalty=limit-bandwidth rate=1000000",
		"chain api",
		"rule bursty-api",
		"tracker: rate leak=10 volume=100 ttl=10s",
		"action report reason=api-rate-overflow ttl=24h0m0s penalty=limit-req-rate rate=200",
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("plan does not contain %q:\n%s", want, plan)
		}
	}
}

func TestFailsOnBadRules(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bandage.yml")
	rulesPath := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(cfgPath, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Test(cfgPath, rulesPath, identity.For("bandage")); err == nil {
		t.Fatal("Test succeeded, want error")
	}
}

// TestShowsActionsInPlan: the --test plan shows every action of every rule.
func TestShowsActionsInPlan(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bandage.yml")
	rulesPath := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(cfgPath, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, []byte(routingRules), 0o600); err != nil {
		t.Fatal(err)
	}

	plan, err := Test(cfgPath, rulesPath, identity.For("bandage"))
	if err != nil {
		t.Fatalf("Test error: %v", err)
	}
	for _, want := range []string{
		"chain routing",
		"rule route-downloads",
		"action log level=debug message=\"ROUTE:\"",
		"action jump target=download-abuse",
		"action report reason=ua-trip ttl=24h0m0s penalty=drop",
		"action stop",
		"chain download-abuse",
		"rule sustained-iso-egress",
		"action goto target=sink",
		"action report reason=iso-egress-overflow ttl=168h0m0s penalty=limit-bandwidth rate=1000000",
		"action stop",
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("plan does not contain %q:\n%s", want, plan)
		}
	}
}

// TestValidatesChainGraph: the --test command rejects unsound goto/jump
// graphs and accepts DAGs.
func TestValidatesChainGraph(t *testing.T) {
	tests := []struct {
		name    string
		rules   string
		wantErr string
	}{
		{
			name: "cyclic rules file rejected",
			rules: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        actions: [{jump: b}]
  - name: b
    rules:
      - id: s
        actions: [{goto: a}]
`,
			wantErr: "cycle",
		},
		{
			name: "dangling goto target rejected",
			rules: `
version: 0
chains:
  - name: a
    rules:
      - id: r
        actions: [{goto: nowhere}]
`,
			wantErr: "nonexistent chain",
		},
		{
			name: "duplicate chain names rejected",
			rules: `
version: 0
chains:
  - name: dup
    rules:
      - id: r
        actions: [stop]
  - name: dup
    rules:
      - id: s
        actions: [stop]
`,
			wantErr: "duplicate chain name",
		},
		{
			name:  "acyclic dispatch DAG accepted",
			rules: routingRules,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "bandage.yml")
			rulesPath := filepath.Join(dir, "rules.yml")
			if err := os.WriteFile(cfgPath, []byte(validConfig), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(rulesPath, []byte(tt.rules), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Test(cfgPath, rulesPath, identity.For("bandage"))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Test error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Test succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

// routingRules is a dispatch DAG (several chains reaching one topic chain)
// exercising the full action vocabulary.
const routingRules = `
version: 0
chains:
  - name: routing
    rules:
      - id: route-downloads
        actions:
          - log: "debug,ROUTE:"
          - jump: download-abuse
      - id: ua-trip
        actions: [{report: {reason: ua-trip, ttl: 24h, penalty: drop}}]
      - id: skip-health
        actions: [stop]
  - name: download-abuse
    rules:
      - id: sustained-iso-egress
        tracker: {track: bandwidth, leak: 1MB, volume: 100GB}
        actions:
          - goto: sink
          - report: {reason: iso-egress-overflow, ttl: 7d, penalty: limit-bandwidth, rate: 1MB}
  - name: sink
    rules:
      - id: terminal
        actions: [stop]
`

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

// TestParseRulesFilterErrors: syntax and value errors reject the rules file
// with filter: L:C positions; valid filters select events at the rule level.
func TestParseRulesFilterErrors(t *testing.T) {
	const doc = `version: 0
chains:
  - name: a
    rules:
      - id: r
        filter: %s
`
	tests := []struct {
		name    string
		filter  string // YAML-quoted
		wantErr string
	}{
		{"unknown keyword", `'bogus'`, `rule "r": filter: 1:1: unknown keyword "bogus"`},
		{"trailing token", `'any any'`, `rule "r": filter: 1:5: unexpected "any", expected end of filter`},
		{"missing operand", `'any and'`, `rule "r": filter: 1:8: unexpected end of filter, expected an operand`},
		{"bad src", `'src 10.0.0.0/33'`, `rule "r": filter: 1:5: invalid IP address or prefix "10.0.0.0/33"`},
		{"status value out of range", `'status 20'`, `rule "r": filter: 1:8: status must be within [100, 599]`},
		{"bad size unit spelling", `'sent >= 10MB'`, `rule "r": filter: 1:9: expected a size after "sent", got "10MB"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRules([]byte(fmt.Sprintf(doc, tt.filter)))
			if err == nil {
				t.Fatalf("ParseRules succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseRulesFilterSelectsEvents(t *testing.T) {
	chains, err := ParseRules([]byte(`version: 0
chains:
  - name: a
    rules:
      - id: r
        filter: 'path prefix "/releases" and method GET'
`))
	if err != nil {
		t.Fatalf("ParseRules error: %v", err)
	}
	rule := chains[0].Rules[0]
	if !rule.Filter.Match(&bandage.Event{Method: "GET", Path: "/releases/24.04.iso"}) {
		t.Error("filter does not match a selected event")
	}
	if rule.Filter.Match(&bandage.Event{Method: "GET", Path: "/api/data"}) {
		t.Error("filter matches a non-matching path")
	}
	if rule.Filter.Match(&bandage.Event{Method: "POST", Path: "/releases/24.04.iso"}) {
		t.Error("filter matches a non-matching method")
	}
}

// TestPrintsFilterSource: the --test plan prints each rule's effective
// filter source expression ("any" where the rule omits it).
func TestPrintsFilterSource(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bandage.yml")
	rulesPath := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(cfgPath, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, []byte(`version: 0
chains:
  - name: a
    rules:
      - id: selected
        filter: 'src 10.0.0.0/8 and path prefix "/api"'
      - id: defaulted
`), 0o600); err != nil {
		t.Fatal(err)
	}

	plan, err := Test(cfgPath, rulesPath, identity.For("bandage"))
	if err != nil {
		t.Fatalf("Test error: %v", err)
	}
	for _, want := range []string{
		"rule selected",
		`filter: src 10.0.0.0/8 and path prefix "/api"`,
		"rule defaulted",
		"filter: any",
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("plan does not contain %q:\n%s", want, plan)
		}
	}
}

// TestReportsFilterErrorPosition: unparseable filters reject the rules file
// at load, reporting filter: L:C with the rule id.
func TestReportsFilterErrorPosition(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bandage.yml")
	rulesPath := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(cfgPath, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, []byte(`version: 0
chains:
  - name: a
    rules:
      - id: typo
        filter: 'status class 9'
`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Test(cfgPath, rulesPath, identity.For("bandage"))
	if err == nil {
		t.Fatal("Test succeeded, want error")
	}
	want := `rule "typo": filter: 1:14: class must be within [1, 5]`
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not contain %q", err, want)
	}
}

// TestParseRulesReplayVolumeMethods: a plain scalar volume is the constant
// method; the volume-method block configures tolerance as a function of size.
func TestParseRulesReplayVolumeMethods(t *testing.T) {
	tests := []struct {
		name     string
		volume   string
		wantDesc string // volume description in the --test plan
		size     float64
		wantVol  float64 // VolumeFor(size)
	}{
		{
			name:     "scalar volume is constant",
			volume:   "volume: 5",
			wantDesc: "5",
			size:     1e9,
			wantVol:  5,
		},
		{
			name:     "constant block",
			volume:   "volume: {method: constant, value: 5}",
			wantDesc: "constant(value=5)",
			size:     123,
			wantVol:  5,
		},
		{
			name:     "clamped-linear (PLAN \u00a71 example)",
			volume:   "volume: {method: clamped-linear, intercept: 5, slope: -1, min: 2, max: 5}",
			wantDesc: "clamped-linear(intercept=5 slope=-1 min=2 max=5)",
			size:     1e9,
			wantVol:  4,
		},
		{
			name:     "inverse-square pivot in bytes",
			volume:   "volume: {method: inverse-square, base: 1, pivot: 1GB}",
			wantDesc: "inverse-square(base=1 pivot=1000000000)",
			size:     2e9,
			wantVol:  1.25,
		},
		{
			name:     "step threshold in bytes",
			volume:   "volume: {method: step, threshold: 1GB, volume_low: 2, volume_high: 5}",
			wantDesc: "step(threshold=1000000000 volume_low=2 volume_high=5)",
			size:     1e9,
			wantVol:  5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker:\n          track: replay\n          leak: 0.1\n          " + tt.volume
			chains, err := ParseRules([]byte(yaml))
			if err != nil {
				t.Fatalf("ParseRules error: %v", err)
			}
			cfg := chains[0].Rules[0].Tracker
			if cfg == nil || cfg.Kind != bandage.TrackReplay {
				t.Fatalf("tracker = %+v, want replay", cfg)
			}
			if cfg.Leak != 0.1 {
				t.Errorf("leak = %v, want 0.1", cfg.Leak)
			}
			if got := cfg.VolumeDesc(); got != tt.wantDesc {
				t.Errorf("volume method = %q, want %q", got, tt.wantDesc)
			}
			if got := cfg.VolumeFor(tt.size); got != tt.wantVol {
				t.Errorf("VolumeFor(%g) = %v, want %v", tt.size, got, tt.wantVol)
			}
			if cfg.TTL != 0 {
				t.Errorf("ttl = %v, want 0 (replay derives its TTL per event)", cfg.TTL)
			}
			if cfg.TargetPrefix != bandage.DefaultTargetPrefix {
				t.Errorf("target_prefix = %+v, want default", cfg.TargetPrefix)
			}
		})
	}
}

// TestParseRulesVolumeValidation: a volume method is replay-only and each
// method validates its own parameters.
func TestParseRulesVolumeValidation(t *testing.T) {
	tests := []struct {
		name    string
		tracker string
		wantErr string
	}{
		{
			name:    "volume method on rate rejected",
			tracker: "track: rate\n          leak: 1\n          volume: {method: constant, value: 2}",
			wantErr: "volume methods are replay-only",
		},
		{
			name:    "volume method on bandwidth rejected",
			tracker: "track: bandwidth\n          leak: 1\n          volume: {method: step, threshold: 1GB, volume_low: 1, volume_high: 2}",
			wantErr: "volume methods are replay-only",
		},
		{
			name:    "non-scalar volume on rate rejected",
			tracker: "track: rate\n          leak: 1\n          volume: [1, 2]",
			wantErr: "volume methods are replay-only",
		},
		{
			name:    "non-scalar volume on bandwidth rejected",
			tracker: "track: bandwidth\n          leak: 1MB\n          volume: [1MB]",
			wantErr: "volume methods are replay-only",
		},
		{
			name:    "rate scalar volume accepted",
			tracker: "track: rate\n          leak: 1\n          volume: 2",
		},
		{
			name:    "bandwidth byte volume accepted",
			tracker: "track: bandwidth\n          leak: 1MB/s\n          volume: 100GB",
		},
		{
			name:    "replay scalar volume accepted",
			tracker: "track: replay\n          leak: 0.1\n          volume: 5",
		},
		{
			name:    "replay byte quantity volume rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: 1GB",
			wantErr: "tracker.volume: invalid quantity",
		},
		{
			name:    "replay byte quantity leak rejected",
			tracker: "track: replay\n          leak: 1MB/s\n          volume: 5",
			wantErr: "tracker.leak: invalid quantity",
		},
		{
			name:    "replay zero scalar volume rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: 0",
			wantErr: "tracker.volume: must be positive",
		},
		{
			name:    "unknown volume method rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: warp, value: 2}",
			wantErr: "unknown volume method",
		},
		{
			name:    "volume block without method rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: {value: 2}",
			wantErr: "volume.method: required",
		},
		{
			name:    "unknown key in volume block rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: constant, value: 2, extra: 3}",
			wantErr: "unknown key",
		},
		{
			name:    "constant without value rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: constant}",
			wantErr: "volume.value: required",
		},
		{
			name:    "constant zero value rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: constant, value: 0}",
			wantErr: "volume.value: must be positive",
		},
		{
			name:    "clamped-linear accepted (PLAN \u00a71 example)",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: clamped-linear, intercept: 5, slope: -1, min: 2, max: 5}",
		},
		{
			name:    "clamped-linear max below min rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: clamped-linear, intercept: 5, slope: -1, min: 5, max: 2}",
			wantErr: "volume.max: must be >= min",
		},
		{
			name:    "clamped-linear missing slope rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: clamped-linear, intercept: 5, min: 2, max: 5}",
			wantErr: "volume.slope: required",
		},
		{
			name:    "clamped-linear non-number rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: clamped-linear, intercept: 5, slope: fast, min: 2, max: 5}",
			wantErr: "volume.slope: invalid number",
		},
		{
			name:    "clamped-linear negative min rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: clamped-linear, intercept: 5, slope: -1, min: -1, max: 5}",
			wantErr: "volume.min: must be non-negative",
		},
		{
			name:    "inverse-square accepted",
			tracker: "track: replay\n          leak: 0\n          volume: {method: inverse-square, base: 1, pivot: 1GB}",
		},
		{
			name:    "inverse-square missing pivot rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: inverse-square, base: 1}",
			wantErr: "volume.pivot: required",
		},
		{
			name:    "inverse-square pivot not a size rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: inverse-square, base: 1, pivot: big}",
			wantErr: "volume.pivot: invalid quantity",
		},
		{
			name:    "inverse-square zero pivot rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: inverse-square, base: 1, pivot: 0}",
			wantErr: "volume.pivot: must be positive",
		},
		{
			name:    "inverse-square negative base rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: inverse-square, base: -1, pivot: 1GB}",
			wantErr: "volume.base: must be non-negative",
		},
		{
			name:    "step accepted",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: step, threshold: 1GB, volume_low: 2, volume_high: 5}",
		},
		{
			name:    "step missing threshold rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: step, volume_low: 2, volume_high: 5}",
			wantErr: "volume.threshold: required",
		},
		{
			name:    "step zero threshold rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: step, threshold: 0, volume_low: 2, volume_high: 5}",
			wantErr: "volume.threshold: must be positive",
		},
		{
			name:    "step negative volume_low rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: step, threshold: 1GB, volume_low: -1, volume_high: 5}",
			wantErr: "volume.volume_low: must be non-negative",
		},
		{
			name:    "step missing volume_high rejected",
			tracker: "track: replay\n          leak: 0.1\n          volume: {method: step, threshold: 1GB, volume_low: 2}",
			wantErr: "volume.volume_high: required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := "version: 0\nchains:\n  - name: a\n    rules:\n      - id: r\n        tracker:\n          " + tt.tracker + "\n        actions: [{report: {reason: x, ttl: 1h, penalty: drop}}]"
			_, err := ParseRules([]byte(yaml))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ParseRules error: %v, want success", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ParseRules succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), `rule "r"`) {
				t.Errorf("error %q does not name the rule", err)
			}
		})
	}
}

// TestShowsReplayVolumeMethod: the --test plan shows the replay tracker's
// volume method (or scalar) and its per-event TTL derivation.
func TestShowsReplayVolumeMethod(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bandage.yml")
	rulesPath := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(cfgPath, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, []byte(`
version: 0
chains:
  - name: download-abuse
    rules:
      - id: iso-replay
        tracker:
          track: replay
          leak: 0.1
          volume:
            method: clamped-linear
            intercept: 5
            slope: -1
            min: 2
            max: 5
        actions: [{report: {reason: iso-replay, ttl: 24h, penalty: limit-bandwidth, rate: 1MB}}]
      - id: small-replay
        tracker: {track: replay, leak: 0, volume: 5}
        actions: [{report: {reason: small-replay, ttl: 24h, penalty: limit-bandwidth, rate: 1MB}}]
`), 0o600); err != nil {
		t.Fatal(err)
	}

	plan, err := Test(cfgPath, rulesPath, identity.For("bandage"))
	if err != nil {
		t.Fatalf("Test error: %v", err)
	}
	for _, want := range []string{
		"tracker: replay leak=0.1 volume=clamped-linear(intercept=5 slope=-1 min=2 max=5) ttl=per-event",
		"tracker: replay leak=0 volume=5 ttl=per-event",
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("plan does not contain %q:\n%s", want, plan)
		}
	}
}
