package domain

import "testing"

// TestTrackerKeyRoundTrip checks builders and splitter are inverses.
func TestTrackerKeyRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		wantTarget string
		wantPath   string
	}{
		{"target key", TrackerKey("203.0.113.0/24"), "203.0.113.0/24", ""},
		{"replay key", ReplayTrackerKey("203.0.113.0/24", "/big.iso"), "203.0.113.0/24", "/big.iso"},
		{"replay key with empty path", ReplayTrackerKey("203.0.113.0/24", ""), "203.0.113.0/24", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, path := SplitTrackerKey(tt.key)
			if target != tt.wantTarget || path != tt.wantPath {
				t.Errorf("SplitTrackerKey(%q) = (%q, %q), want (%q, %q)", tt.key, target, path, tt.wantTarget, tt.wantPath)
			}
		})
	}
}
