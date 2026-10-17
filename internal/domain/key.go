package bandage

import "strings"

// Tracker-cache key convention — the one shared definition. Tracker
// state is stored as (namespace, key) pairs: the namespace is the rule
// ID (which namespaces tracker state), and the key is the tracker's
// Target string — or, for per-(Target, path) trackers (replay), the
// Target and the path joined with KeySep (DECISIONS §9). File-size
// enrichment state shares the store under the reserved FilesizeNamespace
// and keys entries by path alone: it has no Target.

// FilesizeNamespace is the reserved tracker-cache namespace for
// file-size enrichment state (keyed by path, no TTL, no Target).
const FilesizeNamespace = "filesize"

// KeySep joins a Target and a path in a per-(Target, path) tracker key.
// NUL occurs in neither a Target nor a path, so the join is unambiguous.
const KeySep = "\x00"

// TrackerKey builds the cache key for Target-keyed tracker state (rate,
// bandwidth): the Target string itself.
func TrackerKey(target string) string {
	return target
}

// ReplayTrackerKey builds the cache key for per-(Target, path) tracker
// state (replay): Target, KeySep and the path.
func ReplayTrackerKey(target, path string) string {
	return target + KeySep + path
}

// SplitTrackerKey splits a tracker cache key into its Target and, for
// per-(Target, path) keys, its path (empty for plain Target keys). It
// is the inverse of TrackerKey/ReplayTrackerKey and the drop log's
// decoder: log attributes must name the true Target, never the raw key.
func SplitTrackerKey(key string) (target, path string) {
	if i := strings.IndexByte(key, 0); i >= 0 {
		return key[:i], key[i+1:]
	}
	return key, ""
}
