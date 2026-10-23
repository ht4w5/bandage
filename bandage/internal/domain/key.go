package domain

import "strings"

// Tracker-cache key convention: state is stored as (namespace, key)
// pairs; namespace is the rule ID, key is Target or Target+KeySep.

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
// per-(Target, path) keys, its path (empty for plain Target keys): the
// inverse of TrackerKey/ReplayTrackerKey.
func SplitTrackerKey(key string) (target, path string) {
	if i := strings.IndexByte(key, 0); i >= 0 {
		return key[:i], key[i+1:]
	}
	return key, ""
}
