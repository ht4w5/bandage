package firewall

import (
	"encoding/binary"
	"hash"
	"hash/fnv"
	"net/netip"
)

// The ruleset hash — bandaid's rolling-hash construction
// (internal/model/model.go), the shared helper every firewall driver
// folds its own effective rules with: seed 114514, and one fresh
// FNV-1a 32-bit step per effective rule, each step fed the previous
// hash big-endian first, then the rule's own fields with a 0x00
// delimiter after every one of them (bandaid's boundary discipline:
// no two fields can bleed into one another). Because each driver folds
// its effective rules — after declines, after whatever it drops — the
// hash identifies what was actually installed; a change of driver
// configuration that shapes the effective rules (their content or
// their placement) changes the hash and re-enforces. It is a change
// detector, not a cryptographic commitment (rule-body tampering under
// a surviving ruleset stays undetected — the probe is existence).
const hashSeed uint32 = 114514

// hashDelim is the 0x00 field terminator of one hash step (bandaid's
// delimiter).
var hashDelim = []byte{0}

// Hash folds a driver's effective rules — in install order — into the
// ruleset hash. The fold is sensitive to every effective field and to
// the order of the rules and of the targets within a rule; a driver
// whose planning is canonical hashes any permutation of the input
// identically.
func Hash(rules []PlannedRule) uint32 {
	prev := hashSeed
	for _, r := range rules {
		prev = hashRule(prev, r)
	}
	return prev
}

// hashRule is one rolling-hash step over one effective rule: a fresh
// FNV-1a 32-bit digest fed the previous hash big-endian, then the
// rule's fields in their serialization order — Targets, the
// prefilter's destination ports and destination addresses, the stance,
// the rate and the placement label — each item 0x00-terminated.
func hashRule(prev uint32, r PlannedRule) uint32 {
	h := fnv.New32a()
	var prevBytes [4]byte
	binary.BigEndian.PutUint32(prevBytes[:], prev)
	h.Write(prevBytes[:])
	for _, t := range r.Targets {
		hashPrefix(h, t)
	}
	for _, p := range r.Prefilter.DstPorts {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], p)
		h.Write(b[:])
		h.Write(hashDelim)
	}
	for _, a := range r.Prefilter.DstAddrs {
		hashPrefix(h, a)
	}
	h.Write([]byte(r.Stance))
	h.Write(hashDelim)
	if r.Rate != nil {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(*r.Rate))
		h.Write(b[:])
	}
	h.Write(hashDelim)
	h.Write([]byte(r.Placement))
	h.Write(hashDelim)
	return h.Sum32()
}

// hashPrefix feeds one prefix — the base address bytes then the prefix
// length as one byte (bandaid's target bytes) — terminated by the
// delimiter.
func hashPrefix(h hash.Hash32, p netip.Prefix) {
	h.Write(p.Masked().Addr().AsSlice())
	b := [1]byte{byte(p.Bits())}
	h.Write(b[:])
	h.Write(hashDelim)
}
