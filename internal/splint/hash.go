package splint

import (
	"encoding/binary"
	"hash"
	"hash/fnv"
	"net/netip"
)

// The compiled ruleset's rolling hash — bandaid's construction
// (internal/model/model.go) mirrored over the ban rules: seed 114514,
// and one fresh FNV-1a 32-bit step per canonical item, each step fed
// the previous hash big-endian first, then the item's own bytes with a
// 0x00 delimiter after every one of them (bandaid's boundary
// discipline: no two fields can bleed into one another). The chain is
// the ruleset's identity — what skip-if-unchanged compares per
// namespace. It is a change detector, not a cryptographic commitment
// (rule-body tampering under a surviving table stays undetected — see
// the update cycle's skip).
const hashSeed uint32 = 114514

// hashDelim is the 0x00 field terminator of one hash step (bandaid's
// delimiter).
var hashDelim = []byte{0}

// Hash folds the compiled ruleset — after exclusions and merge, in
// canonical order — into the rolling hash chain. The fold is sensitive
// to every effective field and to the order of the rules and of the
// targets within a rule; Compile's canonical order is what makes any
// permutation of the document hash identically.
func Hash(rules []BanRule) uint32 {
	prev := hashSeed
	for _, r := range rules {
		prev = hashRule(prev, r)
	}
	return prev
}

// hashRule is one rolling-hash step over one ban rule: a fresh
// FNV-1a 32-bit digest fed the previous hash big-endian, then the
// rule's fields in their serialization order — Targets, the
// prefilter's destination ports and destination addresses, the stance
// and the rate — each item 0x00-terminated.
func hashRule(prev uint32, r BanRule) uint32 {
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
