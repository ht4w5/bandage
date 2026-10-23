package firewall

import (
	"encoding/binary"
	"hash/fnv"
	"net/netip"
)

// The ruleset hash — bandaid's rolling-hash construction (in the
// reference checkout: .reference/bandaid/internal/model/model.go),
// the shared helpers every firewall driver folds its own effective
// rules with: seed 114514, and one fresh
// FNV-1a 32-bit step per effective rule, each step fed the previous
// hash big-endian first, then the rule's own fields with a 0x00
// delimiter after every one of them (bandaid's boundary discipline:
// no two fields can bleed into one another). Because each driver folds
// its effective rules — after declines, after whatever it drops, and
// under whatever configuration shapes them — the hash identifies what
// was actually installed; a change of driver configuration that shapes
// the effective rules (their content or their placement) changes the
// hash and re-enforces. It is a change detector, not a cryptographic
// commitment (rule-body tampering under a surviving ruleset stays
// undetected — the probe is existence).
const hashSeed uint32 = 114514

// hashDelim is the 0x00 field terminator of one hash step (bandaid's
// delimiter).
var hashDelim = []byte{0}

// Hasher is one rolling-hash fold over a driver's effective rules.
// Drivers fold what their effective rules carry: the plain fold over
// the seam vocabulary is Hash; a driver whose effective rules carry
// fields of its own — the nftables driver folds its configured
// enforcement scope into every effective rule — composes each step
// from the field encoders below.
type Hasher struct {
	prev uint32
}

// NewHasher starts a fold at the construction's seed.
func NewHasher() *Hasher {
	return &Hasher{prev: hashSeed}
}

// Step folds one effective item into the hash: a fresh FNV-1a 32-bit
// digest fed the previous hash big-endian first, then every field
// terminated by the 0x00 delimiter.
func (h *Hasher) Step(fields ...[]byte) *Hasher {
	d := fnv.New32a()
	var prevBytes [4]byte
	binary.BigEndian.PutUint32(prevBytes[:], h.prev)
	d.Write(prevBytes[:])
	for _, f := range fields {
		d.Write(f)
		d.Write(hashDelim)
	}
	h.prev = d.Sum32()
	return h
}

// Sum returns the folded hash.
func (h *Hasher) Sum() uint32 {
	return h.prev
}

// Hash folds a driver's effective rules — in install order — over the
// seam's own fields: the targets, the stance, the rate and the
// placement label. The fold is sensitive to every effective field and
// to the order of the rules and of the targets within a rule; a driver
// whose planning is canonical hashes any permutation of the input
// identically.
func Hash(rules []PlannedRule) uint32 {
	h := NewHasher()
	for _, r := range rules {
		h.Step(r.fields()...)
	}
	return h.Sum()
}

// fields serializes one effective rule's seam-visible fields in their
// serialization order: Targets, the stance, the rate (present only for
// the limit stances) and the placement label.
func (r PlannedRule) fields() [][]byte {
	fields := make([][]byte, 0, len(r.Targets)+3)
	for _, t := range r.Targets {
		fields = append(fields, PrefixField(t))
	}
	fields = append(fields, StringField(string(r.Stance)))
	if r.Rate != nil {
		fields = append(fields, Uint64Field(uint64(*r.Rate)))
	}
	return append(fields, StringField(r.Placement))
}

// PrefixField encodes a masked prefix's hash field: the base address
// bytes then the prefix length as one byte (bandaid's target bytes).
func PrefixField(p netip.Prefix) []byte {
	m := p.Masked()
	return append(m.Addr().AsSlice(), byte(m.Bits()))
}

// Uint16Field encodes a 16-bit value's hash field, big-endian.
func Uint16Field(v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return b[:]
}

// Uint64Field encodes a 64-bit value's hash field, big-endian.
func Uint64Field(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

// StringField encodes a string's hash field.
func StringField(s string) []byte {
	return []byte(s)
}
