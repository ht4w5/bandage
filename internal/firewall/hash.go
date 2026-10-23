package firewall

import (
	"encoding/binary"
	"hash/fnv"
	"net/netip"
)

// The ruleset hash is bandaid's rolling-hash construction
// (.reference/bandaid/internal/model/model.go), shared by every
// firewall driver folding its own effective rules: seed 114514, one
// fresh FNV-1a 32-bit step per effective rule — previous hash
// big-endian first, then the rule's fields, each 0x00-terminated. It
// identifies what was actually installed: a change detector, not a
// cryptographic commitment.
const hashSeed uint32 = 114514

var hashDelim = []byte{0}

// Hasher is one rolling-hash fold over a driver's effective rules.
// Hash is the plain fold over the seam vocabulary; a driver whose
// effective rules carry fields of its own composes each Step from the
// field encoders below.
type Hasher struct {
	prev uint32
}

// NewHasher starts a fold at the construction's seed.
func NewHasher() *Hasher {
	return &Hasher{prev: hashSeed}
}

// Step folds one effective item into the hash.
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

func (h *Hasher) Sum() uint32 {
	return h.prev
}

// Hash folds a driver's effective rules, in install order, over the
// seam's own fields: the targets, the stance, the rate and the
// placement label. Order-sensitive: the rules, and the targets within
// a rule.
func Hash(rules []PlannedRule) uint32 {
	h := NewHasher()
	for _, r := range rules {
		h.Step(r.fields()...)
	}
	return h.Sum()
}

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

func Uint16Field(v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return b[:]
}

func Uint64Field(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func StringField(s string) []byte {
	return []byte(s)
}
