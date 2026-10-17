package track

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// QuantityError reports a value that does not parse as a quantity. Callers
// add the rule ID and field name (DECISIONS §5: "load error with the rule
// id and field name").
type QuantityError struct {
	Value string
}

func (e *QuantityError) Error() string {
	return fmt.Sprintf("invalid quantity %q", e.Value)
}

// numberRe matches a plain decimal number: 10, 0.1.
var numberRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

// sizeRe matches a decimal human size per flux units.FromHumanSize: a
// decimal mantissa, optional space, a single unit letter k|m|g|t|p and an
// optional trailing b/ib (case-insensitive). 1MB = 1e6, 100GB = 1e11.
var sizeRe = regexp.MustCompile(`^([0-9]+(\.[0-9]+)?) ?([kKmMgGtTpP])?[iI]?[bB]?$`)

// sizeMultipliers are decimal (flux units.FromHumanSize parity).
var sizeMultipliers = map[byte]float64{
	'k': 1e3,
	'm': 1e6,
	'g': 1e9,
	't': 1e12,
	'p': 1e15,
}

// ParseNumber parses a plain number quantity ("10", "0.1"), each
// optionally followed by "/s" ("10/s"). It is used for rate trackers
// (request counts). Any other shape is a *QuantityError.
func ParseNumber(s string) (float64, error) {
	base := trimPerSecond(s)
	if !numberRe.MatchString(base) {
		return 0, &QuantityError{Value: s}
	}
	v, err := strconv.ParseFloat(base, 64)
	if err != nil {
		return 0, &QuantityError{Value: s}
	}
	return v, nil
}

// ParseBytes parses a byte quantity: a plain number or a decimal human
// size ("1MB" = 1e6, "100GB" = 1e11, float mantissas ok), each optionally
// followed by "/s" ("1MB/s"). It is used for bandwidth trackers.
// Any other shape is a *QuantityError.
func ParseBytes(s string) (float64, error) {
	base := trimPerSecond(s)
	m := sizeRe.FindStringSubmatch(base)
	if m == nil {
		return 0, &QuantityError{Value: s}
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, &QuantityError{Value: s}
	}
	if unit := m[3]; unit != "" {
		v *= sizeMultipliers[unit[0]|0x20] // fold ASCII case
	}
	return v, nil
}

// trimPerSecond strips the optional "/s" (per second) suffix. It is
// accepted and semantically ignored beyond rate framing (DECISIONS §5).
func trimPerSecond(s string) string {
	if len(s) >= 2 && strings.EqualFold(s[len(s)-2:], "/s") {
		return s[:len(s)-2]
	}
	return s
}
