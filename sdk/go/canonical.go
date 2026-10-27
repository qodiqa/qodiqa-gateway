package qodiqa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Protocol V1 canonical JSON (docs/protocol/QODIQA-PROTOCOL.md section on canonicalization): object keys sorted by UTF-16 code unit, no whitespace, strings escaped exactly like
// ECMAScript JSON.stringify, numbers formatted like ECMAScript Number.prototype.toString. The behaviour is pinned by the shared protocol vectors (conformance_test.go).

const maxDepth = 1000

// CanonicalizationError reports why a value has no canonical form.
type CanonicalizationError struct {
	Code    string // NON_FINITE_NUMBER, UNSUPPORTED_TYPE, MAX_DEPTH_EXCEEDED, FORBIDDEN_KEY
	Message string
}

func (e *CanonicalizationError) Error() string { return e.Code + ": " + e.Message }

var forbiddenKeys = map[string]bool{"__proto__": true, "constructor": true, "prototype": true}

// ParseJSON decodes JSON keeping numbers exact (json.Number) so that they can be canonicalised like a JavaScript double.
func ParseJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after the JSON value")
	}
	return v, nil
}

// Canonicalize returns the canonical string of a decoded JSON value (nil, bool, string, json.Number, float64, ints, []any, map[string]any).
func Canonicalize(v any) (string, error) {
	var b strings.Builder
	if err := writeCanonical(&b, v, 0); err != nil {
		return "", err
	}
	return b.String(), nil
}

func writeCanonical(b *strings.Builder, v any, depth int) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeJSString(b, t)
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil {
			if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
				return &CanonicalizationError{"NON_FINITE_NUMBER", "number outside the double range"}
			}
			return &CanonicalizationError{"UNSUPPORTED_TYPE", "invalid number " + string(t)}
		}
		return writeNumber(b, f)
	case float64:
		return writeNumber(b, t)
	case float32:
		return writeNumber(b, float64(t))
	case int:
		return writeNumber(b, float64(t))
	case int32:
		return writeNumber(b, float64(t))
	case int64:
		return writeNumber(b, float64(t))
	case uint32:
		return writeNumber(b, float64(t))
	case uint64:
		return writeNumber(b, float64(t))
	case []any:
		if depth > maxDepth {
			return &CanonicalizationError{"MAX_DEPTH_EXCEEDED", fmt.Sprintf("nesting exceeds maximum depth of %d", maxDepth)}
		}
		b.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, item, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		if depth > maxDepth {
			return &CanonicalizationError{"MAX_DEPTH_EXCEEDED", fmt.Sprintf("nesting exceeds maximum depth of %d", maxDepth)}
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			if forbiddenKeys[k] {
				return &CanonicalizationError{"FORBIDDEN_KEY", fmt.Sprintf("object key %q is forbidden", k)}
			}
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSString(b, k)
			b.WriteByte(':')
			if err := writeCanonical(b, t[k], depth+1); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return &CanonicalizationError{"UNSUPPORTED_TYPE", fmt.Sprintf("cannot canonicalise a value of type %T", v)}
	}
	return nil
}

// lessUTF16 orders strings by UTF-16 code units (JavaScript's default sort), not by bytes or code points.
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeJSString writes s like ECMAScript JSON.stringify: only " \ and control characters are escaped; everything else (U+2028, non-ASCII, <, >, &) is written as is.
func writeJSString(b *strings.Builder, s string) {
	const hex = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteString("\\ufffd")
		case r == '"':
			b.WriteString("\\\"")
		case r == '\\':
			b.WriteString("\\\\")
		case r == '\b':
			b.WriteString("\\b")
		case r == '\f':
			b.WriteString("\\f")
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteString("\\t")
		case r < 0x20:
			b.WriteString("\\u00")
			b.WriteByte(hex[r>>4])
			b.WriteByte(hex[r&0xf])
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	b.WriteByte('"')
}

// writeNumber formats a double like ECMAScript Number.prototype.toString (radix 10).
func writeNumber(b *strings.Builder, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return &CanonicalizationError{"NON_FINITE_NUMBER", "NaN/Infinity is not a valid canonical number"}
	}
	b.WriteString(jsNumber(f))
	return nil
}

func jsNumber(f float64) string {
	if f == 0 {
		return "0"
	}
	neg := f < 0
	if neg {
		f = -f
	}
	// shortest round-trip digits and the decimal exponent
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddddde±XX
	mant, expStr, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, _ := strconv.Atoi(expStr)
	k := len(digits)
	n := exp + 1 // position of the decimal point relative to the digits
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		sign := "+"
		x := n - 1
		if x < 0 {
			sign = "-"
			x = -x
		}
		if k == 1 {
			out = digits + "e" + sign + strconv.Itoa(x)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + sign + strconv.Itoa(x)
		}
	}
	if neg {
		return "-" + out
	}
	return out
}
