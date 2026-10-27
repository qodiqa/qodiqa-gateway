package qodiqa

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"
)

// TransparencyDetail is the outcome of each check of a transparency inclusion proof.
type TransparencyDetail struct {
	EntryHashValid      bool
	MerklePathValid     bool
	EntrySignatureValid bool
	RootSignatureValid  bool
	LeafIndexValid      bool
	KeyValid            bool
	KeyStatus           string
}

// AllPassed is true only when every check passed.
func (d *TransparencyDetail) AllPassed() bool {
	return d.EntryHashValid && d.MerklePathValid && d.LeafIndexValid && d.KeyValid && d.EntrySignatureValid && d.RootSignatureValid
}

// MerklePathStep is one sibling of a Merkle inclusion path.
type MerklePathStep struct {
	Hash string
	Side string // left | right
}

var (
	canonicalEntryFields = []string{"transparencyId", "entryType", "artifactId", "evidenceChainId", "verificationId", "payloadHash", "previousEntryHash", "signerKeyId"}
	canonicalRootFields  = []string{"rootId", "seqFrom", "seqTo", "entryCount", "rootHash", "previousRootHash"}
)

func pick(rec map[string]any, fields []string) map[string]any {
	out := make(map[string]any, len(fields))
	for _, f := range fields {
		if v, ok := rec[f]; ok {
			out[f] = v
		} else {
			out[f] = nil
		}
	}
	return out
}

func computeEntryHash(entry map[string]any) (string, error) {
	c, err := Canonicalize(pick(entry, canonicalEntryFields))
	if err != nil {
		return "", err
	}
	return DomainHashHex(DomainTransparencyEntry, c), nil
}

func computeRootSigningBuffer(root map[string]any) ([]byte, error) {
	c, err := Canonicalize(pick(root, canonicalRootFields))
	if err != nil {
		return nil, err
	}
	return DomainHash(DomainTransparencyRoot, c), nil
}

func leafHash(entryHashHex string) ([]byte, bool) {
	raw, err := hex.DecodeString(entryHashHex)
	if err != nil {
		return nil, false
	}
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(raw)
	return h.Sum(nil), true
}

func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// ExpectedPathSides returns the sides a path for (leafIndex, treeSize) must have (RFC 6962 shape, leaf-first); nil for an impossible index.
func ExpectedPathSides(leafIndex, treeSize int64) []string {
	if leafIndex < 0 || treeSize <= 0 || leafIndex >= treeSize {
		return nil
	}
	sides := []string{}
	size, idx := treeSize, leafIndex
	for size > 1 {
		k := int64(1)
		for k*2 < size {
			k *= 2
		}
		if idx < k {
			sides = append(sides, "right")
			size = k
		} else {
			sides = append(sides, "left")
			idx -= k
			size -= k
		}
	}
	for i, j := 0, len(sides)-1; i < j; i, j = i+1, j-1 {
		sides[i], sides[j] = sides[j], sides[i]
	}
	return sides
}

// VerifyInclusionPath recomputes the root from a leaf and its path and checks the path's shape against (leafIndex, treeSize).
func VerifyInclusionPath(entryHashHex string, path []MerklePathStep, rootHex string, leafIndex, treeSize int64) bool {
	if entryHashHex == "" || rootHex == "" {
		return false
	}
	sides := ExpectedPathSides(leafIndex, treeSize)
	if sides == nil || len(path) != len(sides) {
		return false
	}
	for i := range sides {
		if path[i].Side != sides[i] {
			return false
		}
	}
	cur, ok := leafHash(entryHashHex)
	if !ok {
		return false
	}
	for _, step := range path {
		sib, err := hex.DecodeString(step.Hash)
		if err != nil {
			return false
		}
		if step.Side == "right" {
			cur = nodeHash(cur, sib)
		} else {
			cur = nodeHash(sib, cur)
		}
	}
	return hex.EncodeToString(cur) == rootHex
}

// jsNumberToInt mirrors JavaScript Number(x) followed by Number.isInteger.
func jsNumberToInt(v any) (int64, bool) {
	var f float64
	switch t := v.(type) {
	case json.Number:
		x, err := strconv.ParseFloat(string(t), 64)
		if err != nil {
			return 0, false
		}
		f = x
	case float64:
		f = t
	case string:
		x, err := strconv.ParseFloat(t, 64)
		if err != nil {
			return 0, false
		}
		f = x
	default:
		return 0, false
	}
	if f != math.Floor(f) || math.Abs(f) > maxSafeInteger {
		return 0, false
	}
	return int64(f), true
}

func asMap(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }
func asString(v any) string              { s, _ := v.(string); return s }

// VerifyTransparencyProof checks an inclusion proof (proof version 2) against a transparency trust bundle. It never panics on malformed input: every check that cannot be made is false.
func VerifyTransparencyProof(proof map[string]any, keys KeyProvider) *TransparencyDetail {
	d := &TransparencyDetail{}
	if proof == nil {
		return d
	}
	entry, ok1 := asMap(proof["entry"])
	root, ok2 := asMap(proof["root"])
	pd, ok3 := asMap(proof["proof"])
	if !ok1 || !ok2 || !ok3 {
		return d
	}
	if asString(proof["proofVersion"]) != "2" || asString(proof["proofType"]) != "TRANSPARENCY_INCLUSION" {
		return d
	}
	if h, err := computeEntryHash(entry); err == nil {
		d.EntryHashValid = h == asString(entry["entryHash"])
	}
	leafIndex, okL := jsNumberToInt(pd["leafIndex"])
	treeSize, okT := jsNumberToInt(pd["treeSize"])
	d.LeafIndexValid = okL && okT && leafIndex >= 0 && leafIndex < treeSize

	entryCount, okC := jsNumberToInt(root["entryCount"])
	pathValid := false
	if okC && okT && okL && entryCount == treeSize {
		var path []MerklePathStep
		valid := true
		if arr, ok := pd["merklePath"].([]any); ok {
			for _, it := range arr {
				m, ok := asMap(it)
				if !ok {
					valid = false
					break
				}
				side := asString(m["side"])
				if _, isStr := m["hash"].(string); !isStr || (side != "left" && side != "right") {
					valid = false
					break
				}
				path = append(path, MerklePathStep{Hash: asString(m["hash"]), Side: side})
			}
		} else {
			valid = false
		}
		pathValid = valid && VerifyInclusionPath(asString(entry["entryHash"]), path, asString(root["rootHash"]), leafIndex, treeSize)
	}
	mr, isStr := pd["merkleRoot"].(string)
	d.MerklePathValid = pathValid && isStr && mr == asString(root["rootHash"])

	if k, err := keys.PublicKey(asString(entry["signerKeyId"])); err == nil && k != nil {
		d.KeyValid = k.Status == "active" || k.Status == "deprecated"
		d.KeyStatus = k.Status
		if d.KeyValid {
			if h, err := hex.DecodeString(computeEntryHashOrEmpty(entry)); err == nil {
				d.EntrySignatureValid = VerifyEd25519(h, asString(entry["signature"]), k.PubDER)
			}
		}
	}
	if k, err := keys.PublicKey(asString(root["signerKeyId"])); err == nil && k != nil && (k.Status == "active" || k.Status == "deprecated") {
		if buf, err := computeRootSigningBuffer(root); err == nil {
			d.RootSignatureValid = VerifyEd25519(buf, asString(root["signature"]), k.PubDER)
		}
	}
	return d
}

func computeEntryHashOrEmpty(entry map[string]any) string {
	h, err := computeEntryHash(entry)
	if err != nil {
		return ""
	}
	return h
}
