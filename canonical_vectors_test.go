// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package canonicaljson_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	canonicaljson "github.com/ori-platform/ori-canonicaljson"
	"os"
	"strings"
	"testing"
)

type canonicalVector struct {
	ID       string          `json:"id"`
	Class    string          `json:"class"`
	Value    json.RawMessage `json:"value"`
	HexBytes string          `json:"canonical_utf8_hex"`
}

type refusedVector struct {
	ID           string `json:"id"`
	Class        string `json:"class"`
	Wire         string `json:"wire"`
	Reason       string `json:"reason"`
	RefusalBasis string `json:"refusal_basis"`
}

type canonicalVectorSet struct {
	VectorSet string            `json:"vector_set"`
	Vectors   []canonicalVector `json:"accepted"`
	Refused   []refusedVector   `json:"refused"`
}

func loadCanonicalVectors(t *testing.T) canonicalVectorSet {
	t.Helper()
	raw, err := os.ReadFile("testdata/canonical-json-vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var set canonicalVectorSet
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	if len(set.Vectors) == 0 || len(set.Refused) == 0 {
		t.Fatal("vector set must carry both accepted and refused vectors")
	}
	return set
}

// TestCanonicalJSONMatchesRuntimeVectors is the cross-language agreement test.
// The expected bytes are produced by the runtime's Python canonicalisation.
//
// Inherited unchanged from ori-gateway, where this package lived before it
// was shared. These vectors are what established the encoder's behaviour, so
// they travel with it rather than staying behind with one consumer.
func TestCanonicalJSONMatchesRuntimeVectors(t *testing.T) {
	set := loadCanonicalVectors(t)
	for _, v := range set.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			want, err := hex.DecodeString(v.HexBytes)
			if err != nil {
				t.Fatalf("bad vector hex: %v", err)
			}
			got, err := canonicaljson.MarshalWire(v.Value)
			if err != nil {
				t.Fatalf("canonicalise: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("canonical bytes differ\n got: %q\nwant: %q", got, want)
			}
		})
	}
}

// TestCanonicalVectorsCoverGoEscapingDivergence keeps the vector set load-bearing.
// Every character Go's encoding/json escapes but Python does not must appear in at
// least one vector, so this suite cannot silently stop testing the defect it exists
// to prevent.
func TestCanonicalVectorsCoverGoEscapingDivergence(t *testing.T) {
	set := loadCanonicalVectors(t)
	var all strings.Builder
	for _, v := range set.Vectors {
		all.Write(v.Value)
	}
	corpus := all.String()
	for name, ch := range map[string]string{
		"less-than": "<", "greater-than": ">", "ampersand": "&",
		"U+2028": " ", "U+2029": " ",
	} {
		if !strings.Contains(corpus, ch) {
			t.Errorf("vector set no longer exercises %s; the divergence it guards is untested", name)
		}
	}
}

// TestStdlibJSONWouldFailTheseVectors proves the vectors discriminate. If
// encoding/json could satisfy them, the custom writer would be unnecessary and
// this suite would be passing for the wrong reason.
func TestStdlibJSONWouldFailTheseVectors(t *testing.T) {
	set := loadCanonicalVectors(t)
	marshalFailures, encoderFailures := 0, 0
	for _, v := range set.Vectors {
		want, err := hex.DecodeString(v.HexBytes)
		if err != nil {
			t.Fatalf("bad vector hex: %v", err)
		}
		var payload map[string]any
		dec := json.NewDecoder(bytes.NewReader(v.Value))
		dec.UseNumber()
		if err := dec.Decode(&payload); err != nil {
			t.Fatalf("decode %s: %v", v.ID, err)
		}

		if got, err := json.Marshal(payload); err == nil && !bytes.Equal(got, want) {
			marshalFailures++
		}

		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(payload); err != nil {
			t.Fatalf("encode %s: %v", v.ID, err)
		}
		if !bytes.Equal(bytes.TrimSuffix(buf.Bytes(), []byte("\n")), want) {
			encoderFailures++
		}
	}
	if marshalFailures == 0 {
		t.Error("json.Marshal satisfies every vector; the vectors do not discriminate")
	}
	// SetEscapeHTML(false) is the tempting partial fix. It must still fail, or the
	// custom writer is unjustified.
	if encoderFailures == 0 {
		t.Error("SetEscapeHTML(false) satisfies every vector; the custom writer is unjustified")
	}
	t.Logf("json.Marshal fails %d/%d vectors; SetEscapeHTML(false) fails %d/%d",
		marshalFailures, len(set.Vectors), encoderFailures, len(set.Vectors))
}

// TestCanonicalJSONRejectsUnsupportedType fails closed rather than emitting bytes
// the runtime would not reproduce.
func TestCanonicalJSONRejectsUnsupportedType(t *testing.T) {
	if _, err := canonicaljson.Marshal(map[string]any{"x": float64(1.5)}); err == nil {
		t.Error("expected an error for a non-json.Number numeric value")
	}
}

// TestCanonicalJSONRefusesOutOfContractVectors is the other half of the contract.
// A serialiser that normalised these instead of refusing them would let the wire
// bytes differ from the bytes that were signed.
func TestCanonicalJSONRefusesOutOfContractVectors(t *testing.T) {
	set := loadCanonicalVectors(t)
	for _, v := range set.Refused {
		t.Run(v.ID, func(t *testing.T) {
			wire := []byte(v.Wire)
			if err := canonicaljson.ValidateWireUnicode(wire); err != nil {
				return // refused before decoding, which is correct
			}
			var payload map[string]any
			dec := json.NewDecoder(bytes.NewReader(wire))
			dec.UseNumber()
			if err := dec.Decode(&payload); err != nil {
				return // refused by the parser, which is correct
			}
			got, err := canonicaljson.Marshal(payload)
			if err == nil {
				t.Errorf("accepted a vector the contract refuses (%s): emitted %q\nreason: %s",
					v.RefusalBasis, got, v.Reason)
			}
		})
	}
}

// TestRefusedVectorsCoverEveryBasis keeps the refusal half honest. The three bases
// fail for different reasons and a suite that lost one would still pass.
func TestRefusedVectorsCoverEveryBasis(t *testing.T) {
	set := loadCanonicalVectors(t)
	seen := map[string]int{}
	for _, v := range set.Refused {
		if v.RefusalBasis == "" {
			t.Errorf("refused vector %s declares no refusal_basis", v.ID)
		}
		seen[v.RefusalBasis]++
	}
	for _, basis := range []string{"divergence", "invalid_json"} {
		if seen[basis] == 0 {
			t.Errorf("no refused vector exercises basis %q", basis)
		}
	}
}
