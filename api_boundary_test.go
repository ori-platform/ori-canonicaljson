// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package canonicaljson_test

import (
	"encoding/json"
	"strings"
	"testing"

	canonicaljson "github.com/ori-platform/ori-canonicaljson"
)

// These pin the public boundary. Everything here is a property a consumer is
// entitled to rely on, so a change that breaks one is a breaking change to the
// module rather than an implementation detail.

// TestMarshalRefusesEveryGoNumericType is the central safety property.
//
// encoding/json renders float64(10) as "10" where the canonical form writes
// "10.0". Every commissioned binding carries integral floats, so a bare Go
// number reaching the encoder would produce a different preimage for every
// document — and the only symptom is a signature that does not verify, with
// nothing pointing at the encoder. Refusing the type is what makes that
// mistake impossible rather than merely discouraged.
func TestMarshalRefusesEveryGoNumericType(t *testing.T) {
	for name, v := range map[string]any{
		"float64": float64(10),
		"float32": float32(10),
		"int":     int(10),
		"int64":   int64(10),
		"uint64":  uint64(10),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := canonicaljson.Marshal(map[string]any{"a": v}); err == nil {
				t.Fatalf("Marshal accepted a bare %s; only json.Number is admissible", name)
			}
		})
	}
}

// TestMarshalPreservesNumberSpelling is the other half of that contract. The
// encoder must not reformat what a producer already decided, in either
// direction: a transport preserving wire spelling and a producer emitting
// D-011 both depend on the bytes surviving untouched.
func TestMarshalPreservesNumberSpelling(t *testing.T) {
	for _, spelling := range []string{"10", "10.0", "0.02", "5e-05", "-0.0", "1E3", "1800000000000"} {
		got, err := canonicaljson.Marshal(map[string]any{"a": json.Number(spelling)})
		if err != nil {
			t.Fatalf("Marshal(%q): %v", spelling, err)
		}
		want := `{"a":` + spelling + `}`
		if string(got) != want {
			t.Errorf("Marshal(%q) = %s, want %s", spelling, got, want)
		}
	}
}

// TestMarshalWireRefusesMalformedUnicode covers the divergence that is worse
// than a crash: Go's decoder substitutes U+FFFD for a lone surrogate while
// Python surfaces it and then fails to encode, so the two sides would
// canonicalise different text from identical input. Only refusal keeps them
// equivalent.
func TestMarshalWireRefusesMalformedUnicode(t *testing.T) {
	cases := map[string]string{
		"unpaired high surrogate":  `{"a":"\ud800"}`,
		"unpaired low surrogate":   `{"a":"\udc00"}`,
		"high not followed by low": `{"a":"\ud800x"}`,
		"truncated escape":         `{"a":"\ud80"}`,
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := canonicaljson.MarshalWire([]byte(wire)); err == nil {
				t.Fatal("MarshalWire accepted input the two runtimes would not agree on")
			}
		})
	}
	if _, err := canonicaljson.MarshalWire([]byte("{\"a\":\"\xff\xfe\"}")); err == nil {
		t.Fatal("MarshalWire accepted invalid UTF-8")
	}
}

// TestMarshalWireAcceptsPairedSurrogates guards the opposite error. A correctly
// paired surrogate escape is ordinary astral-plane text and must survive, or
// the refusal above would be rejecting valid documents.
func TestMarshalWireAcceptsPairedSurrogates(t *testing.T) {
	got, err := canonicaljson.MarshalWire([]byte(`{"a":"😀"}`))
	if err != nil {
		t.Fatalf("MarshalWire refused a valid surrogate pair: %v", err)
	}
	if !strings.Contains(string(got), "\U0001F600") {
		t.Errorf("expected the decoded astral character, got %s", got)
	}
}

// TestMarshalWireRefusesTrailingBytes stops a second document riding along
// behind the one that gets signed.
func TestMarshalWireRefusesTrailingBytes(t *testing.T) {
	if _, err := canonicaljson.MarshalWire([]byte(`{"a":"1"} {"b":"2"}`)); err == nil {
		t.Fatal("MarshalWire accepted trailing bytes after the document")
	}
}

// TestMarshalSortsKeysByCodePoint pins the ordering rule against the UTF-16
// alternative, which disagrees across the BMP/astral boundary.
func TestMarshalSortsKeysByCodePoint(t *testing.T) {
	got, err := canonicaljson.Marshal(map[string]any{
		"\U0001F600": json.Number("1"),
		"＀":          json.Number("2"),
		"a":          json.Number("3"),
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := "{\"a\":3,\"＀\":2,\"\U0001F600\":1}"
	if string(got) != want {
		t.Errorf("key order = %s, want %s", got, want)
	}
}
