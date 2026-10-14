// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package canonicaljson_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	canonicaljson "github.com/ori-platform/ori-canonicaljson"
)

// reasons are the refusals in the strict member rule's order of precedence,
// then the two that follow it.
var reasons = []error{
	canonicaljson.ErrInvalidUnicode,
	canonicaljson.ErrMalformedJSON,
	canonicaljson.ErrNestingTooDeep,
	canonicaljson.ErrTrailingData,
	canonicaljson.ErrDuplicateMember,
	canonicaljson.ErrCaseVariantMember,
	canonicaljson.ErrNotAnObject,
	canonicaljson.ErrMissingMember,
}

// requireReason requires err to be exactly the reason want, and no other.
func requireReason(t *testing.T, label string, err, want error) {
	t.Helper()
	if want == nil {
		if err != nil {
			t.Fatalf("%s: refused: %v", label, err)
		}
		return
	}
	for _, reason := range reasons {
		if errors.Is(err, reason) != (reason == want) {
			t.Fatalf("%s: err = %v, want exactly %v", label, err, want)
		}
	}
}

// nested wraps inner in depth objects. inner adds a level if it is a
// container.
func nested(depth int, inner string) string {
	return strings.Repeat(`{"a":`, depth) + inner + strings.Repeat("}", depth)
}

// strictCases are documents the strict member rule decides alone, without a
// shape. MarshalWire and DecodeStrict must agree on each.
var strictCases = []struct {
	name string
	doc  string
	want error
}{
	{"clean", `{"a":1,"b":[{"c":"d"}],"e":null}`, nil},
	{"clean with whitespace", " {\"a\" : 1 }\n\t", nil},
	{"empty object", `{}`, nil},

	{"duplicate at the top level", `{"status":"critical","status":"healthy"}`, canonicaljson.ErrDuplicateMember},
	{"duplicate in a nested object", `{"o":{"a":1,"a":2}}`, canonicaljson.ErrDuplicateMember},
	{"duplicate in an array element", `{"l":[{"a":1},{"a":1,"a":2}]}`, canonicaljson.ErrDuplicateMember},
	{"duplicate spelled with an escape", `{"status":1,"st\u0061tus":2}`, canonicaljson.ErrDuplicateMember},
	{"same name in sibling objects", `{"a":{"x":1},"b":{"x":1}}`, nil},

	{"ASCII case variants", `{"status":1,"STATUS":2}`, canonicaljson.ErrCaseVariantMember},
	{"long s", `{"status":1,"ſtatus":2}`, canonicaljson.ErrCaseVariantMember},
	{"long s escaped", `{"status":1,"\u017ftatus":2}`, canonicaljson.ErrCaseVariantMember},
	{"Kelvin sign", `{"k":1,"K":2}`, canonicaljson.ErrCaseVariantMember},
	{"Kelvin sign escaped", `{"k":1,"\u212a":2}`, canonicaljson.ErrCaseVariantMember},
	{"Kelvin sign against an upper-case K", `{"K":1,"K":2}`, canonicaljson.ErrCaseVariantMember},
	{"case variants in an array element", `{"l":[{"a":1,"A":2}]}`, canonicaljson.ErrCaseVariantMember},
	{"sharp s against capital sharp s", `{"ß":1,"ẞ":2}`, nil},
	{"sharp s escaped", `{"\u00df":1,"\u1e9e":2}`, nil},
	{"Greek final sigma", `{"σ":1,"ς":2,"Σ":3}`, nil},
	{"Greek final sigma escaped", `{"\u03c3":1,"\u03c2":2,"\u03a3":3}`, nil},
	{"Turkish dotted capital I", `{"i":1,"İ":2}`, nil},
	{"Turkish dotless i", `{"I":1,"ı":2}`, nil},
	{"Turkish escaped", `{"i":1,"\u0130":2,"I":3,"\u0131":4}`, canonicaljson.ErrCaseVariantMember},
	{"Turkish escaped without ASCII pairs", `{"i":1,"\u0130":2,"\u0131":4}`, nil},
	{"composed and decomposed e acute", "{\"é\":1,\"é\":2}", nil},

	{"depth 32", nested(32, `1`), nil},
	{"depth 32 ending in an empty array", nested(31, `[]`), nil},
	{"depth 33", nested(33, `1`), canonicaljson.ErrNestingTooDeep},
	{"depth 33 through arrays", strings.Repeat("[", 32) + strings.Repeat("]", 32), canonicaljson.ErrNotAnObject},
	{"depth 33 through arrays in an object", `{"a":` + strings.Repeat("[", 32) + strings.Repeat("]", 32) + `}`, canonicaljson.ErrNestingTooDeep},
	{"depth 20000", nested(20000, `1`), canonicaljson.ErrNestingTooDeep},

	{"NaN", `{"a":NaN}`, canonicaljson.ErrMalformedJSON},
	{"Infinity", `{"a":Infinity}`, canonicaljson.ErrMalformedJSON},
	{"negative Infinity", `{"a":-Infinity}`, canonicaljson.ErrMalformedJSON},
	{"empty", ``, canonicaljson.ErrMalformedJSON},
	{"truncated", `{"a":1`, canonicaljson.ErrMalformedJSON},
	{"single-quoted", `{'a':1}`, canonicaljson.ErrMalformedJSON},
	{"trailing comma", `{"a":1,}`, canonicaljson.ErrMalformedJSON},
	{"leading zero", `{"a":01}`, canonicaljson.ErrMalformedJSON},
	{"bare fraction", `{"a":.5}`, canonicaljson.ErrMalformedJSON},
	{"control character in a string", "{\"a\":\"x\ny\"}", canonicaljson.ErrMalformedJSON},
	{"invalid escape", `{"a":"\x"}`, canonicaljson.ErrMalformedJSON},

	{"trailing value", `{} {}`, canonicaljson.ErrTrailingData},
	{"trailing bytes", `{"a":1}x`, canonicaljson.ErrTrailingData},
	{"trailing NUL", "{\"a\":1}\x00", canonicaljson.ErrTrailingData},

	{"invalid UTF-8", "{\"a\":\"\xff\"}", canonicaljson.ErrInvalidUnicode},
	{"lone surrogate", `{"a":"\ud800"}`, canonicaljson.ErrInvalidUnicode},

	{"not an object", `[]`, canonicaljson.ErrNotAnObject},
	{"a scalar", `1`, canonicaljson.ErrNotAnObject},

	// Precedence: the earliest reason in the rule's table wins.
	{"a lone surrogate inside a duplicated member", `{"a":"\ud800","a":1}`, canonicaljson.ErrInvalidUnicode},
	{"a lone surrogate after malformed JSON", `{"a":NaN,"b":"\udc00"}`, canonicaljson.ErrInvalidUnicode},
	{"malformed JSON deeper than the bound", nested(40, `NaN`), canonicaljson.ErrMalformedJSON},
	{"malformed JSON after a duplicate", `{"a":1,"a":2,"b":}`, canonicaljson.ErrMalformedJSON},
	{"too deep and trailing", nested(33, `1`) + `x`, canonicaljson.ErrNestingTooDeep},
	{"a duplicate below the bound and nesting above it", `{"a":1,"a":2,"b":` + nested(33, `1`) + `}`, canonicaljson.ErrNestingTooDeep},
	{"a duplicate and trailing data", `{"a":1,"a":2} x`, canonicaljson.ErrTrailingData},
	{"a case variant before a duplicate", `{"A":1,"a":2,"a":3}`, canonicaljson.ErrDuplicateMember},
	{"a case variant and trailing data", `{"A":1,"a":2}x`, canonicaljson.ErrTrailingData},
	{"not an object and trailing data", `[] x`, canonicaljson.ErrTrailingData},
}

// TestStrictMemberRule runs every case through both entry points.
func TestStrictMemberRule(t *testing.T) {
	for _, c := range strictCases {
		t.Run(c.name, func(t *testing.T) {
			_, err := canonicaljson.DecodeStrict([]byte(c.doc), nil)
			requireReason(t, "DecodeStrict", err, c.want)
			_, err = canonicaljson.MarshalWire([]byte(c.doc))
			requireReason(t, "MarshalWire", err, c.want)
		})
	}
}

// TestShapeRefusals covers the refusals that need the contract's names.
func TestShapeRefusals(t *testing.T) {
	heartbeat := &canonicaljson.Shape{
		Members:  []string{"device_id", "status", "evidence"},
		Required: []string{"device_id", "status"},
		Objects: map[string]*canonicaljson.Shape{
			"evidence": {Members: []string{"available", "chain_head_hash"}, Required: []string{"available"}},
		},
	}
	for _, c := range []struct {
		name string
		doc  string
		want error
	}{
		{"conforming", `{"device_id":"d","status":"ok","evidence":{"available":true}}`, nil},
		{"an unknown member is tolerated", `{"device_id":"d","status":"ok","extra":1}`, nil},
		{"a case variant with no exact member", `{"device_id":"d","STATUS":"ok"}`, canonicaljson.ErrCaseVariantMember},
		{"a case variant beside the exact member", `{"device_id":"d","status":"critical","STATUS":"ok"}`, canonicaljson.ErrCaseVariantMember},
		{"a long s variant", `{"device_id":"d","ſtatus":"ok"}`, canonicaljson.ErrCaseVariantMember},
		{"a nested case variant", `{"device_id":"d","status":"ok","evidence":{"Available":true}}`, canonicaljson.ErrCaseVariantMember},
		{"a nested unknown member", `{"device_id":"d","status":"ok","evidence":{"available":true,"x":1}}`, nil},
		{"a missing required member", `{"device_id":"d"}`, canonicaljson.ErrMissingMember},
		{"a missing nested required member", `{"device_id":"d","status":"ok","evidence":{}}`, canonicaljson.ErrMissingMember},
		{"a nested shape is not applied to an array", `{"device_id":"d","status":"ok","evidence":[{"Available":true}]}`, nil},
		{"a case variant outranks a missing member", `{"device_id":"d","STATUS":"ok"}`, canonicaljson.ErrCaseVariantMember},
		{"a duplicate outranks a case variant", `{"device_id":"d","STATUS":"ok","STATUS":"ok"}`, canonicaljson.ErrDuplicateMember},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := canonicaljson.DecodeStrict([]byte(c.doc), heartbeat)
			requireReason(t, "DecodeStrict", err, c.want)
		})
	}
}

// TestDecodeStrictReturnsMembersAsTheyArrived requires each member, by its
// exact unescaped name, to carry the bytes it arrived as.
func TestDecodeStrictReturnsMembersAsTheyArrived(t *testing.T) {
	doc := `{"st\u0061tus" : "ok", "n": 1.50E+3, "o" : { "b":[1, 2] } }`
	members, err := canonicaljson.DecodeStrict([]byte(doc), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"status": `"ok"`, "n": `1.50E+3`, "o": `{ "b":[1, 2] }`} {
		if got := string(members[name]); got != want {
			t.Errorf("member %q = %s, want %s", name, got, want)
		}
	}
	if len(members) != 3 {
		t.Errorf("members = %v, want three", members)
	}
}

// TestACanonicalDocumentRoundTrips requires a clean document already in
// canonical form to come back from MarshalWire byte for byte.
func TestACanonicalDocumentRoundTrips(t *testing.T) {
	for _, doc := range []string{
		`{}`,
		`{"a":1,"b":[true,false,null],"c":{"d":"<&> "}}`,
		`{"ß":1,"σ":"ς","ẞ":2}`,
		nested(32, `"deep"`),
	} {
		got, err := canonicaljson.MarshalWire([]byte(doc))
		if err != nil {
			t.Fatalf("MarshalWire(%.40s): %v", doc, err)
		}
		if !bytes.Equal(got, []byte(doc)) {
			t.Errorf("MarshalWire(%.40s) = %.40s, want the same bytes", doc, got)
		}
	}
}

// TestTheClosedFoldIsWhatTheStructDecoderMatches sweeps every Unicode scalar
// value. For each, encoding/json either matches it to an ASCII struct field or
// does not, and the closed fold must agree: DecodeStrict refuses it as a case
// variant of the field's name exactly when the decoder matches it. Only
// U+017F and U+212A match today. A toolchain whose decoder matches another
// code point fails here, naming it, so the closed fold cannot fall behind the
// decoder it protects.
func TestTheClosedFoldIsWhatTheStructDecoderMatches(t *testing.T) {
	fields := make([]reflect.StructField, 0, 26)
	names := make([]string, 0, 26)
	for c := 'a'; c <= 'z'; c++ {
		fields = append(fields, reflect.StructField{
			Name: "F" + string(unicode.ToUpper(c)), Type: reflect.TypeFor[*int](),
			Tag: reflect.StructTag(`json:"` + string(c) + `"`),
		})
		names = append(names, string(c))
	}
	typ := reflect.StructOf(fields)
	shape := &canonicaljson.Shape{Members: names}
	var nonASCII []rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) || (r >= 'a' && r <= 'z') {
			continue
		}
		doc, err := json.Marshal(map[string]int{string(r): 1})
		if err != nil {
			t.Fatal(err)
		}
		v := reflect.New(typ)
		if err := json.Unmarshal(doc, v.Interface()); err != nil {
			t.Fatalf("U+%04X: %v", r, err)
		}
		matched := false
		for i := range fields {
			matched = matched || !v.Elem().Field(i).IsNil()
		}
		_, err = canonicaljson.DecodeStrict(doc, shape)
		refused := errors.Is(err, canonicaljson.ErrCaseVariantMember)
		if matched != refused {
			t.Fatalf("U+%04X %q: encoding/json matches it to an ASCII field: %v; the closed fold refuses it: %v (%v)",
				r, string(r), matched, refused, err)
		}
		if matched && r > unicode.MaxASCII {
			nonASCII = append(nonASCII, r)
		}
	}
	if fmt.Sprint(nonASCII) != fmt.Sprint([]rune{'ſ', 'K'}) {
		t.Fatalf("non-ASCII code points the decoder matches = %U, want U+017F and U+212A", nonASCII)
	}
}

// FuzzTheScannerAgreesWithEncodingJSON is a differential: on any input with
// valid Unicode and nesting within MaxNestingDepth, the strict scan finds
// malformed or trailing data exactly when json.Valid refuses it.
func FuzzTheScannerAgreesWithEncodingJSON(f *testing.F) {
	for _, c := range strictCases {
		f.Add([]byte(c.doc))
	}
	for _, seed := range []string{`{"a":-0.0e-0}`, `{"a":"\/\b\f\n\r\té"}`, `{"a":[[],{}]}`, `{"a":1e5,"b":-1E+2}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, doc []byte) {
		if canonicaljson.ValidateWireUnicode(doc) != nil || bytes.Count(doc, []byte("{"))+bytes.Count(doc, []byte("[")) > 9000 {
			return
		}
		_, err := canonicaljson.DecodeStrict(doc, nil)
		if errors.Is(err, canonicaljson.ErrNestingTooDeep) {
			// It outranks trailing data, which the scan then does not report.
			return
		}
		invalid := errors.Is(err, canonicaljson.ErrMalformedJSON) || errors.Is(err, canonicaljson.ErrTrailingData)
		if invalid == json.Valid(doc) {
			t.Fatalf("%q: strict scan err = %v, json.Valid = %v", doc, err, json.Valid(doc))
		}
	})
}

// TestHostileDepthCostsNoAllocationPerLevel scans documents a million levels
// deep. Past the bound a level only needs parsing, so a hostile depth must not
// cost an allocation a level: the scan stays within a fixed budget, whatever
// the depth, and still names the right refusal.
func TestHostileDepthCostsNoAllocationPerLevel(t *testing.T) {
	const depth = 1_000_000
	for _, c := range []struct {
		name string
		doc  []byte
		want error
	}{
		{"objects", []byte(nested(depth, `1`)), canonicaljson.ErrNestingTooDeep},
		{"arrays", []byte(`{"a":` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + `}`), canonicaljson.ErrNestingTooDeep},
		{"objects never closed", []byte(strings.Repeat(`{"a":`, depth)), canonicaljson.ErrMalformedJSON},
	} {
		t.Run(c.name, func(t *testing.T) {
			var err error
			allocs := testing.AllocsPerRun(1, func() {
				_, err = canonicaljson.DecodeStrict(c.doc, nil)
			})
			requireReason(t, "DecodeStrict", err, c.want)
			if allocs > 500 {
				t.Fatalf("the scan made %.0f allocations for %d levels; a level past the bound must cost none", allocs, depth)
			}
		})
	}
}
