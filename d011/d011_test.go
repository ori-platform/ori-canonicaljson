// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package d011_test

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/ori-platform/ori-canonicaljson/d011"
)

// TestFloatBoundaries pins the zone in both directions. The boundary is
// inclusive below and exclusive above, so both sides need a case: a rule tested
// only from the outside passes when the comparison is written backwards.
func TestFloatBoundaries(t *testing.T) {
	admitted := []float64{1e-4, 1.0000000000000002e-4, 6.4, 9.999999999999998e15}
	for _, f := range admitted {
		if _, err := d011.Float(f); err != nil {
			t.Errorf("Float(%v) refused inside the zone: %v", f, err)
		}
	}
	refused := []float64{9.999999999999999e-5, 1e-5, 0, 1e16, 1.1e16}
	for _, f := range refused {
		if f == 0 {
			continue // zero is admitted exactly; covered separately
		}
		if _, err := d011.Float(f); err == nil {
			t.Errorf("Float(%v) admitted outside the zone", f)
		}
	}
}

// TestZeroAndNegativeZero pins the one value the magnitude rule cannot judge.
//
// Negative zero is a distinct IEEE-754 value and Python writes it "-0.0".
// Normalising it here would change the bytes a producer signs without changing
// the value it was handed, which is the class of silent rewrite this module
// exists to prevent.
func TestZeroAndNegativeZero(t *testing.T) {
	pos, err := d011.Float(0)
	if err != nil {
		t.Fatalf("Float(0): %v", err)
	}
	if pos.String() != "0.0" {
		t.Errorf("Float(0) = %q, python writes \"0.0\"", pos.String())
	}
	neg, err := d011.Float(math.Copysign(0, -1))
	if err != nil {
		t.Fatalf("Float(-0): %v", err)
	}
	if neg.String() != "-0.0" {
		t.Errorf("Float(-0) = %q, python writes \"-0.0\"", neg.String())
	}
	if pos.String() == neg.String() {
		t.Error("negative zero was normalised away; the signed bytes would differ from the input")
	}
}

// TestNonFinite covers the values that have no canonical spelling at all.
func TestNonFinite(t *testing.T) {
	for _, f := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := d011.Float(f); err == nil {
			t.Errorf("Float(%v) admitted a non-finite value", f)
		}
	}
}

// TestIntBoundaries pins 2^53-1 on both sides and in both signs.
func TestIntBoundaries(t *testing.T) {
	for _, n := range []int64{0, 1, -1, d011.MaxSafeInteger, -d011.MaxSafeInteger} {
		if _, err := d011.Int(n); err != nil {
			t.Errorf("Int(%d) refused inside the zone: %v", n, err)
		}
	}
	for _, n := range []int64{d011.MaxSafeInteger + 1, -(d011.MaxSafeInteger + 1)} {
		if _, err := d011.Int(n); err == nil {
			t.Errorf("Int(%d) admitted above 2^53-1", n)
		}
	}
}

// TestFloatNeverEmitsExponentNotation is the property that makes the zone
// worth having: exponent notation is where the two languages disagree, so it
// must not appear on the wire for any admitted value.
func TestFloatNeverEmitsExponentNotation(t *testing.T) {
	for _, f := range []float64{1e-4, 1e-3, 1e15, 9.99e15, 0.00012345} {
		n, err := d011.Float(f)
		if err != nil {
			t.Fatalf("Float(%v): %v", f, err)
		}
		for _, c := range n.String() {
			if c == 'e' || c == 'E' {
				t.Errorf("Float(%v) = %q uses exponent notation", f, n.String())
			}
		}
	}
}

// TestAdmitRoundTripsEveryProducedValue ties the two halves together: anything
// this package produces, it must also accept.
func TestAdmitRoundTripsEveryProducedValue(t *testing.T) {
	for _, f := range []float64{0, math.Copysign(0, -1), 1e-4, 6.4, 10, 100, 9.99e15} {
		n, err := d011.Float(f)
		if err != nil {
			t.Fatalf("Float(%v): %v", f, err)
		}
		if err := d011.Admit(n); err != nil {
			t.Errorf("Admit(%q) refused a value this package produced: %v", n.String(), err)
		}
	}
	for _, i := range []int64{0, 1, -1, d011.MaxSafeInteger} {
		n, err := d011.Int(i)
		if err != nil {
			t.Fatalf("Int(%d): %v", i, err)
		}
		if err := d011.Admit(n); err != nil {
			t.Errorf("Admit(%q) refused a value this package produced: %v", n.String(), err)
		}
	}
}

// TestAdmitRefusesNonCanonicalSpellings is the consumer-side rule. Bytes are
// the contract, so an in-zone value written another way is still refused.
func TestAdmitRefusesNonCanonicalSpellings(t *testing.T) {
	for _, bad := range []string{"1e3", "1E3", "0.020", "10.00", "+26", "010", "10.", ".5", "", "nan", "Infinity"} {
		if err := d011.Admit(json.Number(bad)); err == nil {
			t.Errorf("Admit(%q) accepted a non-canonical spelling", bad)
		}
	}
}
