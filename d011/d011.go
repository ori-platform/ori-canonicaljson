// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

// Package d011 admits numbers into the cross-language agreement zone that
// evidence artifacts and commissioned bindings sign over.
//
// The zone comes from ori-edge-firmware D-011 and is normative in
// ori-specs/firmware-telemetry/v1, evidence/v2 and
// commissioned-safety-binding/v1: integers satisfy |n| <= 2^53-1; non-integers
// are finite and either exactly zero or of magnitude in [1e-4, 1e16); every
// number is written as the shortest round-trip decimal in fixed notation, and
// a non-integer carries a mandatory fractional part. Exponent notation never
// appears on the wire.
//
// The zone exists because unconstrained shortest-round-trip formatting
// disagrees across languages outside it, and the disagreement is invisible: two
// implementations produce different preimages for the same value and one
// signature simply fails to verify.
//
// # Why this is a separate package
//
// Encoding is not numeric policy. The gateway's MQTT transport preserves the
// spelling it received because it carries telemetry whose range is legitimately
// broader than the zone; imposing D-011 there would reject working readings
// such as 5e-05. A producer of evidence or bindings has the opposite
// obligation. Keeping admission out of the encoder lets one canonical writer
// serve both.
//
// # Why it never takes a float64 on the way out
//
// Go's encoding/json renders float64(10) as "10" while Python's canonical form
// writes "10.0". Every commissioned binding carries integral floats -- rated
// capacities, sensor ranges, noise floors -- so a Go producer that let a bare
// float64 reach the encoder would emit different bytes for every document, and
// the only symptom would be a signature that does not verify. The constructors
// here return json.Number, which canonicaljson accepts and a float64 is not,
// so that mistake cannot be made silently.
package d011

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// MaxSafeInteger is 2^53-1, the largest integer every consumer in the
// agreement zone represents exactly.
const MaxSafeInteger = 1<<53 - 1

// Non-integer magnitude bounds. Zero is admitted separately and exactly.
const (
	minMagnitude = 1e-4
	maxMagnitude = 1e16
)

// Int returns n as a canonical JSON number, or an error if it falls outside
// the agreement zone.
func Int(n int64) (json.Number, error) {
	if n > MaxSafeInteger || n < -MaxSafeInteger {
		return "", fmt.Errorf("d011: integer %d is outside the agreement zone", n)
	}
	return json.Number(strconv.FormatInt(n, 10)), nil
}

// Float returns f as a canonical JSON number in fixed notation with a
// mandatory fractional part, or an error if it falls outside the agreement
// zone.
//
// Exactly zero is admitted and rendered "0.0". Negative zero is preserved as
// "-0.0": it is a distinct IEEE-754 value, and rewriting it would change the
// bytes a producer signs without changing the value it was given.
func Float(f float64) (json.Number, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("d011: %v is not a finite number", f)
	}
	if f != 0 {
		if m := math.Abs(f); m < minMagnitude || m >= maxMagnitude {
			return "", fmt.Errorf(
				"d011: float %v is outside the agreement zone [%v, %v)",
				f, minMagnitude, maxMagnitude,
			)
		}
	}
	// 'f' is fixed notation and -1 is shortest round-trip. Together they are
	// the D-011 rule; either alone is not.
	text := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.ContainsRune(text, '.') {
		text += ".0"
	}
	return json.Number(text), nil
}

// Admit checks a number already on the wire, without reformatting it. Consumers
// use this; producers use Int and Float.
//
// The spelling is checked as well as the value. A number that parses inside the
// zone but was written some other way -- "1e3", "10", "0.10" -- is refused,
// because the bytes are the contract and a consumer that accepted an
// alternative spelling would disagree with the producer about the preimage
// while agreeing about the value.
func Admit(n json.Number) error {
	text := n.String()
	if text == "" {
		return fmt.Errorf("d011: empty number")
	}
	if strings.ContainsAny(text, "eE") {
		return fmt.Errorf("d011: %q uses exponent notation", text)
	}
	if strings.Contains(text, ".") {
		f, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return fmt.Errorf("d011: %q is not a number: %w", text, err)
		}
		canonical, err := Float(f)
		if err != nil {
			return err
		}
		if canonical.String() != text {
			return fmt.Errorf(
				"d011: %q is not the canonical spelling of its value (%q)",
				text, canonical.String(),
			)
		}
		return nil
	}
	i, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return fmt.Errorf("d011: %q is not an integer: %w", text, err)
	}
	canonical, err := Int(i)
	if err != nil {
		return err
	}
	if canonical.String() != text {
		return fmt.Errorf(
			"d011: %q is not the canonical spelling of its value (%q)",
			text, canonical.String(),
		)
	}
	return nil
}
