// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package canonicaljson_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	canonicaljson "github.com/ori-platform/ori-canonicaljson"
	"github.com/ori-platform/ori-canonicaljson/d011"
)

// The commissioned-safety-binding corpus is vendored here rather than fetched,
// so public CI proves these cases rather than skipping them when an
// environment variable happens to be unset. ORI_BINDING_VECTORS overrides the
// path for running against a live ori-specs checkout.
const (
	corpusEnv  = "ORI_BINDING_VECTORS"
	corpusDir  = "testdata/vectors/commissioned_safety_binding"
	corpusFile = "binding-vectors-v1.json"
)

type vectorCase struct {
	Name            string          `json:"name"`
	Binding         json.RawMessage `json:"binding"`
	FirmwareProfile json.RawMessage `json:"firmware_profile"`
	CanonicalHex    string          `json:"canonical_hex"`
	CanonicalSHA256 string          `json:"canonical_sha256"`
	MessageHex      string          `json:"message_hex"`
	SignatureB64    string          `json:"signature_b64"`
}

type corpus struct {
	CommissioningPublicKeyHex string       `json:"commissioning_public_key_hex"`
	Cases                     []vectorCase `json:"cases"`
	RejectCases               []vectorCase `json:"reject_cases"`
	ProfileCases              []vectorCase `json:"firmware_profile_cases"`
	ProfileRejectCases        []vectorCase `json:"firmware_profile_reject_cases"`
}

func decodeCanonical(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

// TestVendoredCorpusMatchesItsManifest is the local-edit check. Upstream drift
// is a separate concern: this module pins one ori-specs commit, and moving that
// pin is a deliberate change reviewed on its own.
func TestVendoredCorpusMatchesItsManifest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(corpusDir, "MANIFEST.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m struct {
		SourceRepository string            `json:"source_repository"`
		SourceCommit     string            `json:"source_commit"`
		Files            map[string]string `json:"files"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if m.SourceRepository == "" || m.SourceCommit == "" || len(m.Files) == 0 {
		t.Fatal("manifest carries no provenance")
	}
	for name, want := range m.Files {
		body, err := os.ReadFile(filepath.Join(corpusDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if got := hex.EncodeToString(sha256Sum(body)); got != want {
			t.Fatalf("%s was edited locally; re-vendor from %s@%s instead",
				name, m.SourceRepository, m.SourceCommit)
		}
	}
}

func loadCorpus(t *testing.T) corpus {
	t.Helper()
	path := os.Getenv(corpusEnv)
	if path == "" {
		path = filepath.Join(corpusDir, corpusFile)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return c
}

// TestGoReproducesEveryCanonicalPreimage is the cross-language claim in full.
// Every case in the corpus was serialised by Python; this asserts Go produces
// the identical bytes for each, which is what ratification of ori-specs#74
// waits on.
func TestGoReproducesEveryCanonicalPreimage(t *testing.T) {
	c := loadCorpus(t)
	total := 0
	for _, group := range [][]vectorCase{c.Cases, c.RejectCases, c.ProfileCases, c.ProfileRejectCases} {
		for _, vc := range group {
			doc := vc.Binding
			if len(doc) == 0 {
				doc = vc.FirmwareProfile
			}
			if len(doc) == 0 || vc.CanonicalHex == "" {
				continue
			}
			total++
			t.Run(vc.Name, func(t *testing.T) {
				got, err := canonicaljson.Marshal(decodeCanonical(t, doc))
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				if hex.EncodeToString(got) != vc.CanonicalHex {
					want, _ := hex.DecodeString(vc.CanonicalHex)
					t.Fatalf("canonical bytes differ\n go: %s\n py: %s", got, want)
				}
				if vc.CanonicalSHA256 != "" {
					sum := "sha256:" + hex.EncodeToString(sha256Sum(got))
					if sum != vc.CanonicalSHA256 {
						t.Fatalf("digest differs: go %s, corpus %s", sum, vc.CanonicalSHA256)
					}
				}
			})
		}
	}
	if total == 0 {
		t.Fatal("no cases carried a canonical preimage; the corpus shape has changed")
	}
	t.Logf("reproduced %d canonical preimages", total)
}

// TestGoVerifiesEveryAcceptSignature proves the interop claim is about signing
// and not only about bytes: Go must verify signatures Python produced over
// those preimages.
func TestGoVerifiesEveryAcceptSignature(t *testing.T) {
	c := loadCorpus(t)
	pub, err := hex.DecodeString(c.CommissioningPublicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("corpus commissioning key is unusable: %v", err)
	}
	for _, vc := range c.Cases {
		t.Run(vc.Name, func(t *testing.T) {
			preimage, err := canonicaljson.Marshal(decodeCanonical(t, vc.Binding))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			sig, err := base64.StdEncoding.DecodeString(vc.SignatureB64)
			if err != nil {
				t.Fatalf("signature: %v", err)
			}
			if !ed25519.Verify(pub, preimage, sig) {
				t.Fatal("signature does not verify over the Go-produced preimage")
			}
		})
	}
}

// TestEncoderRefusesBareFloat pins the property that makes a Go producer safe.
// json.Marshal renders float64(10) as "10" where the canonical form is "10.0",
// so a bare float reaching the encoder would corrupt every binding preimage.
func TestEncoderRefusesBareFloat(t *testing.T) {
	if _, err := canonicaljson.Marshal(map[string]any{"a": float64(10)}); err == nil {
		t.Fatal("encoder accepted a bare float64; it must accept only json.Number")
	}
}

// TestD011ProducesPythonSpellings covers the values a commissioned binding
// actually carries. Each expectation is Python's canonical output.
func TestD011ProducesPythonSpellings(t *testing.T) {
	floats := map[float64]string{
		10.0:  "10.0",
		100.0: "100.0",
		0.0:   "0.0",
		4.0:   "4.0",
		6.4:   "6.4",
		0.02:  "0.02",
		0.05:  "0.05",
		2.1:   "2.1",
		0.01:  "0.01",
		120.0: "120.0",
		25.0:  "25.0",
	}
	for in, want := range floats {
		got, err := d011.Float(in)
		if err != nil {
			t.Fatalf("Float(%v): %v", in, err)
		}
		if got.String() != want {
			t.Errorf("Float(%v) = %q, python writes %q", in, got.String(), want)
		}
	}
	ints := map[int64]string{1: "1", 26: "26", 1800000000000: "1800000000000"}
	for in, want := range ints {
		got, err := d011.Int(in)
		if err != nil {
			t.Fatalf("Int(%d): %v", in, err)
		}
		if got.String() != want {
			t.Errorf("Int(%d) = %q, want %q", in, got.String(), want)
		}
	}
}

// TestD011RefusesOutsideTheZone covers the boundary in both directions.
func TestD011RefusesOutsideTheZone(t *testing.T) {
	for _, f := range []float64{1e-5, 9.9e-5, 1e16, 1e17} {
		if _, err := d011.Float(f); err == nil {
			t.Errorf("Float(%v) was admitted; it is outside the zone", f)
		}
	}
	for _, f := range []float64{1e-4, 6.4, 9.99e15} {
		if _, err := d011.Float(f); err != nil {
			t.Errorf("Float(%v) was refused inside the zone: %v", f, err)
		}
	}
	if _, err := d011.Int(d011.MaxSafeInteger + 1); err == nil {
		t.Error("Int admitted a value above 2^53-1")
	}
}

// TestD011AdmitChecksSpellingNotOnlyValue is the consumer-side rule: bytes are
// the contract, so a different spelling of an in-zone value is still refused.
func TestD011AdmitChecksSpellingNotOnlyValue(t *testing.T) {
	// "10" and "10.0" are both canonical: JSON separates integers from
	// non-integers, and D-011 gives each its own spelling. A binding carries
	// both -- binding_seq is an integer, rated_capacity.value is a float --
	// so Admit cannot infer which was meant and must accept either.
	for _, ok := range []string{"10.0", "10", "0.02", "26", "-0.0", "0.0"} {
		if err := d011.Admit(json.Number(ok)); err != nil {
			t.Errorf("Admit(%q) refused a canonical spelling: %v", ok, err)
		}
	}
	for _, bad := range []string{"1e3", "1E3", "0.020", "+26", "010", "10.", ".5", ""} {
		if err := d011.Admit(json.Number(bad)); err == nil {
			t.Errorf("Admit(%q) accepted a non-canonical spelling", bad)
		}
	}
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
