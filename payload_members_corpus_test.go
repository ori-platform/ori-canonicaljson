// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package canonicaljson_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	canonicaljson "github.com/ori-platform/ori-canonicaljson"
)

// The gateway-api/v2 payload member rule corpus, vendored from ori-specs and
// pinned by its manifest.
const payloadMembersDir = "testdata/vectors/gateway_api"

type payloadMembersCorpus struct {
	VectorSet   string              `json:"vector_set"`
	Contract    string              `json:"contract"`
	Section     string              `json:"section"`
	Conventions map[string]string   `json:"conventions"`
	Reasons     []string            `json:"reasons"`
	Families    map[string][]string `json:"families"`
	Cases       []struct {
		Name        string  `json:"name"`
		Description string  `json:"description"`
		PayloadHex  string  `json:"payload_hex"`
		PayloadText *string `json:"payload_text"`
		Family      *string `json:"family"`
		Expected    string  `json:"expected"`
	} `json:"cases"`
}

func loadPayloadMembersCorpus(t *testing.T) payloadMembersCorpus {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(payloadMembersDir, "payload-members-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Decoded strictly, so a member the corpus gains fails here rather than
	// being ignored.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var corpus payloadMembersCorpus
	if err := dec.Decode(&corpus); err != nil {
		t.Fatalf("decode the payload member corpus: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		t.Fatal("the payload member corpus has trailing data")
	}
	if len(corpus.Cases) == 0 || len(corpus.Families) == 0 {
		t.Fatalf("the payload member corpus has %d cases and %d families", len(corpus.Cases), len(corpus.Families))
	}
	return corpus
}

// TestVendoredPayloadMembersCorpusMatchesItsManifest is the local-edit check
// for the payload member corpus.
func TestVendoredPayloadMembersCorpusMatchesItsManifest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(payloadMembersDir, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		SourceRepository string            `json:"source_repository"`
		SourceCommit     string            `json:"source_commit"`
		Files            map[string]string `json:"files"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.SourceRepository != "ori-platform/ori-specs" || len(m.SourceCommit) != 40 || len(m.Files) == 0 {
		t.Fatal("the manifest does not pin one ori-specs commit")
	}
	for name, want := range m.Files {
		body, err := os.ReadFile(filepath.Join(payloadMembersDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(sha256Sum(body)); got != want {
			t.Fatalf("%s was edited locally; re-vendor from %s@%s instead", name, m.SourceRepository, m.SourceCommit)
		}
	}
}

// reasonOf names the reason err carries in the rule's vocabulary, or accept.
func reasonOf(err error) string {
	if err == nil {
		return "accept"
	}
	for _, reason := range reasons {
		if errors.Is(err, reason) {
			return strings.TrimPrefix(reason.Error(), "canonicaljson: ")
		}
	}
	return "unclassified: " + err.Error()
}

// marshalWireReasons are the rule's reasons MarshalWire also refuses for.
var marshalWireReasons = []string{"invalid_unicode", "malformed_json", "trailing_data", "duplicate_member"}

// TestDecodeStrictNamesEveryCorpusReason runs every case of the corpus, by its
// exact bytes, through DecodeStrict with its family's defined members. Each
// must be accepted or refused for exactly the reason the case expects.
// MarshalWire must agree wherever the case is accepted or refused for a reason
// it shares: no reason only DecodeStrict applies can rank above those.
func TestDecodeStrictNamesEveryCorpusReason(t *testing.T) {
	corpus := loadPayloadMembersCorpus(t)
	var library []string
	for _, reason := range reasons[:7] {
		library = append(library, strings.TrimPrefix(reason.Error(), "canonicaljson: "))
	}
	if !slices.Equal(corpus.Reasons, library) {
		t.Fatalf("the corpus ranks reasons %v; the library ranks %v", corpus.Reasons, library)
	}
	seen := map[string]bool{}
	for _, c := range corpus.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if c.Expected != "accept" && !slices.Contains(corpus.Reasons, c.Expected) {
				t.Fatalf("expected %q is neither accept nor a reason", c.Expected)
			}
			payload, err := hex.DecodeString(c.PayloadHex)
			if err != nil {
				t.Fatal(err)
			}
			var shape *canonicaljson.Shape
			if c.Family != nil {
				names, ok := corpus.Families[*c.Family]
				if !ok {
					t.Fatalf("family %q has no defined members in the corpus", *c.Family)
				}
				shape = &canonicaljson.Shape{Members: names}
			}
			_, err = canonicaljson.DecodeStrict(payload, shape)
			if got := reasonOf(err); got != c.Expected {
				t.Fatalf("DecodeStrict = %s, want %s (%v)", got, c.Expected, err)
			}
			seen[c.Expected] = true
			if c.Expected == "accept" || slices.Contains(marshalWireReasons, c.Expected) {
				_, err = canonicaljson.MarshalWire(payload)
				if got := reasonOf(err); got != c.Expected {
					t.Fatalf("MarshalWire = %s, want %s (%v)", got, c.Expected, err)
				}
			}
		})
	}
	for _, want := range append([]string{"accept"}, corpus.Reasons...) {
		if !seen[want] {
			t.Errorf("no corpus case decides %s", want)
		}
	}
}
