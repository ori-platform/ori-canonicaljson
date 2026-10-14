# ori-canonicaljson

Canonical JSON for the Ori contracts that sign or authenticate JSON payloads.

Bytes are the signing contract. When a Python runtime, a Go gateway and a C
device must agree that a signature covers the same document, they have to
produce the same bytes for it — and the standard libraries do not, quietly.
This module is the Go half of that agreement.

## Why a library rather than a helper

`encoding/json` cannot be configured to produce these bytes:

| Input | canonical form | `encoding/json` |
| --- | --- | --- |
| `<`, `>`, `&` in a string | literal | `<`, `>`, `&` |
| U+2028, U+2029 | literal | escaped, **even with `SetEscapeHTML(false)`** |
| `float64(10)` | `10.0` | `10` |

The first is a flag. The second has no flag. The third is not an encoder
setting at all — it is a numeric policy question the encoder cannot answer.

Each of these fails the same way: the document looks right, the signature does
not verify, and nothing points at the serialiser.

## The two packages

**`canonicaljson`** writes the canonical form: keys sorted by Unicode scalar
value, no insignificant whitespace, RFC 8259 escaping with the short forms, and
every other code point literal. It accepts only `json.Number`, never a bare Go
number, so a caller cannot leak a float's formatting into a preimage by
accident.

**`d011`** admits numbers into the cross-language agreement zone that evidence
artifacts and commissioned bindings sign over — integers within ±(2^53−1),
non-integers finite and either exactly zero or of magnitude in `[1e-4, 1e16)`,
always fixed notation, non-integers carrying a mandatory fractional part. Its
constructors return `json.Number`, which is the only type the encoder takes.

The split is deliberate. Numeric policy is not encoding policy: the gateway's
MQTT transport preserves the spelling it received because it carries telemetry
whose range is legitimately broader than the zone, while a producer of evidence
or bindings has the opposite obligation. One canonical writer serves both.

```go
capacity, err := d011.Float(10.0)           // json.Number("10.0"), not "10"
preimage, err := canonicaljson.Marshal(map[string]any{
    "rated_capacity": capacity,
})
signature := ed25519.Sign(key, preimage)
```

To reproduce a preimage from bytes received on the wire — what a verifier
needs — use `MarshalWire`, which validates the Unicode, decodes with
`UseNumber` so no number is reformatted, and writes the canonical form.

## Unicode is refused, not repaired

Go's JSON decoder substitutes U+FFFD for an unpaired surrogate escape; Python
surfaces the surrogate and then fails to encode it. Both "work", and they
canonicalise different text from identical input. `ValidateWireUnicode` and
`MarshalWire` refuse such a payload rather than accept a document the two sides
would disagree about.

## One signed document, one meaning

`encoding/json` keeps the last of two members with the same name and matches
struct fields without regard to case, `ſ` (U+017F) and the Kelvin sign
(U+212A) included. So `{"status":"critical","status":"healthy"}` canonicalises
to `{"status":"healthy"}` and its signature verifies, while a reader of the
first value sees `critical`; and a struct decoder reads `STATUS` as `status`.

Two functions refuse such documents, each under the rule that fits its
callers, with one sentinel error per reason:

- `MarshalWire` canonicalises for every contract that signs JSON, so it
  refuses only what all of them already refuse: invalid Unicode, malformed
  JSON, trailing data and a member named twice, at any depth. A shared
  canonicaliser that refused more would refuse documents some contract
  accepts.
- `DecodeStrict` applies the strict member rule of
  `ori-specs/gateway-api/v2.md`, for runtime–gateway payloads, which a gateway
  admits with it before it canonicalises or decodes them. It refuses the
  above and also nesting above `MaxNestingDepth` (32), names equal under the
  closed fold, and a top-level value that is not an object.

When several reasons apply, the earliest in this list wins, wherever in the
document each sits, so every reader names the same reason. `MarshalWire`
refuses a value that is not an object, or nests deeper than `encoding/json`
decodes (10000), with the decoder's own error, as it always has:

| Error | Refused when | `MarshalWire` | `DecodeStrict` |
| --- | --- | --- | --- |
| `ErrInvalidUnicode` | invalid UTF-8 anywhere, or a lone or misordered surrogate escape in a name or value, read up to any grammar break | yes | yes |
| `ErrMalformedJSON` | not one complete JSON value at the start: empty, cut short, a grammar break, `NaN`, `Infinity`, an incomplete fraction or exponent, or a byte order mark | yes | yes |
| `ErrNestingTooDeep` | nesting above 32, counting objects and arrays | | yes |
| `ErrTrailingData` | anything but JSON whitespace after the value | yes | yes |
| `ErrDuplicateMember` | two members of one object with the same name, compared after unescaping | yes | yes |
| `ErrCaseVariantMember` | two names in one object equal under the closed fold, or a name equal under it to a member the caller's `Shape` defines for that object or one enclosing it | | yes |
| `ErrNotAnObject` | a top-level value that is not an object | decoder error | yes |

The closed fold folds ASCII letters, `ſ` to `s` and the Kelvin sign to `k`,
and nothing else. It is not Unicode case folding, which changes with the
Unicode version a toolchain ships; it is exactly what `encoding/json` matches
to an ASCII field name, and a test sweeping every scalar value fails if a
toolchain's decoder ever matches more. Every object at every depth is checked,
arrays included, without recursion, so a deep document is refused as too deep
rather than as malformed, and a hostile depth costs a pointer per level past
the depth that can still change the outcome.

`DecodeStrict` also refuses `ErrMissingMember` for a member a `Shape`
requires, after every reason above. It returns the top-level members by exact
name, each the bytes it arrived as; member types are the caller's to check.

```go
members, err := canonicaljson.DecodeStrict(payload, &canonicaljson.Shape{
    Members:  []string{"device_id", "status"},
    Required: []string{"device_id", "status"},
})
```

## What this module guarantees

Every property below is pinned by a test, and breaking one is a breaking change
to the module rather than an implementation detail:

- The canonical bytes match the Python implementation for every vector in
  `testdata/canonical-json-vectors.json`.
- Every canonical preimage in the vendored `commissioned-safety-binding` corpus
  is reproduced byte-for-byte, and Ed25519 signatures produced by Python verify
  over the Go-produced preimage.
- A bare `float64`, `float32`, `int`, `int64` or `uint64` is refused.
- A `json.Number` reaches the wire with its spelling untouched.
- Malformed or unpaired Unicode is refused, and valid surrogate pairs are not.
- `MarshalWire` refuses a member named twice at any depth, and refuses
  nothing a contract it serves accepts. `DecodeStrict` refuses each reason of
  the strict member rule with its own error, in the rule's precedence. A clean
  canonical document round-trips byte for byte, and the scan agrees with
  `encoding/json` on what is valid JSON.
- The `d011` zone boundaries hold on both sides, and negative zero survives as
  `-0.0` rather than being normalised away.

The vendored corpus carries a `MANIFEST.json` recording the `ori-specs` commit
it came from and its digest. A local edit fails the suite; moving the pin is a
deliberate, separately reviewed change.

## Dependencies

None, and that is enforced in CI. A signing preimage is not a place to take a
supply-chain risk, and the standard library is sufficient for every rule here.

## Contracts

- `ori-specs/gateway-mqtt-canonical-json/v1.md` — runtime–gateway MQTT envelopes
- `ori-specs/gateway-api/v2.md` — the strict member rule
- `ori-specs/evidence/v2.md` — evidence artifacts, and the D-011 agreement zone
- `ori-specs/commissioned-safety-binding/v1.md` — commissioned bindings and
  firmware profiles

`ori-specs` is the authority. Where this module and a contract disagree, the
contract is right and this module has a bug.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
