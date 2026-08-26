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
- `ori-specs/evidence/v2.md` — evidence artifacts, and the D-011 agreement zone
- `ori-specs/commissioned-safety-binding/v1.md` — commissioned bindings and
  firmware profiles

`ori-specs` is the authority. Where this module and a contract disagree, the
contract is right and this module has a bug.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
