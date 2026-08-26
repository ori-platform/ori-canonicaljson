# Security Policy

`ori-canonicaljson` produces the bytes that Ori signatures cover. A defect here
does not look like a defect: it looks like a signature that fails to verify, or
worse, like one that verifies over a document nobody intended.

## Reporting

Report vulnerabilities through GitHub private vulnerability reporting on this
repository. If that is unavailable, contact the maintainer directly before
sharing exploit details publicly.

Expected response target: acknowledgement within 72 hours, with coordinated
remediation before public disclosure for issues that affect deployed devices.

High-priority findings include:

- any input for which this module and the Python or C implementations produce
  different bytes,
- a Go numeric type reaching a preimage without passing through `d011`,
- malformed or unpaired Unicode accepted rather than refused,
- a `json.Number` reformatted between input and output,
- a third-party dependency entering `go.mod`,
- a vendored vector edited locally rather than re-vendored from `ori-specs`.

## What this repository may contain

This module is deliberately public and carries no site identity, no
credentials, and no deployment detail.

The test keys in the vendored vectors are **published test-only keys**, marked
as such in the corpus and in the contract. They exist so anyone can reproduce
the byte agreement independently, and they authenticate nothing.

A pull request that adds a real key, a device identifier, a broker address, or
any site-specific value to this repository should be closed rather than
reviewed.

## Scope

This module decides bytes. It never signs, verifies, transports, or stores
anything, and it holds no key material. Cryptographic operations, authority
rules, and freshness belong to the contracts in
[`ori-specs`](https://github.com/ori-platform/ori-specs) and their consumers.
