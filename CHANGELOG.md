# Changelog

All notable changes will be documented here. The project follows Semantic
Versioning once a public package exists; all pre-1.0 APIs may still change.

## Unreleased

- Support the FakturaOnline runtime floor exactly at Ruby 3.2.2 and exercise both
  3.2.2 and the latest tested Ruby 3.2 patch in CI.
- Add `Client.production`, the exact production endpoint, strict production
  response markers, and a separately pinned SSSVD/NCA response trust policy. Live
  production E2E remains gated on DNS availability and production credentials.
- Freeze official EET2 v4.1 Playground sources with checksums and provenance.
- Establish Ruby, test, formatting, type, security, and package-verification gates.
- Add immutable sale and prepared-request values with strict EET2 format checks.
- Add PEM and PKCS#12 credentials with explicit legacy-provider opt-in.
- Add deterministic SOAP v4.1 construction, XSD validation, Exclusive C14N, and
  RSA-SHA256 request signing cross-checked against official samples and `xmlsec1`.
- Add strict response cardinality, ID/reference, transform/algorithm, digest,
  signature, certificate-chain/profile, UUID, and Playground-marker verification.
- Add explicit authenticated `VerifiedReceipt` and unauthenticated `UnsignedError`
  value types so documented error responses cannot be mistaken for signed evidence.
- Add the public prepare/transmit client, exact Playground endpoint allowlist, TLS
  1.2+ peer/hostname verification, bounded response streaming, and one-attempt
  `Net::HTTP` POST with redirects and internal retries disabled.
- Add typed transport-failure certainty and invalid-response outcomes while
  preserving only sanitized support transaction IDs.
- Add an opt-in live Playground matrix that checksum-verifies the official
  credential archive in a private temporary directory, exercises all three
  published identities and positive/retry/negative scenarios, and emits sanitized
  JSON evidence.
- License the clean-room library under MIT, publish the canonical GitHub project
  identity, and leave RubyGems ownership/publishing for a separate authorized step.
- Validate response certificate time against an independent receive clock and
  re-verify complete prepared-request audit/signature integrity before transmission.
- Bound every runtime dependency by reviewed major versions and declare all directly
  required extracted/default gems.
- Ship the official-source provenance manifest and checksum every packaged runtime
  artifact during package verification.
- Pin CI actions to reviewed commit SHAs, add job timeouts, and document the
  process-lifetime and non-zeroization boundaries of legacy credential import.
- Reject any extension of the generated SOAP/WS-Security/XMLDSig request profile,
  including unsigned elements, attributes, comments, namespace changes, reordered
  children, text padding, and renamed UUID-derived IDs, before transport.
- Bind persisted `schema_sha256` audit metadata to the exact packaged official v4.1
  XSD digest before transport.
