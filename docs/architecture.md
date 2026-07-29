# Architecture and security boundaries

The gem is a protocol adapter, not an EET workflow engine. Its design makes each
signed attempt observable and keeps business policy in the host application.

## Request lifecycle

1. The host creates an immutable `Sale` using a durable business identity.
2. `Client#prepare` validates, serializes, XSD-validates, and signs one SOAP Body.
3. The host may persist the returned `PreparedRequest` before network I/O.
4. `Client#transmit` re-verifies request hash, UUID, flags, Sale fields, canonical
   Body digest, exact official schema digest, embedded certificate digest, RSA
   signature, and the exact generated SOAP/WS-Security/XMLDSig tree before invoking
   one transport call. Unsigned extension elements, attributes, comments, namespace
   changes, reordered nodes, or renamed audit IDs fail before transport.
5. A response becomes `VerifiedReceipt` only after strict XML, XSD, XMLDSig,
   certificate, environment, and UUID checks.
6. The host persists the typed result and independently decides whether another
   submission is needed.

There is no hidden queue, idempotency store, backoff, deadline policy, or retry.
These cannot be implemented safely without the host's transaction and payment
state.

## Three separate trust domains

The implementation deliberately does not conflate:

- request credential trust: the cash-register certificate and its private signer;
- HTTPS trust: the operating system store used by `Net::HTTP` for the endpoint;
- response-message trust: environment-specific vendored and versioned anchors plus
  the corresponding EET signer profile used to verify XMLDSig (I.CA for the
  observed Playground service, SSSVD/NCA for the documented production service).

A valid TLS connection does not authenticate a POK. A valid XML signature from an
arbitrary certificate does not authenticate EET. A request credential CA file is
not a response trust anchor.

Playground response trust pins the public root and intermediate fingerprints while
allowing normal leaf renewal under a strict policy/subject/key-usage profile. Trust
is evaluated at an independently observed local receive time; signed `dat_prij` is
receipt metadata, not a trusted timestamp that can revive an expired key. Production
response trust separately pins the official NCA Root CA/RSA 10/2023 and NCA
SubCA2/RSA 12/2023 fingerprints and requires the published RSA technological
certificate policy plus the GFŘ signer identity. The two environments cannot share
response trust material.

## XML verification

The parser uses strict non-network Nokogiri parsing and rejects DTD and XInclude.
The verifier requires exact cardinality and ordering for SOAP/WS-Security nodes,
globally unique IDs, a same-document reference to the sole Body object, exact
Exclusive C14N and SHA-256/RSA-SHA256 algorithms, and the documented token profile.

Digest comparison is constant-time. The embedded leaf must chain to the selected
versioned trust policy and pass that environment's signer profile. Only then are
the request UUID and environment markers accepted: Playground requires `test=true`
and a `-ff` POK; production requires the `test` attribute to be absent and rejects
the `-ff` suffix.

The documented `Chyba` shape is unsigned. It is useful operational information but
is never represented as authenticated evidence.

## Transport boundary

The default adapter uses HTTP/1.1 and exactly one POST. It configures TLS peer and
hostname verification, TLS 1.2 minimum, explicit timeouts, `max_retries = 0`,
identity encoding, an exact endpoint allowlist, no redirect traversal, and a 256 KiB
streaming response limit.

A failure before `Net::HTTP#request` is invoked is `not_sent`. Once request
invocation begins, network failure is `possibly_sent` because the peer may have
processed the sale even if the client did not receive its response.

Socket timeouts are the only time bound the adapter owns. A legal or business
response window spans DNS, queueing, and the host's own scheduling, so it can only
be enforced by the host around the whole attempt. The adapter refuses a
`read_timeout` under two seconds because such a value cannot serve any plausible
window and merely converts avoidable slowness into ambiguous `possibly_sent`
attempts.

Every result derived from a received HTTP response also carries bounded
`Response::ExchangeEvidence`: status, full-body SHA-256 and byte size, plus a 4 KiB
head. It exists for non-200 and SOAP Fault bodies the gem refuses to parse, so
support has a fixed-size, immutable trace without the gem ever retaining an
unbounded response.

## Concurrency

The supported unit of concurrency is one attempt. Build a `Client` (and the
`Credential` it wraps) per attempt, use it for exactly one `prepare` plus one
`transmit`, and discard it. Independent per-attempt instances may run in parallel
threads, processes, or workers; `spec/eet2/concurrency_spec.rb` locks that path by
running parallel per-attempt clients and asserting unique request UUIDs and a
request digest that matches each generated XML.

Sharing a single `Client`, `Credential`, `Contracts::V4_1::Schema`, or signer across
threads is **not supported and not claimed to be safe**. Those objects wrap mutable
non-Ruby state — `Nokogiri::XML::Schema` (one instance shared by the response parser
and the request integrity verifier), the canonicalizer, and `OpenSSL::PKey::RSA` in
`LocalKeySigner` — whose thread safety depends on the linked libxml2 and OpenSSL
builds. An ad-hoc smoke run over a shared client passing is absence of an immediate
crash, not evidence, so the gem does not turn it into a promise.

`PreparedRequest`, `Sale`, and every response value are deeply frozen and safe to
read from any thread once constructed. `fork` after building a client is likewise
outside the contract: re-create the client in the child.

## Package and source integrity

The gemspec is an explicit allowlist. Build verification extracts the package,
rejects private-key filenames and PEM markers, installs into an isolated gem home,
and loads the public API. Official XSD, request samples, and trust material have
canonical source URLs and SHA-256 checksums in `data/source-manifest.yml`.
The manifest itself is shipped with the gem; package verification requires its
`packaged: true` set to match every packaged `data/official/` file and re-hashes
each extracted artifact before the isolated install smoke test.

CI runs tests, Standard, RBS, dependency audit, package verification, source
verification, and an independent `xmlsec1` oracle. The runtime gem does not include
shared test credentials, passwords, signed request fixtures, WSDL research
material, or Goal Maker records.

## Legacy credential import boundary

Normal library loading never activates OpenSSL's legacy provider. An explicit
legacy PKCS#12 import retains that provider for the process lifetime because the
Ruby OpenSSL binding does not expose safe per-operation provider scoping here.
This expands the process-wide algorithm surface. Ruby's managed memory and OpenSSL
objects also cannot guarantee zeroization of container bytes, passwords, or private
key material.

Applications migrating such credentials should use a short-lived isolated import
process, minimize inherited environment and output, and repackage with current
algorithms when policy permits. Filesystem deletion and `String#clear` are useful
hygiene but are not proof of memory zeroization.
