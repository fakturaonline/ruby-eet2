# Public API

This document describes the pre-1.0 API implemented by `ruby-eet2`. Require the
gem with `require "eet2"`; all public constants live below `Eet2`.

## Credential

Import a PEM certificate and matching RSA key:

```ruby
credential = Eet2::Credential.from_pem(
  certificate_pem: File.binread("certificate.pem"),
  private_key_pem: File.binread("private-key.pem"),
  private_key_password: ENV["EET2_PRIVATE_KEY_PASSWORD"],
  chain_pems: [File.binread("intermediate.pem")]
)
```

Or import a PKCS#12 container:

```ruby
credential = Eet2::Credential.from_pkcs12(
  bytes: File.binread(ENV.fetch("EET2_PKCS12_PATH")),
  password: ENV.fetch("EET2_PKCS12_PASSWORD")
)
```

`legacy_provider: :explicitly_allowed` is an explicit migration escape hatch for a
container encrypted with a disabled legacy algorithm. Never enable it globally or
merely because a password is wrong. `require "eet2"` does not activate a legacy
provider.

When this opt-in is needed, the loaded OpenSSL provider handle is retained for the
process lifetime; the provider cannot be scoped to the single import, and its
legacy algorithms become available process-wide. Ruby and OpenSSL cannot guarantee
zeroization of the PKCS#12 bytes, password string, or imported private-key objects.
For migration, prefer a short-lived isolated process with tightly limited inputs
and outputs, then repackage the credential using current algorithms when policy
allows. Do not perform unrelated cryptographic work in that import process.

`Eet2::Credential.new` also accepts a certificate plus a small signer object that
implements `sign_sha256_rsa(bytes)`. This supports an HSM or remote signer without
making key custody part of the gem. The caller remains responsible for ensuring
that the signer key matches the supplied certificate.

## Sale

`Eet2::Sale` is immutable and accepts only validated v4.1 values:

| Ruby keyword | EET attribute | Type |
|---|---|---|
| `taxpayer_eic` | `eic_popl` | `String` |
| `evidence_unit_id` | `id_jednotky` | `Integer` |
| `register_id` | `id_pokl` | `String` |
| `sequence_number` | `porad_cis` | `String` |
| `occurred_at` | `dat_trzby` | `Time` without fractional seconds |
| `amount_czk` | `celk_trzba` | `BigDecimal` |
| `authorizing_taxpayer_eic` | `eic_poverujiciho` | optional `String` |
| `multiple_authorization` | `povereni_vice_popl` | optional boolean |
| `designated_drawdown_amount_czk` | `urceno_cerp_zuct` | optional `BigDecimal` |
| `drawdown_amount_czk` | `cerp_zuct` | optional `BigDecimal` |

`Float` is rejected. Values are serialized to exactly two decimal places, and
negative zero, non-finite values, excessive scale, and the exclusive CZK
100,000,000 boundary are rejected.

## Client

`Eet2::Client.playground` wires protocol v4.1, the versioned Playground response
trust policy, and `Eet2::NetHttpTransport`:

```ruby
client = Eet2::Client.playground(
  credential: credential,
  open_timeout: 5,
  read_timeout: 10,
  write_timeout: 5
)
```

`Eet2::Client.production` wires the exact documented production endpoint and a
separate, versioned SSSVD/NCA response trust policy:

```ruby
client = Eet2::Client.production(
  credential: production_credential,
  open_timeout: 5,
  read_timeout: 10,
  write_timeout: 5
)
```

Custom clocks, UUID generators, and transports are injectable for deterministic
tests. A separate `receive_clock` may be injected to test certificate validity; it
must represent independently observed local time and must never be derived from a
response. The production constructor and offline contracts are implemented, but
the official host does not yet resolve and production credentials are not scheduled
for issuance until 2026-11-01. A real production E2E pass remains a release gate.

### prepare

```ruby
prepared = client.prepare(
  sale: sale,
  first_submission: true,
  verification_mode: false
)
```

`prepare` creates and signs XML without network I/O. The immutable
`Eet2::PreparedRequest` records request UUID, send time, sale, submission flags,
signed XML, request/body/certificate digests, protocol version, and schema digest.
Persist it before transmission if the host needs a durable audit trail.
Construction enforces the request SHA against the XML. Before transmission the
client additionally re-verifies the exact official schema digest, UUID, flags,
Sale fields, canonical Body digest, embedded certificate digest, and RSA signature;
corrupted persisted attempts fail before the transport is invoked.

`PreparedRequest#inspect`, `#to_s`, and pretty printing return only non-sensitive
metadata: request UUID, send time, flags, protocol version, XML byte size, and the
four digests. The signed XML and the Sale are never rendered, so accidentally
logging the object or capturing it in an exception context cannot leak the signed
request. Read `#xml` explicitly when the bytes are genuinely needed.

For a repeat submission of the same sale, preserve all six sale-identity fields,
call `prepare` again to create a new message UUID, and use
`first_submission: false`. The gem never decides when a repeat is lawful.

### transmit

```ruby
result = client.transmit(prepared)
```

This invokes the configured transport once. It never retries or follows a redirect.
The result is one of:

| Class | `accepted?` | `authenticated?` | Meaning |
|---|---:|---:|---|
| `Response::VerifiedReceipt` | true | true | Signature, environment-specific chain/profile, XSD, UUID, and environment markers all passed |
| `Response::UnsignedError` | false | false | Documented unsigned `Chyba` response |
| `Response::InvalidResponse` | false | false | A response arrived but strict verification failed |
| `Response::TransportFailure` | false | false | Network failure or non-200 HTTP status |

Only `VerifiedReceipt#pok` is trustworthy acceptance evidence.
`VerifiedReceipt#test` is `true` on Playground and `nil` in production. A
Playground receipt must also end in `-ff`; production rejects both `test` and the
`-ff` suffix. Unsigned error responses are checked against the same environment
marker rules but remain unauthenticated.

`TransportFailure#certainty` is `not_sent`, `possibly_sent`, or `unknown`. The
built-in transport uses `not_sent` only before request invocation and
`possibly_sent` afterward. Never automatically repeat a `possibly_sent` attempt.
`kind` distinguishes DNS, connect timeout, TLS, connection, timeout, protocol,
oversized-response, and HTTP-status failures.

`InvalidResponse#reason` is a stable symbol for malformed XML, schema,
signature, certificate, or correlation failure. Raw exception messages are not
returned. The response SHA-256 and a sanitized support ID remain available for
diagnostics.

### Exchange evidence

Every result produced from an actual HTTP exchange carries an immutable
`Response::ExchangeEvidence` in `#exchange_evidence`:

| Field | Meaning |
|---|---|
| `http_status` | the observed status |
| `response_sha256` | SHA-256 of the complete received body |
| `response_bytesize` | size of the complete received body |
| `response_body_head` | first 4 KiB of the body, binary encoded and frozen |
| `truncated?` | whether the body was longer than the retained head |

It is populated for a verified receipt, an unsigned error, an invalid response,
**and** for a non-200 status whose body the gem deliberately refuses to parse —
including a SOAP Fault. It is `nil` only when no response was received at all
(`TransportFailure` with a network `kind`).

The head is bounded on purpose: the transport already caps a response at
`Transport::MAX_RESPONSE_BYTES` (256 KiB) and the evidence retains at most
`Response::EXCHANGE_EVIDENCE_MAX_HEAD_BYTES` (4 KiB) of it, so an audit trail costs
a known amount of memory. The head is a byte prefix, so it may end mid-character
and must never be parsed as a document; treat it as opaque support evidence.
Persisting or exposing it is the host's decision, subject to the host's own
retention policy.

## Alternative transport

An injected transport implements:

```ruby
def call(prepared_request)
  Eet2::Transport::HttpResponse.new(
    status: 200,
    headers: {"x-global-transaction-id" => "safe-ascii-id"},
    body: response_xml
  )
end
```

It may instead return `Eet2::Transport::Failure` with a documented certainty and
kind. Returning another type is a configuration error. An alternative is
responsible for exactly-one-attempt behavior, TLS verification, redirect refusal,
response bounds, and accurate failure certainty.

## Exceptions

Invalid local values and extension contracts raise typed exceptions. The main
families are:

- `ValidationError`, `SchemaValidationError`, and `RequestTooLarge`;
- `CredentialError` and `LegacyPkcs12Unsupported`;
- `SigningError`;
- `TransportConfigurationError`;
- `UnsupportedEnvironment`.

Peer-side transport and response failures normally become result values. Low-level
response exception classes remain public for direct use of
`Contracts::V4_1::ResponseParser`.
