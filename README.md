# ruby-eet2

A strict, framework-independent Ruby client for the Czech EET 2.0 SOAP v4.1
protocol.

`ruby-eet2` builds and signs requests, sends exactly one HTTP request per call,
and accepts a receipt only after its XML signature, certificate chain, schema,
environment, and request UUID have all been verified.

> [!IMPORTANT]
> Version `0.1.0` is under active development. Playground interoperability was
> verified end to end on 21 July 2026. Production support is implemented and
> covered offline, but cannot be claimed as live-verified until the official
> production service and credentials are available.

## Installation

The gem has not been published to RubyGems yet. Add the private repository to
your `Gemfile`:

```ruby
gem "ruby-eet2", github: "fakturaonline/ruby-eet2"
```

Then run:

```sh
bundle install
```

Ruby 3.2.2 or newer is required. MRI Ruby is currently the supported engine.

## Quick start

Load a cash-register credential from PKCS#12:

```ruby
require "bigdecimal"
require "eet2"

credential = Eet2::Credential.from_pkcs12(
  bytes: File.binread(ENV.fetch("EET2_PKCS12_PATH")),
  password: ENV.fetch("EET2_PKCS12_PASSWORD")
)
```

Describe the sale and create a Playground client:

```ruby
sale = Eet2::Sale.new(
  taxpayer_eic: "CZ00000019",
  evidence_unit_id: 303,
  register_id: "web-1",
  sequence_number: "payment/2027/123",
  occurred_at: Time.now.floor,
  amount_czk: BigDecimal("1250.00")
)

client = Eet2::Client.playground(
  credential: credential,
  open_timeout: 5,
  read_timeout: 10,
  write_timeout: 5
)
```

Preparing and transmitting are deliberately separate operations:

```ruby
prepared = client.prepare(sale: sale, first_submission: true)

# Persist `prepared` before transmission if you need a durable audit trail.
result = client.transmit(prepared)
```

`prepare` signs the request without network access. `transmit` performs exactly
one POST, never retries, and never follows redirects.

## Handling the result

The result is always one of four explicit types:

```ruby
case result
when Eet2::Response::VerifiedReceipt
  puts "Accepted: #{result.pok}"
when Eet2::Response::UnsignedError
  puts "EET returned an unauthenticated error"
when Eet2::Response::InvalidResponse
  puts "The response failed strict verification"
when Eet2::Response::TransportFailure
  puts "Transport failed; certainty: #{result.certainty}"
end
```

Only `VerifiedReceipt` is accepted and authenticated. A transport failure marked
`possibly_sent` must not be retried automatically because the server may already
have received the sale.

## Production

Production uses the same workflow with an environment-specific endpoint and
trust policy:

```ruby
client = Eet2::Client.production(
  credential: production_credential,
  open_timeout: 5,
  read_timeout: 10,
  write_timeout: 5
)
```

The production constructor, request format, endpoint allowlist, and SSSVD/NCA
response trust chain are implemented. A real production E2E run remains a release
gate; Playground success is not evidence of production readiness.

## What the library guarantees

- deterministic, schema-valid SOAP v4.1 requests;
- RSA-SHA256 XML signatures and Exclusive XML Canonicalization;
- strict response signature, certificate, UUID, and environment verification;
- separate trust policies for Playground and Production;
- immutable request and response values;
- no implicit retries or redirect following;
- bounded response bodies and sanitized diagnostic data;
- explicit PKCS#12, PEM, and external-signer credential boundaries.

The host application remains responsible for deciding which payments enter EET,
persistence, sequence allocation, retry scheduling, deadlines, secret storage,
logging, metrics, and user-facing behavior.

## Documentation

- [Public API](docs/api.md)
- [Architecture and security boundaries](docs/architecture.md)
- [Playground E2E testing](docs/e2e.md)
- [Security policy](SECURITY.md)

## Development

The repository pins its development Ruby version in `.ruby-version`.

```sh
bundle install
bundle exec rake
bundle exec bundler-audit check --update
```

The default task verifies the official-source manifest, documentation, RSpec
suite, formatting, RBS signatures, gem package allowlist, isolated installation,
and XML signatures through `xmlsec1`.

Live Playground tests are opt-in:

```sh
bundle exec ruby script/e2e_playground
```

See [the E2E guide](docs/e2e.md) before running them. Never commit credentials,
passwords, signed live requests, or private keys.

## License

[MIT](LICENSE) © 2026 FakturaOnline.cz contributors.
