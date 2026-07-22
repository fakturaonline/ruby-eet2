# ruby-eet2-cz

`ruby-eet2-cz` is a framework-independent Ruby client under active development for
the Czech EET2 SOAP v4.1 protocol. Its design prioritizes deterministic request
preparation, exact XML signatures, one auditable HTTP attempt per call, and strict
cryptographic verification before an EET acceptance can be trusted.

## Status

The repository freezes the official 2026-07-21 protocol sources and implements
the request-side v4.1 core plus strict environment-specific response
verification: immutable values, PEM/PKCS#12 credentials, deterministic SOAP
construction, XSD validation, Exclusive C14N, RSA-SHA256, signature-wrapping
defenses, UUID/environment correlation, and a versioned I.CA response trust policy.
The implementation reproduces all three official request signatures and verifies a
captured live Playground receipt with both Ruby and `xmlsec1`. The public
`Eet2::Client` and a strict one-attempt `Net::HTTP` transport are implemented and
covered by offline integration tests. The opt-in live client suite passed on
2026-07-21 for all three official identities, verification mode, accepted sale,
same-sale retry, invalid XSD, and invalid signature. Do not use the current `0.1.0`
source for live production sales until the production gate below has passed.

`Eet2::Client.production` is implemented against the published production URL and
the separately pinned SSSVD/NCA response trust chain and signer profile. Production
responses must omit the non-production `test` marker and must not use a `-ff` POK.
As of 2026-07-21 the production DNS name does not resolve, and production cash-register
certificates are not scheduled to become available in DIS+ until 2026-11-01.
Production construction and offline contract tests therefore exist, but a real
production E2E claim is intentionally withheld until the service and credentials
are available. The live evidence currently proves Playground compatibility only.

Run the live matrix explicitly with `bundle exec ruby script/e2e_playground`. It
downloads the public shared test credentials into an automatically deleted private
temporary directory and emits only sanitized JSON evidence; see
[docs/e2e.md](docs/e2e.md).

## Intended scope

The gem will own:

- immutable EET2 v4.1 values and wire-format validation;
- deterministic SOAP construction and request XML signatures;
- strict response structure, digest, signature, certificate, UUID, and environment
  verification;
- explicit credential import and a narrow external-signer interface;
- exactly one `Net::HTTP` POST per `transmit` call;
- typed accepted, rejected, invalid-response, and transport-failure outcomes.

The host application will continue to own payment eligibility, persistence,
sequence allocation, idempotency, retry scheduling, deadlines, secret storage,
logging, metrics, and user interface behavior.

## Usage

The public workflow is intentionally split so a host can durably store a signed
attempt before any network I/O:

```ruby
require "bigdecimal"
require "eet2"

credential = Eet2::Credential.from_pkcs12(
  bytes: encrypted_p12,
  password: password,
  legacy_provider: :explicitly_allowed
)

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
prepared = client.prepare(sale: sale, first_submission: true)
# Persist `prepared` here.
result = client.transmit(prepared)
```

For the documented production environment, use the same workflow with the real
production credential and the production constructor:

```ruby
client = Eet2::Client.production(
  credential: production_credential,
  open_timeout: 5,
  read_timeout: 10,
  write_timeout: 5
)
```

The constructor is safe to instantiate now, but the official production host and
credential issuance must be available before any live production verification can
be performed.

`prepare` never performs network I/O. `transmit` performs exactly one POST, sets
`Net::HTTP#max_retries` to zero, never follows a redirect, and returns one of:

- `Eet2::Response::VerifiedReceipt`: signed, trusted, correlated acceptance;
- `Eet2::Response::UnsignedError`: a documented peer error, explicitly not
  authenticated;
- `Eet2::Response::InvalidResponse`: HTTP 200 was received but strict response
  verification failed;
- `Eet2::Response::TransportFailure`: network or non-200 HTTP failure.

Check the concrete class before using response fields. `accepted?` and
`authenticated?` are true only for `VerifiedReceipt`. A transport failure records
`certainty`: `not_sent` means the connection failed before invoking the request;
`possibly_sent` means the server might have received it. The gem deliberately
provides no retry method—persist the prepared attempt and let the host application
decide whether to create a new UUID with `first_submission: false`.

The injected transport boundary is intentionally small: an alternative transport
must respond to `call(prepared_request)` and return
`Eet2::Transport::HttpResponse` or `Eet2::Transport::Failure`. Invalid extension
contracts raise `Eet2::TransportConfigurationError`.

Detailed references:

- [public API](docs/api.md);
- [architecture and security boundaries](docs/architecture.md);
- [opt-in Playground E2E procedure](docs/e2e.md).

## Ruby compatibility

The minimum supported version is the exact FakturaOnline runtime, Ruby 3.2.2.
That compatibility target is not a statement that the Ruby 3.2 branch or this old
patch level is secure or maintained; upgrading the host remains strongly
recommended. CI covers Ruby 3.2.2 and the latest tested 3.2 patch (3.2.11), plus
3.3.12, 3.4.10, and 4.0.6. MRI is the only promised engine until alternative
engines pass the same Nokogiri C14N and OpenSSL interoperability tests.

## Development

Use Ruby 4.0.6 through `mise` in this checkout:

```sh
bundle install
bundle exec rake
bundle exec bundler-audit check --update
```

The default Rake task verifies official-source checksums, specs, formatting, RBS,
the packaged gem, and XML signatures through `xmlsec1`.
`script/verify_package` builds into a temporary directory, checks the explicit
file allowlist and private-key denylist, verifies every packaged official runtime
artifact against the packaged provenance manifest, installs into an isolated gem
home, and executes `require "eet2"`.

Official artifacts in `data/official/` and `spec/fixtures/official/` are preserved
byte-for-byte. Their canonical URLs, purpose, package status, and SHA-256 values are
recorded in `data/source-manifest.yml`. Never add PKCS#12/PFX files or passwords to
the repository.

## Security model

`require "eet2"` will never silently activate OpenSSL's legacy provider. Legacy
Playground PKCS#12 import requires an explicit opt-in and is separate from normal
runtime loading. The environment-specific response-signing trust stores are also
separate from both the cash-register credential CA chains and the operating system
TLS trust store.

If explicitly activated for a legacy PKCS#12 import, OpenSSL's legacy provider is
retained for the process lifetime and broadens the algorithms available throughout
that process. Ruby and OpenSSL cannot guarantee zeroization of password, container,
or private-key bytes held in managed memory. Prefer a short-lived isolated import
process that re-encodes the credential with current algorithms when organizational
policy permits; see [the credential API](docs/api.md).

An HTTP 200 response, a POK-shaped string, or an XML `Potvrzeni` element alone is
never proof of acceptance. TLS peer/hostname verification and TLS 1.2+ are
mandatory, endpoints are allowlisted exactly, response bodies are bounded, and an
unsafe `X-Global-Transaction-ID` is discarded rather than exposed. See
[SECURITY.md](SECURITY.md) for disclosure and support expectations.

Certificate validity is checked at independent local receive time, never at the
signer-controlled `dat_prij` timestamp. Persisted prepared attempts are integrity
checked again before any network call.

## Official sources

- [EET developer portal](https://eet.gov.cz/pro-vyvojare/)
- [EET2 v4.1 XSD](https://eet.gov.cz/files/EETXMLSchema.xsd)
- [EET2 v4.1 WSDL](https://eet.gov.cz/files/EETServiceSOAP.wsdl)
- [Playground endpoint](https://pg.trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4)
- [production access and operations v1.0](https://eet.gov.cz/files/EET_pristupove_provozni_informace_produkce_v1.pdf)
- [SSSVD/NCA certificate repository](https://www.narodni-ca.gov.cz/Dokumenty.aspx)

## License and publishing

The library is available under the [MIT License](LICENSE), copyright 2026
FakturaOnline.cz contributors. The canonical source repository is
[fakturaonline/ruby-eet2](https://github.com/fakturaonline/ruby-eet2). No package
has been published to RubyGems yet; RubyGems ownership and trusted-publishing
configuration remain separate, explicitly authorized release steps. Pushing this
source repository does not publish a gem.
