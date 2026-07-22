# Playground end-to-end testing

The default test suite is hermetic. Live EET Playground checks are opt-in because
they depend on a public government service and shared test credentials.

## Credential handling

Download the current Playground credential archive only from the official EET
developer portal. Verify the archive checksum recorded by the project before use,
extract it outside the repository, and expose only:

`CAEET_Playground_2026_v1.zip` in the 2026-07-21 source snapshot has SHA-256
`711ca591e2e58e906212befab55ea72cbc5d960af49e444765b0428751002491`.
Treat any different archive as an upstream change that requires review, not as an
automatic checksum update.

```sh
export EET2_PKCS12_PATH=/absolute/path/outside/repository/test-certificate.p12
export EET2_PKCS12_PASSWORD='value-from-the-official-portal'
export EET2_SEQUENCE_NUMBER="agent-or-developer-$(date +%s)"
```

If OpenSSL reports that the published test container uses a disabled legacy
algorithm, set `EET2_ALLOW_LEGACY_PKCS12=1` for that process. This is explicit and
local; the gem never changes the global OpenSSL configuration.

Once activated, the legacy provider remains loaded for the process lifetime. The
runner is deliberately short-lived and isolated from the host application, but
Ruby and OpenSSL cannot guarantee zeroization of PKCS#12 bytes, passwords, or key
objects held in memory. Its mode-0700 temporary directory and exit cleanup prevent
persistent filesystem residue; they do not establish memory zeroization. For real
credential migration, prefer a dedicated short-lived isolated repackaging process
and current encryption algorithms when policy permits.

Never commit the archive, a P12/PFX, its password, an extracted private key, or a
live signed request. Do not pass passwords on the command line or print environment
variables in CI logs.

## Manual smoke

From the repository:

```sh
bundle exec ruby examples/playground.rb
```

The example requires a unique sequence number, prepares one signed attempt, and
prints only non-secret metadata and the typed outcome. It does not print signed XML,
certificate bytes, passwords, or raw responses. It makes one network attempt and
does not retry.

For the complete release matrix, which downloads the official archive into a
mode-0700 temporary directory, verifies its pinned checksum before extraction, runs
all identities and negative scenarios, emits sanitized JSON, and deletes all
credential material on exit:

```sh
bundle exec ruby script/e2e_playground
```

The same matrix can be invoked as `bundle exec rake e2e:playground` or through the
manual `live_playground` CI input. It is never part of a push or pull-request job.

Use `EET2_VERIFICATION_MODE=1` for a connectivity-only request. A documented code
`0` response in verification mode is not a POK and remains an unauthenticated
`UnsignedError` value.

## Required release evidence

Before claiming Playground compatibility, a clean opt-in run must record sanitized
evidence for:

- a valid verification-mode response;
- a valid recorded sale with a cryptographically verified `-ff` POK;
- documented XSD and signature errors;
- retry of the same six-field sale identity with a new UUID and
  `first_submission=false`;
- preservation of a safe `X-Global-Transaction-ID`;
- all currently published shared test credential identities;
- response signer rotation under the pinned chain/profile policy.

The automated matrix covers the first six items on every run. Signer rotation is
continuously accepted through chain/profile verification rather than a leaf pin;
the run records the currently observed leaf fingerprint for review.

Evidence may contain timestamps, response class, error/warning code, redacted UUID,
POK suffix, response/trust SHA-256, support ID, Ruby/OpenSSL/Nokogiri versions, and
pass/fail. It must not contain a private credential, password, full signed request,
raw response token, or private key.

## Production gate

The production constructor, endpoint allowlist, response environment rules, and
versioned SSSVD/NCA trust policy are covered by hermetic tests. They are not a
substitute for a live production E2E run. As of 2026-07-21 the documented host
`trzbyeet.gov.cz` has no DNS record, and production cash-register certificates are
scheduled to become available through DIS+ on 2026-11-01.

Before claiming production readiness, run a controlled verification-mode request
with a real production credential, confirm TLS and the observed response leaf chain,
exercise both a production error and a cryptographically verified receipt, and
record only sanitized evidence. The response must omit `test`, its POK must not end
in `-ff`, and its embedded signer must validate under the pinned SSSVD/NCA policy.
A passing Playground suite must never be described as production readiness.
