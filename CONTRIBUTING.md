# Contributing

Contributions should preserve the library boundary and security invariants described
in the README. Open an issue before changing the public API, XML signature profile,
trust policy, supported Ruby versions, or vendored official artifacts.

## Local checks

Use the Ruby version from `.ruby-version`, then run:

```sh
bundle install
bundle exec rake
bundle exec bundler-audit check --update
```

Ordinary tests must be hermetic. Live Playground tests are opt-in, must extract the
current official shared test credentials outside the repository, and must never
record private keys, passwords, signed request XML, or unredacted response bodies.
Follow [docs/e2e.md](docs/e2e.md) and use a unique sequence number for every run.

When an official artifact changes, update it byte-for-byte together with
`data/source-manifest.yml`, explain the semantic diff, and add or update contract
tests. Never replace a checksum merely to make a failing source-verification test
green.
