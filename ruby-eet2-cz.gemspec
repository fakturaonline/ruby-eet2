# frozen_string_literal: true

require_relative "lib/eet2/version"

Gem::Specification.new do |spec|
  spec.name = "ruby-eet2-cz"
  spec.version = Eet2::VERSION
  spec.summary = "Strict Ruby client for the Czech EET2 protocol"
  spec.description = <<~DESCRIPTION
    A framework-independent EET2 SOAP v4.1 client focused on deterministic
    request preparation, exact XML signatures, one-attempt transport, and strict
    response verification.
  DESCRIPTION
  spec.authors = ["FakturaOnline.cz contributors"]
  spec.homepage = "https://github.com/fakturaonline/ruby-eet2"
  spec.license = "MIT"

  spec.required_ruby_version = Gem::Requirement.new(">= 3.2.2")
  spec.require_paths = ["lib"]

  # Explicit allowlist: contributor research, tests, and private-key formats must
  # never enter the published package implicitly.
  spec.files = %w[
    CHANGELOG.md
    LICENSE
    README.md
    SECURITY.md
    data/source-manifest.yml
    data/official/eet-v4_1/EETXMLSchema.xsd
    data/official/response-trust/production/nca-root-rsa-10-2023.der
    data/official/response-trust/production/nca-subca2-rsa-12-2023.der
    data/official/response-trust/playground/ica-public-rsa-06-2022.pem
    data/official/response-trust/playground/ica-root-rsa-05-2022.pem
    docs/api.md
    docs/architecture.md
    docs/e2e.md
    examples/playground.rb
    lib/eet2.rb
    lib/eet2/certificate_verifier.rb
    lib/eet2/client.rb
    lib/eet2/contracts/v4_1/request_builder.rb
    lib/eet2/contracts/v4_1/response_parser.rb
    lib/eet2/contracts/v4_1/schema.rb
    lib/eet2/credential.rb
    lib/eet2/errors.rb
    lib/eet2/local_key_signer.rb
    lib/eet2/net_http_transport.rb
    lib/eet2/prepared_request.rb
    lib/eet2/request_integrity_verifier.rb
    lib/eet2/response.rb
    lib/eet2/sale.rb
    lib/eet2/trust_policy.rb
    lib/eet2/transport.rb
    lib/eet2/version.rb
    lib/eet2/xml_signature_verifier.rb
    lib/eet2/xml_signer.rb
    sig/eet2.rbs
  ]

  spec.metadata = {
    "bug_tracker_uri" => "https://github.com/fakturaonline/ruby-eet2/issues",
    "changelog_uri" => "https://github.com/fakturaonline/ruby-eet2/blob/main/CHANGELOG.md",
    "homepage_uri" => "https://github.com/fakturaonline/ruby-eet2",
    "source_code_uri" => "https://github.com/fakturaonline/ruby-eet2",
    "rubygems_mfa_required" => "true"
  }

  spec.add_dependency "base64", ">= 0.2", "< 1"
  spec.add_dependency "bigdecimal", ">= 3.1", "< 5"
  spec.add_dependency "digest", ">= 3.1", "< 4"
  spec.add_dependency "net-http", ">= 0.4", "< 1"
  spec.add_dependency "nokogiri", ">= 1.18", "< 2"
  spec.add_dependency "openssl", ">= 3.0", "< 5"
  spec.add_dependency "securerandom", ">= 0.3", "< 1"
  spec.add_dependency "time", ">= 0.3", "< 1"
  spec.add_dependency "uri", ">= 0.12", "< 2"
end
