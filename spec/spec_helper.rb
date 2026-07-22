# frozen_string_literal: true

require "pathname"
require "openssl"

require "simplecov"

SimpleCov.start do
  enable_coverage :branch
  add_filter "/spec/"
  minimum_coverage line: 95, branch: 85
end

require "eet2"

PROJECT_ROOT = Pathname(__dir__).join("..").realpath

module SpecSupport
  module_function

  def rsa_key
    @rsa_key ||= OpenSSL::PKey::RSA.generate(2048)
  end

  def certificate(private_key: rsa_key, common_name: "CZ00000019", serial: 1)
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = serial
    certificate.subject = OpenSSL::X509::Name.parse("/C=CZ/O=EET2 test/CN=#{common_name}")
    certificate.issuer = certificate.subject
    certificate.public_key = private_key.public_key
    certificate.not_before = Time.utc(2026, 1, 1)
    certificate.not_after = Time.utc(2030, 1, 1)

    extension_factory = OpenSSL::X509::ExtensionFactory.new
    extension_factory.subject_certificate = certificate
    extension_factory.issuer_certificate = certificate
    certificate.add_extension(extension_factory.create_extension("basicConstraints", "CA:FALSE", true))
    certificate.add_extension(extension_factory.create_extension("keyUsage", "digitalSignature", true))
    certificate.add_extension(extension_factory.create_extension("subjectKeyIdentifier", "hash"))
    certificate.sign(private_key, OpenSSL::Digest.new("SHA256"))
    certificate
  end

  def credential
    @credential ||= Eet2::Credential.new(
      certificate: certificate,
      signer: Eet2::LocalKeySigner.new(private_key: rsa_key)
    )
  end

  def sale(**overrides)
    defaults = {
      taxpayer_eic: "CZ00000019",
      evidence_unit_id: 303,
      register_id: "web-1",
      sequence_number: "payment/2027/123",
      occurred_at: Time.new(2027, 1, 3, 12, 30, 45, "+01:00"),
      amount_czk: BigDecimal("1250.00")
    }

    Eet2::Sale.new(**defaults.merge(overrides))
  end
end

RSpec.configure do |config|
  config.disable_monkey_patching!
  config.example_status_persistence_file_path = PROJECT_ROOT.join("tmp/rspec-examples.txt").to_s
  config.order = :random
  config.filter_run_excluding live: true unless ENV["RUN_EET2_PLAYGROUND"] == "1"
end
