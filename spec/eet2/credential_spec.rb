# frozen_string_literal: true

RSpec.describe Eet2::Credential do
  let(:key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:certificate) { SpecSupport.certificate(private_key: key, serial: 20) }

  it "imports matching PEM credentials and a certificate chain" do
    chain_certificate = SpecSupport.certificate(private_key: SpecSupport.rsa_key, common_name: "Test CA", serial: 21)
    credential = described_class.from_pem(
      certificate_pem: certificate.to_pem,
      private_key_pem: key.to_pem,
      chain_pems: [chain_certificate.to_pem]
    )

    expect(credential.certificate.to_der).to eq(certificate.to_der)
    expect(credential.chain.map(&:to_der)).to eq([chain_certificate.to_der])
    expect(credential.certificate_sha256).to match(/\A[0-9a-f]{64}\z/)
  end

  it "imports a modern PKCS#12 credential" do
    bytes = OpenSSL::PKCS12.create("correct horse", "eet2 test", key, certificate).to_der
    credential = described_class.from_pkcs12(bytes: bytes, password: "correct horse")

    expect(credential.certificate.to_der).to eq(certificate.to_der)
    expect(credential.signer).to be_a(Eet2::LocalKeySigner)
  end

  it "rejects a certificate and private-key mismatch" do
    other_key = OpenSSL::PKey::RSA.generate(2048)

    expect do
      described_class.from_pem(certificate_pem: certificate.to_pem, private_key_pem: other_key.to_pem)
    end.to raise_error(Eet2::CredentialError, /does not match/)
  end

  it "reports invalid or wrongly encrypted PKCS#12 without exposing secrets" do
    expect do
      described_class.from_pkcs12(bytes: "not a p12", password: "sensitive password")
    end.to raise_error(Eet2::CredentialError, /import failed/) { |error| expect(error.message).not_to include("sensitive") }
  end

  it "requires explicit opt-in when OpenSSL reports disabled legacy algorithms" do
    allow(described_class).to receive(:parse_pkcs12).and_raise(OpenSSL::PKCS12::PKCS12Error, "unsupported algorithm")

    expect do
      described_class.from_pkcs12(bytes: "legacy", password: "secret")
    end.to raise_error(Eet2::LegacyPkcs12Unsupported, /explicitly_allowed/)
  end

  it "rejects unknown legacy-provider policy values" do
    expect do
      described_class.from_pkcs12(bytes: "p12", password: "secret", legacy_provider: :automatic)
    end.to raise_error(ArgumentError, /legacy_provider/)
  end
end
