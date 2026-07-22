# frozen_string_literal: true

RSpec.describe Eet2::LocalKeySigner do
  it "produces an RSA PKCS#1 v1.5 SHA-256 signature" do
    signer = described_class.new(private_key: SpecSupport.rsa_key)
    message = "canonical SignedInfo"
    signature = signer.sign_sha256_rsa(message)

    expect(SpecSupport.rsa_key.public_key.verify(OpenSSL::Digest.new("SHA256"), signature, message)).to be(true)
  end

  it "rejects public-only and non-RSA keys" do
    expect { described_class.new(private_key: SpecSupport.rsa_key.public_key) }.to raise_error(Eet2::CredentialError, /private/)
    expect { described_class.new(private_key: OpenSSL::PKey::EC.generate("prime256v1")) }.to raise_error(Eet2::CredentialError, /RSA/)
  end
end
