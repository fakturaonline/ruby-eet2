# frozen_string_literal: true

require "base64"
require "nokogiri"

RSpec.describe Eet2::CertificateVerifier do
  subject(:verifier) { described_class.new(trust_policy: policy) }

  let(:policy) { Eet2::TrustPolicy.playground }
  let(:live_certificate) do
    document = Nokogiri::XML::Document.parse(
      PROJECT_ROOT.join("spec/fixtures/responses/playground/accepted-live-2026-07-21.xml").binread
    ) { |config| config.strict.nonet }
    token = document.at_xpath("//*[local-name()='BinarySecurityToken']").text
    OpenSSL::X509::Certificate.new(Base64.strict_decode64(token))
  end

  it "builds the observed response leaf to the pinned intermediate and root" do
    evidence = verifier.verify!(certificate: live_certificate, at: Time.utc(2026, 7, 21, 10, 5, 55))

    expect(evidence.certificate_sha256).to eq("b810009edeaf22f6004fb5951e4a10a17ee71e41ab207f912c086ef4cafbf93b")
    expect(evidence.chain_sha256).to eq([
      "b810009edeaf22f6004fb5951e4a10a17ee71e41ab207f912c086ef4cafbf93b",
      Eet2::TrustPolicy::INTERMEDIATE_SHA256,
      Eet2::TrustPolicy::ROOT_SHA256
    ])
  end

  it "rejects certificates outside their validity time" do
    expect do
      verifier.verify!(certificate: live_certificate, at: Time.utc(2035, 1, 1))
    end.to raise_error(Eet2::CertificateVerificationError, /expired/)
  end

  it "rejects an untrusted self-signed signer" do
    expect do
      verifier.verify!(certificate: SpecSupport.certificate, at: Time.utc(2027, 1, 1))
    end.to raise_error(Eet2::CertificateVerificationError, /self-signed|chain validation/)
  end

  it "rejects wrong value types and an incomplete chain policy" do
    expect { verifier.verify!(certificate: "certificate", at: Time.now) }.to raise_error(Eet2::CertificateVerificationError, /X.509/)
    expect { verifier.verify!(certificate: live_certificate, at: "2026") }.to raise_error(Eet2::CertificateVerificationError, /Time/)
    expect { verifier.send(:validate_chain_policy!, [live_certificate]) }.to raise_error(Eet2::CertificateVerificationError, /incomplete/)
  end

  it "rejects a chain that validates structurally but falls outside pinned fingerprints" do
    wrong_root = SpecSupport.certificate
    chain = [live_certificate, policy.intermediates.first, wrong_root]

    expect { verifier.send(:validate_chain_policy!, chain) }.to raise_error(Eet2::CertificateVerificationError, /outside/)
  end
end
