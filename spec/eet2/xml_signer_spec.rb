# frozen_string_literal: true

require "base64"
require "nokogiri"

RSpec.describe Eet2::XmlSigner do
  let(:namespaces) do
    {
      "soapenv" => described_class::SOAP_NAMESPACE,
      "wsse" => described_class::WSSE_NAMESPACE,
      "ds" => described_class::DS_NAMESPACE
    }
  end

  it "reproduces the digest and RSA-SHA256 verification of every official request" do
    canonicalizer = described_class.new(certificate: SpecSupport.credential.certificate, signer: SpecSupport.credential.signer)

    Dir[PROJECT_ROOT.join("spec/fixtures/official/eet-v4_1/*.xml")].each do |fixture|
      document = Nokogiri::XML::Document.parse(File.binread(fixture)) { |config| config.strict.nonet }
      body = document.at_xpath("/soapenv:Envelope/soapenv:Body", namespaces)
      signed_info = document.at_xpath("//ds:SignedInfo", namespaces)
      digest_value = document.at_xpath("//ds:DigestValue", namespaces).text
      signature_value = Base64.strict_decode64(document.at_xpath("//ds:SignatureValue", namespaces).text)
      certificate_der = Base64.strict_decode64(document.at_xpath("//wsse:BinarySecurityToken", namespaces).text)
      certificate = OpenSSL::X509::Certificate.new(certificate_der)

      canonical_body = canonicalizer.canonicalize(body, inclusive_namespaces: ["v4"])
      canonical_signed_info = canonicalizer.canonicalize(signed_info, inclusive_namespaces: %w[soapenv v4])

      expect(Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(canonical_body))).to eq(digest_value)
      expect(certificate.public_key.verify(OpenSSL::Digest.new("SHA256"), signature_value, canonical_signed_info)).to be(true)
    end
  end
end
