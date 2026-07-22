# frozen_string_literal: true

require "nokogiri"

RSpec.describe Eet2::Contracts::V4_1::ResponseParser do
  subject(:parser) { described_class.new }

  let(:accepted_xml) { PROJECT_ROOT.join("spec/fixtures/responses/playground/accepted-live-2026-07-21.xml").binread }
  let(:accepted_uuid) { "03965780-6457-4842-bd80-5f9195c0b8c8" }
  let(:unsigned_error_xml) { PROJECT_ROOT.join("spec/fixtures/responses/playground/unsigned-error.xml").binread }
  let(:unsigned_error_uuid) { "123e4567-e89b-42d3-a456-426614174000" }
  let(:namespaces) do
    {
      "soapenv" => Eet2::XmlSigner::SOAP_NAMESPACE,
      "v4" => Eet2::XmlSigner::EET_NAMESPACE,
      "ds" => Eet2::XmlSigner::DS_NAMESPACE,
      "wsse" => Eet2::XmlSigner::WSSE_NAMESPACE
    }
  end

  it "returns a verified immutable receipt only after signature, chain, UUID, and environment checks" do
    result = parser.call(xml: accepted_xml, expected_request_uuid: accepted_uuid)

    expect(result).to be_a(Eet2::Response::VerifiedReceipt)
    expect(result).to be_authenticated
    expect(result.pok).to end_with("-ff")
    expect(result.request_uuid).to eq(accepted_uuid)
    expect(result.signature_evidence.chain_sha256.last).to eq(Eet2::TrustPolicy::ROOT_SHA256)
    expect(result.response_sha256).to eq(Digest::SHA256.hexdigest(accepted_xml))
  end

  it "validates certificate time against an independent receive clock, not signed dat_prij" do
    future_parser = described_class.new(receive_clock: -> { Time.utc(2035, 1, 1) })

    expect do
      future_parser.call(xml: accepted_xml, expected_request_uuid: accepted_uuid)
    end.to raise_error(Eet2::CertificateVerificationError, /expired/)
  end

  it "requires the independent receive clock to return a Time for signed responses" do
    invalid_clock_parser = described_class.new(receive_clock: -> { "2035" })

    expect do
      invalid_clock_parser.call(xml: accepted_xml, expected_request_uuid: accepted_uuid)
    end.to raise_error(Eet2::ValidationError, /receive_clock/)
    expect { described_class.new(receive_clock: Object.new) }.to raise_error(ArgumentError, /receive_clock/)
  end

  it "parses documented unsigned errors without presenting them as authenticated" do
    result = parser.call(xml: unsigned_error_xml, expected_request_uuid: unsigned_error_uuid)

    expect(result).to be_a(Eet2::Response::UnsignedError)
    expect(result).not_to be_authenticated
    expect(result.code).to eq(3)
    expect(result.message).to include("XML schematu")
    expect(result.warnings.map(&:code)).to eq([1])
  end

  it "rejects UUID mismatch after cryptographic verification" do
    expect do
      parser.call(xml: accepted_xml, expected_request_uuid: "123e4567-e89b-42d3-a456-426614174000")
    end.to raise_error(Eet2::CorrelationError, /does not match/)
  end

  it "rejects missing or production-looking Playground markers" do
    no_test = mutate(accepted_xml) { |document| document.at_xpath("//v4:Potvrzeni", namespaces).remove_attribute("test") }
    expect { parser.call(xml: no_test, expected_request_uuid: accepted_uuid) }.to raise_error(Eet2::MalformedResponse, /environment markers|attribute test/)

    production_pok = mutate(accepted_xml) do |document|
      document.at_xpath("//v4:Potvrzeni", namespaces)["pok"] = "91616ac4-83ae-4cca-89c8-986a62bc0c44-00"
    end
    expect { parser.call(xml: production_pok, expected_request_uuid: accepted_uuid) }.to raise_error(Eet2::MalformedResponse, /environment markers/)
  end

  it "accepts only production markers under the production trust policy" do
    evidence = Eet2::Response::SignatureEvidence.new(
      certificate_sha256: "a" * 64,
      chain_sha256: ["b" * 64, "c" * 64, "d" * 64],
      trust_policy_revision: Eet2::TrustPolicy.production.revision
    )
    verifier = instance_double(Eet2::XmlSignatureVerifier, verify!: evidence)
    production_parser = described_class.new(
      trust_policy: Eet2::TrustPolicy.production,
      signature_verifier: verifier
    )
    production_xml = mutate(accepted_xml) do |document|
      confirmation = document.at_xpath("//v4:Potvrzeni", namespaces)
      confirmation.remove_attribute("test")
      confirmation["pok"] = "91616ac4-83ae-4cca-89c8-986a62bc0c44-02"
    end

    result = production_parser.call(xml: production_xml, expected_request_uuid: accepted_uuid)

    expect(result).to be_a(Eet2::Response::VerifiedReceipt)
    expect(result.test).to be_nil
    expect(result.pok).to end_with("-02")
    expect(verifier).to have_received(:verify!).once

    playground_marker = mutate(production_xml) do |document|
      document.at_xpath("//v4:Potvrzeni", namespaces)["test"] = "true"
    end
    fake_pok = mutate(production_xml) do |document|
      document.at_xpath("//v4:Potvrzeni", namespaces)["pok"] = "91616ac4-83ae-4cca-89c8-986a62bc0c44-ff"
    end
    expect { production_parser.call(xml: playground_marker, expected_request_uuid: accepted_uuid) }.to raise_error(
      Eet2::MalformedResponse,
      /production/
    )
    expect { production_parser.call(xml: fake_pok, expected_request_uuid: accepted_uuid) }.to raise_error(
      Eet2::MalformedResponse,
      /production/
    )
  end

  it "checks unsigned error environment markers in both environments" do
    production_error = mutate(unsigned_error_xml) do |document|
      document.at_xpath("//v4:Chyba", namespaces).remove_attribute("test")
    end
    production_parser = described_class.new(trust_policy: Eet2::TrustPolicy.production)

    expect(production_parser.call(xml: production_error, expected_request_uuid: unsigned_error_uuid).test).to be_nil
    expect do
      production_parser.call(xml: unsigned_error_xml, expected_request_uuid: unsigned_error_uuid)
    end.to raise_error(Eet2::MalformedResponse, /production/)
    expect do
      parser.call(xml: production_error, expected_request_uuid: unsigned_error_uuid)
    end.to raise_error(Eet2::MalformedResponse, /playground/)
  end

  it "accepts every XML Schema boolean lexical form for environment markers" do
    evidence = Eet2::Response::SignatureEvidence.new(
      certificate_sha256: "a" * 64,
      chain_sha256: ["b" * 64, "c" * 64, "d" * 64],
      trust_policy_revision: Eet2::TrustPolicy.playground.revision
    )
    verifier = instance_double(Eet2::XmlSignatureVerifier, verify!: evidence)
    numeric_parser = described_class.new(signature_verifier: verifier)
    numeric_true = mutate(accepted_xml) do |document|
      document.at_xpath("//v4:Potvrzeni", namespaces)["test"] = "1"
    end

    expect(numeric_parser.call(xml: numeric_true, expected_request_uuid: accepted_uuid).test).to be(true)
  end

  it "rejects unsigned acceptance and signed error-shaped responses" do
    unsigned_acceptance = mutate(accepted_xml) { |document| document.at_xpath("/soapenv:Envelope/soapenv:Header", namespaces).children.remove }
    expect { parser.call(xml: unsigned_acceptance, expected_request_uuid: accepted_uuid) }.to raise_error(Eet2::SignatureVerificationError, /exactly one/)

    signed_error = mutate(unsigned_error_xml) do |document|
      accepted_header = Nokogiri::XML::Document.parse(accepted_xml).at_xpath("/soapenv:Envelope/soapenv:Header", namespaces)
      document.at_xpath("/soapenv:Envelope/soapenv:Header", namespaces).add_child(accepted_header.element_children.first.dup(1))
    end
    expect { parser.call(xml: signed_error, expected_request_uuid: unsigned_error_uuid) }.to raise_error(Eet2::MalformedResponse, /unsigned profile/)
  end

  it "rejects wrapping structures, DTDs, and XInclude before trusting payloads" do
    duplicate_body = mutate(accepted_xml) do |document|
      document.root.add_child(document.at_xpath("/soapenv:Envelope/soapenv:Body", namespaces).dup(1))
    end
    expect { parser.call(xml: duplicate_body, expected_request_uuid: accepted_uuid) }.to raise_error(Eet2::MalformedResponse, /Header then Body/)

    dtd = accepted_xml.sub(/\A<\?xml[^>]+>\s*/, "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e \"attack\">]>")
    expect { parser.call(xml: dtd, expected_request_uuid: accepted_uuid) }.to raise_error(Eet2::MalformedResponse, /DTD/)

    xinclude = mutate(unsigned_error_xml) do |document|
      document.at_xpath("//v4:Odpoved", namespaces).add_child('<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/passwd"/>')
    end
    expect { parser.call(xml: xinclude, expected_request_uuid: unsigned_error_uuid) }.to raise_error(Eet2::MalformedResponse, /XInclude/)
  end

  it "rejects invalid input, oversized responses, SOAP shape, and XSD data" do
    expect { parser.call(xml: "", expected_request_uuid: accepted_uuid) }.to raise_error(Eet2::MalformedResponse, /non-empty/)
    expect { parser.call(xml: "x" * (described_class::MAX_RESPONSE_BYTES + 1), expected_request_uuid: accepted_uuid) }.to raise_error(Eet2::MalformedResponse, /exceeds/)
    expect { parser.call(xml: "<root/>", expected_request_uuid: accepted_uuid) }.to raise_error(Eet2::MalformedResponse, /SOAP 1.1/)
    expect { parser.call(xml: unsigned_error_xml, expected_request_uuid: "bad") }.to raise_error(Eet2::ValidationError, /version 4/)

    invalid_code = mutate(unsigned_error_xml) { |document| document.at_xpath("//v4:Chyba", namespaces)["kod"] = "not-an-integer" }
    expect { parser.call(xml: invalid_code, expected_request_uuid: unsigned_error_uuid) }.to raise_error(Eet2::SchemaValidationError)
  end

  private

  def mutate(xml)
    document = Nokogiri::XML::Document.parse(xml) { |config| config.strict.nonet }
    yield document
    document.to_xml
  end
end
