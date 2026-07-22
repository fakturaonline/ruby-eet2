# frozen_string_literal: true

require "base64"
require "digest"
require "nokogiri"

RSpec.describe Eet2::Contracts::V4_1::RequestBuilder do
  let(:request_uuid) { "123e4567-e89b-42d3-a456-426614174000" }
  let(:sent_at) { Time.new(2027, 1, 3, 12, 31, 2, "+01:00") }
  let(:builder) do
    described_class.new(
      credential: SpecSupport.credential,
      uuid_generator: -> { request_uuid },
      clock: -> { sent_at }
    )
  end
  let(:namespaces) do
    {
      "soapenv" => Eet2::XmlSigner::SOAP_NAMESPACE,
      "v4" => Eet2::XmlSigner::EET_NAMESPACE,
      "wsse" => Eet2::XmlSigner::WSSE_NAMESPACE,
      "wsu" => Eet2::XmlSigner::WSU_NAMESPACE,
      "ds" => Eet2::XmlSigner::DS_NAMESPACE,
      "ec" => Eet2::XmlSigner::EXCLUSIVE_C14N_NAMESPACE
    }
  end

  it "creates a deterministic, schema-valid, signed SOAP v4.1 request" do
    prepared = builder.call(sale: SpecSupport.sale, first_submission: true)
    repeated = builder.call(sale: SpecSupport.sale, first_submission: true)
    document = parse(prepared.xml)

    expect(prepared.xml).to eq(repeated.xml)
    expect(prepared.request_sha256).to eq(Digest::SHA256.hexdigest(prepared.xml))
    expect(prepared.xml.bytesize).to be <= Eet2::PreparedRequest::MAX_BYTES
    expect(prepared.protocol_version).to eq("4.1")
    expect(prepared.schema_sha256).to eq(Eet2::Contracts::V4_1::Schema::SHA256)
    expect(document.xpath("/soapenv:Envelope/soapenv:Body", namespaces).length).to eq(1)
    expect(document.xpath("//ds:Signature", namespaces).length).to eq(1)
    expect(document.at_xpath("/soapenv:Envelope/soapenv:Body", namespaces).attribute_with_ns("Id", Eet2::XmlSigner::WSU_NAMESPACE)).not_to be_nil
    expect(document.at_xpath("//v4:Hlavicka", namespaces)["overeni"]).to be_nil
    expect(document.at_xpath("//v4:Data", namespaces)["celk_trzba"]).to eq("1250.00")
    expect(Eet2::Contracts::V4_1::Schema.new.validate_payload!(document.at_xpath("//v4:Trzba", namespaces))).to be(true)

    verify_signature!(document, prepared)
  end

  it "serializes retry, verification mode, delegation, and drawdown fields without empty optionals" do
    sale = SpecSupport.sale(
      authorizing_taxpayer_eic: "CZ12345678",
      multiple_authorization: false,
      designated_drawdown_amount_czk: BigDecimal("25.00"),
      drawdown_amount_czk: BigDecimal("-2.50")
    )
    prepared = builder.call(sale: sale, first_submission: false, verification_mode: true)
    document = parse(prepared.xml)
    header = document.at_xpath("//v4:Hlavicka", namespaces)
    data = document.at_xpath("//v4:Data", namespaces)

    expect(header["prvni_zaslani"]).to eq("false")
    expect(header["overeni"]).to eq("true")
    expect(data["eic_poverujiciho"]).to eq("CZ12345678")
    expect(data["povereni_vice_popl"]).to eq("false")
    expect(data["urceno_cerp_zuct"]).to eq("25.00")
    expect(data["cerp_zuct"]).to eq("-2.50")
    expect(data.attribute_nodes.map(&:value)).not_to include("")
  end

  it "normalizes the send clock to whole seconds but preserves its UTC offset" do
    fractional = Time.at(sent_at.to_i, 123_456, :microsecond).getlocal("+01:00")
    fractional_builder = described_class.new(
      credential: SpecSupport.credential,
      uuid_generator: -> { request_uuid },
      clock: -> { fractional }
    )

    prepared = fractional_builder.call(sale: SpecSupport.sale, first_submission: true)

    expect(prepared.sent_at.nsec).to eq(0)
    expect(parse(prepared.xml).at_xpath("//v4:Hlavicka", namespaces)["dat_odesl"]).to eq("2027-01-03T12:31:02+01:00")
  end

  it "rejects invalid injected UUIDs and non-boolean mode flags" do
    invalid_builder = described_class.new(
      credential: SpecSupport.credential,
      uuid_generator: -> { "not-a-uuid" },
      clock: -> { sent_at }
    )

    expect { invalid_builder.call(sale: SpecSupport.sale, first_submission: true) }.to raise_error(Eet2::ValidationError, /UUID/)
    expect { builder.call(sale: SpecSupport.sale, first_submission: nil) }.to raise_error(Eet2::ValidationError, /first_submission/)
  end

  private

  def parse(xml)
    Nokogiri::XML::Document.parse(xml) { |config| config.strict.nonet }
  end

  def verify_signature!(document, prepared)
    canonicalizer = Eet2::XmlSigner.new(certificate: SpecSupport.credential.certificate, signer: SpecSupport.credential.signer)
    body = document.at_xpath("/soapenv:Envelope/soapenv:Body", namespaces)
    signed_info = document.at_xpath("//ds:SignedInfo", namespaces)
    digest_value = document.at_xpath("//ds:DigestValue", namespaces).text
    signature_value = Base64.strict_decode64(document.at_xpath("//ds:SignatureValue", namespaces).text)
    certificate = OpenSSL::X509::Certificate.new(Base64.strict_decode64(document.at_xpath("//wsse:BinarySecurityToken", namespaces).text))
    canonical_body = canonicalizer.canonicalize(body, inclusive_namespaces: ["v4"])
    canonical_signed_info = canonicalizer.canonicalize(signed_info, inclusive_namespaces: %w[soapenv v4])

    expect(Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(canonical_body))).to eq(digest_value)
    expect(Digest::SHA256.hexdigest(canonical_body)).to eq(prepared.body_sha256)
    expect(certificate.public_key.verify(OpenSSL::Digest.new("SHA256"), signature_value, canonical_signed_info)).to be(true)
    expect(document.at_xpath("//ds:Reference", namespaces)["URI"]).to eq("##{body["wsu:Id"]}")
    expect(document.at_xpath("//ds:SignatureMethod", namespaces)["Algorithm"]).to eq(Eet2::XmlSigner::RSA_SHA256_ALGORITHM)
    expect(document.at_xpath("//ds:DigestMethod", namespaces)["Algorithm"]).to eq(Eet2::XmlSigner::SHA256_ALGORITHM)
  end
end
