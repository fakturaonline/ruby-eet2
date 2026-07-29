# frozen_string_literal: true

RSpec.describe Eet2::PreparedRequest do
  def attributes
    {
      request_uuid: "123e4567-e89b-42d3-a456-426614174000",
      sent_at: Time.utc(2027, 1, 3, 11, 30, 45),
      sale: SpecSupport.sale,
      first_submission: true,
      verification_mode: false,
      xml: "<request/>",
      request_sha256: Digest::SHA256.hexdigest("<request/>"),
      body_sha256: "b" * 64,
      certificate_sha256: "c" * 64,
      protocol_version: "4.1",
      schema_sha256: "d" * 64
    }
  end

  it "defensively freezes persisted attempt metadata" do
    prepared = described_class.new(**attributes)

    expect(prepared).to be_frozen
    expect(prepared.xml).to be_frozen
    expect(prepared.request_uuid).to be_frozen
  end

  it "enforces UUIDv4, booleans, protocol version, and digest formats" do
    expect { described_class.new(**attributes.merge(request_uuid: "not-a-uuid")) }.to raise_error(Eet2::ValidationError, /version 4/)
    expect { described_class.new(**attributes.merge(first_submission: nil)) }.to raise_error(Eet2::ValidationError, /first_submission/)
    expect { described_class.new(**attributes.merge(protocol_version: "4")) }.to raise_error(Eet2::ValidationError, /4.1/)
    expect { described_class.new(**attributes.merge(body_sha256: "A" * 64)) }.to raise_error(Eet2::ValidationError, /lowercase/)
    expect { described_class.new(**attributes.merge(sale: Object.new)) }.to raise_error(Eet2::ValidationError, /Sale/)
    expect { described_class.new(**attributes.merge(request_sha256: "a" * 64)) }.to raise_error(Eet2::ValidationError, /does not match/)
  end

  it "redacts the signed XML from inspect, to_s, and pretty printing" do
    require "pp"

    signed_xml = PROJECT_ROOT.join("spec/fixtures/official/eet-v4_1/CZ00000019.eet.v4.req.xml").binread
    prepared = described_class.new(
      **attributes.merge(xml: signed_xml, request_sha256: Digest::SHA256.hexdigest(signed_xml))
    )
    renderings = [prepared.inspect, prepared.to_s, format("%s", prepared), PP.pp(prepared, +"")]

    renderings.each do |rendering|
      expect(rendering).not_to include("SignatureValue")
      expect(rendering).not_to include("BinarySecurityToken")
      expect(rendering).not_to include("Envelope")
      expect(rendering).not_to include(signed_xml[0, 64])
      expect(rendering).to include(prepared.request_uuid)
      expect(rendering).to include(prepared.request_sha256)
      expect(rendering).to include("xml_bytesize=#{signed_xml.bytesize}")
      expect(rendering).to include("[redacted]")
      expect(rendering.length).to be < 1_000
    end
  end

  it "keeps sale business data out of inspection output" do
    prepared = described_class.new(**attributes)

    expect(prepared.inspect).not_to include(prepared.sale.sequence_number)
    expect(prepared.inspect).not_to include(prepared.sale.taxpayer_eic)
  end

  it "rejects a request over the official 12 kB maximum" do
    oversized = "x" * (described_class::MAX_BYTES + 1)

    expect { described_class.new(**attributes.merge(xml: oversized)) }.to raise_error(Eet2::RequestTooLarge, /maximum/)
  end
end
