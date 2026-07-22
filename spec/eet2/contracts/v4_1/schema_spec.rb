# frozen_string_literal: true

require "nokogiri"

RSpec.describe Eet2::Contracts::V4_1::Schema do
  subject(:schema) { described_class.new }

  it "validates every official v4.1 signed request payload" do
    fixtures = Dir[PROJECT_ROOT.join("spec/fixtures/official/eet-v4_1/*.xml")]

    expect(fixtures.length).to eq(3)
    fixtures.each do |fixture|
      document = Nokogiri::XML::Document.parse(File.binread(fixture)) { |config| config.strict.nonet }
      payload = document.at_xpath("//v4:Trzba", "v4" => Eet2::XmlSigner::EET_NAMESPACE)

      expect(schema.validate_payload!(payload)).to be(true)
    end
  end

  it "returns sanitized XSD errors for malformed request data" do
    xml = <<~XML
      <v4:Trzba xmlns:v4="#{Eet2::XmlSigner::EET_NAMESPACE}">
        <v4:Hlavicka uuid_zpravy="123e4567-e89b-42d3-a456-426614174000" dat_odesl="2027-01-03T11:30:45Z" prvni_zaslani="true"/>
        <v4:Data eic_popl="CZ00000019" id_jednotky="303" id_pokl="web-1" porad_cis="1" dat_trzby="2027-01-03T11:30:45Z" celk_trzba="1.2"/>
      </v4:Trzba>
    XML

    expect { schema.validate_payload!(xml) }.to raise_error(Eet2::SchemaValidationError, /celk_trzba/) do |error|
      expect(error.message).not_to include(PROJECT_ROOT.to_s)
    end
  end
end
