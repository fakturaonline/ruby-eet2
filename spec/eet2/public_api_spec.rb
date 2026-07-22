# frozen_string_literal: true

RSpec.describe "public API" do
  it "exposes every documented entry point" do
    classes = [
      Eet2::Client,
      Eet2::Credential,
      Eet2::NetHttpTransport,
      Eet2::PreparedRequest,
      Eet2::Sale,
      Eet2::Response::VerifiedReceipt,
      Eet2::Response::UnsignedError,
      Eet2::Response::InvalidResponse,
      Eet2::Response::TransportFailure,
      Eet2::Transport::HttpResponse,
      Eet2::Transport::Failure
    ]

    expect(classes).to all(be_a(Class))
    expect(Eet2::Client.instance_methods(false)).to contain_exactly(:prepare, :transmit)
    expect(Eet2::Credential).to respond_to(:from_pem, :from_pkcs12)
    expect(Eet2::NetHttpTransport).to respond_to(:playground, :production)
    expect(Eet2::Client).to respond_to(:playground, :production)
  end

  it "rejects conflicting custom-transport options in either environment" do
    expect do
      Eet2::Client.playground(
        credential: SpecSupport.credential,
        transport: ->(_) {},
        read_timeout: 1
      )
    end.to raise_error(Eet2::TransportConfigurationError, /custom transport/)
    expect do
      Eet2::Client.production(
        credential: SpecSupport.credential,
        transport: ->(_) {},
        read_timeout: 1
      )
    end.to raise_error(Eet2::TransportConfigurationError, /custom transport/)
  end

  it "keeps the protocol endpoint and SOAP action exact" do
    expect(Eet2::Transport::PLAYGROUND_ENDPOINT).to eq(
      "https://pg.trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4"
    )
    expect(Eet2::Transport::PRODUCTION_ENDPOINT).to eq(
      "https://trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4"
    )
    expect(Eet2::Transport::SOAP_ACTION).to eq("http://fs.gov.cz/eet/OdeslaniTrzby")
    expect(Eet2::Transport::ALLOWED_ENDPOINTS).to eq([
      Eet2::Transport::PLAYGROUND_ENDPOINT,
      Eet2::Transport::PRODUCTION_ENDPOINT
    ])
    expect(Eet2::Transport::ALLOWED_ENDPOINTS).to be_frozen
  end
end
