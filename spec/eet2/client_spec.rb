# frozen_string_literal: true

RSpec.describe Eet2::Client do
  let(:request_uuid) { "03965780-6457-4842-bd80-5f9195c0b8c8" }
  let(:prepared_request) do
    Eet2::Contracts::V4_1::RequestBuilder.new(
      credential: SpecSupport.credential,
      clock: -> { Time.new(2027, 1, 3, 12, 31, 2, "+01:00") },
      uuid_generator: -> { request_uuid }
    ).call(sale: SpecSupport.sale, first_submission: true)
  end
  let(:live_response) { PROJECT_ROOT.join("spec/fixtures/responses/playground/accepted-live-2026-07-21.xml").binread }
  let(:response_parser) { Eet2::Contracts::V4_1::ResponseParser.new }

  it "prepares deterministic requests through the configured builder" do
    calls = []
    builder = lambda do |**arguments|
      calls << arguments
      :prepared
    end
    client = described_class.new(
      request_builder: builder,
      response_parser: ->(**) {},
      transport: ->(*) {}
    )

    result = client.prepare(sale: SpecSupport.sale, first_submission: false, verification_mode: true)

    expect(result).to eq(:prepared)
    expect(calls).to contain_exactly(
      sale: SpecSupport.sale,
      first_submission: false,
      verification_mode: true
    )
  end

  it "performs exactly one transport call and returns only a cryptographically verified receipt" do
    calls = []
    transport = lambda do |request|
      calls << request
      Eet2::Transport::HttpResponse.new(
        status: 200,
        headers: {"X-Global-Transaction-ID" => "trace-accepted"},
        body: live_response
      )
    end
    client = described_class.new(
      request_builder: ->(**) {},
      response_parser: response_parser,
      transport: transport
    )

    result = client.transmit(prepared_request)

    expect(calls).to eq([prepared_request])
    expect(result).to be_a(Eet2::Response::VerifiedReceipt)
    expect(result).to be_accepted
    expect(result).to be_authenticated
    expect(result.support_id).to eq("trace-accepted")
  end

  it "returns an explicitly unauthenticated business error received over HTTP 200" do
    error_request = Eet2::Contracts::V4_1::RequestBuilder.new(
      credential: SpecSupport.credential,
      clock: -> { Time.new(2027, 1, 3, 12, 31, 2, "+01:00") },
      uuid_generator: -> { "123e4567-e89b-42d3-a456-426614174000" }
    ).call(sale: SpecSupport.sale, first_submission: true)
    body = PROJECT_ROOT.join("spec/fixtures/responses/playground/unsigned-error.xml").binread
    client = described_class.new(
      request_builder: ->(**) {},
      response_parser: response_parser,
      transport: lambda do |_request|
        Eet2::Transport::HttpResponse.new(status: 200, headers: {}, body: body)
      end
    )

    result = client.transmit(error_request)

    expect(result).to be_a(Eet2::Response::UnsignedError)
    expect(result.code).to eq(3)
    expect(result).not_to be_accepted
    expect(result).not_to be_authenticated
  end

  it "converts an invalid HTTP 200 body into a typed, non-accepted response" do
    body = "<not-soap/>"
    client = described_class.new(
      request_builder: ->(**) {},
      response_parser: response_parser,
      transport: lambda do |_request|
        Eet2::Transport::HttpResponse.new(
          status: 200,
          headers: {"X-Global-Transaction-ID" => "trace-invalid"},
          body: body
        )
      end
    )

    result = client.transmit(prepared_request)

    expect(result).to be_a(Eet2::Response::InvalidResponse)
    expect(result.reason).to eq(:malformed_response)
    expect(result.response_sha256).to eq(Digest::SHA256.hexdigest(body))
    expect(result.http_status).to eq(200)
    expect(result.support_id).to eq("trace-invalid")
    expect(result).not_to be_accepted
    expect(result).not_to be_authenticated
  end

  it "classifies non-200 responses as possibly sent without parsing their bodies" do
    parser = ->(**) { raise "must not parse" }
    client = described_class.new(
      request_builder: ->(**) {},
      response_parser: parser,
      transport: lambda do |_request|
        Eet2::Transport::HttpResponse.new(
          status: 503,
          headers: {"X-Global-Transaction-ID" => "trace-503"},
          body: "<html/>"
        )
      end
    )

    result = client.transmit(prepared_request)

    expect(result).to be_a(Eet2::Response::TransportFailure)
    expect(result.certainty).to eq(:possibly_sent)
    expect(result.kind).to eq(:http_status)
    expect(result.http_status).to eq(503)
    expect(result.support_id).to eq("trace-503")
  end

  it "preserves the transport certainty without retrying" do
    calls = 0
    client = described_class.new(
      request_builder: ->(**) {},
      response_parser: ->(**) {},
      transport: lambda do |_request|
        calls += 1
        Eet2::Transport::Failure.new(certainty: :not_sent, kind: :connect_timeout)
      end
    )

    result = client.transmit(prepared_request)

    expect(calls).to eq(1)
    expect(result).to be_a(Eet2::Response::TransportFailure)
    expect(result.certainty).to eq(:not_sent)
    expect(result.kind).to eq(:connect_timeout)
  end

  it "rejects corrupted prepared audit metadata before invoking transport" do
    calls = 0
    client = described_class.new(
      request_builder: ->(**) {},
      response_parser: response_parser,
      transport: lambda do |_request|
        calls += 1
        Eet2::Transport::Failure.new(certainty: :not_sent, kind: :connection)
      end
    )

    expect do
      client.transmit(prepared_request.with(body_sha256: "a" * 64))
    end.to raise_error(Eet2::ValidationError, /body_sha256/)
    expect do
      client.transmit(prepared_request.with(schema_sha256: "a" * 64))
    end.to raise_error(Eet2::ValidationError, /schema_sha256/)
    expect(calls).to eq(0)
  end

  it "rejects unsigned WS-Security extensions with zero transport calls" do
    document = Nokogiri::XML::Document.parse(prepared_request.xml) { |config| config.strict.nonet }
    namespaces = {"wsse" => Eet2::XmlSigner::WSSE_NAMESPACE}
    security = document.at_xpath("//wsse:Security", namespaces)
    extension = Nokogiri::XML::Node.new("Extension", document)
    extension.namespace = extension.add_namespace_definition("evil", "urn:example")
    security.add_child(extension)
    xml = document.root.to_xml(
      save_with: Nokogiri::XML::Node::SaveOptions::AS_XML |
        Nokogiri::XML::Node::SaveOptions::NO_DECLARATION
    )
    corrupted = prepared_request.with(xml: xml, request_sha256: Digest::SHA256.hexdigest(xml))
    calls = 0
    client = described_class.new(
      request_builder: ->(**) {},
      response_parser: response_parser,
      transport: lambda do |_request|
        calls += 1
        Eet2::Transport::Failure.new(certainty: :not_sent, kind: :connection)
      end
    )

    expect { client.transmit(corrupted) }.to raise_error(Eet2::ValidationError, /Security/)
    expect(calls).to eq(0)
  end

  it "maps each strict verification family to a stable invalid-response reason" do
    errors = {
      Eet2::MalformedResponse.new => :malformed_response,
      Eet2::SignatureVerificationError.new => :signature_verification,
      Eet2::CertificateVerificationError.new => :certificate_verification,
      Eet2::CorrelationError.new => :correlation,
      Eet2::SchemaValidationError.new(["invalid"]) => :schema_validation
    }
    transport = ->(_) { Eet2::Transport::HttpResponse.new(status: 200, headers: {}, body: "<invalid/>") }

    errors.each do |error, reason|
      client = described_class.new(
        request_builder: ->(**) {},
        response_parser: ->(**) { raise error },
        transport: transport
      )

      expect(client.transmit(prepared_request).reason).to eq(reason)
    end
  end

  it "rejects programmer errors and invalid extension contracts instead of disguising them" do
    expect do
      described_class.new(request_builder: Object.new, response_parser: ->(**) {}, transport: ->(*) {})
    end.to raise_error(Eet2::TransportConfigurationError, /request_builder/)

    wrong_transport = described_class.new(
      request_builder: ->(**) {},
      response_parser: ->(**) {},
      transport: ->(_) { Object.new }
    )
    exploding_parser = described_class.new(
      request_builder: ->(**) {},
      response_parser: ->(**) { raise "programmer bug" },
      transport: ->(_) { Eet2::Transport::HttpResponse.new(status: 200, headers: {}, body: "<x/>") }
    )
    exploding_transport = described_class.new(
      request_builder: ->(**) {},
      response_parser: ->(**) {},
      transport: ->(_) { raise Eet2::MalformedResponse, "extension bug" }
    )

    expect { wrong_transport.transmit(prepared_request) }.to raise_error(Eet2::TransportConfigurationError, /transport must return/)
    expect { exploding_parser.transmit(prepared_request) }.to raise_error(RuntimeError, /programmer bug/)
    expect { exploding_transport.transmit(prepared_request) }.to raise_error(Eet2::MalformedResponse, /extension bug/)
    expect { wrong_transport.transmit("xml") }.to raise_error(Eet2::ValidationError, /PreparedRequest/)
  end

  it "wires the Playground request builder and an injected transport without network access" do
    body = PROJECT_ROOT.join("spec/fixtures/responses/playground/unsigned-error.xml").binread
    transport = lambda do |_request|
      Eet2::Transport::HttpResponse.new(status: 200, headers: {}, body: body)
    end
    client = described_class.playground(
      credential: SpecSupport.credential,
      transport: transport,
      clock: -> { Time.new(2027, 1, 3, 12, 31, 2, "+01:00") },
      uuid_generator: -> { "123e4567-e89b-42d3-a456-426614174000" }
    )

    prepared = client.prepare(sale: SpecSupport.sale, first_submission: true, verification_mode: true)
    result = client.transmit(prepared)

    expect(prepared.verification_mode).to be(true)
    expect(result).to be_a(Eet2::Response::UnsignedError)
    expect(result.code).to eq(3)
  end

  it "wires the production request builder, trust policy, and an injected transport without network access" do
    body = mutate_error_for_production(
      PROJECT_ROOT.join("spec/fixtures/responses/playground/unsigned-error.xml").binread
    )
    transport = lambda do |_request|
      Eet2::Transport::HttpResponse.new(status: 200, headers: {}, body: body)
    end
    client = described_class.production(
      credential: SpecSupport.credential,
      transport: transport,
      clock: -> { Time.new(2027, 1, 3, 12, 31, 2, "+01:00") },
      uuid_generator: -> { "123e4567-e89b-42d3-a456-426614174000" }
    )

    prepared = client.prepare(sale: SpecSupport.sale, first_submission: true, verification_mode: true)
    result = client.transmit(prepared)

    expect(prepared.verification_mode).to be(true)
    expect(result).to be_a(Eet2::Response::UnsignedError)
    expect(result.test).to be_nil
    expect(result.code).to eq(3)
  end

  it "provides safe default clock and UUID generators" do
    client = described_class.playground(
      credential: SpecSupport.credential,
      transport: ->(_) { raise "network is not expected" }
    )

    prepared = client.prepare(sale: SpecSupport.sale, first_submission: true)

    expect(prepared.sent_at).to be_a(Time)
    expect(prepared.request_uuid).to match(Eet2::PreparedRequest::UUID_V4_PATTERN)
  end

  def mutate_error_for_production(xml)
    document = Nokogiri::XML::Document.parse(xml) { |config| config.strict.nonet }
    namespaces = {"v4" => Eet2::XmlSigner::EET_NAMESPACE}
    document.at_xpath("//v4:Chyba", namespaces).remove_attribute("test")
    document.to_xml
  end
end
