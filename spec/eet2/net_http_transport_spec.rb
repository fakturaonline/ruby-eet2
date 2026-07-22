# frozen_string_literal: true

module NetHttpTransportSpecSupport
  class Response
    attr_reader :code

    def initialize(code:, headers:, chunks:, read_error: nil)
      @code = code
      @headers = headers
      @chunks = chunks
      @read_error = read_error
    end

    def each_header
      return enum_for(__method__) unless block_given?

      @headers.each { |name, value| yield(name, value) }
    end

    def read_body
      @chunks.each { |chunk| yield chunk }
      raise @read_error if @read_error
    end
  end

  class Http
    SETTINGS = %i[
      use_ssl verify_mode verify_hostname min_version open_timeout read_timeout
      write_timeout max_retries
    ].freeze

    attr_accessor(*SETTINGS)
    attr_reader :requests, :starts

    def initialize(response: nil, start_error: nil, request_error: nil)
      @response = response
      @start_error = start_error
      @request_error = request_error
      @requests = []
      @starts = 0
    end

    def start
      @starts += 1
      raise @start_error if @start_error

      yield self
    end

    def request(request)
      @requests << request
      raise @request_error if @request_error

      yield @response
    end
  end
end

RSpec.describe Eet2::NetHttpTransport do
  let(:prepared_request) do
    Eet2::Contracts::V4_1::RequestBuilder.new(
      credential: SpecSupport.credential,
      clock: -> { Time.new(2027, 1, 3, 12, 31, 2, "+01:00") },
      uuid_generator: -> { "123e4567-e89b-42d3-a456-426614174000" }
    ).call(sale: SpecSupport.sale, first_submission: true)
  end
  let(:response) do
    NetHttpTransportSpecSupport::Response.new(
      code: "200",
      headers: {"X-Global-Transaction-ID" => "trace-123"},
      chunks: ["<one", "/>"]
    )
  end
  let(:http) { NetHttpTransportSpecSupport::Http.new(response: response) }
  let(:factory_calls) { [] }
  let(:factory) do
    calls = factory_calls
    instance = http
    lambda do |host, port|
      calls << [host, port]
      instance
    end
  end

  subject(:transport) { described_class.playground(http_factory: factory) }

  it "performs one exact SOAP POST with strict TLS and retry controls" do
    result = transport.call(prepared_request)

    expect(result).to be_a(Eet2::Transport::HttpResponse)
    expect(result.status).to eq(200)
    expect(result.body).to eq("<one/>")
    expect(result.support_id).to eq("trace-123")
    expect(factory_calls).to eq([["pg.trzbyeet.gov.cz", 443]])
    expect(http.starts).to eq(1)
    expect(http.requests.length).to eq(1)

    request = http.requests.fetch(0)
    expect(request).to be_a(Net::HTTP::Post)
    expect(request.path).to eq("/eet/services/EETServiceSOAP/v4")
    expect(request.body).to eq(prepared_request.xml)
    expect(request["Content-Type"]).to eq("text/xml; charset=utf-8")
    expect(request["SOAPAction"]).to eq(%("#{Eet2::Transport::SOAP_ACTION}"))
    expect(request["Accept"]).to eq("text/xml")
    expect(request["Accept-Encoding"]).to eq("identity")

    expect(http.use_ssl).to be(true)
    expect(http.verify_mode).to eq(OpenSSL::SSL::VERIFY_PEER)
    expect(http.verify_hostname).to be(true)
    expect(http.min_version).to eq(OpenSSL::SSL::TLS1_2_VERSION)
    expect(http.open_timeout).to eq(5)
    expect(http.read_timeout).to eq(10)
    expect(http.write_timeout).to eq(5)
    expect(http.max_retries).to eq(0)
  end

  it "uses the exact production host through the same strict transport" do
    production = described_class.production(http_factory: factory)

    result = production.call(prepared_request)

    expect(result).to be_a(Eet2::Transport::HttpResponse)
    expect(factory_calls).to eq([["trzbyeet.gov.cz", 443]])
    expect(http.requests.fetch(0).path).to eq("/eet/services/EETServiceSOAP/v4")
    expect(http.verify_mode).to eq(OpenSSL::SSL::VERIFY_PEER)
    expect(http.verify_hostname).to be(true)
    expect(http.min_version).to eq(OpenSSL::SSL::TLS1_2_VERSION)
  end

  it "returns redirects without following them" do
    redirect = NetHttpTransportSpecSupport::Response.new(
      code: "302",
      headers: {"Location" => "https://attacker.invalid/"},
      chunks: []
    )
    allow(http).to receive(:request).and_wrap_original do |method, request, &block|
      method.call(request) { block.call(redirect) }
    end

    result = transport.call(prepared_request)

    expect(result.status).to eq(302)
    expect(http.starts).to eq(1)
    expect(http.requests.length).to eq(1)
  end

  it "classifies connect-phase timeout, DNS, TLS, and connection failures as not sent" do
    cases = {
      Net::OpenTimeout.new => :connect_timeout,
      SocketError.new => :dns,
      OpenSSL::SSL::SSLError.new => :tls,
      Errno::ECONNREFUSED.new => :connection
    }

    cases.each do |error, expected_kind|
      failing_http = NetHttpTransportSpecSupport::Http.new(start_error: error)
      result = described_class.playground(http_factory: ->(*) { failing_http }).call(prepared_request)

      expect(result.certainty).to eq(:not_sent)
      expect(result.kind).to eq(expected_kind)
      expect(failing_http.starts).to eq(1)
      expect(failing_http.requests).to be_empty
    end
  end

  it "classifies any timeout or reset after request invocation as possibly sent" do
    [Net::ReadTimeout.new, Net::WriteTimeout.new, Errno::ECONNRESET.new].each do |error|
      failing_http = NetHttpTransportSpecSupport::Http.new(request_error: error)
      result = described_class.playground(http_factory: ->(*) { failing_http }).call(prepared_request)

      expect(result.certainty).to eq(:possibly_sent)
      expect(result.kind).to eq(error.is_a?(Timeout::Error) ? :timeout : :connection)
      expect(failing_http.requests.length).to eq(1)
    end
  end

  it "bounds streamed response bytes after a request may have been sent" do
    limited = described_class.playground(http_factory: factory, max_response_bytes: 4)

    result = limited.call(prepared_request)

    expect(result.certainty).to eq(:possibly_sent)
    expect(result.kind).to eq(:response_too_large)
  end

  it "classifies malformed HTTP after request invocation as a protocol failure" do
    failing_http = NetHttpTransportSpecSupport::Http.new(request_error: Net::HTTPBadResponse.new("bad"))

    result = described_class.playground(http_factory: ->(*) { failing_http }).call(prepared_request)

    expect(result.certainty).to eq(:possibly_sent)
    expect(result.kind).to eq(:protocol)
  end

  it "rejects unallowlisted endpoints, invalid options, and wrong request values" do
    expect { described_class.new(endpoint: "https://example.test/") }.to raise_error(Eet2::TransportConfigurationError, /allowlisted/)
    expect { described_class.playground(open_timeout: 0) }.to raise_error(Eet2::TransportConfigurationError, /open_timeout/)
    expect { described_class.playground(max_response_bytes: 1.5) }.to raise_error(Eet2::TransportConfigurationError, /max_response_bytes/)
    expect { described_class.playground(http_factory: Object.new) }.to raise_error(Eet2::TransportConfigurationError, /http_factory/)
    expect { transport.call("xml") }.to raise_error(Eet2::TransportConfigurationError, /PreparedRequest/)
  end

  it "revalidates the syntax and HTTPS shape of every configured allowlist entry" do
    stub_const("Eet2::Transport::ALLOWED_ENDPOINTS", ["not a URI", "http://example.test/eet"])

    expect { described_class.new(endpoint: "not a URI") }.to raise_error(Eet2::TransportConfigurationError, /valid URI/)
    expect { described_class.new(endpoint: "http://example.test/eet") }.to raise_error(Eet2::TransportConfigurationError, /exact HTTPS/)
  end

  it "fails closed when an HTTP adapter lacks a required security control" do
    incomplete_http = Object.new
    factory = ->(*) { incomplete_http }
    strict_transport = described_class.playground(http_factory: factory)

    expect { strict_transport.call(prepared_request) }.to raise_error(
      Eet2::TransportConfigurationError,
      /required TLS and retry controls/
    )
  end
end
