# frozen_string_literal: true

require "net/http"
require "openssl"
require "uri"

require_relative "prepared_request"
require_relative "transport"

module Eet2
  class NetHttpTransport
    DEFAULT_OPEN_TIMEOUT = 5
    DEFAULT_READ_TIMEOUT = 10
    DEFAULT_WRITE_TIMEOUT = 5
    # Defense in depth only. The host owns the legal response window; this floor
    # merely makes a socket read timeout that could never reach it a configuration
    # error instead of a silent source of avoidable `possibly_sent` outcomes.
    MINIMUM_READ_TIMEOUT = 2

    NETWORK_ERRORS = [
      Timeout::Error,
      SocketError,
      OpenSSL::SSL::SSLError,
      SystemCallError,
      EOFError,
      IOError,
      Net::HTTPBadResponse,
      Net::HTTPHeaderSyntaxError,
      Net::ProtocolError
    ].freeze

    ResponseTooLarge = Class.new(StandardError)

    def self.playground(**options)
      new(endpoint: Transport::PLAYGROUND_ENDPOINT, **options)
    end

    def self.production(**options)
      new(endpoint: Transport::PRODUCTION_ENDPOINT, **options)
    end

    def initialize(
      endpoint:,
      open_timeout: DEFAULT_OPEN_TIMEOUT,
      read_timeout: DEFAULT_READ_TIMEOUT,
      write_timeout: DEFAULT_WRITE_TIMEOUT,
      max_response_bytes: Transport::MAX_RESPONSE_BYTES,
      http_factory: nil
    )
      @uri = parse_endpoint(endpoint)
      @open_timeout = positive_number(open_timeout, "open_timeout")
      @read_timeout = read_timeout_seconds(read_timeout)
      @write_timeout = positive_number(write_timeout, "write_timeout")
      @max_response_bytes = positive_integer(max_response_bytes, "max_response_bytes")
      @http_factory = http_factory || ->(host, port) { Net::HTTP.new(host, port) }
      raise TransportConfigurationError, "http_factory must respond to call" unless @http_factory.respond_to?(:call)
    end

    def call(prepared_request)
      unless prepared_request.is_a?(PreparedRequest)
        raise TransportConfigurationError, "prepared_request must be an Eet2::PreparedRequest"
      end

      request = build_request(prepared_request.xml)
      phase = :connect
      http = @http_factory.call(@uri.host, @uri.port)
      configure_http!(http)

      response = http.start do |connection|
        phase = :request
        perform_request(connection, request)
      end

      Transport::HttpResponse.new(**response)
    rescue ResponseTooLarge
      Transport::Failure.new(certainty: :possibly_sent, kind: :response_too_large)
    rescue *NETWORK_ERRORS => error
      Transport::Failure.new(
        certainty: (phase == :connect) ? :not_sent : :possibly_sent,
        kind: failure_kind(error, phase)
      )
    end

    private

    def parse_endpoint(endpoint)
      unless endpoint.is_a?(String) && Transport::ALLOWED_ENDPOINTS.include?(endpoint)
        raise TransportConfigurationError, "endpoint is not an allowlisted EET2 endpoint"
      end

      uri = URI.parse(endpoint)
      unless uri.is_a?(URI::HTTPS) && uri.userinfo.nil? && uri.query.nil? && uri.fragment.nil?
        raise TransportConfigurationError, "endpoint must be an exact HTTPS URL without credentials, query, or fragment"
      end

      uri
    rescue URI::InvalidURIError => error
      raise TransportConfigurationError, "endpoint is not a valid URI", cause: error
    end

    def positive_number(value, name)
      unless value.is_a?(Numeric) && value.finite? && value.positive?
        raise TransportConfigurationError, "#{name} must be a positive finite number"
      end

      value
    end

    def read_timeout_seconds(value)
      number = positive_number(value, "read_timeout")
      if number < MINIMUM_READ_TIMEOUT
        raise TransportConfigurationError, "read_timeout must be at least #{MINIMUM_READ_TIMEOUT} seconds"
      end

      number
    end

    def positive_integer(value, name)
      unless value.is_a?(Integer) && value.positive?
        raise TransportConfigurationError, "#{name} must be a positive Integer"
      end

      value
    end

    def build_request(xml)
      request = Net::HTTP::Post.new(@uri.request_uri)
      request["Content-Type"] = "text/xml; charset=utf-8"
      request["SOAPAction"] = %("#{Transport::SOAP_ACTION}")
      request["Accept"] = "text/xml"
      request["Accept-Encoding"] = "identity"
      request.body = xml
      request
    end

    def configure_http!(http)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      http.verify_hostname = true
      http.min_version = OpenSSL::SSL::TLS1_2_VERSION
      http.open_timeout = @open_timeout
      http.read_timeout = @read_timeout
      http.write_timeout = @write_timeout
      http.max_retries = 0
    rescue NoMethodError => error
      raise TransportConfigurationError, "HTTP adapter does not support the required TLS and retry controls", cause: error
    end

    def perform_request(connection, request)
      status = nil
      headers = nil
      body = +""

      connection.request(request) do |response|
        status = Integer(response.code, 10)
        headers = response.each_header.to_h
        response.read_body do |chunk|
          raise ResponseTooLarge if body.bytesize + chunk.bytesize > @max_response_bytes

          body << chunk
        end
      end

      {status: status, headers: headers, body: body}
    end

    def failure_kind(error, phase)
      return :connect_timeout if phase == :connect && error.is_a?(Timeout::Error)
      return :dns if phase == :connect && error.is_a?(SocketError)
      return :tls if error.is_a?(OpenSSL::SSL::SSLError)
      return :timeout if error.is_a?(Timeout::Error)
      return :protocol if error.is_a?(Net::HTTPBadResponse) || error.is_a?(Net::HTTPHeaderSyntaxError) || error.is_a?(Net::ProtocolError)

      :connection
    end
  end
end
