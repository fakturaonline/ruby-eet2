# frozen_string_literal: true

require_relative "errors"

module Eet2
  module Transport
    SOAP_ACTION = "http://fs.gov.cz/eet/OdeslaniTrzby"
    PLAYGROUND_ENDPOINT = "https://pg.trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4"
    PRODUCTION_ENDPOINT = "https://trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4"
    ALLOWED_ENDPOINTS = [PLAYGROUND_ENDPOINT, PRODUCTION_ENDPOINT].freeze
    MAX_RESPONSE_BYTES = 256 * 1024
    SUPPORT_ID_PATTERN = /\A[\x21-\x7e]{1,128}\z/
    FAILURE_CERTAINTIES = %i[not_sent possibly_sent unknown].freeze
    FAILURE_KINDS = %i[connect_timeout dns tls connection timeout protocol response_too_large].freeze

    HttpResponse = Data.define(:status, :headers, :body) do
      def initialize(status:, headers:, body:)
        raise TransportConfigurationError, "HTTP status must be an Integer from 100 to 599" unless status.is_a?(Integer) && status.between?(100, 599)
        raise TransportConfigurationError, "HTTP headers must be a Hash" unless headers.is_a?(Hash)
        raise TransportConfigurationError, "HTTP response body must be a String" unless body.is_a?(String)

        normalized_headers = headers.each_with_object({}) do |(name, value), result|
          raise TransportConfigurationError, "HTTP header names and values must be Strings" unless name.is_a?(String) && value.is_a?(String)

          result[name.downcase.freeze] = value.dup.freeze
        end.freeze

        super(status: status, headers: normalized_headers, body: body.dup.freeze)
      end

      def support_id
        value = headers["x-global-transaction-id"]
        value if value&.match?(SUPPORT_ID_PATTERN)
      end
    end

    Failure = Data.define(:certainty, :kind) do
      def initialize(certainty:, kind:)
        raise TransportConfigurationError, "invalid transport certainty" unless FAILURE_CERTAINTIES.include?(certainty)
        raise TransportConfigurationError, "invalid transport failure kind" unless FAILURE_KINDS.include?(kind)

        super
      end
    end
  end
end
