# frozen_string_literal: true

require "digest"
require "securerandom"

require_relative "contracts/v4_1/request_builder"
require_relative "contracts/v4_1/response_parser"
require_relative "errors"
require_relative "net_http_transport"
require_relative "prepared_request"
require_relative "request_integrity_verifier"
require_relative "response"
require_relative "trust_policy"
require_relative "transport"

module Eet2
  class Client
    def self.playground(
      credential:,
      transport: nil,
      clock: -> { Time.now },
      receive_clock: -> { Time.now },
      uuid_generator: -> { SecureRandom.uuid },
      **transport_options
    )
      if transport && !transport_options.empty?
        raise TransportConfigurationError, "transport timeout options cannot be combined with a custom transport"
      end

      trust_policy = TrustPolicy.playground
      new(
        request_builder: Contracts::V4_1::RequestBuilder.new(
          credential: credential,
          clock: clock,
          uuid_generator: uuid_generator
        ),
        response_parser: Contracts::V4_1::ResponseParser.new(
          trust_policy: trust_policy,
          receive_clock: receive_clock
        ),
        transport: transport || NetHttpTransport.playground(**transport_options)
      )
    end

    def self.production(
      credential:,
      transport: nil,
      clock: -> { Time.now },
      receive_clock: -> { Time.now },
      uuid_generator: -> { SecureRandom.uuid },
      **transport_options
    )
      if transport && !transport_options.empty?
        raise TransportConfigurationError, "transport timeout options cannot be combined with a custom transport"
      end

      trust_policy = TrustPolicy.production
      new(
        request_builder: Contracts::V4_1::RequestBuilder.new(
          credential: credential,
          clock: clock,
          uuid_generator: uuid_generator
        ),
        response_parser: Contracts::V4_1::ResponseParser.new(
          trust_policy: trust_policy,
          receive_clock: receive_clock
        ),
        transport: transport || NetHttpTransport.production(**transport_options)
      )
    end

    def initialize(request_builder:, response_parser:, transport:)
      @request_builder = callable(request_builder, "request_builder")
      @response_parser = callable(response_parser, "response_parser")
      @transport = callable(transport, "transport")
      @request_integrity_verifier = RequestIntegrityVerifier.new
    end

    def prepare(sale:, first_submission:, verification_mode: false)
      @request_builder.call(
        sale: sale,
        first_submission: first_submission,
        verification_mode: verification_mode
      )
    end

    def transmit(prepared_request)
      unless prepared_request.is_a?(PreparedRequest)
        raise ValidationError, "prepared_request must be an Eet2::PreparedRequest"
      end

      @request_integrity_verifier.verify!(prepared_request)
      transport_result = @transport.call(prepared_request)
      return transport_failure(transport_result) if transport_result.is_a?(Transport::Failure)

      unless transport_result.is_a?(Transport::HttpResponse)
        raise TransportConfigurationError, "transport must return Eet2::Transport::HttpResponse or Failure"
      end

      return http_failure(transport_result) unless transport_result.status == 200

      parsed = @response_parser.call(
        xml: transport_result.body,
        expected_request_uuid: prepared_request.request_uuid
      )
      parsed.with(
        support_id: transport_result.support_id,
        exchange_evidence: Response::ExchangeEvidence.from_http_response(transport_result)
      )
    rescue InvalidResponse, SchemaValidationError => error
      invalid_response(transport_result, error)
    end

    private

    def callable(object, name)
      raise TransportConfigurationError, "#{name} must respond to call" unless object.respond_to?(:call)

      object
    end

    def transport_failure(result)
      Response::TransportFailure.new(
        certainty: result.certainty,
        kind: result.kind,
        http_status: nil,
        support_id: nil
      )
    end

    def http_failure(result)
      Response::TransportFailure.new(
        certainty: :possibly_sent,
        kind: :http_status,
        http_status: result.status,
        support_id: result.support_id,
        exchange_evidence: Response::ExchangeEvidence.from_http_response(result)
      )
    end

    def invalid_response(result, error)
      raise error unless result.is_a?(Transport::HttpResponse)

      Response::InvalidResponse.new(
        reason: invalid_response_reason(error),
        response_sha256: Digest::SHA256.hexdigest(result.body),
        http_status: result.status,
        support_id: result.support_id,
        exchange_evidence: Response::ExchangeEvidence.from_http_response(result)
      )
    end

    def invalid_response_reason(error)
      case error
      when SignatureVerificationError then :signature_verification
      when CertificateVerificationError then :certificate_verification
      when CorrelationError then :correlation
      when SchemaValidationError then :schema_validation
      else :malformed_response
      end
    end
  end
end
