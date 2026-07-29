# frozen_string_literal: true

require "digest"

require_relative "errors"
require_relative "transport"

module Eet2
  module Response
    EXCHANGE_EVIDENCE_MAX_HEAD_BYTES = 4 * 1024
    TRANSPORT_FAILURE_CERTAINTIES = Transport::FAILURE_CERTAINTIES
    TRANSPORT_FAILURE_KINDS = (Transport::FAILURE_KINDS + [:http_status]).freeze
    INVALID_RESPONSE_REASONS = %i[
      malformed_response
      signature_verification
      certificate_verification
      correlation
      schema_validation
    ].freeze
    SHA256_PATTERN = /\A[0-9a-f]{64}\z/

    def self.copy_support_id(value)
      return nil if value.nil?
      unless value.is_a?(String) && value.match?(Transport::SUPPORT_ID_PATTERN)
        raise TransportConfigurationError, "support_id must be nil or 1 to 128 printable ASCII characters"
      end

      value.dup.freeze
    end

    def self.copy_exchange_evidence(value)
      return nil if value.nil?
      raise TransportConfigurationError, "exchange_evidence must be nil or an Eet2::Response::ExchangeEvidence" unless value.is_a?(ExchangeEvidence)

      value
    end

    # Bounded, immutable audit trace of what the peer actually returned. It exists
    # for every HTTP exchange, including non-200 and SOAP Fault bodies that the
    # gem deliberately refuses to parse. The retained head is capped, so a hostile
    # or oversized body cannot grow the value beyond a known bound.
    ExchangeEvidence = Data.define(:http_status, :response_sha256, :response_bytesize, :response_body_head) do
      def self.from_http_response(response)
        unless response.is_a?(Transport::HttpResponse)
          raise TransportConfigurationError, "exchange evidence requires an Eet2::Transport::HttpResponse"
        end

        new(
          http_status: response.status,
          response_sha256: Digest::SHA256.hexdigest(response.body),
          response_bytesize: response.body.bytesize,
          response_body_head: response.body.byteslice(0, EXCHANGE_EVIDENCE_MAX_HEAD_BYTES)
        )
      end

      def initialize(http_status:, response_sha256:, response_bytesize:, response_body_head:)
        unless http_status.is_a?(Integer) && http_status.between?(100, 599)
          raise TransportConfigurationError, "http_status must be an Integer from 100 to 599"
        end
        unless response_sha256.is_a?(String) && response_sha256.match?(SHA256_PATTERN)
          raise TransportConfigurationError, "response_sha256 must be a lowercase SHA-256 digest"
        end
        unless response_bytesize.is_a?(Integer) && !response_bytesize.negative?
          raise TransportConfigurationError, "response_bytesize must be a non-negative Integer"
        end
        raise TransportConfigurationError, "response_body_head must be a String" unless response_body_head.is_a?(String)
        if response_body_head.bytesize > EXCHANGE_EVIDENCE_MAX_HEAD_BYTES
          raise TransportConfigurationError, "response_body_head must not exceed #{EXCHANGE_EVIDENCE_MAX_HEAD_BYTES} bytes"
        end
        if response_body_head.bytesize > response_bytesize
          raise TransportConfigurationError, "response_body_head must not exceed response_bytesize"
        end

        super(
          http_status: http_status,
          response_sha256: response_sha256.dup.freeze,
          response_bytesize: response_bytesize,
          response_body_head: response_body_head.b.freeze
        )
      end

      def truncated?
        response_bytesize > response_body_head.bytesize
      end
    end

    Warning = Data.define(:code, :message) do
      def initialize(code:, message:)
        raise MalformedResponse, "warning code must be an Integer from 1 to 999" unless code.is_a?(Integer) && code.between?(1, 999)
        raise MalformedResponse, "warning message must be a String" unless message.is_a?(String)

        super(code: code, message: message.dup.freeze)
      end
    end

    SignatureEvidence = Data.define(:certificate_sha256, :chain_sha256, :trust_policy_revision) do
      def initialize(certificate_sha256:, chain_sha256:, trust_policy_revision:)
        super(
          certificate_sha256: certificate_sha256.dup.freeze,
          chain_sha256: chain_sha256.map { |digest| digest.dup.freeze }.freeze,
          trust_policy_revision: trust_policy_revision.dup.freeze
        )
      end
    end

    VerifiedReceipt = Data.define(
      :request_uuid,
      :received_at,
      :pok,
      :test,
      :warnings,
      :response_sha256,
      :signature_evidence,
      :support_id,
      :exchange_evidence
    ) do
      def initialize(request_uuid:, received_at:, pok:, test:, warnings:, response_sha256:, signature_evidence:, support_id: nil, exchange_evidence: nil)
        super(
          request_uuid: request_uuid.dup.freeze,
          received_at: received_at.dup.freeze,
          pok: pok.dup.freeze,
          test: test,
          warnings: warnings.dup.freeze,
          response_sha256: response_sha256.dup.freeze,
          signature_evidence: signature_evidence,
          support_id: Response.copy_support_id(support_id),
          exchange_evidence: Response.copy_exchange_evidence(exchange_evidence)
        )
      end

      def authenticated?
        true
      end

      def accepted?
        true
      end
    end

    UnsignedError = Data.define(
      :request_uuid,
      :rejected_at,
      :code,
      :message,
      :test,
      :warnings,
      :response_sha256,
      :support_id,
      :exchange_evidence
    ) do
      def initialize(request_uuid:, rejected_at:, code:, message:, test:, warnings:, response_sha256:, support_id: nil, exchange_evidence: nil)
        super(
          request_uuid: request_uuid&.dup&.freeze,
          rejected_at: rejected_at&.dup&.freeze,
          code: code,
          message: message.dup.freeze,
          test: test,
          warnings: warnings.dup.freeze,
          response_sha256: response_sha256.dup.freeze,
          support_id: Response.copy_support_id(support_id),
          exchange_evidence: Response.copy_exchange_evidence(exchange_evidence)
        )
      end

      def authenticated?
        false
      end

      def accepted?
        false
      end
    end

    TransportFailure = Data.define(:certainty, :kind, :http_status, :support_id, :exchange_evidence) do
      def initialize(certainty:, kind:, http_status:, support_id:, exchange_evidence: nil)
        raise TransportConfigurationError, "invalid transport certainty" unless TRANSPORT_FAILURE_CERTAINTIES.include?(certainty)
        raise TransportConfigurationError, "invalid public transport failure kind" unless TRANSPORT_FAILURE_KINDS.include?(kind)
        if !http_status.nil? && !(http_status.is_a?(Integer) && http_status.between?(100, 599))
          raise TransportConfigurationError, "http_status must be nil or an Integer from 100 to 599"
        end
        if (kind == :http_status) != !http_status.nil?
          raise TransportConfigurationError, "http_status must be present only for an HTTP status failure"
        end
        evidence = Response.copy_exchange_evidence(exchange_evidence)
        if evidence && evidence.http_status != http_status
          raise TransportConfigurationError, "exchange_evidence http_status must match the failure http_status"
        end

        super(
          certainty: certainty,
          kind: kind,
          http_status: http_status,
          support_id: Response.copy_support_id(support_id),
          exchange_evidence: evidence
        )
      end

      def authenticated?
        false
      end

      def accepted?
        false
      end
    end

    InvalidResponse = Data.define(:reason, :response_sha256, :http_status, :support_id, :exchange_evidence) do
      def initialize(reason:, response_sha256:, http_status:, support_id:, exchange_evidence: nil)
        raise TransportConfigurationError, "invalid response reason" unless INVALID_RESPONSE_REASONS.include?(reason)
        unless response_sha256.is_a?(String) && response_sha256.match?(SHA256_PATTERN)
          raise TransportConfigurationError, "response_sha256 must be a lowercase SHA-256 digest"
        end
        unless http_status.is_a?(Integer) && http_status.between?(100, 599)
          raise TransportConfigurationError, "http_status must be an Integer from 100 to 599"
        end
        evidence = Response.copy_exchange_evidence(exchange_evidence)
        if evidence && (evidence.http_status != http_status || evidence.response_sha256 != response_sha256)
          raise TransportConfigurationError, "exchange_evidence must describe the same response"
        end

        super(
          reason: reason,
          response_sha256: response_sha256.dup.freeze,
          http_status: http_status,
          support_id: Response.copy_support_id(support_id),
          exchange_evidence: evidence
        )
      end

      def authenticated?
        false
      end

      def accepted?
        false
      end
    end
  end
end
