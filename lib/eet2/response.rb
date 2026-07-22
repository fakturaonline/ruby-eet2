# frozen_string_literal: true

require_relative "errors"
require_relative "transport"

module Eet2
  module Response
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
      :support_id
    ) do
      def initialize(request_uuid:, received_at:, pok:, test:, warnings:, response_sha256:, signature_evidence:, support_id: nil)
        super(
          request_uuid: request_uuid.dup.freeze,
          received_at: received_at.dup.freeze,
          pok: pok.dup.freeze,
          test: test,
          warnings: warnings.dup.freeze,
          response_sha256: response_sha256.dup.freeze,
          signature_evidence: signature_evidence,
          support_id: Response.copy_support_id(support_id)
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
      :support_id
    ) do
      def initialize(request_uuid:, rejected_at:, code:, message:, test:, warnings:, response_sha256:, support_id: nil)
        super(
          request_uuid: request_uuid&.dup&.freeze,
          rejected_at: rejected_at&.dup&.freeze,
          code: code,
          message: message.dup.freeze,
          test: test,
          warnings: warnings.dup.freeze,
          response_sha256: response_sha256.dup.freeze,
          support_id: Response.copy_support_id(support_id)
        )
      end

      def authenticated?
        false
      end

      def accepted?
        false
      end
    end

    TransportFailure = Data.define(:certainty, :kind, :http_status, :support_id) do
      def initialize(certainty:, kind:, http_status:, support_id:)
        raise TransportConfigurationError, "invalid transport certainty" unless TRANSPORT_FAILURE_CERTAINTIES.include?(certainty)
        raise TransportConfigurationError, "invalid public transport failure kind" unless TRANSPORT_FAILURE_KINDS.include?(kind)
        if !http_status.nil? && !(http_status.is_a?(Integer) && http_status.between?(100, 599))
          raise TransportConfigurationError, "http_status must be nil or an Integer from 100 to 599"
        end
        if (kind == :http_status) != !http_status.nil?
          raise TransportConfigurationError, "http_status must be present only for an HTTP status failure"
        end

        super(
          certainty: certainty,
          kind: kind,
          http_status: http_status,
          support_id: Response.copy_support_id(support_id)
        )
      end

      def authenticated?
        false
      end

      def accepted?
        false
      end
    end

    InvalidResponse = Data.define(:reason, :response_sha256, :http_status, :support_id) do
      def initialize(reason:, response_sha256:, http_status:, support_id:)
        raise TransportConfigurationError, "invalid response reason" unless INVALID_RESPONSE_REASONS.include?(reason)
        unless response_sha256.is_a?(String) && response_sha256.match?(SHA256_PATTERN)
          raise TransportConfigurationError, "response_sha256 must be a lowercase SHA-256 digest"
        end
        unless http_status.is_a?(Integer) && http_status.between?(100, 599)
          raise TransportConfigurationError, "http_status must be an Integer from 100 to 599"
        end

        super(
          reason: reason,
          response_sha256: response_sha256.dup.freeze,
          http_status: http_status,
          support_id: Response.copy_support_id(support_id)
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
