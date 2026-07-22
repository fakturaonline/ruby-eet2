# frozen_string_literal: true

require "digest"
require "time"

require_relative "errors"
require_relative "sale"

module Eet2
  PreparedRequest = Data.define(
    :request_uuid,
    :sent_at,
    :sale,
    :first_submission,
    :verification_mode,
    :xml,
    :request_sha256,
    :body_sha256,
    :certificate_sha256,
    :protocol_version,
    :schema_sha256
  ) do
    def initialize(
      request_uuid:,
      sent_at:,
      sale:,
      first_submission:,
      verification_mode:,
      xml:,
      request_sha256:,
      body_sha256:,
      certificate_sha256:,
      protocol_version:,
      schema_sha256:
    )
      validate_uuid!(request_uuid)
      validate_time!(sent_at)
      raise ValidationError, "sale must be an Eet2::Sale" unless sale.is_a?(Sale)
      validate_boolean!(first_submission, :first_submission)
      validate_boolean!(verification_mode, :verification_mode)
      validate_xml!(xml)
      [request_sha256, body_sha256, certificate_sha256, schema_sha256].each { |digest| validate_digest!(digest) }
      unless request_sha256 == Digest::SHA256.hexdigest(xml)
        raise ValidationError, "request_sha256 does not match request XML"
      end
      raise ValidationError, "protocol_version must be 4.1" unless protocol_version == "4.1"

      super(
        request_uuid: request_uuid.dup.freeze,
        sent_at: sent_at.dup.freeze,
        sale: sale,
        first_submission: first_submission,
        verification_mode: verification_mode,
        xml: xml.dup.freeze,
        request_sha256: request_sha256.dup.freeze,
        body_sha256: body_sha256.dup.freeze,
        certificate_sha256: certificate_sha256.dup.freeze,
        protocol_version: protocol_version.dup.freeze,
        schema_sha256: schema_sha256.dup.freeze
      )
    end

    private

    def validate_uuid!(value)
      raise ValidationError, "request_uuid must be an RFC 4122 version 4 UUID" unless value.is_a?(String) && value.match?(self.class::UUID_V4_PATTERN)
    end

    def validate_time!(value)
      raise ValidationError, "sent_at must be a Time without fractional seconds" unless value.is_a?(Time) && value.nsec.zero?
    end

    def validate_boolean!(value, field)
      raise ValidationError, "#{field} must be true or false" unless value == true || value == false
    end

    def validate_xml!(value)
      raise ValidationError, "xml must be a non-empty String" unless value.is_a?(String) && !value.empty?
      if value.bytesize > self.class::MAX_BYTES
        raise RequestTooLarge, "EET2 request is #{value.bytesize} bytes; maximum is #{self.class::MAX_BYTES}"
      end
    end

    def validate_digest!(value)
      raise ValidationError, "SHA-256 metadata must be lowercase hexadecimal" unless value.is_a?(String) && value.match?(self.class::SHA256_PATTERN)
    end
  end

  PreparedRequest.const_set(:MAX_BYTES, 12 * 1024)
  PreparedRequest.const_set(:UUID_V4_PATTERN, /\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/i)
  PreparedRequest.const_set(:SHA256_PATTERN, /\A[0-9a-f]{64}\z/)
end
