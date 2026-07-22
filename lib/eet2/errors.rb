# frozen_string_literal: true

module Eet2
  class Error < StandardError; end

  class ValidationError < Error; end

  class SchemaValidationError < ValidationError
    attr_reader :validation_errors

    def initialize(validation_errors)
      @validation_errors = validation_errors.map(&:to_s).freeze
      super("EET2 XML does not conform to schema v4.1: #{@validation_errors.join("; ")}")
    end
  end

  class CredentialError < Error; end
  class LegacyPkcs12Unsupported < CredentialError; end
  class SigningError < Error; end
  class RequestTooLarge < ValidationError; end

  class InvalidResponse < Error; end
  class MalformedResponse < InvalidResponse; end
  class SignatureVerificationError < InvalidResponse; end
  class CertificateVerificationError < InvalidResponse; end
  class CorrelationError < InvalidResponse; end
  class UnsupportedEnvironment < Error; end
  class TransportConfigurationError < Error; end
end
