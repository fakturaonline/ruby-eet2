# frozen_string_literal: true

require "openssl"

require_relative "errors"

module Eet2
  class LocalKeySigner
    def initialize(private_key:)
      unless private_key.is_a?(OpenSSL::PKey::RSA) && private_key.private?
        raise CredentialError, "private_key must be an RSA private key"
      end

      @private_key = private_key
      freeze
    end

    def sign_sha256_rsa(bytes)
      raise SigningError, "bytes to sign must be a non-empty String" unless bytes.is_a?(String) && !bytes.empty?

      @private_key.sign(OpenSSL::Digest.new("SHA256"), bytes)
    rescue OpenSSL::PKey::PKeyError => error
      raise SigningError, "RSA-SHA256 signing failed", cause: error
    end

    def matches_certificate?(certificate)
      certificate.check_private_key(@private_key)
    end
  end
end
