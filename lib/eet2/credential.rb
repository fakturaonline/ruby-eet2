# frozen_string_literal: true

require "openssl"

require_relative "errors"
require_relative "local_key_signer"

module Eet2
  class Credential
    LEGACY_PROVIDER_MUTEX = Mutex.new

    attr_reader :certificate, :chain, :signer

    def self.from_pem(certificate_pem:, private_key_pem:, private_key_password: nil, chain_pems: [])
      certificate = OpenSSL::X509::Certificate.new(certificate_pem)
      private_key = OpenSSL::PKey.read(private_key_pem, private_key_password)
      chain = chain_pems.map { |pem| OpenSSL::X509::Certificate.new(pem) }

      new(certificate: certificate, signer: LocalKeySigner.new(private_key: private_key), chain: chain)
    rescue OpenSSL::OpenSSLError => error
      raise CredentialError, "PEM credential import failed", cause: error
    end

    def self.from_pkcs12(bytes:, password:, legacy_provider: :forbid)
      unless %i[forbid explicitly_allowed].include?(legacy_provider)
        raise ArgumentError, "legacy_provider must be :forbid or :explicitly_allowed"
      end

      pkcs12 = parse_pkcs12(bytes, password)
      build_from_pkcs12(pkcs12)
    rescue OpenSSL::PKCS12::PKCS12Error => error
      if legacy_algorithm_error?(error)
        raise LegacyPkcs12Unsupported, legacy_pkcs12_message, cause: error if legacy_provider == :forbid

        load_legacy_provider!
        begin
          return build_from_pkcs12(parse_pkcs12(bytes, password))
        rescue OpenSSL::PKCS12::PKCS12Error => retry_error
          raise CredentialError, "PKCS#12 credential import failed after explicit legacy-provider activation", cause: retry_error
        end
      end

      raise CredentialError, "PKCS#12 credential import failed", cause: error
    end

    def self.parse_pkcs12(bytes, password)
      raise CredentialError, "PKCS#12 bytes must be a non-empty String" unless bytes.is_a?(String) && !bytes.empty?

      OpenSSL::PKCS12.new(bytes, password)
    end
    private_class_method :parse_pkcs12

    def self.build_from_pkcs12(pkcs12)
      new(
        certificate: pkcs12.certificate,
        signer: LocalKeySigner.new(private_key: pkcs12.key),
        chain: pkcs12.ca_certs || []
      )
    end
    private_class_method :build_from_pkcs12

    def self.legacy_algorithm_error?(error)
      error.message.downcase.include?("unsupported")
    end
    private_class_method :legacy_algorithm_error?

    def self.load_legacy_provider!
      unless defined?(OpenSSL::Provider)
        raise LegacyPkcs12Unsupported, "this Ruby OpenSSL build cannot explicitly load the legacy provider"
      end

      LEGACY_PROVIDER_MUTEX.synchronize do
        @legacy_provider ||= OpenSSL::Provider.load("legacy")
      end
    rescue OpenSSL::OpenSSLError => error
      raise LegacyPkcs12Unsupported, "OpenSSL legacy provider could not be loaded explicitly", cause: error
    end
    private_class_method :load_legacy_provider!

    def self.legacy_pkcs12_message
      "PKCS#12 uses algorithms disabled by OpenSSL 3; pass legacy_provider: :explicitly_allowed only in a controlled import path, or repackage the credential securely"
    end
    private_class_method :legacy_pkcs12_message

    def initialize(certificate:, signer:, chain: [])
      raise CredentialError, "certificate must be an X.509 certificate" unless certificate.is_a?(OpenSSL::X509::Certificate)
      raise CredentialError, "signer must implement sign_sha256_rsa" unless signer.respond_to?(:sign_sha256_rsa)
      unless chain.is_a?(Array) && chain.all? { |item| item.is_a?(OpenSSL::X509::Certificate) }
        raise CredentialError, "chain must contain only X.509 certificates"
      end
      if signer.respond_to?(:matches_certificate?) && !signer.matches_certificate?(certificate)
        raise CredentialError, "private key does not match certificate"
      end

      @certificate = certificate
      @signer = signer
      @chain = chain.dup.freeze
      freeze
    end

    def certificate_sha256
      OpenSSL::Digest::SHA256.hexdigest(certificate.to_der)
    end
  end
end
