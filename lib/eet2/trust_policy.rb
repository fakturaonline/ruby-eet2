# frozen_string_literal: true

require "openssl"

require_relative "errors"

module Eet2
  class TrustPolicy
    PLAYGROUND_ROOT_PATH = File.expand_path("../../data/official/response-trust/playground/ica-root-rsa-05-2022.pem", __dir__)
    PLAYGROUND_INTERMEDIATE_PATH = File.expand_path("../../data/official/response-trust/playground/ica-public-rsa-06-2022.pem", __dir__)
    PRODUCTION_ROOT_PATH = File.expand_path("../../data/official/response-trust/production/nca-root-rsa-10-2023.der", __dir__)
    PRODUCTION_INTERMEDIATE_PATH = File.expand_path("../../data/official/response-trust/production/nca-subca2-rsa-12-2023.der", __dir__)
    ROOT_PATH = PLAYGROUND_ROOT_PATH
    INTERMEDIATE_PATH = PLAYGROUND_INTERMEDIATE_PATH
    ROOT_SHA256 = "d279c01a12e8dd9a6230e459faa447ceb336998477338c2ee4135c96737418eb"
    INTERMEDIATE_SHA256 = "df5baf6d7e1a7d14e9911c5b8c676ec6ebcad9354a74f4ac7314e133e07a94de"
    PRODUCTION_ROOT_SHA256 = "d2d98e1b7af2d0e33276a33120d30863a66858d881eafd7400d09a4942630cb7"
    PRODUCTION_INTERMEDIATE_SHA256 = "ae36c864fc904b29cbc4b38a096364ae311ff1db544c5c064c12ec4bf9c5a8b3"
    PLAYGROUND_POLICY_OID = "1.3.6.1.4.1.23624.10.1.71.1.1"
    PRODUCTION_POLICY_OID = "1.2.203.19122063.10.1.72.1.0"
    SIGNER_ORGANIZATION = "Generální finanční ředitelství"
    SIGNER_ORGANIZATION_IDENTIFIER = "NTRCZ-72080043"
    PLAYGROUND_ORGANIZATION = SIGNER_ORGANIZATION
    PLAYGROUND_ORGANIZATION_IDENTIFIER = SIGNER_ORGANIZATION_IDENTIFIER
    PLAYGROUND_COMMON_NAME_PATTERN = /\A(?=.*playground)(?=.*EET).+\z/i

    attr_reader :anchors, :environment, :intermediates, :revision

    def self.playground
      new(
        environment: :playground,
        revision: "playground-2026-07-21",
        anchors: [load_certificate(PLAYGROUND_ROOT_PATH, ROOT_SHA256)],
        intermediates: [load_certificate(PLAYGROUND_INTERMEDIATE_PATH, INTERMEDIATE_SHA256)],
        policy_oid: PLAYGROUND_POLICY_OID,
        common_name_pattern: PLAYGROUND_COMMON_NAME_PATTERN
      )
    end

    def self.production
      new(
        environment: :production,
        revision: "production-2026-06-02-nca-rsa-2023",
        anchors: [load_certificate(PRODUCTION_ROOT_PATH, PRODUCTION_ROOT_SHA256)],
        intermediates: [load_certificate(PRODUCTION_INTERMEDIATE_PATH, PRODUCTION_INTERMEDIATE_SHA256)],
        policy_oid: PRODUCTION_POLICY_OID
      )
    end

    def self.load_certificate(path, expected_sha256)
      certificate = OpenSSL::X509::Certificate.new(File.binread(path))
      actual_sha256 = OpenSSL::Digest::SHA256.hexdigest(certificate.to_der)
      unless actual_sha256 == expected_sha256
        raise CertificateVerificationError, "vendored trust certificate fingerprint mismatch"
      end

      certificate
    rescue Errno::ENOENT, OpenSSL::X509::CertificateError => error
      raise CertificateVerificationError, "vendored response trust certificate cannot be loaded", cause: error
    end
    private_class_method :load_certificate

    def initialize(environment:, revision:, anchors:, intermediates:, policy_oid:, common_name_pattern: nil)
      unless %i[playground production].include?(environment)
        raise UnsupportedEnvironment, "unsupported EET2 trust environment"
      end

      @environment = environment
      @revision = revision.dup.freeze
      @anchors = anchors.dup.freeze
      @intermediates = intermediates.dup.freeze
      @policy_oid = policy_oid.dup.freeze
      @common_name_pattern = common_name_pattern
      freeze
    end

    def validate_leaf_profile!(certificate)
      subject = certificate.subject.to_a.to_h { |name, value, _type| [name, value.dup.force_encoding(Encoding::UTF_8)] }
      subject_matches = subject.fetch("O", nil) == SIGNER_ORGANIZATION &&
        subject.fetch("organizationIdentifier", nil) == SIGNER_ORGANIZATION_IDENTIFIER &&
        subject.fetch("C", nil) == "CZ" &&
        !subject.fetch("CN", "").empty? &&
        (@common_name_pattern.nil? || subject.fetch("CN").match?(@common_name_pattern))
      unless subject_matches
        raise CertificateVerificationError, "response signer subject does not match the #{environment} EET profile"
      end

      key_usage = extension_value(certificate, "keyUsage")
      basic_constraints = extension_value(certificate, "basicConstraints")
      policies = extension_value(certificate, "certificatePolicies")
      unless key_usage&.include?("Digital Signature") && basic_constraints&.include?("CA:FALSE") && policies&.include?(@policy_oid)
        raise CertificateVerificationError, "response signer extensions do not match the #{environment} EET profile"
      end

      public_key = certificate.public_key
      unless public_key.is_a?(OpenSSL::PKey::RSA) && public_key.n.num_bits >= 2048
        raise CertificateVerificationError, "response signer must use an RSA key of at least 2048 bits"
      end

      if certificate.signature_algorithm.downcase.include?("sha1")
        raise CertificateVerificationError, "response signer certificate uses a forbidden SHA-1 signature"
      end

      true
    end

    def anchor_sha256
      anchors.map { |certificate| OpenSSL::Digest::SHA256.hexdigest(certificate.to_der) }.freeze
    end

    def intermediate_sha256
      intermediates.map { |certificate| OpenSSL::Digest::SHA256.hexdigest(certificate.to_der) }.freeze
    end

    private

    def extension_value(certificate, oid)
      certificate.extensions.find { |extension| extension.oid == oid }&.value
    end
  end
end
