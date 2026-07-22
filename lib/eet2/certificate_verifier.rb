# frozen_string_literal: true

require "openssl"

require_relative "errors"
require_relative "response"
require_relative "trust_policy"

module Eet2
  class CertificateVerifier
    def initialize(trust_policy:)
      @trust_policy = trust_policy
    end

    def verify!(certificate:, at:)
      raise CertificateVerificationError, "response signer is not an X.509 certificate" unless certificate.is_a?(OpenSSL::X509::Certificate)
      raise CertificateVerificationError, "certificate verification time must be a Time" unless at.is_a?(Time)

      store = OpenSSL::X509::Store.new
      @trust_policy.anchors.each { |anchor| store.add_cert(anchor) }
      store.time = at
      store.flags = OpenSSL::X509::V_FLAG_X509_STRICT

      unless store.verify(certificate, @trust_policy.intermediates)
        raise CertificateVerificationError, "response signer chain validation failed: #{store.error_string}"
      end

      chain = store.chain
      validate_chain_policy!(chain)
      @trust_policy.validate_leaf_profile!(certificate)

      Response::SignatureEvidence.new(
        certificate_sha256: fingerprint(certificate),
        chain_sha256: chain.map { |chain_certificate| fingerprint(chain_certificate) },
        trust_policy_revision: @trust_policy.revision
      )
    rescue OpenSSL::X509::StoreError => error
      raise CertificateVerificationError, "response signer chain validation could not be performed", cause: error
    end

    private

    def validate_chain_policy!(chain)
      if chain.nil? || chain.length < 3
        raise CertificateVerificationError, "response signer chain is incomplete"
      end

      root_fingerprint = fingerprint(chain.last)
      intermediate_fingerprints = chain[1...-1].map { |certificate| fingerprint(certificate) }
      unless @trust_policy.anchor_sha256.include?(root_fingerprint) &&
          intermediate_fingerprints.all? { |digest| @trust_policy.intermediate_sha256.include?(digest) }
        raise CertificateVerificationError, "response signer chain is outside the versioned trust policy"
      end
    end

    def fingerprint(certificate)
      OpenSSL::Digest::SHA256.hexdigest(certificate.to_der)
    end
  end
end
