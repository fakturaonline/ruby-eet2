# frozen_string_literal: true

require "base64"
require "nokogiri"
require "openssl"

require_relative "certificate_verifier"
require_relative "errors"
require_relative "xml_signer"

module Eet2
  class XmlSignatureVerifier
    NAMESPACES = {
      "soapenv" => XmlSigner::SOAP_NAMESPACE,
      "wsse" => XmlSigner::WSSE_NAMESPACE,
      "wsu" => XmlSigner::WSU_NAMESPACE,
      "ds" => XmlSigner::DS_NAMESPACE
    }.freeze

    def initialize(trust_policy:, certificate_verifier: CertificateVerifier.new(trust_policy: trust_policy))
      @certificate_verifier = certificate_verifier
      @canonicalizer = XmlSigner.allocate
    end

    def verify!(document:, body:, verification_time:)
      bodies = document.xpath("/soapenv:Envelope/soapenv:Body", NAMESPACES)
      unless bodies.length == 1 && bodies.first == body
        raise SignatureVerificationError, "signature verification requires the sole SOAP Body object"
      end

      _security, token, signature = validate_security_structure!(document)
      signed_info, signature_value, key_info = validate_signature_structure!(signature)
      reference, digest_value = validate_signed_info_profile!(signed_info)
      ids = collect_unique_ids!(document)
      validate_body_reference!(reference, ids, body)
      certificate = certificate_from_token!(token, ids, key_info)

      evidence = @certificate_verifier.verify!(certificate: certificate, at: verification_time)
      verify_digest!(body, digest_value)
      verify_signature!(certificate, signed_info, signature_value)

      evidence
    end

    private

    def validate_security_structure!(document)
      headers = document.xpath("/soapenv:Envelope/soapenv:Header", NAMESPACES)
      securities = document.xpath("/soapenv:Envelope/soapenv:Header/wsse:Security", NAMESPACES)
      tokens = document.xpath("//wsse:BinarySecurityToken", NAMESPACES)
      signatures = document.xpath("//ds:Signature", NAMESPACES)
      unless headers.length == 1 && securities.length == 1 && tokens.length == 1 && signatures.length == 1
        raise SignatureVerificationError, "signed response must contain exactly one Header, Security, BinarySecurityToken, and Signature"
      end

      security = securities.first
      token = tokens.first
      signature = signatures.first
      assert_attributes!(security, [[XmlSigner::SOAP_NAMESPACE, "mustUnderstand"]], "Security")
      raise SignatureVerificationError, "Security mustUnderstand must be 1" unless security["soapenv:mustUnderstand"] == "1"
      assert_attributes!(
        token,
        [[XmlSigner::WSU_NAMESPACE, "Id"], [nil, "EncodingType"], [nil, "ValueType"]],
        "BinarySecurityToken"
      )
      raise SignatureVerificationError, "BinarySecurityToken must not contain elements" unless token.element_children.empty?
      assert_attributes!(signature, [], "Signature")
      expected_children = [[XmlSigner::WSSE_NAMESPACE, "BinarySecurityToken"], [XmlSigner::DS_NAMESPACE, "Signature"]]
      assert_exact_children!(security, expected_children, "Security")
      [security, token, signature]
    end

    def validate_signature_structure!(signature)
      assert_exact_children!(
        signature,
        [
          [XmlSigner::DS_NAMESPACE, "SignedInfo"],
          [XmlSigner::DS_NAMESPACE, "SignatureValue"],
          [XmlSigner::DS_NAMESPACE, "KeyInfo"]
        ],
        "Signature"
      )
      assert_attributes!(signature, [], "Signature")

      signed_info = exact_child(signature, "ds:SignedInfo", "SignedInfo")
      signature_value = exact_child(signature, "ds:SignatureValue", "SignatureValue")
      key_info = exact_child(signature, "ds:KeyInfo", "KeyInfo")
      assert_attributes!(signed_info, [], "SignedInfo")
      assert_attributes!(signature_value, [], "SignatureValue")
      assert_attributes!(key_info, [], "KeyInfo")
      raise SignatureVerificationError, "SignatureValue must not contain elements" unless signature_value.element_children.empty?

      [signed_info, signature_value, key_info]
    end

    def validate_signed_info_profile!(signed_info)
      assert_exact_children!(
        signed_info,
        [
          [XmlSigner::DS_NAMESPACE, "CanonicalizationMethod"],
          [XmlSigner::DS_NAMESPACE, "SignatureMethod"],
          [XmlSigner::DS_NAMESPACE, "Reference"]
        ],
        "SignedInfo"
      )
      canonicalization = exact_child(signed_info, "ds:CanonicalizationMethod", "CanonicalizationMethod")
      signature_method = exact_child(signed_info, "ds:SignatureMethod", "SignatureMethod")
      reference = exact_child(signed_info, "ds:Reference", "Reference")
      assert_attributes!(canonicalization, [[nil, "Algorithm"]], "CanonicalizationMethod")
      assert_attributes!(signature_method, [[nil, "Algorithm"]], "SignatureMethod")
      assert_attributes!(reference, [[nil, "URI"]], "Reference")
      unless canonicalization["Algorithm"] == XmlSigner::EXCLUSIVE_C14N_ALGORITHM && canonicalization.element_children.empty?
        raise SignatureVerificationError, "response uses a forbidden SignedInfo canonicalization profile"
      end
      unless signature_method["Algorithm"] == XmlSigner::RSA_SHA256_ALGORITHM && signature_method.element_children.empty?
        raise SignatureVerificationError, "response uses a forbidden signature algorithm"
      end

      assert_exact_children!(
        reference,
        [
          [XmlSigner::DS_NAMESPACE, "Transforms"],
          [XmlSigner::DS_NAMESPACE, "DigestMethod"],
          [XmlSigner::DS_NAMESPACE, "DigestValue"]
        ],
        "Reference"
      )
      transforms = exact_child(reference, "ds:Transforms", "Transforms")
      transform = exact_child(transforms, "ds:Transform", "Transform")
      digest_method = exact_child(reference, "ds:DigestMethod", "DigestMethod")
      digest_value = exact_child(reference, "ds:DigestValue", "DigestValue")
      assert_attributes!(transforms, [], "Transforms")
      assert_attributes!(transform, [[nil, "Algorithm"]], "Transform")
      assert_attributes!(digest_method, [[nil, "Algorithm"]], "DigestMethod")
      assert_attributes!(digest_value, [], "DigestValue")
      raise SignatureVerificationError, "DigestValue must not contain elements" unless digest_value.element_children.empty?
      unless transforms.element_children.length == 1 && transform["Algorithm"] == XmlSigner::EXCLUSIVE_C14N_ALGORITHM && transform.element_children.empty?
        raise SignatureVerificationError, "response uses a forbidden Reference transform profile"
      end
      unless digest_method["Algorithm"] == XmlSigner::SHA256_ALGORITHM && digest_method.element_children.empty?
        raise SignatureVerificationError, "response uses a forbidden digest algorithm"
      end

      [reference, digest_value]
    end

    def collect_unique_ids!(document)
      ids = {}
      document.xpath('//@*[local-name()="Id"]').each do |attribute|
        id = attribute.value
        raise SignatureVerificationError, "response contains an empty XML ID" if id.empty?
        raise SignatureVerificationError, "response contains a duplicate XML ID" if ids.key?(id)

        ids[id] = attribute.parent
      end
      ids
    end

    def validate_body_reference!(reference, ids, body)
      assert_attributes!(body, [[XmlSigner::WSU_NAMESPACE, "Id"]], "SOAP Body")
      uri = reference["URI"]
      unless uri.match?(/\A#[A-Za-z_][A-Za-z0-9_.:-]*\z/)
        raise SignatureVerificationError, "signature Reference must be a same-document XML ID fragment"
      end

      referenced_node = ids[uri.delete_prefix("#")]
      unless referenced_node && referenced_node == body
        raise SignatureVerificationError, "signature Reference must identify the sole SOAP Body object"
      end
    end

    def certificate_from_token!(token, ids, key_info)
      unless token["EncodingType"] == XmlSigner::BASE64_ENCODING_TYPE && token["ValueType"] == XmlSigner::X509_VALUE_TYPE
        raise SignatureVerificationError, "BinarySecurityToken profile is not X.509 Base64"
      end

      token_reference = exact_child(key_info, "wsse:SecurityTokenReference", "SecurityTokenReference")
      assert_exact_children!(key_info, [[XmlSigner::WSSE_NAMESPACE, "SecurityTokenReference"]], "KeyInfo")
      assert_attributes!(token_reference, [], "SecurityTokenReference")
      assert_exact_children!(token_reference, [[XmlSigner::WSSE_NAMESPACE, "Reference"]], "SecurityTokenReference")
      reference = exact_child(token_reference, "wsse:Reference", "security token Reference")
      assert_attributes!(reference, [[nil, "URI"], [nil, "ValueType"]], "security token Reference")
      token_uri = reference["URI"]
      unless reference["ValueType"] == XmlSigner::X509_VALUE_TYPE && token_uri.start_with?("#") && ids[token_uri.delete_prefix("#")] == token
        raise SignatureVerificationError, "KeyInfo must reference the sole BinarySecurityToken by XML ID"
      end

      OpenSSL::X509::Certificate.new(Base64.strict_decode64(token.text.strip))
    rescue ArgumentError, OpenSSL::X509::CertificateError => error
      raise SignatureVerificationError, "BinarySecurityToken is not a strict DER X.509 certificate", cause: error
    end

    def verify_digest!(body, digest_value)
      expected = Base64.strict_decode64(digest_value.text.strip)
      actual = OpenSSL::Digest::SHA256.digest(@canonicalizer.canonicalize(body, inclusive_namespaces: []))
      unless expected.bytesize == actual.bytesize && OpenSSL.fixed_length_secure_compare(expected, actual)
        raise SignatureVerificationError, "SOAP Body digest verification failed"
      end
    rescue ArgumentError => error
      raise SignatureVerificationError, "DigestValue is not strict Base64", cause: error
    end

    def verify_signature!(certificate, signed_info, signature_value)
      signature = Base64.strict_decode64(signature_value.text.strip)
      canonical_signed_info = @canonicalizer.canonicalize(signed_info, inclusive_namespaces: [])
      unless certificate.public_key.verify(OpenSSL::Digest.new("SHA256"), signature, canonical_signed_info)
        raise SignatureVerificationError, "RSA-SHA256 response signature verification failed"
      end
    rescue ArgumentError, OpenSSL::PKey::PKeyError => error
      raise SignatureVerificationError, "SignatureValue is invalid", cause: error
    end

    def exact_child(parent, xpath, label)
      nodes = parent.xpath("./#{xpath}", NAMESPACES)
      raise SignatureVerificationError, "#{label} must occur exactly once" unless nodes.length == 1

      nodes.first
    end

    def assert_exact_children!(node, expected, label)
      actual = node.element_children.map { |child| [child.namespace&.href, child.name] }
      raise SignatureVerificationError, "#{label} contains unexpected or out-of-order elements" unless actual == expected
    end

    def assert_attributes!(node, expected, label)
      actual = node.attribute_nodes.map { |attribute| [attribute.namespace&.href, attribute.name] }.sort_by { |namespace, name| [namespace.to_s, name] }
      sorted_expected = expected.sort_by { |namespace, name| [namespace.to_s, name] }
      raise SignatureVerificationError, "#{label} contains unexpected attributes" unless actual == sorted_expected
    end
  end
end
