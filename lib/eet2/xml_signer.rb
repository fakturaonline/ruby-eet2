# frozen_string_literal: true

require "base64"
require "nokogiri"
require "openssl"

require_relative "errors"

module Eet2
  class XmlSigner
    SOAP_NAMESPACE = "http://schemas.xmlsoap.org/soap/envelope/"
    EET_NAMESPACE = "http://fs.gov.cz/eet/schema/v4"
    WSSE_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    WSU_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"
    EXCLUSIVE_C14N_NAMESPACE = "http://www.w3.org/2001/10/xml-exc-c14n#"
    EXCLUSIVE_C14N_ALGORITHM = "http://www.w3.org/2001/10/xml-exc-c14n#"
    RSA_SHA256_ALGORITHM = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    SHA256_ALGORITHM = "http://www.w3.org/2001/04/xmlenc#sha256"
    BASE64_ENCODING_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
    X509_VALUE_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"

    SignedDocument = Data.define(:document, :canonical_body, :canonical_signed_info)

    def initialize(certificate:, signer:)
      @certificate = certificate
      @signer = signer
    end

    def sign(document:, security:, body:, id_suffix:)
      validate_inputs!(document, security, body, id_suffix)
      identifiers = identifiers(id_suffix)
      body["wsu:Id"] = identifiers.fetch(:body)

      token = add_binary_security_token(security, identifiers.fetch(:token))
      signature, signed_info, digest_value, signature_value = add_signature(security, identifiers)

      canonical_body = canonicalize(body, inclusive_namespaces: ["v4"])
      digest_value.content = Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(canonical_body))

      canonical_signed_info = canonicalize(signed_info, inclusive_namespaces: %w[soapenv v4])
      signature_value.content = Base64.strict_encode64(@signer.sign_sha256_rsa(canonical_signed_info))

      token.content = Base64.strict_encode64(@certificate.to_der)
      signature["Id"] = identifiers.fetch(:signature)

      SignedDocument.new(document: document, canonical_body: canonical_body.freeze, canonical_signed_info: canonical_signed_info.freeze)
    rescue OpenSSL::OpenSSLError => error
      raise SigningError, "XML RSA-SHA256 signing failed", cause: error
    end

    def canonicalize(node, inclusive_namespaces:)
      node.canonicalize(
        Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0,
        inclusive_namespaces,
        false
      )
    end

    private

    def validate_inputs!(document, security, body, id_suffix)
      raise SigningError, "document must be a Nokogiri XML document" unless document.is_a?(Nokogiri::XML::Document)
      raise SigningError, "security must belong to document" unless security.document.equal?(document)
      raise SigningError, "body must belong to document" unless body.document.equal?(document)
      raise SigningError, "id_suffix must use UUID hexadecimal and hyphens" unless id_suffix.is_a?(String) && id_suffix.match?(/\A[0-9a-f-]+\z/i)
    end

    def identifiers(suffix)
      {
        body: "body-#{suffix}",
        token: "x509-#{suffix}",
        signature: "signature-#{suffix}",
        key_info: "key-info-#{suffix}",
        token_reference: "token-reference-#{suffix}"
      }
    end

    def add_binary_security_token(security, token_id)
      token = Nokogiri::XML::Node.new("BinarySecurityToken", security.document)
      token.namespace = security.namespace
      token["EncodingType"] = BASE64_ENCODING_TYPE
      token["ValueType"] = X509_VALUE_TYPE
      token["wsu:Id"] = token_id
      security.add_child(token)
      token
    end

    def add_signature(security, ids)
      document = security.document
      signature = Nokogiri::XML::Node.new("Signature", document)
      signature.add_namespace_definition("ds", DS_NAMESPACE)
      signature.namespace = signature.namespace_definitions.find { |namespace| namespace.prefix == "ds" }
      security.add_child(signature)

      signed_info = child(signature, "SignedInfo")
      canonicalization_method = child(signed_info, "CanonicalizationMethod", "Algorithm" => EXCLUSIVE_C14N_ALGORITHM)
      inclusive_namespaces(canonicalization_method, "soapenv v4")
      child(signed_info, "SignatureMethod", "Algorithm" => RSA_SHA256_ALGORITHM)

      reference = child(signed_info, "Reference", "URI" => "##{ids.fetch(:body)}")
      transforms = child(reference, "Transforms")
      transform = child(transforms, "Transform", "Algorithm" => EXCLUSIVE_C14N_ALGORITHM)
      inclusive_namespaces(transform, "v4")
      child(reference, "DigestMethod", "Algorithm" => SHA256_ALGORITHM)
      digest_value = child(reference, "DigestValue")

      signature_value = child(signature, "SignatureValue")
      key_info = child(signature, "KeyInfo", "Id" => ids.fetch(:key_info))
      token_reference = Nokogiri::XML::Node.new("SecurityTokenReference", document)
      token_reference.namespace = security.namespace
      token_reference["wsu:Id"] = ids.fetch(:token_reference)
      key_info.add_child(token_reference)
      reference_to_token = Nokogiri::XML::Node.new("Reference", document)
      reference_to_token.namespace = security.namespace
      reference_to_token["URI"] = "##{ids.fetch(:token)}"
      reference_to_token["ValueType"] = X509_VALUE_TYPE
      token_reference.add_child(reference_to_token)

      [signature, signed_info, digest_value, signature_value]
    end

    def child(parent, name, attributes = {})
      node = Nokogiri::XML::Node.new(name, parent.document)
      node.namespace = parent.namespace
      attributes.each { |attribute, value| node[attribute] = value }
      parent.add_child(node)
      node
    end

    def inclusive_namespaces(parent, prefix_list)
      node = Nokogiri::XML::Node.new("InclusiveNamespaces", parent.document)
      node.add_namespace_definition("ec", EXCLUSIVE_C14N_NAMESPACE)
      node.namespace = node.namespace_definitions.find { |namespace| namespace.prefix == "ec" }
      node["PrefixList"] = prefix_list
      parent.add_child(node)
    end
  end
end
