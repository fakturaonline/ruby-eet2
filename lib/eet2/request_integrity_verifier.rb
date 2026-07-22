# frozen_string_literal: true

require "base64"
require "digest"
require "nokogiri"
require "openssl"
require "time"

require_relative "contracts/v4_1/schema"
require_relative "errors"
require_relative "prepared_request"
require_relative "xml_signer"

module Eet2
  class RequestIntegrityVerifier
    NAMESPACES = {
      "soapenv" => XmlSigner::SOAP_NAMESPACE,
      "v4" => XmlSigner::EET_NAMESPACE,
      "wsse" => XmlSigner::WSSE_NAMESPACE,
      "wsu" => XmlSigner::WSU_NAMESPACE,
      "ds" => XmlSigner::DS_NAMESPACE,
      "ec" => XmlSigner::EXCLUSIVE_C14N_NAMESPACE
    }.freeze

    def initialize(schema: Contracts::V4_1::Schema.new)
      @schema = schema
      @canonicalizer = XmlSigner.allocate
    end

    def verify!(prepared_request)
      unless prepared_request.is_a?(PreparedRequest)
        raise ValidationError, "request integrity verification requires an Eet2::PreparedRequest"
      end
      unless prepared_request.schema_sha256 == Contracts::V4_1::Schema::SHA256
        raise ValidationError, "prepared request schema_sha256 does not match the official v4.1 schema"
      end

      document = parse!(prepared_request.xml)
      body, payload, request_header, sale_data, security = validate_message_structure!(document)
      @schema.validate_payload!(payload)
      validate_attempt_metadata!(prepared_request, request_header)
      validate_sale_metadata!(prepared_request.sale, sale_data)
      validate_signature_metadata!(prepared_request, body, security)
      true
    rescue Nokogiri::XML::SyntaxError => error
      raise ValidationError, "prepared request XML is not strict well-formed XML", cause: error
    rescue ArgumentError, OpenSSL::OpenSSLError => error
      raise ValidationError, "prepared request cryptographic metadata is malformed", cause: error
    end

    private

    def parse!(xml)
      raise ValidationError, "prepared request XML must not contain a DTD" if xml.match?(/<!DOCTYPE/i)

      Nokogiri::XML::Document.parse(xml) { |config| config.strict.nonet }
    end

    def validate_message_structure!(document)
      envelope = document.root
      unless envelope&.name == "Envelope" && envelope.namespace&.href == XmlSigner::SOAP_NAMESPACE
        raise ValidationError, "prepared request root must be a SOAP 1.1 Envelope"
      end

      children = envelope.element_children.map { |child| [child.namespace&.href, child.name] }
      expected = [[XmlSigner::SOAP_NAMESPACE, "Header"], [XmlSigner::SOAP_NAMESPACE, "Body"]]
      raise ValidationError, "prepared request Envelope must contain exactly Header then Body" unless children == expected

      header = exact_one(document, "/soapenv:Envelope/soapenv:Header", "SOAP Header")
      body = exact_one(document, "/soapenv:Envelope/soapenv:Body", "SOAP Body")
      payload = exact_one(body, "./v4:Trzba", "Trzba")
      request_header = exact_one(payload, "./v4:Hlavicka", "Hlavicka")
      sale_data = exact_one(payload, "./v4:Data", "Data")
      security = exact_one(header, "./wsse:Security", "Security")

      assert_exact_children!(document, [envelope], "XML document")
      assert_profile!(
        envelope,
        name: "Envelope",
        namespace: XmlSigner::SOAP_NAMESPACE,
        prefix: "soapenv",
        attributes: [],
        namespace_definitions: [["soapenv", XmlSigner::SOAP_NAMESPACE], ["v4", XmlSigner::EET_NAMESPACE]],
        children: [header, body],
        label: "SOAP Envelope"
      )
      assert_profile!(
        header,
        name: "Header",
        namespace: XmlSigner::SOAP_NAMESPACE,
        prefix: "soapenv",
        attributes: [],
        namespace_definitions: [],
        children: [security],
        label: "SOAP Header"
      )
      assert_profile!(
        body,
        name: "Body",
        namespace: XmlSigner::SOAP_NAMESPACE,
        prefix: "soapenv",
        attributes: [[XmlSigner::WSU_NAMESPACE, "wsu", "Id"]],
        namespace_definitions: [["wsu", XmlSigner::WSU_NAMESPACE]],
        children: [payload],
        label: "SOAP Body"
      )
      assert_profile!(
        payload,
        name: "Trzba",
        namespace: XmlSigner::EET_NAMESPACE,
        prefix: "v4",
        attributes: [],
        namespace_definitions: [],
        children: [request_header, sale_data],
        label: "Trzba"
      )

      [body, payload, request_header, sale_data, security]
    end

    def validate_attempt_metadata!(prepared_request, request_header)
      expected = {
        "uuid_zpravy" => prepared_request.request_uuid,
        "dat_odesl" => prepared_request.sent_at.iso8601(0),
        "prvni_zaslani" => prepared_request.first_submission.to_s
      }
      expected["overeni"] = "true" if prepared_request.verification_mode
      assert_profile!(
        request_header,
        name: "Hlavicka",
        namespace: XmlSigner::EET_NAMESPACE,
        prefix: "v4",
        attributes: expected.keys.map { |name| [nil, nil, name] },
        namespace_definitions: [],
        children: [],
        label: "Hlavicka"
      )
      actual = request_header.attribute_nodes.to_h { |attribute| [attribute.name, attribute.value] }
      raise ValidationError, "prepared request header does not match attempt metadata" unless actual == expected
    end

    def validate_sale_metadata!(sale, sale_data)
      expected = {
        "eic_popl" => sale.taxpayer_eic,
        "eic_poverujiciho" => sale.authorizing_taxpayer_eic,
        "povereni_vice_popl" => sale.multiple_authorization&.to_s,
        "id_jednotky" => sale.evidence_unit_id.to_s,
        "id_pokl" => sale.register_id,
        "porad_cis" => sale.sequence_number,
        "dat_trzby" => sale.occurred_at_wire_value,
        "celk_trzba" => sale.amount_wire_value(sale.amount_czk),
        "urceno_cerp_zuct" => optional_amount(sale, sale.designated_drawdown_amount_czk),
        "cerp_zuct" => optional_amount(sale, sale.drawdown_amount_czk)
      }.compact
      assert_profile!(
        sale_data,
        name: "Data",
        namespace: XmlSigner::EET_NAMESPACE,
        prefix: "v4",
        attributes: expected.keys.map { |name| [nil, nil, name] },
        namespace_definitions: [],
        children: [],
        label: "Data"
      )
      actual = sale_data.attribute_nodes.to_h { |attribute| [attribute.name, attribute.value] }
      raise ValidationError, "prepared request Data does not match Sale metadata" unless actual == expected
    end

    def optional_amount(sale, amount)
      sale.amount_wire_value(amount) unless amount.nil?
    end

    def validate_signature_metadata!(prepared_request, body, security)
      token = exact_one(security, "./wsse:BinarySecurityToken", "BinarySecurityToken")
      signature = exact_one(security, "./ds:Signature", "Signature")
      signed_info = exact_one(signature, "./ds:SignedInfo", "SignedInfo")
      signature_value = exact_one(signature, "./ds:SignatureValue", "SignatureValue")
      key_info = exact_one(signature, "./ds:KeyInfo", "KeyInfo")
      canonicalization = exact_one(signed_info, "./ds:CanonicalizationMethod", "CanonicalizationMethod")
      signature_method = exact_one(signed_info, "./ds:SignatureMethod", "SignatureMethod")
      reference = exact_one(signed_info, "./ds:Reference", "signed Body Reference")
      transforms = exact_one(reference, "./ds:Transforms", "Transforms")
      transform = exact_one(transforms, "./ds:Transform", "Transform")
      digest_method = exact_one(reference, "./ds:DigestMethod", "DigestMethod")
      digest_value = exact_one(reference, "./ds:DigestValue", "DigestValue")
      signed_inclusive = exact_one(canonicalization, "./ec:InclusiveNamespaces", "SignedInfo InclusiveNamespaces")
      body_inclusive = exact_one(transform, "./ec:InclusiveNamespaces", "Body InclusiveNamespaces")
      token_reference = exact_one(key_info, "./wsse:SecurityTokenReference", "SecurityTokenReference")
      reference_to_token = exact_one(token_reference, "./wsse:Reference", "token Reference")

      ids = validate_security_profile!(
        prepared_request: prepared_request,
        body: body,
        security: security,
        token: token,
        signature: signature,
        signed_info: signed_info,
        signature_value: signature_value,
        key_info: key_info,
        canonicalization: canonicalization,
        signature_method: signature_method,
        reference: reference,
        transforms: transforms,
        transform: transform,
        digest_method: digest_method,
        digest_value: digest_value,
        signed_inclusive: signed_inclusive,
        body_inclusive: body_inclusive,
        token_reference: token_reference,
        reference_to_token: reference_to_token
      )
      validate_algorithms!(signed_info, reference)
      validate_references!(body, token, reference, reference_to_token, ids)

      canonical_body = @canonicalizer.canonicalize(body, inclusive_namespaces: ["v4"])
      body_digest = OpenSSL::Digest::SHA256.digest(canonical_body)
      unless prepared_request.body_sha256 == OpenSSL::Digest::SHA256.hexdigest(canonical_body)
        raise ValidationError, "prepared request body_sha256 does not match the signed SOAP Body"
      end
      unless secure_equal?(Base64.strict_decode64(exact_text!(digest_value, "DigestValue")), body_digest)
        raise ValidationError, "prepared request DigestValue does not match the signed SOAP Body"
      end

      certificate = OpenSSL::X509::Certificate.new(Base64.strict_decode64(exact_text!(token, "BinarySecurityToken")))
      certificate_sha256 = OpenSSL::Digest::SHA256.hexdigest(certificate.to_der)
      unless prepared_request.certificate_sha256 == certificate_sha256
        raise ValidationError, "prepared request certificate_sha256 does not match BinarySecurityToken"
      end

      canonical_signed_info = @canonicalizer.canonicalize(signed_info, inclusive_namespaces: %w[soapenv v4])
      raw_signature = Base64.strict_decode64(exact_text!(signature_value, "SignatureValue"))
      unless certificate.public_key.verify(OpenSSL::Digest.new("SHA256"), raw_signature, canonical_signed_info)
        raise ValidationError, "prepared request RSA-SHA256 signature is invalid"
      end
    end

    def validate_security_profile!(nodes)
      prepared_request = nodes.fetch(:prepared_request)
      ids = {
        body: "body-#{prepared_request.request_uuid}",
        token: "x509-#{prepared_request.request_uuid}",
        signature: "signature-#{prepared_request.request_uuid}",
        key_info: "key-info-#{prepared_request.request_uuid}",
        token_reference: "token-reference-#{prepared_request.request_uuid}"
      }

      assert_profile!(
        nodes.fetch(:security),
        name: "Security",
        namespace: XmlSigner::WSSE_NAMESPACE,
        prefix: "wsse",
        attributes: [],
        namespace_definitions: [["wsse", XmlSigner::WSSE_NAMESPACE], ["wsu", XmlSigner::WSU_NAMESPACE]],
        children: [nodes.fetch(:token), nodes.fetch(:signature)],
        label: "Security"
      )
      assert_profile!(
        nodes.fetch(:token),
        name: "BinarySecurityToken",
        namespace: XmlSigner::WSSE_NAMESPACE,
        prefix: "wsse",
        attributes: [[nil, nil, "EncodingType"], [nil, nil, "ValueType"], [XmlSigner::WSU_NAMESPACE, "wsu", "Id"]],
        namespace_definitions: [],
        children: :text,
        label: "BinarySecurityToken"
      )
      assert_profile!(
        nodes.fetch(:signature),
        name: "Signature",
        namespace: XmlSigner::DS_NAMESPACE,
        prefix: "ds",
        attributes: [[nil, nil, "Id"]],
        namespace_definitions: [["ds", XmlSigner::DS_NAMESPACE]],
        children: [nodes.fetch(:signed_info), nodes.fetch(:signature_value), nodes.fetch(:key_info)],
        label: "Signature"
      )
      validate_signed_info_structure!(nodes)
      validate_key_info_structure!(nodes)

      expected_ids = {
        ids.fetch(:body) => nodes.fetch(:body),
        ids.fetch(:token) => nodes.fetch(:token),
        ids.fetch(:signature) => nodes.fetch(:signature),
        ids.fetch(:key_info) => nodes.fetch(:key_info),
        ids.fetch(:token_reference) => nodes.fetch(:token_reference)
      }
      actual_ids = unique_ids!(nodes.fetch(:security).document)
      raise ValidationError, "prepared request XML IDs do not match its UUID-derived profile" unless actual_ids == expected_ids

      actual_ids
    end

    def validate_signed_info_structure!(nodes)
      profile!(nodes, :signed_info, "SignedInfo", [], [], %i[canonicalization signature_method reference])
      profile!(nodes, :canonicalization, "CanonicalizationMethod", [[nil, nil, "Algorithm"]], [], [:signed_inclusive])
      profile!(nodes, :signed_inclusive, "InclusiveNamespaces", [[nil, nil, "PrefixList"]], [["ec", XmlSigner::EXCLUSIVE_C14N_NAMESPACE]], [])
      profile!(nodes, :signature_method, "SignatureMethod", [[nil, nil, "Algorithm"]], [], [])
      profile!(nodes, :reference, "Reference", [[nil, nil, "URI"]], [], %i[transforms digest_method digest_value])
      profile!(nodes, :transforms, "Transforms", [], [], [:transform])
      profile!(nodes, :transform, "Transform", [[nil, nil, "Algorithm"]], [], [:body_inclusive])
      profile!(nodes, :body_inclusive, "InclusiveNamespaces", [[nil, nil, "PrefixList"]], [["ec", XmlSigner::EXCLUSIVE_C14N_NAMESPACE]], [])
      profile!(nodes, :digest_method, "DigestMethod", [[nil, nil, "Algorithm"]], [], [])
      profile!(nodes, :digest_value, "DigestValue", [], [], :text)
      profile!(nodes, :signature_value, "SignatureValue", [], [], :text)
    end

    def validate_key_info_structure!(nodes)
      profile!(nodes, :key_info, "KeyInfo", [[nil, nil, "Id"]], [], [:token_reference])
      assert_profile!(
        nodes.fetch(:token_reference),
        name: "SecurityTokenReference",
        namespace: XmlSigner::WSSE_NAMESPACE,
        prefix: "wsse",
        attributes: [[XmlSigner::WSU_NAMESPACE, "wsu", "Id"]],
        namespace_definitions: [],
        children: [nodes.fetch(:reference_to_token)],
        label: "SecurityTokenReference"
      )
      assert_profile!(
        nodes.fetch(:reference_to_token),
        name: "Reference",
        namespace: XmlSigner::WSSE_NAMESPACE,
        prefix: "wsse",
        attributes: [[nil, nil, "URI"], [nil, nil, "ValueType"]],
        namespace_definitions: [],
        children: [],
        label: "security token Reference"
      )
    end

    def profile!(nodes, key, name, attributes, namespace_definitions, children)
      expected_children = (children == :text) ? :text : children.map { |child| nodes.fetch(child) }
      assert_profile!(
        nodes.fetch(key),
        name: name,
        namespace: key.to_s.include?("inclusive") ? XmlSigner::EXCLUSIVE_C14N_NAMESPACE : XmlSigner::DS_NAMESPACE,
        prefix: key.to_s.include?("inclusive") ? "ec" : "ds",
        attributes: attributes,
        namespace_definitions: namespace_definitions,
        children: expected_children,
        label: name
      )
    end

    def validate_algorithms!(signed_info, reference)
      canonicalization = exact_one(signed_info, "./ds:CanonicalizationMethod", "CanonicalizationMethod")
      signature_method = exact_one(signed_info, "./ds:SignatureMethod", "SignatureMethod")
      transforms = exact_one(reference, "./ds:Transforms", "Transforms")
      transform = exact_one(transforms, "./ds:Transform", "Transform")
      digest_method = exact_one(reference, "./ds:DigestMethod", "DigestMethod")
      signed_inclusive = exact_one(canonicalization, "./ec:InclusiveNamespaces", "SignedInfo InclusiveNamespaces")
      body_inclusive = exact_one(transform, "./ec:InclusiveNamespaces", "Body InclusiveNamespaces")

      valid = canonicalization["Algorithm"] == XmlSigner::EXCLUSIVE_C14N_ALGORITHM &&
        signature_method["Algorithm"] == XmlSigner::RSA_SHA256_ALGORITHM &&
        transform["Algorithm"] == XmlSigner::EXCLUSIVE_C14N_ALGORITHM &&
        digest_method["Algorithm"] == XmlSigner::SHA256_ALGORITHM &&
        signed_inclusive["PrefixList"] == "soapenv v4" &&
        body_inclusive["PrefixList"] == "v4" &&
        transforms.element_children.to_a == [transform]
      raise ValidationError, "prepared request signature algorithm profile changed" unless valid
    end

    def validate_references!(body, token, reference, token_reference, ids)
      body_id = body["wsu:Id"]
      unless body_id && ids[body_id] == body && reference["URI"] == "##{body_id}"
        raise ValidationError, "prepared request signature does not reference the sole SOAP Body"
      end

      token_id = token["wsu:Id"]
      unless token_id && ids[token_id] == token &&
          token_reference["URI"] == "##{token_id}" &&
          token_reference["ValueType"] == XmlSigner::X509_VALUE_TYPE &&
          token["EncodingType"] == XmlSigner::BASE64_ENCODING_TYPE &&
          token["ValueType"] == XmlSigner::X509_VALUE_TYPE
        raise ValidationError, "prepared request KeyInfo does not reference its X.509 token"
      end
    end

    def unique_ids!(document)
      document.xpath('//@*[local-name()="Id"]').each_with_object({}) do |attribute, ids|
        raise ValidationError, "prepared request contains an empty or duplicate XML ID" if attribute.value.empty? || ids.key?(attribute.value)

        ids[attribute.value] = attribute.parent
      end
    end

    def assert_profile!(node, name:, namespace:, prefix:, attributes:, namespace_definitions:, children:, label:)
      unless node.element? && node.name == name && node.namespace&.href == namespace && node.namespace&.prefix == prefix
        raise ValidationError, "prepared request #{label} QName changed"
      end

      actual_attributes = node.attribute_nodes.map do |attribute|
        [attribute.namespace&.href, attribute.namespace&.prefix, attribute.name]
      end
      unless sorted_profile(actual_attributes) == sorted_profile(attributes)
        raise ValidationError, "prepared request #{label} contains unexpected attributes"
      end

      actual_definitions = node.namespace_definitions.map { |definition| [definition.prefix, definition.href] }
      unless sorted_profile(actual_definitions) == sorted_profile(namespace_definitions)
        raise ValidationError, "prepared request #{label} namespace declarations changed"
      end

      if children == :text
        exact_text!(node, label)
      else
        assert_exact_children!(node, children, label)
      end
    end

    def assert_exact_children!(node, expected, label)
      unless node.children.to_a == expected
        raise ValidationError, "prepared request #{label} contains unexpected, out-of-order, or non-element content"
      end
    end

    def exact_text!(node, label)
      children = node.children.to_a
      text = children.first
      unless children.length == 1 && text.text? && !text.content.empty? && text.content == text.content.strip
        raise ValidationError, "prepared request #{label} must contain one unpadded text node"
      end

      text.content
    end

    def sorted_profile(values)
      values.sort_by { |value| value.map(&:to_s) }
    end

    def exact_one(parent, xpath, label)
      nodes = parent.xpath(xpath, NAMESPACES)
      raise ValidationError, "prepared request #{label} must occur exactly once" unless nodes.length == 1

      nodes.first
    end

    def secure_equal?(left, right)
      left.bytesize == right.bytesize && OpenSSL.fixed_length_secure_compare(left, right)
    end
  end
end
