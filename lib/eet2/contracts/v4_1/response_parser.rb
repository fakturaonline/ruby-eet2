# frozen_string_literal: true

require "digest"
require "nokogiri"
require "time"

require_relative "../../errors"
require_relative "../../prepared_request"
require_relative "../../response"
require_relative "../../trust_policy"
require_relative "../../xml_signature_verifier"
require_relative "schema"

module Eet2
  module Contracts
    # standard:disable Naming/ClassAndModuleCamelCase
    module V4_1
      class ResponseParser
        MAX_RESPONSE_BYTES = 256 * 1024
        NAMESPACES = {
          "soapenv" => XmlSigner::SOAP_NAMESPACE,
          "v4" => XmlSigner::EET_NAMESPACE,
          "ds" => XmlSigner::DS_NAMESPACE,
          "wsse" => XmlSigner::WSSE_NAMESPACE
        }.freeze

        def initialize(trust_policy: TrustPolicy.playground, schema: Schema.new, signature_verifier: nil, receive_clock: -> { Time.now })
          raise ArgumentError, "receive_clock must respond to call" unless receive_clock.respond_to?(:call)

          @trust_policy = trust_policy
          @schema = schema
          @signature_verifier = signature_verifier || XmlSignatureVerifier.new(trust_policy: trust_policy)
          @receive_clock = receive_clock
        end

        def call(xml:, expected_request_uuid:)
          validate_input!(xml, expected_request_uuid)
          document = parse_strictly(xml)
          header, body, payload = validate_soap_structure!(document)
          reject_xinclude!(document)
          @schema.validate_payload!(payload)

          response_header = exact_child(payload, "v4:Hlavicka", "response Hlavicka")
          confirmation = payload.xpath("./v4:Potvrzeni", NAMESPACES)
          error = payload.xpath("./v4:Chyba", NAMESPACES)
          warnings = parse_warnings(payload)
          response_sha256 = Digest::SHA256.hexdigest(xml)

          if confirmation.length == 1 && error.empty?
            parse_verified_receipt(
              document: document,
              body: body,
              response_header: response_header,
              confirmation: confirmation.first,
              warnings: warnings,
              expected_request_uuid: expected_request_uuid,
              response_sha256: response_sha256
            )
          elsif error.length == 1 && confirmation.empty?
            parse_unsigned_error(
              document: document,
              header: header,
              response_header: response_header,
              error: error.first,
              warnings: warnings,
              expected_request_uuid: expected_request_uuid,
              response_sha256: response_sha256
            )
          else
            raise MalformedResponse, "response must contain exactly one Potvrzeni or Chyba"
          end
        end

        private

        def validate_input!(xml, expected_request_uuid)
          raise MalformedResponse, "response XML must be a non-empty String" unless xml.is_a?(String) && !xml.empty?
          raise MalformedResponse, "response exceeds #{MAX_RESPONSE_BYTES} bytes" if xml.bytesize > MAX_RESPONSE_BYTES
          raise MalformedResponse, "response XML must not contain a DTD" if xml.match?(/<!DOCTYPE/i)
          unless expected_request_uuid.is_a?(String) && expected_request_uuid.match?(PreparedRequest::UUID_V4_PATTERN)
            raise ValidationError, "expected_request_uuid must be an RFC 4122 version 4 UUID"
          end
        end

        def parse_strictly(xml)
          Nokogiri::XML::Document.parse(xml) { |config| config.strict.nonet }
        rescue Nokogiri::XML::SyntaxError => error
          raise MalformedResponse, "response is not strict well-formed XML", cause: error
        end

        def validate_soap_structure!(document)
          root = document.root
          unless root && root.name == "Envelope" && root.namespace&.href == XmlSigner::SOAP_NAMESPACE
            raise MalformedResponse, "response root must be a SOAP 1.1 Envelope"
          end

          expected_children = [[XmlSigner::SOAP_NAMESPACE, "Header"], [XmlSigner::SOAP_NAMESPACE, "Body"]]
          actual_children = root.element_children.map { |child| [child.namespace&.href, child.name] }
          raise MalformedResponse, "SOAP Envelope must contain exactly Header then Body" unless actual_children == expected_children

          header = document.at_xpath("/soapenv:Envelope/soapenv:Header", NAMESPACES)
          bodies = document.xpath("/soapenv:Envelope/soapenv:Body", NAMESPACES)
          raise MalformedResponse, "response must contain exactly one SOAP Body" unless bodies.length == 1

          body = bodies.first
          payloads = body.xpath("./v4:Odpoved", NAMESPACES)
          unless payloads.length == 1 && body.element_children.length == 1
            raise MalformedResponse, "SOAP Body must contain exactly one v4:Odpoved"
          end

          [header, body, payloads.first]
        end

        def reject_xinclude!(document)
          unless document.xpath('//*[namespace-uri()="http://www.w3.org/2001/XInclude"]').empty?
            raise MalformedResponse, "response must not contain XInclude elements"
          end
        end

        def parse_verified_receipt(document:, body:, response_header:, confirmation:, warnings:, expected_request_uuid:, response_sha256:)
          request_uuid = required_attribute(response_header, "uuid_zpravy")
          received_at = parse_time(required_attribute(response_header, "dat_prij"), "dat_prij")
          pok = required_attribute(confirmation, "pok")
          test_value = confirmation["test"]
          test = test_value && parse_boolean(test_value, "Potvrzeni test")
          validate_confirmation_environment!(test: test, test_present: !test_value.nil?, pok: pok)

          verification_time = @receive_clock.call
          raise ValidationError, "receive_clock must return a Time" unless verification_time.is_a?(Time)

          evidence = @signature_verifier.verify!(document: document, body: body, verification_time: verification_time)
          validate_correlation!(request_uuid, expected_request_uuid)

          Response::VerifiedReceipt.new(
            request_uuid: request_uuid,
            received_at: received_at,
            pok: pok,
            test: test,
            warnings: warnings,
            response_sha256: response_sha256,
            signature_evidence: evidence
          )
        end

        def parse_unsigned_error(document:, header:, response_header:, error:, warnings:, expected_request_uuid:, response_sha256:)
          unless header.element_children.empty? && document.xpath("//ds:Signature | //wsse:BinarySecurityToken", NAMESPACES).empty?
            raise MalformedResponse, "Chyba response must use the documented unsigned profile"
          end

          request_uuid = response_header["uuid_zpravy"]
          validate_correlation!(request_uuid, expected_request_uuid) if request_uuid
          rejected_at_value = response_header["dat_odmit"]
          test_value = error["test"]
          test = test_value && parse_boolean(test_value, "Chyba test")
          validate_error_environment!(test: test, test_present: !test_value.nil?)

          Response::UnsignedError.new(
            request_uuid: request_uuid,
            rejected_at: rejected_at_value && parse_time(rejected_at_value, "dat_odmit"),
            code: Integer(required_attribute(error, "kod"), 10),
            message: error.text.to_s.strip,
            test: test,
            warnings: warnings,
            response_sha256: response_sha256
          )
        rescue ArgumentError => parse_error
          raise MalformedResponse, "Chyba code is not an Integer", cause: parse_error
        end

        def parse_warnings(payload)
          payload.xpath("./v4:Varovani", NAMESPACES).map do |warning|
            Response::Warning.new(
              code: Integer(required_attribute(warning, "kod_varov"), 10),
              message: warning.text.to_s.strip
            )
          end.freeze
        rescue ArgumentError => parse_error
          raise MalformedResponse, "warning code is not an Integer", cause: parse_error
        end

        def validate_correlation!(actual, expected)
          raise CorrelationError, "response UUID does not match the prepared request" unless actual == expected
        end

        def validate_confirmation_environment!(test:, test_present:, pok:)
          valid = case @trust_policy.environment
          when :playground
            test_present && test && pok.downcase.end_with?("-ff")
          when :production
            !test_present && !pok.downcase.end_with?("-ff")
          else
            false
          end

          raise MalformedResponse, "Potvrzeni environment markers do not match #{@trust_policy.environment}" unless valid
        end

        def validate_error_environment!(test:, test_present:)
          valid = case @trust_policy.environment
          when :playground then test_present && test
          when :production then !test_present
          else false
          end

          raise MalformedResponse, "Chyba environment marker does not match #{@trust_policy.environment}" unless valid
        end

        def parse_time(value, field)
          Time.iso8601(value).freeze
        rescue ArgumentError => error
          raise MalformedResponse, "#{field} is not a strict ISO 8601 timestamp", cause: error
        end

        def parse_boolean(value, field)
          return true if value == "true" || value == "1"
          return false if value == "false" || value == "0"

          raise MalformedResponse, "#{field} must be true or false"
        end

        def required_attribute(node, name)
          value = node[name]
          raise MalformedResponse, "required response attribute #{name} is missing" if value.nil? || value.empty?

          value
        end

        def exact_child(parent, xpath, label)
          nodes = parent.xpath("./#{xpath}", NAMESPACES)
          raise MalformedResponse, "#{label} must occur exactly once" unless nodes.length == 1

          nodes.first
        end
      end
    end
    # standard:enable Naming/ClassAndModuleCamelCase
  end
end
