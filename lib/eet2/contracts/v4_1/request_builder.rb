# frozen_string_literal: true

require "digest"
require "nokogiri"
require "securerandom"
require "time"

require_relative "../../credential"
require_relative "../../prepared_request"
require_relative "../../sale"
require_relative "../../xml_signer"
require_relative "schema"

module Eet2
  module Contracts
    # standard:disable Naming/ClassAndModuleCamelCase
    module V4_1
      class RequestBuilder
        PROTOCOL_VERSION = "4.1"
        SOAP_NAMESPACE = XmlSigner::SOAP_NAMESPACE
        EET_NAMESPACE = XmlSigner::EET_NAMESPACE
        WSSE_NAMESPACE = XmlSigner::WSSE_NAMESPACE
        WSU_NAMESPACE = XmlSigner::WSU_NAMESPACE

        def initialize(
          credential:,
          schema: Schema.new,
          uuid_generator: -> { SecureRandom.uuid },
          clock: -> { Time.now }
        )
          raise CredentialError, "credential must be an Eet2::Credential" unless credential.is_a?(Credential)
          raise ArgumentError, "uuid_generator must respond to call" unless uuid_generator.respond_to?(:call)
          raise ArgumentError, "clock must respond to call" unless clock.respond_to?(:call)

          @credential = credential
          @schema = schema
          @uuid_generator = uuid_generator
          @clock = clock
        end

        def call(sale:, first_submission:, verification_mode: false)
          raise ValidationError, "sale must be an Eet2::Sale" unless sale.is_a?(Sale)
          validate_boolean!(first_submission, :first_submission)
          validate_boolean!(verification_mode, :verification_mode)

          request_uuid = @uuid_generator.call.to_s.downcase
          validate_uuid!(request_uuid)
          sent_at = normalize_time(@clock.call)
          document, security, body, payload = build_document(
            sale: sale,
            request_uuid: request_uuid,
            sent_at: sent_at,
            first_submission: first_submission,
            verification_mode: verification_mode
          )
          @schema.validate_payload!(payload)

          signed = XmlSigner.new(certificate: @credential.certificate, signer: @credential.signer).sign(
            document: document,
            security: security,
            body: body,
            id_suffix: request_uuid
          )
          xml = serialize(signed.document)

          PreparedRequest.new(
            request_uuid: request_uuid,
            sent_at: sent_at,
            sale: sale,
            first_submission: first_submission,
            verification_mode: verification_mode,
            xml: xml,
            request_sha256: Digest::SHA256.hexdigest(xml),
            body_sha256: Digest::SHA256.hexdigest(signed.canonical_body),
            certificate_sha256: @credential.certificate_sha256,
            protocol_version: PROTOCOL_VERSION,
            schema_sha256: Schema::SHA256
          )
        end

        private

        def normalize_time(value)
          raise ValidationError, "clock must return a Time" unless value.is_a?(Time)

          Time.at(value.to_i, in: value.utc_offset).freeze
        end

        def validate_boolean!(value, field)
          raise ValidationError, "#{field} must be true or false" unless value == true || value == false
        end

        def validate_uuid!(value)
          unless value.match?(PreparedRequest::UUID_V4_PATTERN)
            raise ValidationError, "uuid_generator must return an RFC 4122 version 4 UUID"
          end
        end

        def build_document(sale:, request_uuid:, sent_at:, first_submission:, verification_mode:)
          document = Nokogiri::XML::Document.new
          envelope = Nokogiri::XML::Node.new("Envelope", document)
          soap_namespace = envelope.add_namespace_definition("soapenv", SOAP_NAMESPACE)
          envelope.add_namespace_definition("v4", EET_NAMESPACE)
          envelope.namespace = soap_namespace
          document.root = envelope

          header = soap_node("Header", document, soap_namespace)
          envelope.add_child(header)
          security = Nokogiri::XML::Node.new("Security", document)
          wsse_namespace = security.add_namespace_definition("wsse", WSSE_NAMESPACE)
          security.add_namespace_definition("wsu", WSU_NAMESPACE)
          security.namespace = wsse_namespace
          header.add_child(security)

          body = soap_node("Body", document, soap_namespace)
          body.add_namespace_definition("wsu", WSU_NAMESPACE)
          envelope.add_child(body)

          payload = eet_node("Trzba", document, envelope)
          body.add_child(payload)
          add_header(payload, document, envelope, request_uuid, sent_at, first_submission, verification_mode)
          add_sale_data(payload, document, envelope, sale)

          [document, security, body, payload]
        end

        def add_header(payload, document, envelope, request_uuid, sent_at, first_submission, verification_mode)
          header = eet_node("Hlavicka", document, envelope)
          header["uuid_zpravy"] = request_uuid
          header["dat_odesl"] = sent_at.iso8601(0)
          header["prvni_zaslani"] = first_submission.to_s
          header["overeni"] = "true" if verification_mode
          payload.add_child(header)
        end

        def add_sale_data(payload, document, envelope, sale)
          data = eet_node("Data", document, envelope)
          attributes = {
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
          }
          attributes.each { |name, value| data[name] = value unless value.nil? }
          payload.add_child(data)
        end

        def optional_amount(sale, amount)
          sale.amount_wire_value(amount) unless amount.nil?
        end

        def soap_node(name, document, namespace)
          node = Nokogiri::XML::Node.new(name, document)
          node.namespace = namespace
          node
        end

        def eet_node(name, document, envelope)
          node = Nokogiri::XML::Node.new(name, document)
          node.namespace = envelope.namespace_definitions.find { |namespace| namespace.prefix == "v4" }
          node
        end

        def serialize(document)
          document.root.to_xml(
            save_with: Nokogiri::XML::Node::SaveOptions::AS_XML |
              Nokogiri::XML::Node::SaveOptions::NO_DECLARATION
          ).freeze
        end
      end
    end
    # standard:enable Naming/ClassAndModuleCamelCase
  end
end
