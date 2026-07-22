# frozen_string_literal: true

require "nokogiri"

require_relative "../../errors"

module Eet2
  module Contracts
    # standard:disable Naming/ClassAndModuleCamelCase
    module V4_1
      class Schema
        SHA256 = "83597d08520cbfab7e51145df9a765d5ca22e2f9a38644a468d695657c7a032a"
        PATH = File.expand_path("../../../../data/official/eet-v4_1/EETXMLSchema.xsd", __dir__)

        def initialize(path: PATH)
          @schema = Nokogiri::XML::Schema(File.binread(path))
        rescue Errno::ENOENT, Nokogiri::XML::SyntaxError => error
          raise SchemaValidationError, ["unable to load EET2 schema: #{error.message}"]
        end

        def validate_payload!(payload)
          payload_xml = payload.is_a?(Nokogiri::XML::Node) ? payload.dup(1).to_xml : payload.to_s
          document = Nokogiri::XML::Document.parse(payload_xml) do |config|
            config.strict.nonet
          end
          errors = @schema.validate(document)
          raise SchemaValidationError, errors.map { |error| sanitize(error.message) } unless errors.empty?

          true
        rescue Nokogiri::XML::SyntaxError => error
          raise SchemaValidationError, [sanitize(error.message)]
        end

        private

        def sanitize(message)
          message.to_s.gsub(PATH, "EETXMLSchema.xsd").strip
        end
      end
    end
    # standard:enable Naming/ClassAndModuleCamelCase
  end
end
