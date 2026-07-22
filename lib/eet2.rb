# frozen_string_literal: true

require_relative "eet2/version"

# Framework-independent support for the Czech EET2 protocol.
module Eet2
  autoload :Credential, "eet2/credential"
  autoload :CredentialError, "eet2/errors"
  autoload :CertificateVerificationError, "eet2/errors"
  autoload :CertificateVerifier, "eet2/certificate_verifier"
  autoload :Client, "eet2/client"
  autoload :CorrelationError, "eet2/errors"
  autoload :Error, "eet2/errors"
  autoload :InvalidResponse, "eet2/errors"
  autoload :LegacyPkcs12Unsupported, "eet2/errors"
  autoload :LocalKeySigner, "eet2/local_key_signer"
  autoload :MalformedResponse, "eet2/errors"
  autoload :NetHttpTransport, "eet2/net_http_transport"
  autoload :PreparedRequest, "eet2/prepared_request"
  autoload :RequestIntegrityVerifier, "eet2/request_integrity_verifier"
  autoload :Response, "eet2/response"
  autoload :RequestTooLarge, "eet2/errors"
  autoload :Sale, "eet2/sale"
  autoload :SchemaValidationError, "eet2/errors"
  autoload :SignatureVerificationError, "eet2/errors"
  autoload :SigningError, "eet2/errors"
  autoload :TrustPolicy, "eet2/trust_policy"
  autoload :Transport, "eet2/transport"
  autoload :TransportConfigurationError, "eet2/errors"
  autoload :UnsupportedEnvironment, "eet2/errors"
  autoload :ValidationError, "eet2/errors"
  autoload :XmlSignatureVerifier, "eet2/xml_signature_verifier"
  autoload :XmlSigner, "eet2/xml_signer"

  module Contracts
    # Protocol versions mirror the official dotted version identifier.
    # standard:disable Naming/ClassAndModuleCamelCase
    module V4_1
      autoload :RequestBuilder, "eet2/contracts/v4_1/request_builder"
      autoload :ResponseParser, "eet2/contracts/v4_1/response_parser"
      autoload :Schema, "eet2/contracts/v4_1/schema"
    end
    # standard:enable Naming/ClassAndModuleCamelCase
  end
end
