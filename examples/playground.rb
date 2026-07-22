# frozen_string_literal: true

require "bigdecimal"
require "eet2"

module Eet2PlaygroundExample
  module_function

  def build_client(credential:, transport: nil)
    return Eet2::Client.playground(credential: credential, transport: transport) if transport

    Eet2::Client.playground(credential: credential, open_timeout: 5, read_timeout: 10, write_timeout: 5)
  end

  def build_sale(sequence_number:, occurred_at: Time.now.floor)
    Eet2::Sale.new(
      taxpayer_eic: "CZ00000019",
      evidence_unit_id: 303,
      register_id: "ruby-eet2",
      sequence_number: sequence_number,
      occurred_at: occurred_at,
      amount_czk: BigDecimal("1.00")
    )
  end

  def summarize(result)
    case result
    when Eet2::Response::VerifiedReceipt
      "accepted pok=#{result.pok} support_id=#{result.support_id || "-"}"
    when Eet2::Response::UnsignedError
      "unsigned_error code=#{result.code} support_id=#{result.support_id || "-"}"
    when Eet2::Response::InvalidResponse
      "invalid_response reason=#{result.reason} sha256=#{result.response_sha256} support_id=#{result.support_id || "-"}"
    when Eet2::Response::TransportFailure
      "transport_failure kind=#{result.kind} certainty=#{result.certainty} http_status=#{result.http_status || "-"} support_id=#{result.support_id || "-"}"
    else
      raise "unexpected EET2 result class: #{result.class}"
    end
  end
end

if $PROGRAM_NAME == __FILE__
  credential_path = ENV.fetch("EET2_PKCS12_PATH")
  password = ENV.fetch("EET2_PKCS12_PASSWORD")
  sequence_number = ENV.fetch("EET2_SEQUENCE_NUMBER")
  legacy_provider = (ENV["EET2_ALLOW_LEGACY_PKCS12"] == "1") ? :explicitly_allowed : :forbid

  credential = Eet2::Credential.from_pkcs12(
    bytes: File.binread(credential_path),
    password: password,
    legacy_provider: legacy_provider
  )
  client = Eet2PlaygroundExample.build_client(credential: credential)
  sale = Eet2PlaygroundExample.build_sale(sequence_number: sequence_number)
  prepared = client.prepare(
    sale: sale,
    first_submission: true,
    verification_mode: ENV["EET2_VERIFICATION_MODE"] == "1"
  )

  warn "prepared request_uuid=#{prepared.request_uuid} request_sha256=#{prepared.request_sha256}"
  result = client.transmit(prepared)
  puts Eet2PlaygroundExample.summarize(result)
end
