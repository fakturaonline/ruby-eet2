# frozen_string_literal: true

require "bigdecimal"
require "digest"
require "fileutils"
require "net/http"
require "nokogiri"
require "open3"
require "openssl"
require "securerandom"
require "tmpdir"
require "time"
require "uri"

require "eet2"

module Eet2PlaygroundE2E
  ARCHIVE_URL = "https://eet.gov.cz/files/CAEET_Playground_2026_v1.zip"
  ARCHIVE_SHA256 = "711ca591e2e58e906212befab55ea72cbc5d960af49e444765b0428751002491"
  MAX_ARCHIVE_BYTES = 1024 * 1024
  EXPECTED_ARCHIVE_FILES = %w[
    CA_EET-Playground-CZ00000019.p12
    CA_EET-Playground-CZ683555118.p12
    CA_EET-Playground-CZ8551015704.p12
    ca_eet-root_cert-playground.crt
    ca_eet-sub_cert-playground.crt
    password_pokladni_cert_playground.txt
  ].freeze
  IDENTITIES = {
    "CZ00000019" => 303,
    "CZ683555118" => 101,
    "CZ8551015704" => 202
  }.freeze

  class Failure < StandardError; end

  module_function

  def run
    evidence = base_evidence
    password = nil

    Dir.mktmpdir("ruby-eet2-cz-live-") do |temporary_directory|
      FileUtils.chmod(0o700, temporary_directory)
      archive_path = File.join(temporary_directory, "credentials.zip")
      extracted_path = File.join(temporary_directory, "credentials")

      download_archive(archive_path)
      verify_archive!(archive_path)
      extract_archive!(archive_path, extracted_path)
      password = File.binread(File.join(extracted_path, "password_pokladni_cert_playground.txt"))
      raise Failure, "official credential password has an unexpected format" unless password.match?(/\A[A-Za-z0-9]{8}\z/)

      credentials = load_credentials(extracted_path, password)
      scenarios = evidence.fetch(:scenarios)
      primary_client = build_client(credentials.fetch("CZ00000019"))

      scenarios << run_verification_mode(primary_client)
      accepted_sale, accepted = run_accepted(primary_client, "CZ00000019", IDENTITIES.fetch("CZ00000019"))
      scenarios << accepted
      scenarios << run_retry(primary_client, accepted_sale)

      IDENTITIES.each do |taxpayer_eic, evidence_unit_id|
        next if taxpayer_eic == "CZ00000019"

        _sale, result = run_accepted(build_client(credentials.fetch(taxpayer_eic)), taxpayer_eic, evidence_unit_id)
        scenarios << result
      end

      scenarios << run_invalid_xsd(primary_client)
      scenarios << run_invalid_signature(primary_client)
    ensure
      password&.clear
    end

    evidence[:status] = "pass"
    evidence
  end

  def base_evidence
    {
      status: "running",
      checked_at: Time.now.utc.iso8601,
      endpoint: Eet2::Transport::PLAYGROUND_ENDPOINT,
      archive_sha256: ARCHIVE_SHA256,
      runtime: {
        ruby: RUBY_VERSION,
        openssl: OpenSSL::OPENSSL_VERSION,
        nokogiri: Nokogiri::VERSION
      },
      scenarios: []
    }
  end

  def download_archive(path)
    uri = URI(ARCHIVE_URL)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    http.verify_hostname = true
    http.min_version = OpenSSL::SSL::TLS1_2_VERSION
    http.open_timeout = 5
    http.read_timeout = 10
    http.write_timeout = 5
    http.max_retries = 0

    request = Net::HTTP::Get.new(uri.request_uri)
    request["Accept-Encoding"] = "identity"
    body = +""

    http.start do |connection|
      connection.request(request) do |response|
        raise Failure, "official credential archive download did not return HTTP 200" unless response.code == "200"

        response.read_body do |chunk|
          raise Failure, "official credential archive exceeds the safety limit" if body.bytesize + chunk.bytesize > MAX_ARCHIVE_BYTES

          body << chunk
        end
      end
    end

    File.binwrite(path, body)
    FileUtils.chmod(0o600, path)
  end

  def verify_archive!(path)
    actual = Digest::SHA256.file(path).hexdigest
    raise Failure, "official credential archive checksum changed" unless actual == ARCHIVE_SHA256

    stdout, _stderr, status = Open3.capture3("unzip", "-Z1", path)
    raise Failure, "could not inspect the official credential archive" unless status.success?

    entries = stdout.lines(chomp: true)
    unless entries.sort == EXPECTED_ARCHIVE_FILES.sort && entries.all? { |entry| File.basename(entry) == entry }
      raise Failure, "official credential archive has an unexpected file manifest"
    end
  end

  def extract_archive!(archive_path, destination)
    FileUtils.mkdir(destination, mode: 0o700)
    _stdout, _stderr, status = Open3.capture3("unzip", "-qq", archive_path, "-d", destination)
    raise Failure, "could not extract the verified official credential archive" unless status.success?

    EXPECTED_ARCHIVE_FILES.each do |entry|
      path = File.join(destination, entry)
      raise Failure, "verified credential archive extraction is incomplete" unless File.file?(path) && !File.symlink?(path)

      FileUtils.chmod(0o600, path)
    end
  end

  def load_credentials(directory, password)
    IDENTITIES.to_h do |taxpayer_eic, _evidence_unit_id|
      filename = "CA_EET-Playground-#{taxpayer_eic}.p12"
      credential = Eet2::Credential.from_pkcs12(
        bytes: File.binread(File.join(directory, filename)),
        password: password,
        legacy_provider: :explicitly_allowed
      )
      common_name = credential.certificate.subject.to_a.find { |name, _value, _type| name == "CN" }&.fetch(1)
      raise Failure, "official credential identity does not match its filename" unless common_name == taxpayer_eic

      [taxpayer_eic, credential]
    end
  end

  def build_client(credential)
    Eet2::Client.playground(
      credential: credential,
      open_timeout: 5,
      read_timeout: 10,
      write_timeout: 5
    )
  end

  def run_verification_mode(client)
    prepared = client.prepare(
      sale: build_sale("CZ00000019", IDENTITIES.fetch("CZ00000019"), "verify"),
      first_submission: true,
      verification_mode: true
    )
    result = client.transmit(prepared)
    assert_unsigned_error!(result, scenario: "verification_mode", expected_code: 0)
    error_evidence("verification_mode", prepared, result)
  end

  def run_accepted(client, taxpayer_eic, evidence_unit_id)
    sale = build_sale(taxpayer_eic, evidence_unit_id, "sale")
    prepared = client.prepare(sale: sale, first_submission: true)
    result = client.transmit(prepared)
    assert_verified_receipt!(result, scenario: "accepted_#{taxpayer_eic}")
    [sale, receipt_evidence("accepted_#{taxpayer_eic}", taxpayer_eic, prepared, result)]
  end

  def run_retry(client, sale)
    prepared = client.prepare(sale: sale, first_submission: false)
    result = client.transmit(prepared)
    assert_verified_receipt!(result, scenario: "retry_same_sale")
    receipt_evidence("retry_same_sale", sale.taxpayer_eic, prepared, result)
  end

  def run_invalid_xsd(client)
    prepared = client.prepare(
      sale: build_sale("CZ00000019", IDENTITIES.fetch("CZ00000019"), "xsd"),
      first_submission: true
    )
    mutated_xml = prepared.xml.sub(/celk_trzba="[^"]+"/, 'celk_trzba="invalid"')
    raise Failure, "could not build the invalid-XSD live case" if mutated_xml == prepared.xml

    mutated = prepared.with(xml: mutated_xml, request_sha256: Digest::SHA256.hexdigest(mutated_xml))
    result = transmit_unsafe_negative_case(mutated)
    assert_unsigned_error!(result, scenario: "invalid_xsd", expected_code: 3)
    error_evidence("invalid_xsd", mutated, result)
  end

  def run_invalid_signature(client)
    prepared = client.prepare(
      sale: build_sale("CZ00000019", IDENTITIES.fetch("CZ00000019"), "signature"),
      first_submission: true
    )
    mutated_xml = prepared.xml.sub(/(<ds:SignatureValue>)([A-Za-z0-9+\/])/) do
      replacement = (Regexp.last_match(2) == "A") ? "B" : "A"
      "#{Regexp.last_match(1)}#{replacement}"
    end
    raise Failure, "could not build the invalid-signature live case" if mutated_xml == prepared.xml

    mutated = prepared.with(xml: mutated_xml, request_sha256: Digest::SHA256.hexdigest(mutated_xml))
    result = transmit_unsafe_negative_case(mutated)
    assert_unsigned_error!(result, scenario: "invalid_signature", expected_code: 4)
    error_evidence("invalid_signature", mutated, result)
  end

  # Negative interoperability cases intentionally bypass Client#transmit because
  # the public client rejects corrupted PreparedRequest integrity before network I/O.
  def transmit_unsafe_negative_case(prepared)
    transport_result = Eet2::NetHttpTransport.playground(
      open_timeout: 5,
      read_timeout: 10,
      write_timeout: 5
    ).call(prepared)
    unless transport_result.is_a?(Eet2::Transport::HttpResponse) && transport_result.status == 200
      raise Failure, "negative protocol case did not receive HTTP 200"
    end

    Eet2::Contracts::V4_1::ResponseParser.new.call(
      xml: transport_result.body,
      expected_request_uuid: prepared.request_uuid
    ).with(support_id: transport_result.support_id)
  end

  def build_sale(taxpayer_eic, evidence_unit_id, label)
    Eet2::Sale.new(
      taxpayer_eic: taxpayer_eic,
      evidence_unit_id: evidence_unit_id,
      register_id: "ruby-eet2-e2e",
      sequence_number: unique_sequence(label),
      occurred_at: Time.now.floor,
      amount_czk: BigDecimal("1.00")
    )
  end

  def unique_sequence(label)
    prefix = label.delete("^a-z")[0, 4]
    "#{prefix}-#{Time.now.to_i}-#{SecureRandom.hex(3)}"
  end

  def assert_verified_receipt!(result, scenario:)
    unless result.is_a?(Eet2::Response::VerifiedReceipt) && result.accepted? && result.authenticated?
      raise Failure, "#{scenario} did not return a verified receipt"
    end
    raise Failure, "#{scenario} returned an invalid Playground POK marker" unless result.test && result.pok.end_with?("-ff")
  end

  def assert_unsigned_error!(result, scenario:, expected_code:)
    unless result.is_a?(Eet2::Response::UnsignedError) && !result.accepted? && !result.authenticated?
      raise Failure, "#{scenario} did not return a documented unsigned error"
    end
    raise Failure, "#{scenario} returned an unexpected error code" unless result.code == expected_code
  end

  def receipt_evidence(scenario, taxpayer_eic, prepared, result)
    {
      scenario: scenario,
      taxpayer_eic: taxpayer_eic,
      outcome: "verified_receipt",
      authenticated: result.authenticated?,
      request_uuid_prefix: prepared.request_uuid[0, 8],
      first_submission: prepared.first_submission,
      pok_suffix: result.pok[-3, 3],
      warning_codes: result.warnings.map(&:code),
      response_sha256: result.response_sha256,
      response_certificate_sha256: result.signature_evidence.certificate_sha256,
      trust_policy_revision: result.signature_evidence.trust_policy_revision,
      support_id: result.support_id
    }
  end

  def error_evidence(scenario, prepared, result)
    {
      scenario: scenario,
      outcome: "unsigned_error",
      authenticated: result.authenticated?,
      request_uuid_prefix: prepared.request_uuid[0, 8],
      error_code: result.code,
      warning_codes: result.warnings.map(&:code),
      response_sha256: result.response_sha256,
      support_id: result.support_id
    }
  end
end
