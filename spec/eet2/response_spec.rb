# frozen_string_literal: true

RSpec.describe Eet2::Response do
  let(:warning) { described_class::Warning.new(code: 1, message: "Clock differs") }
  let(:evidence) do
    described_class::SignatureEvidence.new(
      certificate_sha256: "a" * 64,
      chain_sha256: ["a" * 64, "b" * 64, "c" * 64],
      trust_policy_revision: "playground-2026-07-21"
    )
  end

  it "marks verified receipts as accepted and authenticated" do
    receipt = described_class::VerifiedReceipt.new(
      request_uuid: "123e4567-e89b-42d3-a456-426614174000",
      received_at: Time.utc(2027, 1, 3),
      pok: "123e4567-e89b-42d3-a456-426614174000-ff",
      test: true,
      warnings: [warning],
      response_sha256: "d" * 64,
      signature_evidence: evidence
    )

    expect(receipt).to be_authenticated
    expect(receipt).to be_accepted
    expect(receipt.warnings).to be_frozen
    expect(receipt.signature_evidence.chain_sha256).to be_frozen
  end

  it "makes the lack of authentication explicit on documented unsigned errors" do
    error = described_class::UnsignedError.new(
      request_uuid: nil,
      rejected_at: nil,
      code: -1,
      message: "Temporary technical error",
      test: true,
      warnings: [],
      response_sha256: "e" * 64
    )

    expect(error).not_to be_authenticated
    expect(error).not_to be_accepted
    expect(error.message).to be_frozen
  end

  it "validates warning codes and freezes messages" do
    expect(warning.message).to be_frozen
    expect { described_class::Warning.new(code: 0, message: "invalid") }.to raise_error(Eet2::MalformedResponse, /1 to 999/)
    expect { described_class::Warning.new(code: 1, message: nil) }.to raise_error(Eet2::MalformedResponse, /String/)
  end

  it "makes transport and invalid-response outcomes immutable and explicitly unauthenticated" do
    failure = described_class::TransportFailure.new(
      certainty: :possibly_sent,
      kind: :http_status,
      http_status: 503,
      support_id: "trace-503"
    )
    invalid = described_class::InvalidResponse.new(
      reason: :signature_verification,
      response_sha256: "a" * 64,
      http_status: 200,
      support_id: "trace-invalid"
    )

    expect(failure).not_to be_accepted
    expect(failure).not_to be_authenticated
    expect(invalid).not_to be_accepted
    expect(invalid).not_to be_authenticated
    expect(failure.support_id).to be_frozen
    expect(invalid.response_sha256).to be_frozen
  end

  it "rejects inconsistent public failure and invalid-response values" do
    expect do
      described_class::TransportFailure.new(certainty: :not_sent, kind: :http_status, http_status: nil, support_id: nil)
    end.to raise_error(Eet2::TransportConfigurationError, /http_status/)
    expect do
      described_class::TransportFailure.new(certainty: :unknown, kind: :dns, http_status: 500, support_id: nil)
    end.to raise_error(Eet2::TransportConfigurationError, /http_status/)
    expect do
      described_class::InvalidResponse.new(reason: :other, response_sha256: "a" * 64, http_status: 200, support_id: nil)
    end.to raise_error(Eet2::TransportConfigurationError, /reason/)
    expect do
      described_class::InvalidResponse.new(reason: :correlation, response_sha256: "A" * 64, http_status: 200, support_id: nil)
    end.to raise_error(Eet2::TransportConfigurationError, /SHA-256/)
    expect do
      described_class::InvalidResponse.new(reason: :correlation, response_sha256: "a" * 64, http_status: nil, support_id: nil)
    end.to raise_error(Eet2::TransportConfigurationError, /http_status/)
  end
end
