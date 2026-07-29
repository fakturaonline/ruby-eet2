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

  it "bounds and freezes the retained exchange evidence for any HTTP status" do
    body = "<fault>" + ("x" * (described_class::EXCHANGE_EVIDENCE_MAX_HEAD_BYTES * 4))
    response = Eet2::Transport::HttpResponse.new(status: 500, headers: {}, body: body)

    evidence = described_class::ExchangeEvidence.from_http_response(response)

    expect(evidence.http_status).to eq(500)
    expect(evidence.response_sha256).to eq(Digest::SHA256.hexdigest(body))
    expect(evidence.response_bytesize).to eq(body.bytesize)
    expect(evidence.response_body_head.bytesize).to eq(described_class::EXCHANGE_EVIDENCE_MAX_HEAD_BYTES)
    expect(evidence.response_body_head).to start_with("<fault>")
    expect(evidence.response_body_head).to be_frozen
    expect(evidence.response_body_head.encoding).to eq(Encoding::BINARY)
    expect(evidence).to be_truncated
    expect(evidence).to be_frozen
  end

  it "keeps a short body whole and reports it as untruncated" do
    response = Eet2::Transport::HttpResponse.new(status: 200, headers: {}, body: "<x/>")

    evidence = described_class::ExchangeEvidence.from_http_response(response)

    expect(evidence.response_body_head).to eq("<x/>")
    expect(evidence).not_to be_truncated
  end

  it "rejects exchange evidence that is not an observed HTTP response" do
    expect do
      described_class::ExchangeEvidence.from_http_response("<x/>")
    end.to raise_error(Eet2::TransportConfigurationError, /HttpResponse/)
    expect do
      described_class::ExchangeEvidence.new(http_status: 99, response_sha256: "a" * 64, response_bytesize: 0, response_body_head: "")
    end.to raise_error(Eet2::TransportConfigurationError, /http_status/)
    expect do
      described_class::ExchangeEvidence.new(http_status: 200, response_sha256: "A" * 64, response_bytesize: 0, response_body_head: "")
    end.to raise_error(Eet2::TransportConfigurationError, /SHA-256/)
    expect do
      described_class::ExchangeEvidence.new(http_status: 200, response_sha256: "a" * 64, response_bytesize: -1, response_body_head: "")
    end.to raise_error(Eet2::TransportConfigurationError, /response_bytesize/)
    expect do
      described_class::ExchangeEvidence.new(http_status: 200, response_sha256: "a" * 64, response_bytesize: 4, response_body_head: nil)
    end.to raise_error(Eet2::TransportConfigurationError, /response_body_head must be a String/)
    expect do
      described_class::ExchangeEvidence.new(
        http_status: 200,
        response_sha256: "a" * 64,
        response_bytesize: 1_000_000,
        response_body_head: "y" * (described_class::EXCHANGE_EVIDENCE_MAX_HEAD_BYTES + 1)
      )
    end.to raise_error(Eet2::TransportConfigurationError, /must not exceed 4096 bytes/)
    expect do
      described_class::ExchangeEvidence.new(http_status: 200, response_sha256: "a" * 64, response_bytesize: 1, response_body_head: "ab")
    end.to raise_error(Eet2::TransportConfigurationError, /response_bytesize/)
  end

  it "refuses exchange evidence that contradicts the result it is attached to" do
    evidence = described_class::ExchangeEvidence.from_http_response(
      Eet2::Transport::HttpResponse.new(status: 503, headers: {}, body: "<html/>")
    )

    expect do
      described_class::TransportFailure.new(certainty: :possibly_sent, kind: :http_status, http_status: 500, support_id: nil, exchange_evidence: evidence)
    end.to raise_error(Eet2::TransportConfigurationError, /exchange_evidence http_status/)
    expect do
      described_class::InvalidResponse.new(reason: :correlation, response_sha256: "a" * 64, http_status: 503, support_id: nil, exchange_evidence: evidence)
    end.to raise_error(Eet2::TransportConfigurationError, /same response/)
    expect do
      described_class::InvalidResponse.new(reason: :correlation, response_sha256: "a" * 64, http_status: 200, support_id: nil, exchange_evidence: Object.new)
    end.to raise_error(Eet2::TransportConfigurationError, /ExchangeEvidence/)
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
