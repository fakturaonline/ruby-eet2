# frozen_string_literal: true

require PROJECT_ROOT.join("examples/playground").to_s

RSpec.describe Eet2PlaygroundExample do
  it "executes the documented preparation flow with an injected transport and no network" do
    calls = []
    transport = lambda do |prepared_request|
      calls << prepared_request
      Eet2::Transport::Failure.new(certainty: :not_sent, kind: :connect_timeout)
    end
    client = described_class.build_client(credential: SpecSupport.credential, transport: transport)
    sale = described_class.build_sale(
      sequence_number: "docs-example-1",
      occurred_at: Time.new(2027, 1, 3, 12, 30, 45, "+01:00")
    )

    prepared = client.prepare(sale: sale, first_submission: true)
    result = client.transmit(prepared)

    expect(calls).to eq([prepared])
    expect(result).to be_a(Eet2::Response::TransportFailure)
    expect(described_class.summarize(result)).to include("certainty=not_sent")
  end

  it "safely summarizes every documented outcome without raw XML" do
    evidence = Eet2::Response::SignatureEvidence.new(
      certificate_sha256: "a" * 64,
      chain_sha256: ["b" * 64],
      trust_policy_revision: "test"
    )
    values = [
      Eet2::Response::VerifiedReceipt.new(
        request_uuid: "123e4567-e89b-42d3-a456-426614174000",
        received_at: Time.utc(2027),
        pok: "123e4567-e89b-42d3-a456-426614174000-ff",
        test: true,
        warnings: [],
        response_sha256: "c" * 64,
        signature_evidence: evidence,
        support_id: nil
      ),
      Eet2::Response::UnsignedError.new(
        request_uuid: nil,
        rejected_at: nil,
        code: -1,
        message: "temporary",
        test: true,
        warnings: [],
        response_sha256: "d" * 64,
        support_id: "trace-error"
      ),
      Eet2::Response::InvalidResponse.new(
        reason: :correlation,
        response_sha256: "e" * 64,
        http_status: 200,
        support_id: nil
      ),
      Eet2::Response::TransportFailure.new(
        certainty: :possibly_sent,
        kind: :http_status,
        http_status: 503,
        support_id: "trace-http"
      )
    ]

    summaries = values.map { |value| described_class.summarize(value) }

    expect(summaries).to all(be_a(String))
    expect(summaries.join(" ")).not_to include("<soap")
    expect { described_class.summarize(Object.new) }.to raise_error(RuntimeError, /unexpected EET2 result/)
  end

  it "passes the repository documentation verifier" do
    expect(system(Gem.ruby, PROJECT_ROOT.join("script/verify_docs").to_s)).to be(true)
  end

  it "documents the irreversible process boundary of legacy credential import" do
    credential_api = PROJECT_ROOT.join("docs/api.md").read
    e2e_guide = PROJECT_ROOT.join("docs/e2e.md").read

    expect(credential_api).to include("process lifetime")
    expect(credential_api).to include("cannot guarantee\nzeroization")
    expect(credential_api).to include("short-lived isolated process")
    expect(e2e_guide).to include("process lifetime")
    expect(e2e_guide).to include("cannot guarantee zeroization")
    expect(e2e_guide).to include("short-lived isolated repackaging process")
  end
end
