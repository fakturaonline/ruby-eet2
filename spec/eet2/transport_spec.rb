# frozen_string_literal: true

RSpec.describe Eet2::Transport do
  describe Eet2::Transport::HttpResponse do
    it "normalizes and freezes headers while preserving a safe support ID" do
      response = described_class.new(
        status: 200,
        headers: {"X-Global-Transaction-ID" => "trace-123", "CONTENT-TYPE" => "text/xml"},
        body: "<ok/>"
      )

      expect(response.headers).to eq(
        "x-global-transaction-id" => "trace-123",
        "content-type" => "text/xml"
      )
      expect(response.support_id).to eq("trace-123")
      expect(response.headers).to be_frozen
      expect(response.body).to be_frozen
    end

    it "does not expose unsafe support IDs" do
      newline = described_class.new(status: 500, headers: {"X-Global-Transaction-ID" => "trace\nforged"}, body: "")
      oversized = described_class.new(status: 500, headers: {"X-Global-Transaction-ID" => "x" * 129}, body: "")

      expect(newline.support_id).to be_nil
      expect(oversized.support_id).to be_nil
    end

    it "rejects invalid HTTP response values" do
      expect { described_class.new(status: 99, headers: {}, body: "") }.to raise_error(Eet2::TransportConfigurationError)
      expect { described_class.new(status: 200, headers: [], body: "") }.to raise_error(Eet2::TransportConfigurationError)
      expect { described_class.new(status: 200, headers: {1 => "x"}, body: "") }.to raise_error(Eet2::TransportConfigurationError)
      expect { described_class.new(status: 200, headers: {}, body: nil) }.to raise_error(Eet2::TransportConfigurationError)
    end
  end

  describe Eet2::Transport::Failure do
    it "accepts only the documented certainty and failure vocabularies" do
      failure = described_class.new(certainty: :not_sent, kind: :dns)

      expect(failure).to eq(described_class.new(certainty: :not_sent, kind: :dns))
      expect { described_class.new(certainty: :certain, kind: :dns) }.to raise_error(Eet2::TransportConfigurationError)
      expect { described_class.new(certainty: :not_sent, kind: :other) }.to raise_error(Eet2::TransportConfigurationError)
    end
  end
end
