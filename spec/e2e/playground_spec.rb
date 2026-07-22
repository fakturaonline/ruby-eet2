# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "official EET2 Playground", :live do
  it "passes the sanitized end-to-end scenario matrix" do
    require_relative "support/playground_runner"

    evidence = Eet2PlaygroundE2E.run
    scenarios = evidence.fetch(:scenarios)

    expect(evidence.fetch(:status)).to eq("pass")
    expect(scenarios.map { |item| item.fetch(:scenario) }).to contain_exactly(
      "verification_mode",
      "accepted_CZ00000019",
      "retry_same_sale",
      "accepted_CZ683555118",
      "accepted_CZ8551015704",
      "invalid_xsd",
      "invalid_signature"
    )
    expect(scenarios.count { |item| item[:outcome] == "verified_receipt" }).to eq(4)
    expect(scenarios.count { |item| item[:outcome] == "unsigned_error" }).to eq(3)
    expect(scenarios).to all(satisfy { |item| item[:support_id].is_a?(String) && !item[:support_id].empty? })
  end
end
