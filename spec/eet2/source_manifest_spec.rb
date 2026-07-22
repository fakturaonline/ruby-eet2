# frozen_string_literal: true

require "open3"

RSpec.describe "official source manifest" do
  it "matches every vendored official artifact byte-for-byte" do
    stdout, stderr, status = Open3.capture3(Gem.ruby, PROJECT_ROOT.join("script/verify_source_manifest").to_s)

    expect(status).to be_success, stderr
    expect(stdout).to include("Verified 11 official artifacts")
  end
end
