# frozen_string_literal: true

require "open3"

RSpec.describe Eet2 do
  it "loads without activating the OpenSSL legacy provider" do
    command = <<~RUBY
      require "eet2"
      abort "wrong version" unless Eet2::VERSION == "0.1.0"
      abort "OpenSSL loaded eagerly" if defined?(OpenSSL)
    RUBY
    _stdout, stderr, status = Open3.capture3(Gem.ruby, "-I", PROJECT_ROOT.join("lib").to_s, "-e", command)

    expect(status).to be_success, stderr
  end
end
