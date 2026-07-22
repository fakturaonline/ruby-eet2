# frozen_string_literal: true

require "open3"
require "yaml"

RSpec.describe "gem package" do
  let(:specification) { Gem::Specification.load(PROJECT_ROOT.join("ruby-eet2-cz.gemspec").to_s) }

  it "contains only allowlisted public files and loads after an isolated install" do
    stdout, stderr, status = Open3.capture3(Gem.ruby, PROJECT_ROOT.join("script/verify_package").to_s)

    expect(status).to be_success, stderr
    expect(stdout).to include("Verified package allowlist")
    expect(stdout).to include("5 official runtime artifacts")
  end

  it "declares every directly required extracted/default gem with reviewed bounds" do
    expected = %w[base64 bigdecimal digest net-http nokogiri openssl securerandom time uri]
    dependencies = specification.runtime_dependencies.to_h { |dependency| [dependency.name, dependency] }

    expect(dependencies.keys.sort).to eq(expected.sort)
    dependencies.each_value do |dependency|
      requirements = dependency.requirement.requirements

      expect(requirements).to include(satisfy { |operator, _version| %w[>= > ~> =].include?(operator) })
      expect(requirements).to include(satisfy { |operator, _version| %w[< <= ~> =].include?(operator) })
    end
  end

  it "installs on the exact FakturaOnline Ruby patch while rejecting older 3.2 releases" do
    requirement = specification.required_ruby_version

    expect(requirement).to be_satisfied_by(Gem::Version.new("3.2.2"))
    expect(requirement).not_to be_satisfied_by(Gem::Version.new("3.2.1"))
  end

  it "publishes only the authorized GitHub project identity" do
    repository = "https://github.com/fakturaonline/ruby-eet2"

    expect(specification.homepage).to eq(repository)
    expect(specification.metadata).to include(
      "homepage_uri" => repository,
      "source_code_uri" => repository,
      "bug_tracker_uri" => "#{repository}/issues",
      "changelog_uri" => "#{repository}/blob/main/CHANGELOG.md",
      "rubygems_mfa_required" => "true"
    )
  end

  it "pins every CI action by commit and bounds every CI job runtime" do
    workflow_paths = PROJECT_ROOT.join(".github/workflows").glob("*.yml")

    workflow_paths.each do |path|
      content = path.read
      action_references = content.scan(/^\s*- uses: (\S+)/).flatten

      expect(action_references).to all(match(/\A[^@\s]+@[0-9a-f]{40}\z/)), path.to_s

      workflow = YAML.safe_load_file(path, permitted_classes: [], aliases: false)
      workflow.fetch("jobs").each_value do |job|
        expect(job.fetch("timeout-minutes")).to be_between(1, 30), path.to_s
      end
    end
  end
end
