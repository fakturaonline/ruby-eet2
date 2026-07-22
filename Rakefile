# frozen_string_literal: true

require "fileutils"
require "rspec/core/rake_task"
require "standard/rake"

RSpec::Core::RakeTask.new(:spec)

desc "Validate RBS signatures"
task :rbs do
  sh "bundle exec rbs validate"
end

namespace :sources do
  desc "Verify vendored official artifacts against the source manifest"
  task :verify do
    ruby "script/verify_source_manifest"
  end
end

namespace :package do
  desc "Build, inspect, install, and require the gem in an isolated directory"
  task :verify do
    ruby "script/verify_package"
  end
end

namespace :docs do
  desc "Verify documentation files, links, secret markers, and example syntax"
  task :verify do
    ruby "script/verify_docs"
  end
end

namespace :xmlsec do
  desc "Cross-check official and Ruby-generated XML signatures with xmlsec1"
  task :verify do
    ruby "script/verify_xmlsec"
  end
end

namespace :e2e do
  desc "Run the opt-in live EET2 Playground matrix with ephemeral public test credentials"
  task :playground do
    ruby "script/e2e_playground"
  end
end

desc "Build the gem into pkg/"
task :build do
  require_relative "lib/eet2/version"

  FileUtils.mkdir_p("pkg")
  sh "gem build ruby-eet2.gemspec --output pkg/ruby-eet2-#{Eet2::VERSION}.gem"
end

task default: ["sources:verify", "docs:verify", :spec, :standard, :rbs, "package:verify", "xmlsec:verify"]
