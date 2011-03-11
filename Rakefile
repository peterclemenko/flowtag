require 'rubygems'
require 'bundler'
begin
  Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
  $stderr.puts e.message
  $stderr.puts "Run `bundle install` to install missing gems"
  exit e.status_code
end
require 'rake'

require 'jeweler'
Jeweler::Tasks.new do |gem|
  # gem is a Gem::Specification... see http://docs.rubygems.org/read/chapter/20 for more options
  gem.name = "flowtag"
  gem.homepage = "https://rubygems.org/gems/flowtag"
  gem.license = "MIT"
  gem.summary = %Q{FlowTag visualizes pcap files for forensic analysis}
  gem.description = %Q{presents the user with a GUI interface to visualize and explore flows found from a given pcap file}
  gem.email = "rubygems@chrislee.dhs.org"
  gem.authors = ["Chris Lee"]
  # Include your dependencies below. Runtime dependencies are required when using your gem,
  # and development dependencies are only needed for development (ie running rake tasks, tests, etc)
  gem.signing_key = "#{ENV['HOME']}/bin/ruby/rubygems/gem-private_key.pem"
  gem.cert_chain  = ["#{ENV['HOME']}/bin/ruby/rubygems/gem-public_cert.pem"]
  gem.files = FileList["{bin,lib}/**/*"].to_a
  gem.add_runtime_dependency "tk-double-slider", ">= 0.1.0"
  gem.add_runtime_dependency "tk-parallel-coordinates", ">= 0.1.0"
  gem.executables = ["flowtag","ftlistflows","ftpcap2flowdb","ftprintflow"]
end
Jeweler::RubygemsDotOrgTasks.new

require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/**/test_*.rb'
  test.verbose = true
end

require 'rcov/rcovtask'
Rcov::RcovTask.new do |test|
  test.libs << 'test'
  test.pattern = 'test/**/test_*.rb'
  test.verbose = true
end

task :default => :test

require 'rake/rdoctask'
Rake::RDocTask.new do |rdoc|
  version = File.exist?('VERSION') ? File.read('VERSION') : ""

  rdoc.rdoc_dir = 'rdoc'
  rdoc.title = "flowtag #{version}"
  rdoc.rdoc_files.include('README*')
  rdoc.rdoc_files.include('lib/**/*.rb')
end
