# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path('lib', __dir__)
require 'ssrf_filter/version'

Gem::Specification.new do |gem|
  gem.name        = 'ssrf_filter'
  gem.platform    = Gem::Platform::RUBY
  gem.version     = SsrfFilter::VERSION
  gem.authors     = ['Arkadiy Tetelman']
  gem.required_ruby_version = '>= 2.7.0'
  gem.summary     = 'A gem that makes it easy to prevent server side request forgery (SSRF) attacks'
  gem.description = gem.summary
  gem.homepage    = 'https://github.com/arkadiyt/ssrf_filter'
  gem.license     = 'MIT'
  gem.files       = Dir['lib/**/*.rb']
  gem.metadata    = {'changelog_uri' => "#{gem.homepage}/blob/main/CHANGELOG.md",
                     'rubygems_mfa_required' => 'true'}

  gem.add_development_dependency('base64', '~> 0.2.0') # For ruby >= 3.4
  gem.add_development_dependency('bundler-audit', '~> 0.9.2')
  gem.add_development_dependency('pry-byebug')
  gem.add_development_dependency('rspec', '~> 3.13.0')
  gem.add_development_dependency('rubocop', '~> 1.68.0')
  gem.add_development_dependency('rubocop-rspec', '~> 3.2.0')
  gem.add_development_dependency('simplecov', '~> 0.22.0')
  gem.add_development_dependency('simplecov-lcov', '~> 0.8.0')
  gem.add_development_dependency('webmock', '>= 3.24.0')
  gem.add_development_dependency('webrick')
end
