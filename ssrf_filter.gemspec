# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path('lib', __dir__)
require 'ssrf_filter/version'

Gem::Specification.new do |gem|
  gem.name        = 'ssrf_filter'
  gem.platform    = Gem::Platform::RUBY
  gem.version     = SsrfFilter::VERSION
  gem.authors     = ['Arkadiy Tetelman']
  gem.required_ruby_version = '>= 2.0.0'
  gem.summary     = 'A gem that makes it easy to prevent server side request forgery (SSRF) attacks'
  gem.description = gem.summary
  gem.homepage    = 'https://github.com/arkadiyt/ssrf_filter'
  gem.license     = 'MIT'
  gem.files       = Dir['lib/**/*.rb']
  gem.metadata    = {'rubygems_mfa_required' => 'true'}

  gem.add_development_dependency('bundler-audit', '~> 0.9.1')
  gem.add_development_dependency('coveralls', '~> 0.8.23')
  gem.add_development_dependency('rspec', '~> 3.11.0')
  gem.add_development_dependency('rubocop', '~> 0.65.0')
  gem.add_development_dependency('webmock', '>= 3.14.0')
  gem.add_development_dependency('webrick')
end
