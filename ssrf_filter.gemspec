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

  major, minor = RUBY_VERSION.scan(/\A(\d+)\.(\d+)\.\d+\Z/).first.map(&:to_i)

  gem.add_development_dependency('bundler-audit', '~> 0.6.1')
  gem.add_development_dependency('coveralls', '~> 0.8.22')
  gem.add_development_dependency('rspec', '~> 3.8.0')
  gem.add_development_dependency('webmock', '>= 3.5.1')
  gem.add_development_dependency('webrick') if major >= 3

  if minor > 1
    gem.add_development_dependency('rubocop', '~> 0.65.0')
  elsif minor == 1
    gem.add_development_dependency('rubocop', '~> 0.57.2')
  else
    # ssrf_filter doesn't use public_suffix directly, it's required by `addressable` which is required
    # by `webmock`. We need to set this requirement here to pin a version that is compatible with ruby 2.0
    gem.add_development_dependency('public_suffix', '2.0.5')
    gem.add_development_dependency('rubocop', '~> 0.50.0')
  end
end
