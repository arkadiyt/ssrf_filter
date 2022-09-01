# frozen_string_literal: true

require 'pry-byebug'
require 'simplecov'
require 'simplecov-lcov'
SimpleCov.start do
  SimpleCov::Formatter::LcovFormatter.config do |c|
    c.report_with_single_file = true
    c.single_report_path = 'coverage/lcov.info'
  end

  SimpleCov.formatters = SimpleCov::Formatter::MultiFormatter.new([
    SimpleCov::Formatter::HTMLFormatter,
    SimpleCov::Formatter::LcovFormatter
  ])
  add_filter %w[spec]
end
require 'webmock/rspec'
require 'ssrf_filter'

def allow_net_connections_for_context(context)
  context.before :all do
    WebMock.disable!
  end

  context.after :all do
    WebMock.enable!
  end
end

Object.class_eval do
  def self.make_all_class_methods_public!
    private_methods.each(&method(:public_class_method))
    protected_methods.each(&method(:public_class_method))
  end
end
