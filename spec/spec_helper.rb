require 'coveralls'
Coveralls.wear!
ENV['COVERALLS_NOISY'] = '1'
require 'webmock/rspec'
require 'ssrf_filter'

def allow_net_connections_for_context(context)
  context.before :all do
    WebMock.allow_net_connect!
  end

  context.after :all do
    WebMock.disable_net_connect!
  end
end

Object.class_eval do
  def self.make_all_class_methods_public!
    private_methods.each(&method(:public_class_method))
    protected_methods.each(&method(:public_class_method))
  end
end
