# frozen_string_literal: true

require 'resolv'

class SsrfFilter
  module Patch
    module Resolv
      # As described in ssl_socket.rb, we want to patch ruby's http connection code to allow us to make outbound network
      # requests while ensuring that both:
      # 1) we're connecting to a public / non-private ip address
      # 2) https connections continue to work
      #
      # This used to work fine prior to this change in ruby's net/http library:
      # https://github.com/ruby/net-http/pull/36
      # After this changed was introduced our patch no longer works - we need to set the hostname to the correct
      # value on the SSLSocket (`s.hostname = ssl_host_address`), but that code path no longer executes due to the
      # modification in the linked pull request.
      #
      # To work around this we introduce the patch below, which forces our ip address string to not match against the
      # Resolv IPv4/IPv6 regular expressions. This is ugly and cumbersome but I didn't see any better path.
      class PatchedRegexp < Regexp
        def ===(other)
          if ::Thread.current.key?(::SsrfFilter::FIBER_ADDRESS_KEY) &&
             other.object_id.equal?(::Thread.current[::SsrfFilter::FIBER_ADDRESS_KEY].object_id)
            false
          else
            super(other)
          end
        end
      end

      def self.apply!
        return if instance_variable_defined?(:@patched_resolv)

        @patched_resolv = true

        old_ipv4 = ::Resolv::IPv4.send(:remove_const, :Regex)
        old_ipv6 = ::Resolv::IPv6.send(:remove_const, :Regex)
        ::Resolv::IPv4.const_set(:Regex, PatchedRegexp.new(old_ipv4))
        ::Resolv::IPv6.const_set(:Regex, PatchedRegexp.new(old_ipv6))
      end
    end
  end
end
