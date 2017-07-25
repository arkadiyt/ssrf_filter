require 'ipaddr'
require 'net/http'
require 'resolv'
require 'uri'

class SsrfFilter
  # https://en.wikipedia.org/wiki/Reserved_IP_addresses
  IPV4_BLACKLIST = [
    ::IPAddr.new('0.0.0.0/8'), # Current network (only valid as source address)
    ::IPAddr.new('10.0.0.0/8'), # Private network
    ::IPAddr.new('100.64.0.0/10'), # Shared Address Space
    ::IPAddr.new('127.0.0.0/8'), # Loopback
    ::IPAddr.new('169.254.0.0/16'), # Link-local
    ::IPAddr.new('172.16.0.0/12'), # Private network
    ::IPAddr.new('192.0.0.0/24'), # IETF Protocol Assignments
    ::IPAddr.new('192.0.2.0/24'), # TEST-NET-1, documentation and examples
    ::IPAddr.new('192.88.99.0/24'), # IPv6 to IPv4 relay (includes 2002::/16)
    ::IPAddr.new('192.168.0.0/16'), # Private network
    ::IPAddr.new('198.18.0.0/15'), # Network benchmark tests
    ::IPAddr.new('198.51.100.0/24'), # TEST-NET-2, documentation and examples
    ::IPAddr.new('203.0.113.0/24'), # TEST-NET-3, documentation and examples
    ::IPAddr.new('224.0.0.0/4'), # IP multicast (former Class D network)
    ::IPAddr.new('240.0.0.0/4'), # Reserved (former Class E network)
    ::IPAddr.new('255.255.255.255') # Broadcast
  ].freeze

  IPV6_BLACKLIST = [
    ::IPAddr.new('::1/128'), # Loopback
    ::IPAddr.new('64:ff9b::/96'), # IPv4/IPv6 translation (RFC 6052)
    ::IPAddr.new('100::/64'), # Discard prefix (RFC 6666)
    ::IPAddr.new('2001::/32'), # Teredo tunneling
    ::IPAddr.new('2001:10::/28'), # Deprecated (previously ORCHID)
    ::IPAddr.new('2001:20::/28'), # ORCHIDv2
    ::IPAddr.new('2001:db8::/32'), # Addresses used in documentation and example source code
    ::IPAddr.new('2002::/16'), # 6to4
    ::IPAddr.new('fc00::/7'), # Unique local address
    ::IPAddr.new('fe80::/10'), # Link-local address
    ::IPAddr.new('ff00::/8'), # Multicast
  ].freeze

  DEFAULT_SCHEME_WHITELIST = %w[http https].freeze

  DEFAULT_RESOLVER = proc do |hostname|
    ::Resolv.getaddresses(hostname).map { |ip| ::IPAddr.new(ip) }
  end

  DEFAULT_MAX_REDIRECTS = 10

  VERB_MAP = {
    get: ::Net::HTTP::Get,
    put: ::Net::HTTP::Put,
    post: ::Net::HTTP::Post,
    delete: ::Net::HTTP::Delete
  }.freeze

  FIBER_LOCAL_KEY = :__ssrf_filter_hostname

  class Error < ::StandardError
  end

  class InvalidUriScheme < Error
  end

  class PrivateIPAddress < Error
  end

  class UnresolvedHostname < Error
  end

  class TooManyRedirects < Error
  end

  %i[get put post delete].each do |method|
    define_singleton_method(method) do |url, options = {}, &block|
      original_url = url
      scheme_whitelist = options[:scheme_whitelist] || DEFAULT_SCHEME_WHITELIST
      resolver = options[:resolver] || DEFAULT_RESOLVER
      max_redirects = options[:max_redirects] || DEFAULT_MAX_REDIRECTS
      url = url.to_s

      (max_redirects + 1).times do
        uri = URI(url)

        unless scheme_whitelist.include?(uri.scheme)
          raise InvalidUriScheme, "URI scheme '#{uri.scheme}' not in whitelist: #{scheme_whitelist}"
        end

        hostname = uri.hostname
        ip_addresses = resolver.call(hostname)
        raise UnresolvedHostname, "Could not resolve hostname '#{hostname}'" if ip_addresses.empty?

        public_addresses = ip_addresses.reject(&method(:unsafe_ip_address?))
        raise PrivateIPAddress, "Hostname '#{hostname}' has no public ip addresses" if public_addresses.empty?

        response = fetch_once(uri, public_addresses.sample.to_s, method, options, &block)

        case response
        when ::Net::HTTPRedirection then
          url = response['location']
        else
          return response
        end
      end

      raise TooManyRedirects, "Got #{max_redirects} redirects fetching #{original_url}"
    end
  end

  def self.unsafe_ip_address?(ip_address)
    return true if ipaddr_has_mask?(ip_address)

    return IPV4_BLACKLIST.any? { |range| range.include?(ip_address) } if ip_address.ipv4?

    if ip_address.ipv6?
      result = IPV6_BLACKLIST.any? { |range| range.include?(ip_address) }
      # TODO: convert these to be members of IPV6_BLACKLIST
      result ||= ip_address.ipv4_compat? && IPV4_BLACKLIST.any? { |range| range.include?(ip_address.ipv4_compat) }
      result ||= ip_address.ipv4_mapped? && IPV4_BLACKLIST.any? { |range| range.include?(ip_address.ipv4_mapped) }
      return result
    end

    true
  end
  private_class_method :unsafe_ip_address?

  def self.ipaddr_has_mask?(ipaddr)
    range = ipaddr.to_range
    range.first != range.last
  end
  private_class_method :ipaddr_has_mask?

  def self.fetch_once(uri, ip, verb, options, &block)
    if options[:params]
      params = uri.query ? ::Hash[::URI.decode_www_form(uri.query)] : {}
      params.merge!(options[:params])
      uri.query = ::URI.encode_www_form(params)
    end

    hostname = uri.hostname
    uri.hostname = ip

    request = VERB_MAP[verb].new(uri)
    request['host'] = hostname

    Array(options[:headers]).each do |header, value|
      request[header] = value
    end

    request.body = options[:body] if options[:body]

    block.call(request) if block_given?

    use_ssl = uri.scheme == 'https'
    with_forced_hostname(hostname) do
      ::Net::HTTP.start(uri.hostname, uri.port, use_ssl: use_ssl) do |http|
        http.request(request)
      end
    end
  end
  private_class_method :fetch_once

  def self.patch_ssl_socket!
    return if instance_variable_defined?(:@patched_ssl_socket)

    # What we'd like to do is have the following workflow:
    # 1) resolve the hostname www.example.com, and choose a public ip address to connect to
    # 2) connect to that specific ip address, to prevent things like DNS TOCTTOU bugs or other trickery
    #
    # Ideally this would happen by the ruby http library giving us control over DNS resolution,
    # but it doesn't. Instead, when making the request we set the uri.hostname to the chosen ip address,
    # and send a 'Host' header of the original hostname, i.e. connect to 'http://93.184.216.34/' and send
    # a 'Host: www.example.com' header.
    #
    # This works for the http case, http://www.example.com. For the https case, this causes certificate
    # validation failures, since the server certificate does not have a Subject Alternate Name for 93.184.216.34.
    #
    # Thus we perform the monkey-patch below, modifying SSLSocket's `post_connection_check(hostname)`
    # and `hostname=(hostname)` methods:
    # If our fiber local variable is set, use that for the hostname instead, otherwise behave as usual.
    # The only time the variable will be set is if you are executing inside a `with_forced_hostname` block,
    # which is used above.
    #
    # An alternative approach could be to pass in our own OpenSSL::X509::Store with a custom
    # `verify_callback` to the ::Net::HTTP.start call, but this would require reimplementing certification
    # validation, which is dangerous. This way we can piggyback on the existing validation and simply pretend
    # that we connected to the desired hostname.

    ::OpenSSL::SSL::SSLSocket.class_eval do
      original_post_connection_check = instance_method(:post_connection_check)
      define_method(:post_connection_check) do |hostname|
        original_post_connection_check.bind(self).call(::Thread.current[FIBER_LOCAL_KEY] || hostname)
      end

      if method_defined?(:hostname=)
        original_hostname = instance_method(:hostname=)
        define_method(:hostname=) do |hostname|
          original_hostname.bind(self).call(::Thread.current[FIBER_LOCAL_KEY] || hostname)
        end
      end
    end

    @patched_ssl_socket = true
  end
  private_class_method :patch_ssl_socket!

  def self.with_forced_hostname(hostname, &_block)
    patch_ssl_socket!
    ::Thread.current[FIBER_LOCAL_KEY] = hostname
    yield
  ensure
    ::Thread.current[FIBER_LOCAL_KEY] = nil
  end
  private_class_method :with_forced_hostname
end
