# frozen_string_literal: true

require 'ipaddr'
require 'net/http'
require 'resolv'
require 'uri'

class SsrfFilter
  private_class_method def self.prefixlen_from_ipaddr(ipaddr)
    mask_addr = ipaddr.instance_variable_get('@mask_addr')
    raise ArgumentError, 'Invalid mask' if mask_addr.zero?

    while mask_addr.nobits?(0x1)
      mask_addr >>= 1
    end

    length = 0
    while mask_addr & 0x1 == 0x1
      length += 1
      mask_addr >>= 1
    end

    length
  end

  private_class_method def self.ipv4_from_rfc6052(ipv6_addr, prefix_len)
    n = ipv6_addr.to_i
    ipv4_int = case prefix_len
    when 32 then (n >> 64) & 0xFFFF_FFFF
    when 40 then (((n >> 64) & 0xFFFFFF) << 8)  | ((n >> 48) & 0xFF)
    when 48 then (((n >> 64) & 0xFFFF)   << 16) | ((n >> 40) & 0xFFFF)
    when 56 then (((n >> 64) & 0xFF)     << 24) | ((n >> 32) & 0xFFFFFF)
    when 64 then (n >> 24) & 0xFFFF_FFFF
    when 96 then n & 0xFFFF_FFFF
    end
    ::IPAddr.new(ipv4_int, Socket::AF_INET) if ipv4_int
  end

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
    ::IPAddr.new('192.168.0.0/16'), # Private network
    ::IPAddr.new('198.18.0.0/15'), # Network benchmark tests
    ::IPAddr.new('198.51.100.0/24'), # TEST-NET-2, documentation and examples
    ::IPAddr.new('203.0.113.0/24'), # TEST-NET-3, documentation and examples
    ::IPAddr.new('224.0.0.0/4'), # IP multicast (former Class D network)
    ::IPAddr.new('240.0.0.0/4'), # Reserved (former Class E network)
    ::IPAddr.new('255.255.255.255') # Broadcast
  ].freeze

  # NAT64 local-use prefix (RFC 8215), uses RFC 6052 /48 encoding (checked at runtime).
  NAT64_LOCAL_PREFIX = ::IPAddr.new('64:ff9b:1::/48').freeze

  IPV6_BLACKLIST = ([
    ::IPAddr.new('::1/128'), # Loopback
    ::IPAddr.new('100::/64'), # Discard prefix (RFC 6666)
    ::IPAddr.new('2001::/32'), # Teredo tunneling
    ::IPAddr.new('2001:10::/28'), # Deprecated (previously ORCHID)
    ::IPAddr.new('2001:20::/28'), # ORCHIDv2
    ::IPAddr.new('2001:db8::/32'), # Addresses used in documentation and example source code
    ::IPAddr.new('2002::/16'), # 6to4
    ::IPAddr.new('fc00::/7'), # Unique local address
    ::IPAddr.new('fe80::/10'), # Link-local address
    ::IPAddr.new('ff00::/8') # Multicast
  ] + IPV4_BLACKLIST.flat_map do |ipaddr|
    prefixlen = prefixlen_from_ipaddr(ipaddr)

    # Don't call ipaddr.ipv4_compat because it prints out a deprecation warning on ruby 2.5+
    ipv4_compatible  = IPAddr.new(ipaddr.to_i, Socket::AF_INET6).mask(96 + prefixlen)
    ipv4_mapped      = ipaddr.ipv4_mapped.mask(80 + prefixlen)
    # IPv4-translated (RFC 2765): ::ffff:0:x.x.x.x/96+n
    ipv4_translated  = IPAddr.new("::ffff:0:#{ipaddr}").mask(96 + prefixlen)
    # NAT64 well-known prefix (RFC 6052): 64:ff9b::x.x.x.x/96+n
    nat64_well_known = IPAddr.new("64:ff9b::#{ipaddr}").mask(96 + prefixlen)

    [ipv4_compatible, ipv4_mapped, ipv4_translated, nat64_well_known]
  end).freeze

  DEFAULT_SCHEME_WHITELIST = %w[http https].freeze

  DEFAULT_RESOLVER = proc do |hostname|
    ::Resolv.getaddresses(hostname).map { |ip| ::IPAddr.new(ip) }
  end

  DEFAULT_ALLOW_UNFOLLOWED_REDIRECTS = false
  DEFAULT_MAX_REDIRECTS = 10
  DEFAULT_SENSITIVE_HEADERS = %w[authorization cookie].freeze
  DEFAULT_ON_CROSS_ORIGIN_REDIRECT = :strip

  VERB_MAP = {
    get: ::Net::HTTP::Get,
    put: ::Net::HTTP::Put,
    post: ::Net::HTTP::Post,
    delete: ::Net::HTTP::Delete,
    head: ::Net::HTTP::Head,
    patch: ::Net::HTTP::Patch
  }.freeze

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

  class CRLFInjection < Error
  end

  class CredentialLeakage < Error
  end

  VERB_MAP.each_key do |method|
    define_singleton_method(method) do |url, options = {}, &block|
      url = url.to_s
      original_url = url
      original_uri = URI(url)
      scheme_whitelist = options.fetch(:scheme_whitelist, DEFAULT_SCHEME_WHITELIST)
      resolver = options.fetch(:resolver, DEFAULT_RESOLVER)
      allow_unfollowed_redirects = options.fetch(:allow_unfollowed_redirects, DEFAULT_ALLOW_UNFOLLOWED_REDIRECTS)
      max_redirects = options.fetch(:max_redirects, DEFAULT_MAX_REDIRECTS)
      sensitive_headers = options.fetch(:sensitive_headers, DEFAULT_SENSITIVE_HEADERS)

      response = nil
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

        headers_to_strip = if !sensitive_headers.empty? && different_origin?(original_uri, uri)
          sensitive_headers
        else
          []
        end

        response, url = fetch_once(uri, public_addresses.sample.to_s, method,
          options.merge(headers_to_strip: headers_to_strip), &block)
        return response if url.nil?
      end

      return response if allow_unfollowed_redirects

      raise TooManyRedirects, "Got #{max_redirects} redirects fetching #{original_url}"
    end
  end

  private_class_method def self.unsafe_ip_address?(ip_address)
    return true if ipaddr_has_mask?(ip_address)

    return IPV4_BLACKLIST.any? { |range| range.include?(ip_address) } if ip_address.ipv4?

    if ip_address.ipv6?
      return true if IPV6_BLACKLIST.any? { |range| range.include?(ip_address) }

      # RFC 6052 /48 encoding for NAT64 local-use prefix (RFC 8215): 64:ff9b:1::/48
      # IPv4 is split around u-bits at positions 64-71, so must be decoded at runtime
      if NAT64_LOCAL_PREFIX.dup.include?(ip_address)
        ipv4 = ipv4_from_rfc6052(ip_address, 48)
        return unsafe_ip_address?(ipv4)
      end
      return false
    end

    true
  end

  private_class_method def self.ipaddr_has_mask?(ipaddr)
    range = ipaddr.to_range
    range.first != range.last
  end

  private_class_method def self.different_origin?(uri1, uri2)
    uri1.scheme != uri2.scheme || uri1.hostname != uri2.hostname || uri1.port != uri2.port
  end

  private_class_method def self.normalized_hostname(uri)
    # Attach port for non-default as per RFC2616
    if (uri.port == 80 && uri.scheme == 'http') ||
       (uri.port == 443 && uri.scheme == 'https')
      uri.hostname
    else
      "#{uri.hostname}:#{uri.port}"
    end
  end

  private_class_method def self.fetch_once(uri, ip, verb, options, &block)
    if options[:params]
      params = uri.query ? ::URI.decode_www_form(uri.query).to_h : {}
      params.merge!(options[:params])
      uri.query = ::URI.encode_www_form(params)
    end

    request = VERB_MAP[verb].new(uri)
    request['host'] = normalized_hostname(uri)

    Array(options[:headers]).each do |header, value|
      request[header] = value
    end

    request.body = options[:body] if options[:body]

    options[:request_proc].call(request) if options[:request_proc].respond_to?(:call)

    headers_to_strip = Array(options[:headers_to_strip])
    unless headers_to_strip.empty?
      if options[:on_cross_origin_redirect] == :raise
        leaking = headers_to_strip.select { |h| request[h] }
        unless leaking.empty?
          raise CredentialLeakage,
            "Cross-origin redirect would leak sensitive headers: #{leaking.join(', ')}"
        end
      else
        headers_to_strip.each { |h| request.delete(h) }
      end
    end

    validate_request(request)

    http_options = (options[:http_options] || {}).merge(
      use_ssl: uri.scheme == 'https',
      ipaddr: ip
    )

    ::Net::HTTP.start(uri.hostname, uri.port, nil, **http_options) do |http|
      response = http.request(request) do |res|
        block&.call(res)
      end
      case response
      when ::Net::HTTPRedirection
        url = response['location']
        # Handle relative redirects
        url = "#{uri.scheme}://#{normalized_hostname(uri)}#{url}" if url&.start_with?('/')
      else
        url = nil
      end
      return response, url
    end
  end

  private_class_method def self.validate_request(request)
    # RFC822 allows multiline "folded" headers:
    # https://tools.ietf.org/html/rfc822#section-3.1
    # In practice if any user input is ever supplied as a header key/value, they'll get
    # arbitrary header injection and possibly connect to a different host, so we block it
    request.each do |header, value|
      if header.count("\r\n") != 0 || value.count("\r\n") != 0
        raise CRLFInjection, "CRLF injection in header #{header} with value #{value}"
      end
    end
  end
end
