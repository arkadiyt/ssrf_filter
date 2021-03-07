# frozen_string_literal: true

class SsrfFilter
  class OpenURI
    def self.open_uri(name, *rest, &block)
      require 'open-uri'

      uri = name.is_a?(URI::Generic) ? name : URI.parse(name)
      options = parse_arguments(rest)

      response = SsrfFilter.get(uri, options) do |request|
        uri = request.uri
      end

      buf = ::OpenURI::Buffer.new
      buf.io.status = [response.code, response.message]
      raise ::OpenURI::HTTPError.new(buf.io.status.join(' '), buf.io) unless response.is_a? Net::HTTPSuccess

      response.read_body do |segment|
        buf << segment
      end
      io = buf.io

      io.rewind
      io.base_uri = uri
      response.each_name do |header_name|
        if io.respond_to?(:meta_add_field2)
          io.meta_add_field2 header_name, response.get_fields(header_name)
        else
          io.meta_add_field header_name, response.get_fields(header_name).join(', ')
        end
      end

      if block_given?
        yield_with_io(io, &block)
      else
        io
      end
    end

    def self.parse_arguments(rest)
      _, _, rest = ::OpenURI.scan_open_optional_arguments(*rest)
      options = rest.shift if !rest.empty? && rest.first.is_a?(Hash)
      raise ArgumentError, 'extra arguments' unless rest.empty?

      options ||= {}
      validate_options!(options)
      options[:headers] ||= {}
      options.each do |key, value|
        next unless key.is_a?(String)

        options[:headers][key] = value
        options.delete(key)
      end

      options
    end
    private_class_method :parse_arguments

    def self.validate_options!(options)
      unsupported = %i[proxy proxy_http_basic_authentication progress_proc content_length_proc
                       http_basic_authentication read_timeout open_timeout ssl_ca_cert ssl_verify_mode
                       ftp_active_mode redirect encoding]
      given = options.keys.select { |key| key.is_a?(Symbol) } & unsupported
      raise ArgumentError, "Unsupported OpenURI option(s): #{given.join(', ')}" unless given.empty?
    end
    private_class_method :validate_options!

    def self.yield_with_io(io)
      yield io
    ensure
      if io.respond_to? :close!
        io.close! # Tempfile
      else
        io.close unless io.closed?
      end
    end
    private_class_method :yield_with_io
  end
end
