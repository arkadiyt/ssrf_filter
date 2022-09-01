# ssrf_filter [![Gem](https://img.shields.io/gem/v/ssrf_filter.svg)](https://rubygems.org/gems/ssrf_filter) [![Tests](https://github.com/arkadiyt/ssrf_filter/actions/workflows/build-test.yml/badge.svg)](https://github.com/arkadiyt/ssrf_filter/actions/workflows/build-test.yml/badge.svg) [![Coverage Status](https://coveralls.io/repos/github/arkadiyt/ssrf_filter/badge.svg?branch=main)](https://coveralls.io/github/arkadiyt/ssrf_filter?branch=main) [![License](https://img.shields.io/github/license/arkadiyt/ssrf_filter.svg)](https://github.com/arkadiyt/ssrf_filter/blob/master/LICENSE.md)

## Table of Contents
- [What's it for](https://github.com/arkadiyt/ssrf_filter#whats-it-for)
- [Quick start](https://github.com/arkadiyt/ssrf_filter#quick-start)
- [API Reference](https://github.com/arkadiyt/ssrf_filter#api-reference)
- [Changelog](https://github.com/arkadiyt/ssrf_filter#changelog)
- [Contributing](https://github.com/arkadiyt/ssrf_filter#contributing)

### What's it for

ssrf_filter makes it easy to defend against server side request forgery (SSRF) attacks. SSRF vulnerabilities happen when you accept URLs as user input and fetch them on your server (for instance, when a user enters a link into a Twitter/Facebook status update and a content preview is generated).

Users can pass in URLs or IPs such that your server will make requests to the internal network. For example if you're hosted on AWS they can request the [instance metadata endpoint](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html) `http://169.254.169.254/latest/meta-data/` and get your IAM credentials.

Attempts to guard against this are often implemented incorrectly, by blocking all ip addresses, not handling IPv6 or http redirects correctly, or having TOCTTOU bugs and other issues.

This gem provides a safe and easy way to fetch content from user-submitted urls. It:
- handles URIs/IPv4/IPv6, redirects, DNS, etc, correctly
- has 0 runtime dependencies
- has a comprehensive test suite (100% code coverage)
- is tested against ruby `2.6`, `2.7`, `3.0`, `3.1`, and `ruby-head`

### Quick start

1) Add the gem to your Gemfile:

```ruby
gem 'ssrf_filter', '~> 1.1.1'
```

2) In your code:

```ruby
require 'ssrf_filter'
response = SsrfFilter.get(params[:url]) # throws an exception for unsafe fetches
response.code
=> "200"
response.body
=> "<!doctype html>\n<html>\n<head>\n..."
```

### API reference

`SsrfFilter.get/.put/.post/.delete/.head/.patch(url, options = {}, &block)`

Fetches the requested url using a get/put/post/delete/head/patch request, respectively.

Params:
- `url` — the url to fetch.
- `options` — options hash (described below).
- `block` — a block that will receive the [HTTPRequest](https://ruby-doc.org/stdlib-2.4.1/libdoc/net/http/rdoc/Net/HTTPGenericRequest.html) object before it's sent, if you need to do any pre-processing on it (see examples below).

Options hash:
- `:scheme_whitelist` — an array of schemes to allow. Defaults to `%w[http https]`.
- `:resolver` — a proc that receives a hostname string and returns an array of [IPAddr](https://ruby-doc.org/stdlib-2.4.1/libdoc/ipaddr/rdoc/IPAddr.html) objects. Defaults to resolving with Ruby's [Resolv](https://ruby-doc.org/stdlib-2.4.1/libdoc/resolv/rdoc/Resolv.html). See examples below for a custom resolver.
- `:max_redirects` — Maximum number of redirects to follow. Defaults to 10.
- `:params` — Hash of params to send with the request.
- `:headers` — Hash of headers to send with the request.
- `:body` — Body to send with the request.
- `:http_options` – Options to pass to [Net::HTTP.start](https://ruby-doc.org/stdlib-2.6.4/libdoc/net/http/rdoc/Net/HTTP.html#method-c-start). Use this to set custom timeouts or SSL options.
- `:request_proc` - a proc that receives the request object, for custom modifications before sending the request.

Returns:

An [HTTPResponse](https://ruby-doc.org/stdlib-2.4.1/libdoc/net/http/rdoc/Net/HTTPResponse.html) object if the url was fetched safely, or throws an exception if it was unsafe. All exceptions inherit from `SsrfFilter::Error`.

Examples:

```ruby
# GET www.example.com
SsrfFilter.get('https://www.example.com')

# Pass params - these are equivalent
SsrfFilter.get('https://www.example.com?param=value')
SsrfFilter.get('https://www.example.com', params: {'param' => 'value'})

# POST, send custom header, and don't follow redirects
begin
  SsrfFilter.post('https://www.example.com', max_redirects: 0,
    headers: {'content-type' => 'application/json'})
rescue SsrfFilter::Error => e
  # Got an unsafe url
end

# Custom DNS resolution and request processing
resolver = proc do |hostname|
  [IPAddr.new('2001:500:8f::53')] # Static resolver
end
# Do some extra processing on the request
request_proc = proc do |request|
  request['content-type'] = 'application/json'
  request.basic_auth('username', 'password')
end
SsrfFilter.get('https://www.example.com', resolver: resolver, request_proc: request_proc)

# Stream response
SsrfFilter.get('https://www.example.com') do |response|
  response.read_body do |chunk|
    puts chunk
  end
end
```

### Changelog

Please see [CHANGELOG.md](https://github.com/arkadiyt/ssrf_filter/blob/master/CHANGELOG.md). This project follows [semantic versioning](https://semver.org/).

### Contributing

Please see [CONTRIBUTING.md](https://github.com/arkadiyt/ssrf_filter/blob/master/CONTRIBUTING.md).
