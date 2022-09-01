### 1.1.1 (8/31/2022)
* Fix network connection errors if you were making https requests while using [net-http](https://github.com/ruby/net-http) 2.2 or higher ([arkadiyt](https://github.com/arkadiyt/ssrf_filter/pull/54))

### 1.1.0 (8/28/2022)
* Add support for chunked responses ([mrhaddad](https://github.com/arkadiyt/ssrf_filter/pull/30))

### 1.0.8 (8/3/2022)
* Add support for HEAD requests ([jakeyheath](https://github.com/arkadiyt/ssrf_filter/pull/38))

### 1.0.7 (10/21/2019)
* Allow passing custom options to Net::HTTP.start ([groe](https://github.com/arkadiyt/ssrf_filter/pull/26))

### 1.0.6 (2/24/2018)
* Backport a fix for a [bug](https://bugs.ruby-lang.org/issues/10054) in Ruby's http library

### 1.0.5 (1/17/2018)
* Don't send the port number in the Host header if it's HTTPS and on port 443

### 1.0.4 (1/17/2018)
* Handle relative redirects

### 1.0.3 (12/4/2017)
* Use `frozen_string_literal` pragma in all ruby files
* Handle new ruby 2.5 behavior when encountering newlines in header names

### 1.0.2 (8/3/2017)
* Block newlines and carriage returns in header names/values

### 1.0.1 (7/26/2017)
* Fixed a bug in how ipv4-compatible and ipv4-mapped addresses were handled
* Fixed a bug where the Host header did not include the port number

### 1.0.0 (7/24/2017)
* Initial release
