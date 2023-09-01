# frozen_string_literal: true

require 'timeout'
require 'webrick/https'

describe SsrfFilter do
  before :all do
    described_class.make_all_class_methods_public!
  end

  let(:public_ipv4) { IPAddr.new('172.217.6.78') }
  let(:private_ipv4) { IPAddr.new('127.0.0.1') }
  let(:public_ipv6) { IPAddr.new('2606:2800:220:1:248:1893:25c8:1946') }
  let(:private_ipv6) { IPAddr.new('::1') }

  describe 'unsafe_ip_address?' do
    it 'returns true if the ipaddr has a mask' do
      expect(described_class.unsafe_ip_address?(IPAddr.new("#{public_ipv4}/16"))).to be(true)
    end

    it 'returns true for private ipv4 addresses' do
      expect(described_class.unsafe_ip_address?(private_ipv4)).to be(true)
    end

    it 'returns false for public ipv4 addresses' do
      expect(described_class.unsafe_ip_address?(public_ipv4)).to be(false)
    end

    it 'returns true for private ipv6 addresses' do
      expect(described_class.unsafe_ip_address?(private_ipv6)).to be(true)
    end

    it 'returns true for mapped/compat ipv4 addresses' do
      described_class::IPV4_BLACKLIST.each do |addr|
        %i[ipv4_compat ipv4_mapped].each do |method|
          first = addr.to_range.first.send(method).mask(128)
          expect(described_class.unsafe_ip_address?(first)).to be(true)

          last = addr.to_range.last.send(method).mask(128)
          expect(described_class.unsafe_ip_address?(last)).to be(true)
        end
      end
    end

    it 'returns false for public ipv6 addresses' do
      expect(described_class.unsafe_ip_address?(public_ipv6)).to be(false)
    end

    it 'returns true for unknown ip families' do
      allow(public_ipv4).to receive(:ipv4?).and_return(false)
      allow(public_ipv4).to receive(:ipv6?).and_return(false)
      expect(described_class.unsafe_ip_address?(public_ipv4)).to be(true)
    end
  end

  describe 'prefixlen_from_ipaddr' do
    it 'returns the prefix length' do
      expect(described_class.prefixlen_from_ipaddr(IPAddr.new('0.0.0.0/8'))).to eq(8)
      expect(described_class.prefixlen_from_ipaddr(IPAddr.new('198.18.0.0/15'))).to eq(15)
      expect(described_class.prefixlen_from_ipaddr(IPAddr.new('255.255.255.255'))).to eq(32)

      expect(described_class.prefixlen_from_ipaddr(IPAddr.new('::1'))).to eq(128)
      expect(described_class.prefixlen_from_ipaddr(IPAddr.new('64:ff9b::/96'))).to eq(96)
      expect(described_class.prefixlen_from_ipaddr(IPAddr.new('fc00::/7'))).to eq(7)
    end
  end

  describe 'ipaddr_has_mask?' do
    it 'returns true if the ipaddr has a mask' do
      expect(described_class.ipaddr_has_mask?(IPAddr.new("#{private_ipv4}/8"))).to be(true)
    end

    it 'returns false if the ipaddr has no mask' do
      expect(described_class.ipaddr_has_mask?(private_ipv4)).to be(false)
      expect(described_class.ipaddr_has_mask?(IPAddr.new("#{private_ipv4}/32"))).to be(false)
      expect(described_class.ipaddr_has_mask?(IPAddr.new("#{private_ipv6}/128"))).to be(false)
    end
  end

  describe 'fetch_once' do
    it 'sets the host header' do
      stub_request(:post, "https://#{public_ipv4}").with(headers: {host: 'www.example.com'})
        .to_return(status: 200, body: 'response body')
      response, url = described_class.fetch_once(URI('https://www.example.com'), public_ipv4.to_s, :post, {})
      expect(response.code).to eq('200')
      expect(response.body).to eq('response body')
      expect(url).to be_nil
    end

    it 'does not send the port in the host header for default ports (http)' do
      stub_request(:post, "http://#{public_ipv4}").with(headers: {host: 'www.example.com'})
        .to_return(status: 200, body: 'response body')
      response, url = described_class.fetch_once(URI('http://www.example.com'), public_ipv4.to_s, :post, {})
      expect(response.code).to eq('200')
      expect(response.body).to eq('response body')
      expect(url).to be_nil
    end

    it 'sends the port in the host header for non-default ports' do
      stub_request(:post, "https://#{public_ipv4}:80").with(headers: {host: 'www.example.com:80'})
        .to_return(status: 200, body: 'response body')
      response, url = described_class.fetch_once(URI('https://www.example.com:80'), public_ipv4.to_s, :post, {})
      expect(response.code).to eq('200')
      expect(response.body).to eq('response body')
      expect(url).to be_nil
    end

    it 'passes headers, params, and blocks' do
      stub_request(:get, "https://#{public_ipv4}/?key=value").with(headers:
        {host: 'www.example.com', header: 'value', header2: 'value2'}).to_return(status: 200, body: 'response body')
      options = {
        headers: {'header' => 'value'},
        params: {'key' => 'value'},
        request_proc: proc do |req|
          req['header2'] = 'value2'
        end
      }
      uri = URI('https://www.example.com/?key=value')
      response, url = described_class.fetch_once(uri, public_ipv4.to_s, :get, options)
      expect(response.code).to eq('200')
      expect(response.body).to eq('response body')
      expect(url).to be_nil
    end

    it 'merges params' do
      stub_request(:get, "https://#{public_ipv4}/?key=value&key2=value2")
        .with(headers: {host: 'www.example.com'}).to_return(status: 200, body: 'response body')
      uri = URI('https://www.example.com/?key=value')
      response, url = described_class.fetch_once(uri, public_ipv4.to_s, :get, params: {'key2' => 'value2'})
      expect(response.code).to eq('200')
      expect(response.body).to eq('response body')
      expect(url).to be_nil
    end

    it 'does not use tls for http urls', only: true do
      expect(::Net::HTTP).to receive(:start).with(public_ipv4.to_s, 80, use_ssl: false)
      described_class.fetch_once(URI('http://www.example.com'), public_ipv4.to_s, :get, {})
    end

    it 'uses tls for https urls' do
      expect(::Net::HTTP).to receive(:start).with(public_ipv4.to_s, 443, use_ssl: true)
      described_class.fetch_once(URI('https://www.example.com'), public_ipv4.to_s, :get, {})
    end
  end

  describe 'with_forced_hostname' do
    it 'sets the value for the block and clear it afterwards' do
      expect(Thread.current[described_class::FIBER_HOSTNAME_KEY]).to be_nil
      expect(Thread.current[described_class::FIBER_ADDRESS_KEY]).to be_nil
      described_class.with_forced_hostname('test', '1.2.3.4') do
        expect(Thread.current[described_class::FIBER_HOSTNAME_KEY]).to eq('test')
        expect(Thread.current[described_class::FIBER_ADDRESS_KEY]).to eq('1.2.3.4')
      end
      expect(Thread.current[described_class::FIBER_HOSTNAME_KEY]).to be_nil
      expect(Thread.current[described_class::FIBER_ADDRESS_KEY]).to be_nil
    end

    it 'clears the value even if an exception is raised' do
      expect(Thread.current[described_class::FIBER_HOSTNAME_KEY]).to be_nil
      expect(Thread.current[described_class::FIBER_ADDRESS_KEY]).to be_nil
      expect do
        described_class.with_forced_hostname('test', '1.2.3.4') do
          expect(Thread.current[described_class::FIBER_HOSTNAME_KEY]).to eq('test')
          expect(Thread.current[described_class::FIBER_ADDRESS_KEY]).to eq('1.2.3.4')
          raise StandardError
        end
      end.to raise_error(StandardError)
      expect(Thread.current[described_class::FIBER_HOSTNAME_KEY]).to be_nil
      expect(Thread.current[described_class::FIBER_ADDRESS_KEY]).to be_nil
    end
  end

  describe 'validate_request' do
    it 'disallows header names with newlines and carriage returns' do
      expect do
        described_class.get("https://#{public_ipv4}", headers: {"nam\ne" => 'value'})
      end.to raise_error(described_class::CRLFInjection)

      expect do
        described_class.get("https://#{public_ipv4}", headers: {"nam\re" => 'value'})
      end.to raise_error(described_class::CRLFInjection)
    end

    it 'disallows header values with newlines and carriage returns' do
      # In more recent versions of ruby, assigning a header value with newlines throws an ArgumentError
      major, minor = RUBY_VERSION.scan(/\A(\d+)\.(\d+)\.\d+\Z/).first.map(&:to_i)
      exception = major >= 3 || (major >= 2 && minor >= 3) ? ArgumentError : described_class::CRLFInjection

      expect do
        described_class.get("https://#{public_ipv4}", headers: {'name' => "val\nue"})
      end.to raise_error(exception)

      expect do
        described_class.get("https://#{public_ipv4}", headers: {'name' => "val\rue"})
      end.to raise_error(exception)
    end
  end

  describe 'integration tests' do
    # To test the SSLSocket patching logic (and hit 100% code coverage), we need to make a real connection to a
    # TLS-enabled server. To do this we create a private key and certificate, spin up a web server in
    # a thread (serving traffic on localhost), and make a request to the server. This requires several things:
    # 1) creating a custom trust store with our certificate and using that for validation
    # 2) allowing (non-mocked) network connections
    # 3) stubbing out the IPV4_BLACKLIST to allow connections to localhost

    allow_net_connections_for_context(self)

    def make_keypair(subject)
      private_key = OpenSSL::PKey::RSA.new(2048)
      public_key = private_key.public_key
      subject = OpenSSL::X509::Name.parse(subject)

      certificate = OpenSSL::X509::Certificate.new
      certificate.subject = subject
      certificate.issuer = subject
      certificate.not_before = Time.now
      certificate.not_after = Time.now + (60 * 60 * 24)
      certificate.public_key = public_key
      certificate.serial = 0x0
      certificate.version = 2

      certificate.sign(private_key, OpenSSL::Digest.new('SHA256'))

      [private_key, certificate]
    end

    def make_web_server(port, private_key, certificate, opts = {}, &block)
      server = WEBrick::HTTPServer.new({
        BindAddress: '127.0.0.1',
        Port: port,
        SSLEnable: true,
        SSLCertificate: certificate,
        SSLPrivateKey: private_key,
        StartCallback: block
      }.merge(opts))

      server.mount_proc '/' do |req, res|
        res.status = 200
        res['X-Subject'] = certificate.subject
        res['X-Host'] = req['host']
      end

      server
    end

    def inject_custom_trust_store(*certificates)
      store = OpenSSL::X509::Store.new
      certificates.each do |certificate|
        store.add_cert(certificate)
      end

      expect(::Net::HTTP).to receive(:start).exactly(certificates.length).times
        .and_wrap_original do |orig, *args, &block|
        args.last[:cert_store] = store # Inject our custom trust store
        orig.call(*args, &block)
      end
    end

    it 'validates TLS certificates' do
      hostname = 'ssrf-filter.example.com'
      port = 8443
      private_key, certificate = make_keypair("CN=#{hostname}")
      stub_const('SsrfFilter::IPV4_BLACKLIST', [])

      inject_custom_trust_store(certificate)

      begin
        queue = Queue.new # Used as a semaphore

        web_server_thread = Thread.new do
          make_web_server(port, private_key, certificate) do
            queue.push(nil)
          end.start
        end

        Timeout.timeout(2) do
          queue.pop
          response = described_class.get("https://#{hostname}:#{port}", resolver: proc { [IPAddr.new('127.0.0.1')] })
          expect(response.code).to eq('200')
          expect(response['X-Subject']).to eq("/CN=#{hostname}")
          expect(response['X-Host']).to eq("#{hostname}:#{port}")
        end
      ensure
        web_server_thread&.kill
      end
    end

    it 'connects when using SNI' do
      require 'webrick/https'

      port = 8443
      private_key, certificate = make_keypair('CN=localhost')
      virtualhost_private_key, virtualhost_certificate = make_keypair('CN=virtualhost')
      stub_const('SsrfFilter::IPV4_BLACKLIST', [])

      inject_custom_trust_store(certificate, virtualhost_certificate)

      begin
        queue = Queue.new # Used as a semaphore

        web_server_thread = Thread.new do
          server = make_web_server(port, private_key, certificate, ServerName: 'localhost') do
            queue.push(nil)
          end

          options = {ServerName: 'virtualhost', DoNotListen: true}
          virtualhost = make_web_server(port, virtualhost_private_key, virtualhost_certificate, options)
          server.virtual_host(virtualhost)

          server.start
        end

        Timeout.timeout(2) do
          queue.pop

          options = {
            resolver: proc { [IPAddr.new('127.0.0.1')] }
          }

          response = described_class.get("https://localhost:#{port}", options)
          expect(response.code).to eq('200')
          expect(response['X-Subject']).to eq('/CN=localhost')
          expect(response['X-Host']).to eq("localhost:#{port}")

          response = described_class.get("https://virtualhost:#{port}", options)
          expect(response.code).to eq('200')
          expect(response['X-Subject']).to eq('/CN=virtualhost')
          expect(response['X-Host']).to eq("virtualhost:#{port}")
        end
      ensure
        web_server_thread&.kill
      end
    end

    it 'supports chunked responses' do
      hostname = 'ssrf-filter.example.com'
      port = 8443

      private_key, certificate = make_keypair("CN=#{hostname}")
      inject_custom_trust_store(certificate)
      stub_const('SsrfFilter::IPV4_BLACKLIST', [])

      begin
        queue = Queue.new # Used as a semaphore

        chunks = ['chunk 1', 'chunk 2', 'chunk 3']

        web_server_thread = Thread.new do
          server = make_web_server(port, private_key, certificate) do
            queue.push(nil)
          end

          server.mount_proc '/chunked' do |_, res|
            res.status = 200
            res.chunked = true
            res.body = proc do |chunked_wrapper|
              chunks.each { |chunk| chunked_wrapper.write(chunk) }
            end
          end

          server.start
        end

        Timeout.timeout(2) do
          queue.pop

          chunk_index = 0
          url = "https://#{hostname}:#{port}/chunked"
          described_class.get(url, resolver: proc { [IPAddr.new('127.0.0.1')] }) do |response|
            expect(response.code).to eq('200')
            response.read_body do |chunk|
              expect(chunk).to eq(chunks[chunk_index])
              chunk_index += 1
            end
          end
          expect(chunk_index).to eq(chunks.length)
        end
      ensure
        web_server_thread&.kill
      end
    end

    it 'does not break when reading the body without using a block' do
      port = 8443

      private_key, certificate = make_keypair('CN=localhost')
      inject_custom_trust_store(certificate)
      stub_const('SsrfFilter::IPV4_BLACKLIST', [])

      begin
        queue = Queue.new # Used as a semaphore

        web_server_thread = Thread.new do
          server = make_web_server(port, private_key, certificate) do
            queue.push(nil)
          end
          server.mount('/README.md', WEBrick::HTTPServlet::FileHandler, 'README.md')
          server.start
        end

        Timeout.timeout(2) do
          queue.pop

          options = {
            resolver: proc { [IPAddr.new('127.0.0.1')] }
          }

          response = described_class.get("https://localhost:#{port}/README.md", options)
          expect(response.code).to eq('200')
          expect(response.body).to match(/ssrf_filter/)
        end
      ensure
        web_server_thread&.kill
      end
    end
  end

  describe 'get/put/post/delete' do
    it 'fails if the scheme is not in the default whitelist' do
      expect do
        described_class.get('ftp://example.com')
      end.to raise_error(described_class::InvalidUriScheme)
    end

    it 'fails if the scheme is not in a custom whitelist' do
      expect do
        described_class.get('https://example.com', scheme_whitelist: [])
      end.to raise_error(described_class::InvalidUriScheme)
    end

    it 'fails if the hostname does not resolve' do
      expect(Resolv).to receive(:getaddresses).and_return([])
      expect do
        described_class.get('https://example.com')
      end.to raise_error(described_class::UnresolvedHostname)
    end

    it 'fails if the hostname does not resolve with a custom resolver' do
      called = false
      resolver = proc do
        called = true
        []
      end

      expect(described_class::DEFAULT_RESOLVER).not_to receive(:call)
      expect do
        described_class.get('https://example.com', resolver: resolver)
      end.to raise_error(described_class::UnresolvedHostname)
      expect(called).to be(true)
    end

    it 'fails if the hostname has no public ip address' do
      expect(described_class::DEFAULT_RESOLVER).to receive(:call).and_return([private_ipv4])
      expect do
        described_class.get('https://example.com')
      end.to raise_error(described_class::PrivateIPAddress)
    end

    it 'fails if there are too many redirects' do
      stub_request(:get, "https://#{public_ipv4}").with(headers: {host: 'www.example.com'})
        .to_return(status: 301, headers: {location: private_ipv4})
      resolver = proc { [public_ipv4] }
      expect do
        described_class.get('https://www.example.com', resolver: resolver, max_redirects: 0)
      end.to raise_error(described_class::TooManyRedirects)
    end

    it 'fails if the redirected url is not in the scheme whitelist' do
      stub_request(:put, "https://#{public_ipv4}").with(headers: {host: 'www.example.com'})
        .to_return(status: 301, headers: {location: 'ftp://www.example.com'})
      resolver = proc { [public_ipv4] }
      expect do
        described_class.put('https://www.example.com', resolver: resolver)
      end.to raise_error(described_class::InvalidUriScheme)
    end

    it 'fails if the redirected url has no public ip address' do
      stub_request(:delete, "https://#{public_ipv4}").with(headers: {host: 'www.example.com'})
        .to_return(status: 301, headers: {location: 'https://www.example2.com'})
      resolver = proc do |hostname|
        [{
          'www.example.com' => public_ipv4,
          'www.example2.com' => private_ipv6
        }[hostname]]
      end
      expect do
        described_class.delete('https://www.example.com', resolver: resolver)
      end.to raise_error(described_class::PrivateIPAddress)
    end

    it 'fails when the hostname or path contain linefeeds and carriage returns' do
      [
        "https://www.exam\nple.com",
        "https://www.exam\rple.com",
        "https://www.example.com/te\nst",
        "https://www.example.com/te\rst"
      ].each do |uri|
        expect do
          described_class.get(uri)
        end.to raise_error(URI::InvalidURIError)
      end
    end

    it 'follows redirects and succeed on a public hostname' do
      stub_request(:post, "https://#{public_ipv4}/path?key=value").with(headers: {host: 'www.example.com'})
        .to_return(status: 301, headers: {location: 'https://www.example2.com/path2?key2=value2'})
      stub_request(:post, "https://[#{public_ipv6}]/path2?key2=value2")
        .with(headers: {host: 'www.example2.com'}).to_return(status: 200, body: 'response body')
      resolver = proc do |hostname|
        [{
          'www.example.com' => public_ipv4,
          'www.example2.com' => public_ipv6
        }[hostname]]
      end
      response = described_class.post('https://www.example.com/path?key=value', resolver: resolver)
      expect(response.code).to eq('200')
      expect(response.body).to eq('response body')
    end

    it 'follows relative redirects and succeed' do
      stub_request(:post, "https://#{public_ipv4}/path?key=value").with(headers: {host: 'www.example.com'})
        .to_return(status: 301, headers: {location: '/path2?key2=value2'})
      stub_request(:post, "https://#{public_ipv4}/path2?key2=value2")
        .with(headers: {host: 'www.example.com'}).to_return(status: 200, body: 'response body')
      resolver = proc do |hostname|
        [{
          'www.example.com' => public_ipv4
        }[hostname]]
      end
      response = described_class.post('https://www.example.com/path?key=value', resolver: resolver)
      expect(response.code).to eq('200')
      expect(response.body).to eq('response body')
    end
  end
end
