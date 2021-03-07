# frozen_string_literal: true

require 'open-uri'

describe SsrfFilter::OpenURI do
  let(:public_ipv4) { IPAddr.new('172.217.6.78') }

  context 'open_uri' do
    it 'can be called in a OpenURI-compatible way' do
      allow(SsrfFilter::DEFAULT_RESOLVER).to receive(:call).and_return([public_ipv4])
      stub_request(:get, "https://#{public_ipv4}/")
        .with(headers: {host: 'www.example.com'}).to_return(status: [200, 'OK'], body: 'response body')
      response = SsrfFilter::OpenURI.open_uri('https://www.example.com')
      expect(response.status).to eq(%w[200 OK])
      expect(response.read).to eq('response body')
    end

    it 'accepts request headers' do
      allow(SsrfFilter::DEFAULT_RESOLVER).to receive(:call).and_return([public_ipv4])
      stub_request(:get, "https://#{public_ipv4}/")
        .with(headers: {host: 'www.example.com', accept: 'application/json'})
        .to_return(status: [200, 'OK'], body: 'response body')
      response = SsrfFilter::OpenURI.open_uri('https://www.example.com', 'Accept' => 'application/json')
      expect(response.status).to eq(%w[200 OK])
    end

    it 'raises ArgumentError when unsupported OpenURI option is given' do
      expect do
        SsrfFilter::OpenURI.open_uri('https://www.example.com', http_basic_authentication: %w[user pass])
      end.to raise_error ArgumentError, 'Unsupported OpenURI option(s): http_basic_authentication'
    end

    it 'can be called with a block' do
      allow(SsrfFilter::DEFAULT_RESOLVER).to receive(:call).and_return([public_ipv4])
      stub_request(:get, "https://#{public_ipv4}/")
        .with(headers: {host: 'www.example.com'}).to_return(status: [200, 'OK'], body: 'response body')
      expect do |block|
        SsrfFilter::OpenURI.open_uri('https://www.example.com', &block)
      end.to yield_with_args(OpenURI::Meta)
    end

    it 'closes Tempfile after execution of given block' do
      allow(SsrfFilter::DEFAULT_RESOLVER).to receive(:call).and_return([public_ipv4])
      stub_request(:get, "https://#{public_ipv4}/")
        .with(headers: {host: 'www.example.com'}).to_return(status: [200, 'OK'], body: 'a' * 10241)
      tempfile = nil
      SsrfFilter::OpenURI.open_uri('https://www.example.com') do |io|
        expect(io).to be_a Tempfile
        tempfile = io
      end
      expect(tempfile).to be_closed
    end

    it 'returns an OpenURI::Meta instance' do
      allow(SsrfFilter::DEFAULT_RESOLVER).to receive(:call).and_return([public_ipv4])
      stub_request(:get, "https://#{public_ipv4}/")
        .with(headers: {host: 'www.example.com'})
        .to_return(status: [200, 'OK'], body: 'response body',
                   headers: {'Content-Type' => 'text/plain', 'Cache-Control' => 'private'})
      response = SsrfFilter::OpenURI.open_uri('https://www.example.com')
      expect(response).to be_a OpenURI::Meta
      expect(response.content_type).to eq('text/plain')
      if response.respond_to?(:metas)
        expect(response.metas).to eq('cache-control' => ['private'], 'content-type' => ['text/plain'])
      end
    end

    it 'works even if OpenURI::Meta does not have #meta_add_field2 (Ruby <= 2.0)' do
      allow_any_instance_of(OpenURI::Meta).to receive(:respond_to?).with(:meta_add_field2).and_return(false)
      allow(SsrfFilter::DEFAULT_RESOLVER).to receive(:call).and_return([public_ipv4])
      stub_request(:get, "https://#{public_ipv4}/")
        .with(headers: {host: 'www.example.com'})
        .to_return(status: [200, 'OK'], body: 'response body',
                   headers: {'Set-Cookie' => ['foo=bar', 'baz=qux']})
      response = SsrfFilter::OpenURI.open_uri('https://www.example.com')
      expect(response.meta).to eq('set-cookie' => 'baz=qux, foo=bar')
    end

    it 'uses Tempfile as IO when the response is large' do
      allow(SsrfFilter::DEFAULT_RESOLVER).to receive(:call).and_return([public_ipv4])
      stub_request(:get, "https://#{public_ipv4}/")
        .with(headers: {host: 'www.example.com'})
        .to_return(status: [200, 'OK'], body: 'a' * 10241,
                   headers: {'Content-Type' => 'text/plain', 'Cache-Control' => 'private'})
      response = SsrfFilter::OpenURI.open_uri('https://www.example.com')
      expect(response).to be_a Tempfile
    end

    it 'follows redirects and sets the final url to #base_uri' do
      allow(SsrfFilter::DEFAULT_RESOLVER).to receive(:call).and_return([public_ipv4])
      stub_request(:get, "https://#{public_ipv4}/")
        .with(headers: {host: 'www.example.com'})
        .to_return(status: [302, 'Found'], headers: {'Location' => 'https://www.example.com/redirected'})
      stub_request(:get, "https://#{public_ipv4}/redirected")
        .with(headers: {host: 'www.example.com'}).to_return(status: [200, 'OK'], body: 'response body')
      response = SsrfFilter::OpenURI.open_uri('https://www.example.com')
      expect(response.status).to eq(%w[200 OK])
      expect(response.read).to eq('response body')
      expect(response.base_uri).to eq(URI("https://#{public_ipv4}/redirected"))
    end

    it 'raises OpenURI::HTTPError on failure' do
      allow(SsrfFilter::DEFAULT_RESOLVER).to receive(:call).and_return([public_ipv4])
      stub_request(:get, "https://#{public_ipv4}/")
        .with(headers: {host: 'www.example.com'}).to_return(status: [404, 'Not Found'])
      expect do
        SsrfFilter::OpenURI.open_uri('https://www.example.com')
      end.to raise_error OpenURI::HTTPError, '404 Not Found'
    end
  end
end
