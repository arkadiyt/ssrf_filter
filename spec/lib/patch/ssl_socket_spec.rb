# frozen_string_literal: true

describe ::SsrfFilter::Patch::SSLSocket do
  before do
    if described_class.instance_variable_defined?(:@patched_ssl_socket)
      described_class.remove_instance_variable(:@patched_ssl_socket)
    end
  end

  it 'only patches once' do
    expect(::OpenSSL::SSL::SSLSocket).to receive(:class_eval).once.and_call_original
    described_class.apply!
    described_class.apply!
  end
end
