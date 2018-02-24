# frozen_string_literal: true

describe ::SsrfFilter::Patch::SSLSocket do
  before :each do
    subject.remove_instance_variable(:@patched_ssl_socket) if subject.instance_variable_defined?(:@patched_ssl_socket)
  end

  it 'should only patch once' do
    expect(::OpenSSL::SSL::SSLSocket).to receive(:class_eval).once.and_call_original
    subject.apply!
    subject.apply!
  end
end
