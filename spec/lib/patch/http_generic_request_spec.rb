# frozen_string_literal: true

describe ::SsrfFilter::Patch::HTTPGenericRequest do
  before :each do
    if subject.instance_variable_defined?(:@checked_http_generic_request)
      subject.remove_instance_variable(:@checked_http_generic_request)
    end
  end

  it 'should only apply once, on unpatched versions of ruby' do
    expect(::Net::HTTPGenericRequest).to receive(:class_eval).exactly(subject.should_apply? ? 1 : 0).times
      .and_call_original
    subject.apply!
    subject.apply!
  end
end
