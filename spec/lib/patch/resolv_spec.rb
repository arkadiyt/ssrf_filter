# frozen_string_literal: true

describe ::SsrfFilter::Patch::Resolv do
  describe 'apply' do
    before do
      if described_class.instance_variable_defined?(:@patched_resolv)
        described_class.remove_instance_variable(:@patched_resolv)
      end
    end

    it 'only patches once' do
      expect(::Resolv::IPv4).to receive(:remove_const).once.and_call_original
      expect(::Resolv::IPv6).to receive(:remove_const).once.and_call_original
      described_class.apply!
      described_class.apply!
    end
  end

  describe ::SsrfFilter::Patch::Resolv::PatchedRegexp do
    it 'forces the ip regex to not match the supplied address' do
      # rubocop:disable Style/CaseEquality
      ipaddress1 = '1.2.3.4'
      ipaddress2 = '5.6.7.8'
      SsrfFilter.send(:with_forced_hostname, nil, ipaddress1) do
        expect(described_class.new(Resolv::IPv4::Regex) === ipaddress1).to be false
        expect(described_class.new(Resolv::IPv4::Regex) === ipaddress2).to be true
      end
      expect(described_class.new(Resolv::IPv4::Regex) === ipaddress1).to be true
      expect(described_class.new(Resolv::IPv4::Regex) === ipaddress2).to be true
      # rubocop:enable Style/CaseEquality
    end
  end
end
