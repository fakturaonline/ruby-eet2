# frozen_string_literal: true

# The supported concurrency contract is one Client, Credential, and PreparedRequest
# per attempt. This locks that contract: independent per-attempt instances running
# in parallel must not corrupt each other. It deliberately does not exercise a
# shared Client, because the gem does not promise that and a green run would not
# prove it.
RSpec.describe "concurrent per-attempt clients" do
  let(:threads) { 4 }
  let(:iterations) { 5 }

  it "produces independent, self-consistent attempts from parallel per-attempt clients" do
    barrier = Queue.new
    attempts_per_thread = iterations
    results = threads.times.map do |thread_index|
      key = OpenSSL::PKey::RSA.generate(2048)
      credential = Eet2::Credential.new(
        certificate: SpecSupport.certificate(private_key: key, serial: thread_index + 1),
        signer: Eet2::LocalKeySigner.new(private_key: key)
      )

      Thread.new do
        barrier.pop
        attempts_per_thread.times.map do |iteration|
          client = Eet2::Client.playground(
            credential: credential,
            transport: ->(_) { Eet2::Transport::Failure.new(certainty: :not_sent, kind: :connect_timeout) }
          )
          prepared = client.prepare(
            sale: SpecSupport.sale(sequence_number: "t#{thread_index}/#{iteration}"),
            first_submission: true
          )
          outcome = client.transmit(prepared)

          {prepared: prepared, outcome: outcome, sequence_number: "t#{thread_index}/#{iteration}"}
        end
      end
    end
    threads.times { barrier << :go }
    attempts = results.flat_map(&:value)

    expect(attempts.length).to eq(threads * iterations)
    expect(attempts.map { |attempt| attempt[:prepared].request_uuid }.uniq.length).to eq(attempts.length)
    attempts.each do |attempt|
      prepared = attempt[:prepared]

      expect(prepared.request_sha256).to eq(Digest::SHA256.hexdigest(prepared.xml))
      expect(prepared.sale.sequence_number).to eq(attempt[:sequence_number])
      expect(prepared.xml).to include(attempt[:sequence_number])
      expect(prepared.xml).to include(prepared.request_uuid)
      expect(attempt[:outcome]).to be_a(Eet2::Response::TransportFailure)
      expect(attempt[:outcome].certainty).to eq(:not_sent)
    end
  end
end
