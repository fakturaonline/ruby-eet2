# frozen_string_literal: true

require "nokogiri"

RSpec.describe Eet2::RequestIntegrityVerifier do
  subject(:verifier) { described_class.new }

  let(:prepared) do
    Eet2::Contracts::V4_1::RequestBuilder.new(
      credential: SpecSupport.credential,
      clock: -> { Time.new(2027, 1, 3, 12, 31, 2, "+01:00") },
      uuid_generator: -> { "123e4567-e89b-42d3-a456-426614174000" }
    ).call(sale: SpecSupport.sale, first_submission: true)
  end
  let(:namespaces) do
    {
      "v4" => Eet2::XmlSigner::EET_NAMESPACE,
      "wsu" => Eet2::XmlSigner::WSU_NAMESPACE,
      "ds" => Eet2::XmlSigner::DS_NAMESPACE,
      "wsse" => Eet2::XmlSigner::WSSE_NAMESPACE,
      "ec" => Eet2::XmlSigner::EXCLUSIVE_C14N_NAMESPACE
    }
  end

  it "verifies the complete generated request audit state" do
    expect(verifier.verify!(prepared)).to be(true)
  end

  it "rejects UUID, send flags, and Sale metadata that diverge from signed XML" do
    other_uuid = prepared.with(request_uuid: "a23e4567-e89b-42d3-a456-426614174000")
    other_sale = prepared.with(sale: SpecSupport.sale(sequence_number: "different"))
    other_flags = prepared.with(first_submission: false)

    expect { verifier.verify!(other_uuid) }.to raise_error(Eet2::ValidationError, /header/)
    expect { verifier.verify!(other_sale) }.to raise_error(Eet2::ValidationError, /Sale/)
    expect { verifier.verify!(other_flags) }.to raise_error(Eet2::ValidationError, /header/)
  end

  it "rejects body and certificate digests that diverge from signed XML" do
    expect { verifier.verify!(prepared.with(body_sha256: "a" * 64)) }.to raise_error(Eet2::ValidationError, /body_sha256/)
    expect { verifier.verify!(prepared.with(certificate_sha256: "a" * 64)) }.to raise_error(Eet2::ValidationError, /certificate_sha256/)
  end

  it "binds persisted schema metadata to the exact official v4.1 XSD" do
    corrupted = prepared.with(schema_sha256: "a" * 64)

    expect { verifier.verify!(corrupted) }.to raise_error(Eet2::ValidationError, /schema_sha256/)
  end

  it "rejects signature tampering even when the outer request hash is updated" do
    tampered = mutate(prepared) do |document|
      value = document.at_xpath("//ds:SignatureValue", namespaces)
      value.content = value.text.sub(/\A./, value.text.start_with?("A") ? "B" : "A")
    end

    expect { verifier.verify!(tampered) }.to raise_error(Eet2::ValidationError, /signature is invalid/)
  end

  it "rejects reference, algorithm, token, ID, schema, and DTD corruption" do
    reference = mutate(prepared) { |document| document.at_xpath("//ds:Reference", namespaces)["URI"] = "#missing" }
    algorithm = mutate(prepared) { |document| document.at_xpath("//ds:DigestMethod", namespaces)["Algorithm"] = "urn:sha1" }
    token = mutate(prepared) do |document|
      document.at_xpath("//wsse:SecurityTokenReference/wsse:Reference", namespaces)["URI"] = "#missing"
    end
    duplicate_id = mutate(prepared) do |document|
      token_node = document.at_xpath("//wsse:BinarySecurityToken", namespaces)
      token_node["wsu:Id"] = document.at_xpath("//*[local-name()='Body']", namespaces)["wsu:Id"]
    end
    schema = mutate(prepared) { |document| document.at_xpath("//v4:Data", namespaces)["celk_trzba"] = "invalid" }
    dtd_xml = prepared.xml.sub(/\A/, '<!DOCTYPE x [<!ENTITY x "attack">]>')
    dtd = prepared.with(xml: dtd_xml, request_sha256: Digest::SHA256.hexdigest(dtd_xml))

    expect { verifier.verify!(reference) }.to raise_error(Eet2::ValidationError, /sole SOAP Body/)
    expect { verifier.verify!(algorithm) }.to raise_error(Eet2::ValidationError, /algorithm profile/)
    expect { verifier.verify!(token) }.to raise_error(Eet2::ValidationError, /X.509 token/)
    expect { verifier.verify!(duplicate_id) }.to raise_error(Eet2::ValidationError, /duplicate XML ID/)
    expect { verifier.verify!(schema) }.to raise_error(Eet2::SchemaValidationError)
    expect { verifier.verify!(dtd) }.to raise_error(Eet2::ValidationError, /DTD/)
    expect { verifier.verify!(Object.new) }.to raise_error(Eet2::ValidationError, /PreparedRequest/)
  end

  it "rejects every unsigned extension of the exact WS-Security profile" do
    mutations = {
      extra_security_child: lambda do |document|
        security = document.at_xpath("//wsse:Security", namespaces)
        extension = Nokogiri::XML::Node.new("Extension", document)
        extension.namespace = extension.add_namespace_definition("evil", "urn:example")
        security.add_child(extension)
      end,
      ds_object: lambda do |document|
        signature = document.at_xpath("//ds:Signature", namespaces)
        object = Nokogiri::XML::Node.new("Object", document)
        object.namespace = signature.namespace
        signature.add_child(object)
      end,
      security_attribute: ->(document) { document.at_xpath("//wsse:Security", namespaces)["role"] = "attack" },
      token_attribute: ->(document) { document.at_xpath("//wsse:BinarySecurityToken", namespaces)["extra"] = "attack" },
      token_child: lambda do |document|
        token = document.at_xpath("//wsse:BinarySecurityToken", namespaces)
        child = Nokogiri::XML::Node.new("Injected", document)
        child.namespace = token.namespace
        token.add_child(child)
      end,
      key_info_child: lambda do |document|
        key_info = document.at_xpath("//ds:KeyInfo", namespaces)
        child = Nokogiri::XML::Node.new("Object", document)
        child.namespace = key_info.namespace
        key_info.add_child(child)
      end,
      comment: lambda do |document|
        document.at_xpath("//wsse:Security", namespaces).add_child(Nokogiri::XML::Comment.new(document, "attack"))
      end,
      processing_instruction: lambda do |document|
        instruction = Nokogiri::XML::ProcessingInstruction.new(document, "attack", "value")
        document.at_xpath("//wsse:Security", namespaces).add_child(instruction)
      end,
      namespace_declaration: lambda do |document|
        document.at_xpath("//wsse:Security", namespaces).add_namespace_definition("evil", "urn:example")
      end,
      reordered_security: lambda do |document|
        security = document.at_xpath("//wsse:Security", namespaces)
        signature = security.at_xpath("./ds:Signature", namespaces).unlink
        security.children.first.add_previous_sibling(signature)
      end,
      renamed_unsigned_ids: lambda do |document|
        token = document.at_xpath("//wsse:BinarySecurityToken", namespaces)
        token["wsu:Id"] = "x509-alternate"
        document.at_xpath("//wsse:SecurityTokenReference/wsse:Reference", namespaces)["URI"] = "#x509-alternate"
        document.at_xpath("//ds:Signature", namespaces)["Id"] = "signature-alternate"
        document.at_xpath("//ds:KeyInfo", namespaces)["Id"] = "key-info-alternate"
        document.at_xpath("//wsse:SecurityTokenReference", namespaces)["wsu:Id"] = "token-reference-alternate"
      end
    }

    aggregate_failures do
      mutations.each do |name, mutation|
        expect { verifier.verify!(mutate(prepared, &mutation)) }
          .to raise_error(Eet2::ValidationError), name.to_s
      end
    end
  end

  it "rejects altered QName prefixes, nested profile content, and padded signature text" do
    prefix = mutate(prepared) do |document|
      security = document.at_xpath("//wsse:Security", namespaces)
      security.namespace = security.add_namespace_definition("security", Eet2::XmlSigner::WSSE_NAMESPACE)
    end
    nested_transform = mutate(prepared) do |document|
      transform = document.at_xpath("//ds:Transform", namespaces)
      child = Nokogiri::XML::Node.new("Object", document)
      child.namespace = transform.namespace
      transform.add_child(child)
    end
    padded_signature = mutate(prepared) do |document|
      value = document.at_xpath("//ds:SignatureValue", namespaces)
      value.content = "\n#{value.text}\n"
    end

    expect { verifier.verify!(prefix) }.to raise_error(Eet2::ValidationError, /QName|namespace/)
    expect { verifier.verify!(nested_transform) }.to raise_error(Eet2::ValidationError, /Transform/)
    expect { verifier.verify!(padded_signature) }.to raise_error(Eet2::ValidationError, /unpadded text/)
  end

  private

  def mutate(original)
    document = Nokogiri::XML::Document.parse(original.xml) { |config| config.strict.nonet }
    yield document
    xml = document.root.to_xml(
      save_with: Nokogiri::XML::Node::SaveOptions::AS_XML |
        Nokogiri::XML::Node::SaveOptions::NO_DECLARATION
    )
    original.with(xml: xml, request_sha256: Digest::SHA256.hexdigest(xml))
  end
end
