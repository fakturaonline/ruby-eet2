# frozen_string_literal: true

require "nokogiri"

RSpec.describe Eet2::XmlSignatureVerifier do
  subject(:verifier) { described_class.new(trust_policy: Eet2::TrustPolicy.playground) }

  let(:fixture_xml) { PROJECT_ROOT.join("spec/fixtures/responses/playground/accepted-live-2026-07-21.xml").binread }
  let(:namespaces) do
    {
      "soapenv" => Eet2::XmlSigner::SOAP_NAMESPACE,
      "wsse" => Eet2::XmlSigner::WSSE_NAMESPACE,
      "wsu" => Eet2::XmlSigner::WSU_NAMESPACE,
      "ds" => Eet2::XmlSigner::DS_NAMESPACE
    }
  end
  let(:verification_time) { Time.utc(2026, 7, 21, 10, 5, 55) }

  it "strictly verifies the captured Playground signature and chain" do
    document = parse(fixture_xml)
    evidence = verifier.verify!(document: document, body: body(document), verification_time: verification_time)

    expect(evidence.trust_policy_revision).to eq("playground-2026-07-21")
  end

  it "rejects body tampering after signature" do
    document = parse(fixture_xml)
    document.at_xpath("//*[local-name()='Potvrzeni']")["pok"] = "00000000-0000-4000-8000-000000000000-ff"

    expect { verify(document) }.to raise_error(Eet2::SignatureVerificationError, /digest/)
  end

  it "rejects SignatureValue tampering" do
    document = parse(fixture_xml)
    signature_value = document.at_xpath("//ds:SignatureValue", namespaces)
    signature_value.content = signature_value.text.sub(/\A./, signature_value.text.start_with?("A") ? "B" : "A")

    expect { verify(document) }.to raise_error(Eet2::SignatureVerificationError, /signature|SignatureValue/)
  end

  it "rejects duplicate Bodies and duplicate XML IDs before cryptographic acceptance" do
    duplicate_body_document = parse(fixture_xml)
    duplicate_body_document.root.add_child(body(duplicate_body_document).dup(1))
    expect { verify(duplicate_body_document) }.to raise_error(Eet2::SignatureVerificationError, /sole SOAP Body/)

    duplicate_id_document = parse(fixture_xml)
    token = duplicate_id_document.at_xpath("//wsse:BinarySecurityToken", namespaces)
    token["wsu:Id"] = body(duplicate_id_document)["wsu:Id"]
    expect { verify(duplicate_id_document) }.to raise_error(Eet2::SignatureVerificationError, /duplicate XML ID/)
  end

  it "rejects references to anything except the exact sole Body object" do
    document = parse(fixture_xml)
    token_id = document.at_xpath("//wsse:BinarySecurityToken", namespaces)["wsu:Id"]
    document.at_xpath("//ds:SignedInfo/ds:Reference", namespaces)["URI"] = "##{token_id}"

    expect { verify(document) }.to raise_error(Eet2::SignatureVerificationError, /sole SOAP Body/)
  end

  it "rejects algorithm downgrade and additional transforms" do
    sha1_document = parse(fixture_xml)
    sha1_document.at_xpath("//ds:SignatureMethod", namespaces)["Algorithm"] = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    expect { verify(sha1_document) }.to raise_error(Eet2::SignatureVerificationError, /signature algorithm/)

    transform_document = parse(fixture_xml)
    transforms = transform_document.at_xpath("//ds:Transforms", namespaces)
    transforms.add_child(transforms.element_children.first.dup(1))
    expect { verify(transform_document) }.to raise_error(Eet2::SignatureVerificationError, /[Tt]ransform/)
  end

  it "rejects InclusiveNamespaces and unexpected attributes in the observed response profile" do
    child_document = parse(fixture_xml)
    canonicalization = child_document.at_xpath("//ds:CanonicalizationMethod", namespaces)
    canonicalization.add_child('<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="soapenv"/>')
    expect { verify(child_document) }.to raise_error(Eet2::SignatureVerificationError, /canonicalization/)

    attribute_document = parse(fixture_xml)
    attribute_document.at_xpath("//ds:SignedInfo", namespaces)["unexpected"] = "true"
    expect { verify(attribute_document) }.to raise_error(Eet2::SignatureVerificationError, /unexpected attributes/)
  end

  it "rejects malformed digest, certificate token, and token reference" do
    digest_document = parse(fixture_xml)
    digest_document.at_xpath("//ds:DigestValue", namespaces).content = "not base64!"
    expect { verify(digest_document) }.to raise_error(Eet2::SignatureVerificationError, /Base64/)

    certificate_document = parse(fixture_xml)
    certificate_document.at_xpath("//wsse:BinarySecurityToken", namespaces).content = Base64.strict_encode64("not a certificate")
    expect { verify(certificate_document) }.to raise_error(Eet2::SignatureVerificationError, /X.509/)

    reference_document = parse(fixture_xml)
    reference_document.at_xpath("//ds:KeyInfo/wsse:SecurityTokenReference/wsse:Reference", namespaces)["URI"] = "#missing"
    expect { verify(reference_document) }.to raise_error(Eet2::SignatureVerificationError, /BinarySecurityToken/)
  end

  it "rejects unexpected Security and KeyInfo elements" do
    security_document = parse(fixture_xml)
    security_document.at_xpath("//wsse:Security", namespaces).add_child("<extra/>")
    expect { verify(security_document) }.to raise_error(Eet2::SignatureVerificationError, /Security contains/)

    key_info_document = parse(fixture_xml)
    key_info_document.at_xpath("//ds:KeyInfo", namespaces).add_child('<ds:KeyName xmlns:ds="http://www.w3.org/2000/09/xmldsig#">attacker</ds:KeyName>')
    expect { verify(key_info_document) }.to raise_error(Eet2::SignatureVerificationError, /KeyInfo/)
  end

  it "rejects relaxed mustUnderstand, token, SignatureValue, and DigestValue structures" do
    must_understand_document = parse(fixture_xml)
    must_understand_document.at_xpath("//wsse:Security", namespaces)["soapenv:mustUnderstand"] = "0"
    expect { verify(must_understand_document) }.to raise_error(Eet2::SignatureVerificationError, /mustUnderstand/)

    token_child_document = parse(fixture_xml)
    token_child_document.at_xpath("//wsse:BinarySecurityToken", namespaces).add_child("<unexpected/>")
    expect { verify(token_child_document) }.to raise_error(Eet2::SignatureVerificationError, /must not contain elements/)

    signature_value_child_document = parse(fixture_xml)
    signature_value_child_document.at_xpath("//ds:SignatureValue", namespaces).add_child('<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>')
    expect { verify(signature_value_child_document) }.to raise_error(Eet2::SignatureVerificationError, /SignatureValue must not/)

    digest_value_child_document = parse(fixture_xml)
    digest_value_child_document.at_xpath("//ds:DigestValue", namespaces).add_child('<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>')
    expect { verify(digest_value_child_document) }.to raise_error(Eet2::SignatureVerificationError, /DigestValue must not/)
  end

  it "rejects a wrong transform, digest method, or empty XML ID" do
    transform_document = parse(fixture_xml)
    transform_document.at_xpath("//ds:Transform", namespaces)["Algorithm"] = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    expect { verify(transform_document) }.to raise_error(Eet2::SignatureVerificationError, /transform profile/)

    digest_method_document = parse(fixture_xml)
    digest_method_document.at_xpath("//ds:DigestMethod", namespaces)["Algorithm"] = "http://www.w3.org/2000/09/xmldsig#sha1"
    expect { verify(digest_method_document) }.to raise_error(Eet2::SignatureVerificationError, /digest algorithm/)

    empty_id_document = parse(fixture_xml)
    body(empty_id_document)["wsu:Id"] = ""
    expect { verify(empty_id_document) }.to raise_error(Eet2::SignatureVerificationError, /empty XML ID/)
  end

  it "rejects missing fragment and token URIs and a wrong token encoding profile" do
    missing_reference_uri_document = parse(fixture_xml)
    missing_reference_uri_document.at_xpath("//ds:SignedInfo/ds:Reference", namespaces).remove_attribute("URI")
    expect { verify(missing_reference_uri_document) }.to raise_error(Eet2::SignatureVerificationError, /unexpected attributes|same-document/)

    empty_reference_uri_document = parse(fixture_xml)
    empty_reference_uri_document.at_xpath("//ds:SignedInfo/ds:Reference", namespaces)["URI"] = ""
    expect { verify(empty_reference_uri_document) }.to raise_error(Eet2::SignatureVerificationError, /same-document/)

    missing_token_uri_document = parse(fixture_xml)
    missing_token_uri_document.at_xpath("//ds:KeyInfo/wsse:SecurityTokenReference/wsse:Reference", namespaces).remove_attribute("URI")
    expect { verify(missing_token_uri_document) }.to raise_error(Eet2::SignatureVerificationError, /unexpected attributes|BinarySecurityToken/)

    empty_token_uri_document = parse(fixture_xml)
    empty_token_uri_document.at_xpath("//ds:KeyInfo/wsse:SecurityTokenReference/wsse:Reference", namespaces)["URI"] = ""
    expect { verify(empty_token_uri_document) }.to raise_error(Eet2::SignatureVerificationError, /BinarySecurityToken/)

    encoding_document = parse(fixture_xml)
    encoding_document.at_xpath("//wsse:BinarySecurityToken", namespaces)["EncodingType"] = "urn:wrong"
    expect { verify(encoding_document) }.to raise_error(Eet2::SignatureVerificationError, /profile/)
  end

  private

  def parse(xml)
    Nokogiri::XML::Document.parse(xml) { |config| config.strict.nonet }
  end

  def body(document)
    document.at_xpath("/soapenv:Envelope/soapenv:Body", namespaces)
  end

  def verify(document)
    verifier.verify!(document: document, body: body(document), verification_time: verification_time)
  end
end
