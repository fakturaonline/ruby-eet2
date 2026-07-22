# frozen_string_literal: true

require "base64"
require "nokogiri"

RSpec.describe Eet2::TrustPolicy do
  subject(:policy) { described_class.playground }

  let(:live_certificate) do
    document = Nokogiri::XML::Document.parse(
      PROJECT_ROOT.join("spec/fixtures/responses/playground/accepted-live-2026-07-21.xml").binread
    ) { |config| config.strict.nonet }
    token = document.at_xpath("//*[local-name()='BinarySecurityToken']").text
    OpenSSL::X509::Certificate.new(Base64.strict_decode64(token))
  end

  it "loads only the pinned, versioned I.CA Playground response chain" do
    expect(policy.environment).to eq(:playground)
    expect(policy.revision).to eq("playground-2026-07-21")
    expect(policy.anchor_sha256).to eq([described_class::ROOT_SHA256])
    expect(policy.intermediate_sha256).to eq([described_class::INTERMEDIATE_SHA256])
    expect(policy).to be_frozen
  end

  it "accepts the observed EET Playground leaf profile without pinning its fingerprint" do
    expect(policy.validate_leaf_profile!(live_certificate)).to be(true)
    expect(policy.anchor_sha256 + policy.intermediate_sha256).not_to include(OpenSSL::Digest::SHA256.hexdigest(live_certificate.to_der))
  end

  it "rejects a wrong organization/environment subject" do
    wrong_subject = OpenSSL::X509::Certificate.new(live_certificate.to_der)
    wrong_subject.subject = OpenSSL::X509::Name.parse("/C=CZ/O=Other/CN=production EET/organizationIdentifier=NTRCZ-72080043")

    expect { policy.validate_leaf_profile!(wrong_subject) }.to raise_error(Eet2::CertificateVerificationError, /subject/)
  end

  it "rejects missing profile extensions and non-RSA keys" do
    missing_extensions = SpecSupport.certificate
    missing_extensions.subject = OpenSSL::X509::Name.parse(
      "/CN=NEOSTRE - playground prostredi EET/C=CZ/O=Generální finanční ředitelství/organizationIdentifier=NTRCZ-72080043"
    )
    expect { policy.validate_leaf_profile!(missing_extensions) }.to raise_error(Eet2::CertificateVerificationError, /extensions/)

    ec_key = OpenSSL::PKey::EC.generate("prime256v1")
    ec_certificate = OpenSSL::X509::Certificate.new(live_certificate.to_der)
    ec_certificate.public_key = ec_key
    expect { policy.validate_leaf_profile!(ec_certificate) }.to raise_error(Eet2::CertificateVerificationError, /RSA/)
  end

  it "loads the pinned SSSVD/NCA production response chain and profile" do
    production = described_class.production

    expect(production.environment).to eq(:production)
    expect(production.revision).to eq("production-2026-06-02-nca-rsa-2023")
    expect(production.anchor_sha256).to eq([described_class::PRODUCTION_ROOT_SHA256])
    expect(production.intermediate_sha256).to eq([described_class::PRODUCTION_INTERMEDIATE_SHA256])
    expect(production.validate_leaf_profile!(production_profile_certificate)).to be(true)
    expect(production).to be_frozen
  end

  it "verifies the published NCA production intermediate under the pinned root" do
    production = described_class.production
    root = production.anchors.fetch(0)
    intermediate = production.intermediates.fetch(0)
    store = OpenSSL::X509::Store.new
    store.add_cert(root)
    store.time = Time.utc(2026, 7, 21)
    store.flags = OpenSSL::X509::V_FLAG_X509_STRICT

    expect(intermediate.verify(root.public_key)).to be(true)
    expect(store.verify(intermediate)).to be(true), store.error_string
  end

  it "rejects a production signer outside the documented SSSVD system-certificate profile" do
    wrong_policy = production_profile_certificate(policy_oid: described_class::PLAYGROUND_POLICY_OID)
    wrong_organization = production_profile_certificate(organization: "Other")

    expect { described_class.production.validate_leaf_profile!(wrong_policy) }.to raise_error(
      Eet2::CertificateVerificationError,
      /extensions/
    )
    expect { described_class.production.validate_leaf_profile!(wrong_organization) }.to raise_error(
      Eet2::CertificateVerificationError,
      /subject/
    )
  end

  it "fails closed when a vendored trust file fingerprint differs" do
    expect do
      described_class.send(:load_certificate, described_class::ROOT_PATH, "0" * 64)
    end.to raise_error(Eet2::CertificateVerificationError, /fingerprint mismatch/)
  end

  it "requires each profile extension independently and forbids a SHA-1 leaf signature" do
    missing_basic_constraints = OpenSSL::X509::Certificate.new(live_certificate.to_der)
    missing_basic_constraints.extensions = live_certificate.extensions.reject { |extension| extension.oid == "basicConstraints" }
    expect { policy.validate_leaf_profile!(missing_basic_constraints) }.to raise_error(Eet2::CertificateVerificationError, /extensions/)

    missing_policies = OpenSSL::X509::Certificate.new(live_certificate.to_der)
    missing_policies.extensions = live_certificate.extensions.reject { |extension| extension.oid == "certificatePolicies" }
    expect { policy.validate_leaf_profile!(missing_policies) }.to raise_error(Eet2::CertificateVerificationError, /extensions/)

    sha1_certificate = sha1_profile_certificate(live_certificate)
    expect { policy.validate_leaf_profile!(sha1_certificate) }.to raise_error(Eet2::CertificateVerificationError, /SHA-1/)
  end

  def sha1_profile_certificate(template)
    key = OpenSSL::PKey::RSA.generate(2048)
    certificate = OpenSSL::X509::Certificate.new(template.to_der)
    certificate.issuer = certificate.subject
    certificate.public_key = key.public_key
    certificate.sign(key, OpenSSL::Digest.new("SHA1"))
    certificate
  end

  def production_profile_certificate(
    policy_oid: described_class::PRODUCTION_POLICY_OID,
    organization: described_class::SIGNER_ORGANIZATION
  )
    key = OpenSSL::PKey::RSA.generate(2048)
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = 42
    certificate.subject = OpenSSL::X509::Name.parse(
      "/C=CZ/O=#{organization}/CN=EET production response/organizationIdentifier=NTRCZ-72080043"
    )
    certificate.issuer = certificate.subject
    certificate.public_key = key.public_key
    certificate.not_before = Time.utc(2026, 1, 1)
    certificate.not_after = Time.utc(2028, 1, 1)

    extension_factory = OpenSSL::X509::ExtensionFactory.new
    extension_factory.subject_certificate = certificate
    extension_factory.issuer_certificate = certificate
    certificate.add_extension(extension_factory.create_extension("basicConstraints", "CA:FALSE", true))
    certificate.add_extension(extension_factory.create_extension("keyUsage", "digitalSignature,nonRepudiation", true))
    policy_der = OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId(policy_oid)])
    ]).to_der
    certificate.add_extension(OpenSSL::X509::Extension.new("certificatePolicies", policy_der, false))
    certificate.sign(key, OpenSSL::Digest.new("SHA256"))
    certificate
  end
end
