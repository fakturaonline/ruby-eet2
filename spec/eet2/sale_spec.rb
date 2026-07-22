# frozen_string_literal: true

require "bigdecimal"

RSpec.describe Eet2::Sale do
  subject(:sale) { SpecSupport.sale }

  it "normalizes immutable wire values without using Float" do
    expect(sale.taxpayer_eic).to eq("CZ00000019")
    expect(sale.amount_wire_value(sale.amount_czk)).to eq("1250.00")
    expect(sale.occurred_at_wire_value).to eq("2027-01-03T12:30:45+01:00")
    expect(sale).to be_frozen
    expect(sale.taxpayer_eic).to be_frozen
  end

  it "supports every optional v4.1 sale field" do
    optional_sale = SpecSupport.sale(
      authorizing_taxpayer_eic: "CZ12345678",
      multiple_authorization: true,
      designated_drawdown_amount_czk: BigDecimal("25.00"),
      drawdown_amount_czk: BigDecimal("-2.50")
    )

    expect(optional_sale.authorizing_taxpayer_eic).to eq("CZ12345678")
    expect(optional_sale.multiple_authorization).to be(true)
    expect(optional_sale.amount_wire_value(optional_sale.drawdown_amount_czk)).to eq("-2.50")
  end

  it "accepts the XSD amount boundaries but rejects the exclusive limits" do
    expect(SpecSupport.sale(amount_czk: BigDecimal("99999999.99")).amount_czk).to eq(BigDecimal("99999999.99"))
    expect(SpecSupport.sale(amount_czk: BigDecimal("-99999999.99")).amount_czk).to eq(BigDecimal("-99999999.99"))

    expect { SpecSupport.sale(amount_czk: BigDecimal("100000000.00")) }.to raise_error(Eet2::ValidationError, /below/)
    expect { SpecSupport.sale(amount_czk: BigDecimal("-100000000.00")) }.to raise_error(Eet2::ValidationError, /below/)
  end

  it "rejects non-decimal, non-finite, excessive-scale, and negative-zero amounts" do
    expect { SpecSupport.sale(amount_czk: 12.34) }.to raise_error(Eet2::ValidationError, /BigDecimal/)
    expect { SpecSupport.sale(amount_czk: BigDecimal("NaN")) }.to raise_error(Eet2::ValidationError, /finite/)
    expect { SpecSupport.sale(amount_czk: BigDecimal("1.001")) }.to raise_error(Eet2::ValidationError, /two decimal/)
    expect { SpecSupport.sale(amount_czk: BigDecimal("-0.00")) }.to raise_error(Eet2::ValidationError, /negative zero/)
  end

  it "rejects invalid identifiers and empty optional values" do
    expect { SpecSupport.sale(taxpayer_eic: "CZ123") }.to raise_error(Eet2::ValidationError, /taxpayer_eic/)
    expect { SpecSupport.sale(evidence_unit_id: 0) }.to raise_error(Eet2::ValidationError, /evidence_unit_id/)
    expect { SpecSupport.sale(register_id: "emoji-🚫") }.to raise_error(Eet2::ValidationError, /register_id/)
    expect { SpecSupport.sale(sequence_number: "x" * 26) }.to raise_error(Eet2::ValidationError, /sequence_number/)
    expect { SpecSupport.sale(authorizing_taxpayer_eic: "") }.to raise_error(Eet2::ValidationError, /authorizing_taxpayer_eic/)
    expect { SpecSupport.sale(multiple_authorization: "true") }.to raise_error(Eet2::ValidationError, /multiple_authorization/)
  end

  it "rejects fractional event timestamps rather than silently changing sale identity" do
    fractional_time = Time.at(1_800_000_000, 123_456, :microsecond)

    expect { SpecSupport.sale(occurred_at: fractional_time) }.to raise_error(Eet2::ValidationError, /fractional seconds/)
  end
end
