# frozen_string_literal: true

require "bigdecimal"
require "time"

require_relative "errors"

module Eet2
  Sale = Data.define(
    :taxpayer_eic,
    :authorizing_taxpayer_eic,
    :multiple_authorization,
    :evidence_unit_id,
    :register_id,
    :sequence_number,
    :occurred_at,
    :amount_czk,
    :designated_drawdown_amount_czk,
    :drawdown_amount_czk
  ) do
    def initialize(
      taxpayer_eic:,
      evidence_unit_id:,
      register_id:,
      sequence_number:,
      occurred_at:,
      amount_czk:,
      authorizing_taxpayer_eic: nil,
      multiple_authorization: nil,
      designated_drawdown_amount_czk: nil,
      drawdown_amount_czk: nil
    )
      values = {
        taxpayer_eic: validate_eic(taxpayer_eic, :taxpayer_eic),
        authorizing_taxpayer_eic: validate_optional_eic(authorizing_taxpayer_eic),
        multiple_authorization: validate_optional_boolean(multiple_authorization),
        evidence_unit_id: validate_evidence_unit_id(evidence_unit_id),
        register_id: validate_string(register_id, :register_id, self.class::REGISTER_ID_PATTERN),
        sequence_number: validate_string(sequence_number, :sequence_number, self.class::SEQUENCE_NUMBER_PATTERN),
        occurred_at: validate_time(occurred_at),
        amount_czk: validate_amount(amount_czk, :amount_czk),
        designated_drawdown_amount_czk: validate_optional_amount(designated_drawdown_amount_czk, :designated_drawdown_amount_czk),
        drawdown_amount_czk: validate_optional_amount(drawdown_amount_czk, :drawdown_amount_czk)
      }

      super(**values)
    end

    def amount_wire_value(amount)
      cents = (amount * 100).to_i
      absolute_cents = cents.abs
      sign = cents.negative? ? "-" : ""

      format("%s%d.%02d", sign, absolute_cents / 100, absolute_cents % 100)
    end

    def occurred_at_wire_value
      occurred_at.iso8601(0)
    end

    private

    def validate_eic(value, field)
      validate_string(value, field, self.class::EIC_PATTERN)
    end

    def validate_optional_eic(value)
      return if value.nil?

      validate_eic(value, :authorizing_taxpayer_eic)
    end

    def validate_optional_boolean(value)
      return if value.nil?
      return value if value == true || value == false

      raise ValidationError, "multiple_authorization must be true, false, or nil"
    end

    def validate_evidence_unit_id(value)
      unless value.is_a?(Integer) && value.between?(1, 999_999_999)
        raise ValidationError, "evidence_unit_id must be an Integer between 1 and 999999999"
      end

      value
    end

    def validate_string(value, field, pattern)
      unless value.is_a?(String) && value.valid_encoding? && value.match?(pattern)
        raise ValidationError, "#{field} has an invalid EET2 format"
      end

      value.dup.freeze
    end

    def validate_time(value)
      unless value.is_a?(Time) && value.nsec.zero?
        raise ValidationError, "occurred_at must be a Time without fractional seconds"
      end

      value.dup.freeze
    end

    def validate_optional_amount(value, field)
      return if value.nil?

      validate_amount(value, field)
    end

    def validate_amount(value, field)
      unless value.is_a?(BigDecimal) && value.finite?
        raise ValidationError, "#{field} must be a finite BigDecimal"
      end
      unless value > self.class::MINIMUM_AMOUNT && value < self.class::MAXIMUM_AMOUNT
        raise ValidationError, "#{field} must have an absolute value below 100000000 CZK"
      end
      unless ((value * 100) % 1).zero?
        raise ValidationError, "#{field} must have at most two decimal places"
      end
      if value.zero? && value.sign == BigDecimal::SIGN_NEGATIVE_ZERO
        raise ValidationError, "#{field} cannot be negative zero"
      end

      value.dup.freeze
    end
  end

  Sale.const_set(:EIC_PATTERN, /\ACZ[0-9]{8,10}\z/)
  Sale.const_set(:REGISTER_ID_PATTERN, /\A[0-9A-Za-z.,:;\/#\-_ ]{1,20}\z/)
  Sale.const_set(:SEQUENCE_NUMBER_PATTERN, /\A[0-9A-Za-z.,:;\/#\-_ ]{1,25}\z/)
  Sale.const_set(:MINIMUM_AMOUNT, BigDecimal(-100_000_000))
  Sale.const_set(:MAXIMUM_AMOUNT, BigDecimal(100_000_000))
end
