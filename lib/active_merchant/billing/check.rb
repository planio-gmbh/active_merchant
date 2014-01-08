module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    # The Check object is a plain old Ruby object, similar to CreditCard. It supports validation
    # of necessary attributes such as checkholder's name, routing and account numbers, but it is
    # not backed by any database.
    # 
    # You may use Check in place of CreditCard with any gateway that supports it. Currently, only
    # +BrainTreeGateway+ and +WirecardGateway+ support the Check object.
    class Check
      include Validateable
      
      attr_accessor :first_name, :last_name, :company_name, :routing_number, :account_number, :account_holder_type, :account_type, :number, :country
      
      # Used for Canadian bank accounts
      attr_accessor :institution_number, :transit_number
      
      # Used for Italian bank accounts
      attr_accessor :identification_number
      
      # Used for SEPA Direct Debit
      attr_accessor :mandate_id, :signed_at

      def name
        @name ||= "#{@first_name} #{@last_name}".strip
        @name = @company_name if @name.blank?
        @name
      end
      
      def name=(value)
        return if value.blank?

        @name = value
        segments = value.split(/\s+/)
        @last_name = segments.pop
        @first_name = segments.present? ? segments.join(' ') : @last_name
      end
      
      def country
        @country ||= 'US'
      end
      
      def validate
        [:name, :routing_number, :account_number, :mandate_id, :signed_at].each do |attr|
          errors.add(attr, "cannot be empty") if self.send(attr).blank?
        end
        
        errors.add(:routing_number, "is invalid") unless valid_routing_number?
        
        errors.add(:account_holder_type, "must be personal or business") if
            !account_holder_type.blank? && !%w[business personal].include?(account_holder_type.to_s)
        
        errors.add(:account_type, "must be checking or savings") if
            !account_type.blank? && !%w[checking savings].include?(account_type.to_s)

        validate_iban # TODO: only if account country in SEPA countries
      end
      
      def type
        'check'
      end
      

      def validate_iban
        iban = IBANTools::IBAN.new(self.account_number)
        iban.validation_errors.each{|e| errors.add :account_number, e }
        self.account_number = iban.code
      end

      # Routing numbers may be validated by calculating a checksum and dividing it by 10. The
      # formula is:
      #   (3(d1 + d4 + d7) + 7(d2 + d5 + d8) + 1(d3 + d6 + d9))mod 10 = 0
      # See http://en.wikipedia.org/wiki/Routing_transit_number#Internal_checksums
      def valid_routing_number?
        if country == 'US' # checksums validation only works within the U.S.
          d = routing_number.to_s.split('').map(&:to_i).select { |d| (0..9).include?(d) }
          case d.size
            when 9 then
              checksum = ((3 * (d[0] + d[3] + d[6])) +
                          (7 * (d[1] + d[4] + d[7])) +
                               (d[2] + d[5] + d[8])) % 10
              case checksum
                when 0 then true
                else        false
              end
            else false
          end
        else
          true
        end
      end
    end
  end
end
