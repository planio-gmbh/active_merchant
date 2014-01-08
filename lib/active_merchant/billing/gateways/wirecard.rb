require 'base64'

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class WirecardGateway < Gateway
      # Test server location
      TEST_URLS = {
        :elastic_payments =>  'https://api-test.wirecard.com/engine/rest/paymentmethods/', #'http://requestb.in/q1oqovq1'
        :legacy_c3_gateway => 'https://c3-test.wirecard.com/secure/ssl-gateway'
      }
     
      # Live server location
      LIVE_URLS = {
        :elastic_payments => '',
        :legacy_c3_gateway => 'https://c3.wirecard.com/secure/ssl-gateway'
      }

      # The Namespaces are not really needed, because it just tells the System, that there's actually no namespace used.
      # It's just specified here for completeness.
      ENVELOPE_NAMESPACES = {
        :elastic_payments => {
  				'xmlns' => 'http://www.elastic-payments.com/schema/payment'
        },
        :legacy_c3_gateway => {
          'xmlns:xsi' => 'http://www.w3.org/1999/XMLSchema-instance',
  				'xsi:noNamespaceSchemaLocation' => 'wirecard.xsd'
			  }
			}

			PERMITTED_TRANSACTIONS = %w[ AUTHORIZATION CAPTURE_AUTHORIZATION PURCHASE DEBIT ]

      RETURN_CODES = %w[ ACK NOK ]

      # Wirecard only allows phone numbers with a format like this: +xxx(yyy)zzz-zzzz-ppp, where:
      #   xxx = Country code
      #   yyy = Area or city code
      #   zzz-zzzz = Local number
      #   ppp = PBX extension
      # For example, a typical U.S. or Canadian number would be "+1(202)555-1234-739" indicating PBX extension 739 at phone
      # number 5551234 within area code 202 (country code 1).
      VALID_PHONE_FORMAT = /\+\d{1,3}(\(?\d{3}\)?)?\d{3}-\d{4}-\d{3}/

      BAD_XML_ERROR_MESSAGE = "No valid XML response message received. \
                            Propably wrong credentials supplied with HTTP header."

      # The countries the gateway supports merchants from as 2 digit ISO country codes
      # TODO: Check supported countries
      self.supported_countries = ['DE']

      # Wirecard supports all major credit and debit cards:
      # Visa, Mastercard, American Express, Diners Club,
      # JCB, Switch, VISA Carte Bancaire, Visa Electron and UATP cards.
      # They also support the latest anti-fraud systems such as Verified by Visa or Master Secure Code.
      self.supported_cardtypes = [
        :visa, :master, :american_express, :diners_club, :jcb, :switch
      ]

      # The homepage URL of the gateway
      self.homepage_url = 'http://www.wirecard.com'

      # The name of the gateway
      self.display_name = 'Wirecard'

      # The currency should normally be EUROs
      self.default_currency = 'EUR'

      def money_format
        return :cents if @options[:api_version] == :legacy_c3_gateway
      end

      def initialize(options = {})
        # verify that username and password are supplied
        [:legacy_c3_gateway, :elastic_payments].each do |api_version|
          requires!(options[api_version], :login, :password)
        end
        # unfortunately Wirecard also requires a BusinessCaseSignature in the XML request
        requires!(options[:legacy_c3_gateway], :signature)
        @options = options
        super
      end

      # Should run against the test servers or not?
      def test?
        @options[:test] || super
      end

      # Authorization
      def authorize(money, creditcard_or_check, options = {})
        if options[:transaction_mode] == :eft
          Response.new(true, "EFT does not support Authorizations. Returning success, but we didn't do anything.")
        else
          prepare_options_hash(options)
          @options[:credit_card_or_check] = creditcard_or_check
          request = build_request(:authorization, money, @options)
          commit(request, options)
        end
      end
      
      # Authorize 1 Euro to get a guwid
      # This is the official way of doing a store according to WC's support staff.
      # The authorization will invalidate after a couple of days, because it will never be captured.
      # YOU SHOULD MAKE THIS CLEAR TO YOUR USERS IN YOUR T&C's.
      def store(creditcard_or_check, options = {})
        authorize(100, creditcard_or_check, options.merge(:recurring => 'Initial'))
      end

      # update means unstoring and storing the new one
      def update(billing_id, creditcard_or_check, options = {})
        unstore(billing_id, options)
        store(creditcard_or_check, options)
      end

      # this is not supported by wirecard. just be sure to forget the guwid and never use it again ;-)
      def unstore(billing_id, options = {})
        # NOP
      end

      # Capture Authorization
      def capture(money, authorization, options = {})
        prepare_options_hash(options)
        @options[:authorization] = authorization
        request = build_request(:capture_authorization, money, @options)
        commit(request, options)
      end


      # Purchase
      def purchase(money, creditcard_or_billing_id, options = {})
        prepare_options_hash(options)
        if creditcard_or_billing_id.is_a?(String)
          @options[:authorization] = creditcard_or_billing_id
          @options[:recurring] = 'Repeated'
        else
          @options[:credit_card_or_check] = creditcard_or_billing_id
        end
        request = build_request(:purchase, money, @options)
        commit(request, options)
      end

      # Debit
      def debit(money, check, options={})
        prepare_options_hash(options)

        @options[:credit_card_or_check] = check
        @options[:recurring] = options[:authorization].present? ? 'recurring' : 'first'

        request = build_request(:debit, money, @options)
        commit(request, options)
      end

    private

      def prepare_options_hash(options)
        options[:api_version] ||= :legacy_c3_gateway
        @options.update(options)
        setup_address_hash!(options)
      end

      # Create all address hash key value pairs so that
      # it still works if only provided with one or two of them
      def setup_address_hash!(options)
        options[:billing_address] = options[:billing_address] || options[:address] || {}
        options[:shipping_address] = options[:shipping_address] || {}
        # Include Email in address-hash from options-hash
        options[:billing_address][:email] = options[:email] if options[:email]
      end

      # Contact WireCard, make the XML request, and parse the
      # reply into a Response object
      def commit(request, options={})
	      headers = { 'Content-Type' => 'application/xml',
	                  'Accept' => 'application/xml',
	                  'Authorization' => encoded_credentials }

	      response = parse(ssl_post(test? ? TEST_URLS[options[:api_version]] : LIVE_URLS[options[:api_version]], request, headers), options)
        # Pending Status also means Acknowledged (as stated in their specification)
	      success = response[:TransactionState] == "success" || response[:FunctionResult] == "ACK" || response[:FunctionResult] == "PENDING"
	      message = response[:Message]
        authorization = if success && @options[:action] == :authorization
          response[:GuWID]
        elsif success && @options[:transaction_mode] == :eft
          response[:TransactionID]
        else
          nil
        end

        Response.new(success, message, response,
          :test => test?,
          :authorization => authorization,
          :avs_result => { :code => response[:avsCode] },
          :cvv_result => response[:cvCode]
        )
      end

      # Generates the complete xml-message, that gets sent to the gateway
      def build_request(action, money, options = {})
				xml = Builder::XmlMarkup.new :indent => 2
				xml.instruct!

        case options[:api_version]
        when :elastic_payments
          xml.tag! 'payment', ENVELOPE_NAMESPACES[:elastic_payments] do
            xml.tag! 'merchant-account-id', options[:elastic_payments][:merchant_account_id] || options[:legacy_c3_gateway][:login]
            add_transaction_data(xml, action, money, options)
          end
        when :legacy_c3_gateway
  				xml.tag! 'WIRECARD_BXML' do
  				  xml.tag! 'W_REQUEST' do
            xml.tag! 'W_JOB' do
                # TODO: OPTIONAL, check what value needs to be insert here
                xml.tag! 'JobID', 'test dummy data'
                # UserID for this transaction
                xml.tag! 'BusinessCaseSignature', options[:legacy_c3_gateway][:signature] || options[:legacy_c3_gateway][:login]
                # Create the whole rest of the message
                add_transaction_data(xml, action, money, options)
  				    end
  				  end
  				end
  			end
				xml.target!
      end

      # Includes the whole transaction data (payment, creditcard, address)
      def add_transaction_data(xml, action, money, options = {})
        options[:action] = action
        # TODO: require order_id instead of auto-generating it if not supplied
        options[:order_id] ||= generate_unique_id
        transaction_type = action.to_s.upcase

        case options[:api_version]
        when :elastic_payments
          raise 'Only Sepa direct debit transactions are supported by elastic payments api client atm.' unless options[:transaction_mode] == :eft
          xml.tag! 'request-id', options[:order_id]
          case options[:transaction_mode]
          when :eft
            xml.tag! 'transaction-type', 'pending-debit'
            xml.tag! 'payment-methods' do
              xml.tag! 'payment-method', :name => 'sepadirectdebit'
            end
            xml.tag! 'periodic' do
              xml.tag! 'periodic-type', 'recurring'
              xml.tag! 'sequence-type', options[:recurring]
            end
            if options[:authorization]
              xml.tag! 'parent-transaction-id', options[:authorization]
            end
          end
          add_invoice(xml, money, options)
          add_check(xml, options[:credit_card_or_check])
          xml.tag! 'descriptor', options[:usage] unless options[:usage].blank?
        when :legacy_c3_gateway
          mode = options[:transaction_mode] == :eft ? 'FT' : 'CC'
          xml.tag! "FNC_#{mode}_#{transaction_type}" do
            # TODO: OPTIONAL, check which param should be used here
            xml.tag! 'FunctionID', options[:description] || 'Test dummy FunctionID'

            xml.tag! "#{mode}_TRANSACTION", :mode => test? ? 'demo' : 'live' do
              xml.tag! 'TransactionID', options[:order_id]
              if options[:recurring] == 'Repeated' && options[:authorization]
                add_invoice(xml, money, options)
                xml.tag!((options[:transaction_mode] == :eft ? 'ReferenceGuWID' : 'GuWID'), options[:authorization])
              elsif [:authorization, :purchase, :debit].include?(action)
                add_invoice(xml, money, options)
                if options[:transaction_mode] == :eft
                  add_check(xml, options[:credit_card_or_check])
                else
                  add_creditcard(xml, options[:credit_card_or_check])
                end
                add_address(xml, options[:billing_address])
              elsif action == :capture_authorization
                xml.tag! 'GuWID', options[:authorization] if options[:authorization]
              end
              xml.tag! 'Usage', options[:usage] unless options[:usage].blank?
            end
          end
        end
      end

			# Includes the payment (amount, currency, country) to the transaction-xml
      def add_invoice(xml, money, options)
        case options[:api_version]
        when :elastic_payments
          xml.tag! 'requested-amount', amount(money), :currency => self.default_currency
        when :legacy_c3_gateway
          xml.tag! 'Amount', amount(money)
          xml.tag! 'Currency', options[:currency] || currency(money)
          xml.tag! 'CountryCode', options[:billing_address][:country] if options[:transaction_mode] != :eft and options[:billing_address] and options[:billing_address][:country]
          xml.tag! 'RECURRING_TRANSACTION' do
            xml.tag! 'Type', options[:recurring] || 'Single'
          end
        end
      end

			# Includes the credit-card data to the transaction-xml
			def add_creditcard(xml, creditcard)
        raise "Creditcard must be supplied!" if creditcard.nil?
        xml.tag! 'CREDIT_CARD_DATA' do
          xml.tag! 'CreditCardNumber', creditcard.number
          xml.tag! 'CVC2', creditcard.verification_value
          xml.tag! 'ExpirationYear', creditcard.year
          xml.tag! 'ExpirationMonth', format(creditcard.month, :two_digits)
          xml.tag! 'CardHolderName', [creditcard.first_name, creditcard.last_name].join(' ')
        end
      end
      
      # Adds check data to the transaction-xml
      def add_check(xml, check)
        raise "Check must be supplied!" if check.nil?
        case options[:api_version]
        when :elastic_payments
          xml.tag! 'account-holder' do
            xml.tag! 'first-name', check.first_name
            xml.tag! 'last-name', check.last_name
          end
          xml.tag! 'bank-account' do
            xml.tag! 'iban', check.account_number
            xml.tag! 'bic', check.routing_number
          end
          xml.tag! 'mandate' do
            xml.tag! 'mandate-id', check.mandate_id
            xml.tag! 'signed-date', check.signed_at.strftime('%F')
          end
          xml.tag! 'creditor-id', options[:elastic_payments][:creditor_id]
        when :legacy_c3_gateway
          xml.tag! 'EXTERNAL_ACCOUNT' do
            xml.tag! 'FirstName', check.first_name
            xml.tag! 'LastName', check.last_name
            xml.tag! 'CompanyName', check.company_name unless check.company_name.blank?
            xml.tag! 'AccountNumber', check.account_number
            xml.tag! 'AccountType', check.account_type == 'savings' ? 'S' : 'C'
            xml.tag! 'BankCode', check.routing_number
            xml.tag! 'Country', check.country
            xml.tag! 'CheckNumber', check.number
            unless check.identification_number.blank?
              xml.tag! 'COUNTRY_SPECIFIC' do
                xml.tag! 'IdentificationNumber', check.identification_number
              end
            end
          end
        end
      end

			# Includes the IP address of the customer to the transaction-xml
      def add_customer_data(xml, options)
        return unless options[:ip]
				xml.tag! 'CONTACT_DATA' do
					xml.tag! 'IPAddress', options[:ip]
				end
			end

      # Includes the address to the transaction-xml
      def add_address(xml, address)
        return if address.nil?
        xml.tag! 'CORPTRUSTCENTER_DATA' do
	        xml.tag! 'ADDRESS' do
	          xml.tag! 'Address1', address[:address1]
	          xml.tag! 'Address2', address[:address2] if address[:address2]
	          xml.tag! 'City', address[:city]
	          xml.tag! 'ZipCode', address[:zip]
	          
	          if address[:state] =~ /[A-Za-z]{2}/ && address[:country] =~ /^(us|ca)$/i
	            xml.tag! 'State', address[:state].upcase
	          end
	          
	          xml.tag! 'Country', address[:country]
            xml.tag! 'Phone', address[:phone] if address[:phone] =~ VALID_PHONE_FORMAT
	          xml.tag! 'Email', address[:email]
	        end
	      end
      end


      # Read the XML message from the gateway and check if it was successful,
			# and also extract required return values from the response.
      def parse(xml, options={})
        response = {}
        xml = REXML::Document.new(xml)

        case options[:api_version]
        when :elastic_payments
          response[:TransactionState] = REXML::XPath.first(xml, "/payment/transaction-state").try(:text)
          statuses = REXML::XPath.first(xml, "/payment/statuses")
          if response[:TransactionState].present?
            response[:TransactionID] = REXML::XPath.first(xml, "/payment/transaction-id").try(:text)
            response[:RequestID] = REXML::XPath.first(xml, "/payment/request-id").try(:text)
            response[:ReferenceID] = REXML::XPath.first(xml, "/payment/provider-transaction-reference-id").try(:text)
            response[:DueDate] = REXML::XPath.first(xml, "/payment/due-date").try(:text)
            response[:Message] = statuses.map{|status| status.attributes['description']}
          else
            response[:Message] = BAD_XML_ERROR_MESSAGE
          end
        when :legacy_c3_gateway
          basepath = '/WIRECARD_BXML/W_RESPONSE'

          if root = REXML::XPath.first(xml, "#{basepath}/W_JOB")
            parse_response(response, root, options)
          elsif root = REXML::XPath.first(xml, "//ERROR")
            parse_error(response, root)
          else
            response[:Message] = BAD_XML_ERROR_MESSAGE
          end

        end
        response
      end

      # Parse the <ProcessingStatus> Element which contains all important information
      def parse_response(response, root, options={})
        status = nil
        mode = options[:transaction_mode] == :eft ? 'FT' : 'CC'
        # get the root element for this Transaction
        root.elements.to_a.each do |node|
          if node.name =~ Regexp.new("FNC_#{mode}_")
            status = REXML::XPath.first(node, "#{mode}_TRANSACTION/PROCESSING_STATUS")
            transaction_id = REXML::XPath.first(node, "#{mode}_TRANSACTION/TransactionID")
            if transaction_id && transaction_id.respond_to?(:text)
              response[:TransactionID] = transaction_id.text
            end
          end
        end
        message = []
        if status
          if info = status.elements['Info']
            message << info.text
          end
          # Get basic response information
          status.elements.to_a.each do |node|
            response[node.name.to_sym] = (node.text || '').strip
          end
        end
        message = parse_error(root, message)
        response[:Message] = message
      end

      # Parse a generic error response from the gateway
      def parse_error(root, message = [])
        # Get errors if available and append them to the message
        message += errors_to_array(root)
      end

      # Parses all <ERROR> elements in the response and converts the information
      # to a single string
      def errors_to_array(root)
        # Get context error messages (can be 0..*)
        errors = []
        REXML::XPath.each(root, "//ERROR | //DETAIL") do |error_elem|
          error = {}
          error[:Advice] = []
          error[:Message] = error_elem.elements['Message'].text
          error_elem.elements.each('Advice') do |advice|
            error[:Advice] << advice.text
          end
          errors << error
        end
        # Convert all messages to nice strings
        result = []
        errors.each do |error|
          string = error[:Message]
          error[:Advice].each_with_index do |advice, index|
            string << ' (' if index == 0
            string << "#{index+1}. #{advice}"
            string << ' and ' if index < error[:Advice].size - 1
            string << ')' if index == error[:Advice].size - 1
          end
          result << string
        end
        result
      end

      # Encode login and password in Base64 to supply as HTTP header
      # (for http basic authentication)
      def encoded_credentials
        credentials = [@options[@options[:api_version]][:login], @options[@options[:api_version]][:password]].join(':')
        "Basic " << Base64.encode64(credentials).strip
      end
      
    end
  end
end
