require "base64"
require "uuid"

module Onelogin::Saml

	class Authrequest
		def create(settings, options = {})
			@id                = Onelogin::Saml::Authrequest.generateUniqueID(42)
			@issue_instant     = Onelogin::Saml::Authrequest.getTimestamp
			debugger
			request = generate_saml_request(settings, options)
			

			deflated_request  = Zlib::Deflate.deflate(request, 9)[2..-5]     
			base64_request    = Base64.encode64(deflated_request)  
			encoded_request   = CGI.escape(base64_request)  

			settings.idp_sso_target_url + "?SAMLRequest=" + encoded_request
		end

		private 

		def self.generateUniqueID(length)
			UUID.new.generate
		end
		
		def generate_saml_request(settings, options = {})
			options[:style] ||= :default
			case options[:style]
			when :default
				standard_saml_request(settings)
			when :google
				google_saml_request(settings)
			end
		end
		
		def standard_saml_request(settings)
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>
			<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"#{@id}\" Version=\"2.0\" IssueInstant=\"#{@issue_instant}\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"#{settings.assertion_consumer_service_url}\">" +
			"<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">#{settings.issuer}</saml:Issuer>\n" +
			"<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"#{settings.name_identifier_format}\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n" +
			"<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">" +
			"<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>\n" +
			"</samlp:AuthnRequest>"
		end
		
		def google_saml_request(settings)
			%Q(<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="#{@id}" Version="2.0" IssueInstant="#{@issue_instant}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ProviderName="#{settings.issuer}" AssertionConsumerServiceURL="#{settings.assertion_consumer_service_url}"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">#{settings.issuer}</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format="#{settings.name_identifier_format}" /></samlp:AuthnRequest>)
		end

		def self.getTimestamp
			Time.new().strftime("%Y-%m-%dT%H:%M:%SZ")
		end
	end

end
