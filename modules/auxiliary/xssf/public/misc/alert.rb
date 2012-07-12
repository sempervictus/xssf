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
			'Name'        => 'ALERT XSSF',
			'Description' => 'Simple XSSF alert'
		))
		
		register_options(
			[
				OptString.new('AlertMessage', [true, 'Message you want to send to the victim.', 'XSSF ALERT !'])
			], self.class
		)
	end

	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		send_response(cli, %Q{alert('#{datastore['AlertMessage']}');})
	end
end