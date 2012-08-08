require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	# mixin Tcp
	include Msf::Exploit::Remote::Tcp
	# create alias methods
	alias_method :cleanup_tcp, :cleanup
	alias_method :run_tcp, :run
	# mixin TcpServer
	include Msf::Exploit::Remote::TcpServer
	# create alias methods
	alias_method :cleanup_tcpserver, :cleanup
	alias_method :run_tcpserver, :run
	alias_method :exploit_tcpserver, :exploit


	def initialize
		super(
			'Name'        => 'TCP Proxy',
			'Version'     => '$Revision$',
			'Description' => %q{
				Screw with TCP
			},
			'Author'      => 'unknown',
			'License'     => MSF_LICENSE
		)

		# in my case I didn't need this SSL stuff
		deregister_options('SSL', 'SSLCert', 'SSLVersion', 'RPORT')

		register_options(
			[
				OptPort.new('SRVPORT', [ true, "", 0 ]),
				OptString.new('SRVHOST', [ true, "Local listen address", "0.0.0.0" ]),
				OptString.new('RHOST', [ true, "", "0.0.0.0" ]),
			], self.class)

		#
		datastore["RPORT"] = datastore["SRVPORT"]
	end


	# run tcp server, i.e. start listening port
	def run
		exploit_tcpserver
	end
	alias_method :exploit, :run

	# cleanup method, which calls both Tcp and TcpServer cleanup
	def cleanup
		cleanup_tcp()
		cleanup_tcpserver()
	end

	# client connected, so we let the Tcp mixin connect
	def on_client_connect(client)
		print_status("client connected " + client.peerinfo())
		connect()
	end

	# client disconnected, so we let the Tcp mixin disconnect
	def on_client_close(client)
		print_status("client disconnected " + client.peerinfo())
		disconnect()
	end

	def on_client_data(client)
		begin
			# receive from client
			data = client.get_once()
			return if data.nil? or data.length == 0

			### do something evil with the tcp data here

			# send data to server
			sock.send(data, 0)
			# receive data from server
			respdata = sock.get_once()
			return if respdata.nil? or respdata.length == 0

			### do something evil with the tcp data here

			# send data back to client
			client.put(respdata)
		rescue ::EOFError, ::Errno::EACCES, ::Errno::ECONNABORTED, ::Errno::ECONNRESET
		rescue ::Exception
			print_status("Error: #{$!.class} #{$!} #{$!.backtrace}")
		end
	end


end

