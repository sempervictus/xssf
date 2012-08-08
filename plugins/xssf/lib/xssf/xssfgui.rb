#
# This class implements a Graphical User Interface for the XSSF Plugin
#
module Msf
	module Xssf
		module XssfGui
			include Msf::Xssf::XssfDatabase
			
			#
			# Build graphical HTML interface (logs and statistics)
			#
			def build_log_page(req, res)
				case req.query["#{PARAM_GUI_PAGE}"]
					when /^banner$/
						XSSF_RESP(res, get_html_banner())
						
					when /^victims$/
						XSSF_RESP(res, get_html_victims())
						
					when /^logs$/
						XSSF_RESP(res, get_html_logs((req.query["#{PARAM_GUI_VICTIMID}"]).to_i))
						
					when /^attack$/
						if (req.query["#{PARAM_GUI_ACTION}"] =~ /^export$/)
							filename = "LOG." + (URI.unescape(req.query["#{PARAM_GUI_EXTENTION}"])).strip
							XSSF_RESP(res, get_log_content((req.query["#{PARAM_GUI_LOGID}"]).to_i), 200, "OK", {"Content-Disposition" => "attachment; filename=#{filename}", "Content-Type" => "application/octet-stream"})
						else
							XSSF_RESP(res, get_html_attack((req.query["#{PARAM_GUI_LOGID}"]).to_i))
						end
						
					when /^stats$/
						code = %Q{
							<html><head><title>XSSF Stats</title></head>
								<frameset rows="160px,*" BORDERCOLOR=GREEN>
									<frame src="#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=banner" noresize>
									<frame src="#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=stat">
								</frameset>
							</html>
						}
						XSSF_RESP(res, code)
						
					when /^stat$/
						if (req.query["#{PARAM_GUI_JSON}"])
							XSSF_RESP(res, build_json(req.query["#{PARAM_GUI_JSON}"]), 200, "OK", {'Content-type' => 'application/octet-stream', 'Cache-Control' => 'no-cache'})
						else
							XSSF_RESP(res, get_html_stats())
						end
						
					when /^help$/
						code = %Q{
							<html><head><title>XSSF Logs</title></head>
								<frameset rows="160px,*" BORDERCOLOR=GREEN>
									<frame src="#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=banner" noresize>
									<frame name="fr1" 	src="#{XSSF_GUI_FILES}help.html">
								</frameset>
							</html>
						}
						XSSF_RESP(res, code)
							
					else
						code = %Q{
							<html><head><title>XSSF Logs</title></heads>
								<frameset rows="160px,*" BORDERCOLOR=GREEN>
									<frame src="#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=banner" noresize>
										<frameset cols="30%, 35%, 35%">
											<frame name="fr1" 	src="#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=victims">
											<frame name="fr2" 	src="#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=logs">
											<frame name="fr3" 	src="#{VICTIM_GUI}?#{PARAM_GUI_PAGE}=attack">
										</frameset>
								</frameset>
							</html>
						}
						XSSF_RESP(res, code)
				end
			end
		end
	end
end