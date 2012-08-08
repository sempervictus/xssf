#
# List of patches for the WEBrick HTTP server
#
module WEBrick
  
  class HTTPServer < ::WEBrick::GenericServer   
    # Stop loging requests (faster)
    def access_log(config, req, res); return; end  
  end
  
   #TODO: Increase webrick requests URI size. HTTPREQUEST.RB l.246. Check if compatible with all Ruby versions
end
