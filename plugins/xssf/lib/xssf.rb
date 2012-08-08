#
# XSSF management
#
require "#{::File.join(File.dirname(__FILE__),"xssf","xssftunnel")}"
require "#{::File.join(File.dirname(__FILE__),"xssf","xssfdatabase")}"
require "#{::File.join(File.dirname(__FILE__),"xssf","xssfgui")}"
require "#{::File.join(File.dirname(__FILE__),"xssf","xssfmaster")}"
require "#{::File.join(File.dirname(__FILE__),"xssf","xssfserver")}"
require "#{::File.join(File.dirname(__FILE__),"xssf","webrickpatches")}"

# require 'xssf/xssftunnel'
# require 'xssf/xssfdatabase'
# require 'xssf/xssfgui'
# require 'xssf/xssfmaster'
# require 'xssf/xssfserver'
# require 'xssf/webrickpatches'

module Msf
	module Xssf

		XSSF_VERSION	= '2.2.1'
		
		### CONSTANTS ###
		SERVER_PORT		= 8888
		SERVER_URI 		= '/'
		
		VICTIM_LOOP		= 'loop'			# Loads victim malicious loop code inside page (Javascript)
		VICTIM_ASK		= 'ask'
		VICTIM_ANSWER	= 'answer'
		VICTIM_SAFARI	= 'cookie_safari'	# Safari needs a first special POST insade Iframe to set Cross-Domain Cookie
		VICTIM_TEST		= 'test.html'
		VICTIM_GUI		= 'gui.html'
		VICTIM_INTERVAL	= 10				# in sec (victim requests for new code comming from attacker each 10 seconds)
		
		PARAM_LOCATION	= 'location'		# Information relative to parameters in request (POST/GET)
		PARAM_INTERVAL	= 'interval'
		PARAM_RESPONSE	= 'response'
		PARAM_HEADERS	= 'headers'
		PARAM_NAME		= 'name'
		PARAM_RESPID	= 'responseid'		# Useful for XSSF Tunnel
		PARAM_ID		= 'id'				# Rescue param for browser desactivating cookies
		
		PARAM_GUI_PAGE		= 'guipage'			# main | banner | victims | logs | attack | stats | stat | help | helpmenu | helpdetails
		PARAM_GUI_ACTION	= 'guiaction'		# view | (export [if log_page=attack])
		PARAM_GUI_JSON		= 'guijson'			# if guipage=stat
		PARAM_GUI_VICTIMID	= 'guivictimid'
		PARAM_GUI_LOGID		= 'guilogid'
		PARAM_GUI_EXTENTION	= 'guiextention'	# Extention of file to export
		
		XSSF_PUBLIC		= [false]			# Defines if XSSF GUI pages or Tunnel are accessible from internet (Default is only by local machine running MSF)
		XSSF_MODE		= ['Normal']		# Quiet / Normal / Verbose / Debug : Defines XSSF attack messages. 
												# Quiet mode does not display anything. 
												# Normal mode displays attacks and tunnel status messages only. 
												# Verbose mode displays all 'Normal' mode messages plus received results from victims
												# Debug mode displays all 'Verbose' mode messages plus XSSF exceptions error messages if exceptions are trigered (should not :-) )
		
		INCLUDED_FILES = ::File.join(File.dirname(__FILE__),"..","data")
		#Config.data_directory + '/xssf'
		XSSF_RRC_FILES = '/resources/'
		XSSF_GUI_FILES = '/gui/'
		XSSF_LOG_FILES = '/logs/'
		
		AUTO_ATTACKS = []					# Automated attacks for XSSF (cleared when closing XSSF)
		
		TUNNEL = Hash.new					# Information relative to XSSF Tunnel
		TUNNEL_LOCKED = Mutex.new			# Manages accesses to TUNNEL
		TUNNEL_TIMEOUT= 10
		
		
		#								    TUNNEL
		#         	---------------------------------------------------------
		#			|  id  |     code     |   response   |      headers     |
		#			---------------------------------------------------------
		#			---------------------------------------------------------	
		#			|  01  |     AJAX     |   abcdefgh   |      headers     |
		#			---------------------------------------------------------	
		#			|  02  |     AJAX     |   xyzhrjeu   |      headers     |
		#			---------------------------------------------------------	
		#			|  ..  |     ....     |   ........   |   ............   |
		#
		#
		#   Tunnel = { 	'id' => [code, response, headers],
		#				'01' => [AJAX, abcdefgh, headers]}
		# 	When tunneled victim asks: concatenate and send all codes where (code != nil). Sets all sents to nil
    end
end

require "#{::File.join(File.dirname(__FILE__),"xssf","xssfbanner")}"

# require 'xssf/xssfbanner'