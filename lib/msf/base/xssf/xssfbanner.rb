#!/usr/bin/env ruby

#
# This class implements a HTTP Server used for the new XSSF plugin.
#
module Msf
module Xssf

module XssfBanner
		Logos =
		[
'
      ___           ___           ___           ___     
     |\__\         /\  \         /\  \         /\  \    
     |:|  |       /::\  \       /::\  \       /::\  \   
     |:|  |      /:/\ \  \     /:/\ \  \     /:/\:\  \  
     |:|__|__   _\:\~\ \  \   _\:\~\ \  \   /::\~\:\  \ 
 ____/::::\__\ /\ \:\ \ \__\ /\ \:\ \ \__\ /:/\:\ \:\__\
 \::::/~~/~    \:\ \:\ \/__/ \:\ \:\ \/__/ \/__\:\ \/__/
  ~~|:|~~|      \:\ \:\__\    \:\ \:\__\        \:\__\  
    |:|  |       \:\/:/  /     \:\/:/  /         \/__/  
    |:|  |        \::/  /       \::/  /                 
     \|__|         \/__/         \/__/  Cross-Site Scripting Framework '+XSSF_VERSION+'
                                        Ludovic Courgnaud - CONIX Security',
'
 __  __     ______     ______     ______  
/\_\_\_\   /\  ___\   /\  ___\   /\  ___\ 
\/_/\_\/_  \ \___  \  \ \___  \  \ \  __\ 
  /\_\/\_\  \/\_____\  \/\_____\  \ \_\   
  \/_/\/_/   \/_____/   \/_____/   \/_/   Cross-Site Scripting Framework '+XSSF_VERSION+'
                                          Ludovic Courgnaud - CONIX Security',
'
ooooooo  ooooo  .oooooo..o  .oooooo..o oooooooooooo 
 `8888    d8\'  d8P\'    `Y8 d8P\'    `Y8 `888\'     `8 
   Y888..8P    Y88bo.      Y88bo.       888         
    `8888\'      `"Y8888o.   `"Y8888o.   888oooo8    
   .8PY888.         `"Y88b      `"Y88b  888    "    
  d8\'  `888b   oo     .d8P oo     .d8P  888         
o888o  o88888o 8""88888P\'  8""88888P\'  o888o  Cross-Site Scripting Framework '+XSSF_VERSION+'
                                                Ludovic Courgnaud - CONIX Security',
'
 ____  ____   ______    ______   ________  
|_  _||_  _|.\' ____ \ .\' ____ \ |_   __  | 
  \ \  / /  | (___ \_|| (___ \_|  | |_ \_| 
   > `\' <    _.____`.  _.____`.   |  _|    
 _/ /\'`\ \_ | \____) || \____) | _| |_     
|____||____| \______.\' \______.\'|_____| Cross-Site Scripting Framework '+XSSF_VERSION+'
                                          Ludovic Courgnaud - CONIX Security',
'
    _/      _/    _/_/_/    _/_/_/  _/_/_/_/   
     _/  _/    _/        _/        _/          
      _/        _/_/      _/_/    _/_/_/       
   _/  _/          _/        _/  _/            
# _/      _/  _/_/_/    _/_/_/    _/     Cross-Site Scripting Framework '+XSSF_VERSION+'
                                       Ludovic Courgnaud - CONIX Security'
		]
	def self.to_s
		Logos[rand(Logos.length)]		
	end
end
end
end