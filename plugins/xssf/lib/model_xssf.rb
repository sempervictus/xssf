# Require hackery since the plugin expects all of this to be in lib already and calls before $.unshift for the plugin lib dir
require "#{::File.join(File.dirname(__FILE__),"model","xssf_victim")}"
require "#{::File.join(File.dirname(__FILE__),"model","xssf_server")}"
require "#{::File.join(File.dirname(__FILE__),"model","xssf_log")}"
require "#{::File.join(File.dirname(__FILE__),"model","xssf_waiting_attack")}"

# require 'model/xssf_victim'
# require 'model/xssf_server'
# require 'model/xssf_log'
# require 'model/xssf_waiting_attack'