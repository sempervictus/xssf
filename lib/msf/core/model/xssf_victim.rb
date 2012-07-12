module Msf
class DBManager

class XssfVictim < ActiveRecord::Base
	include DBSave
	
	has_many :xssf_logs
	
	belongs_to :xssf_server
	
	has_many :xssf_waiting_attacks
end

end
end