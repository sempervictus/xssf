module Msf
class DBManager

class XssfServer < ActiveRecord::Base
	include DBSave
	
	has_many :xssf_victims
end

end
end