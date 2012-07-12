module Msf
class DBManager

class XssfLog < ActiveRecord::Base
	include DBSave
	
	belongs_to :xssf_victim
end

end
end