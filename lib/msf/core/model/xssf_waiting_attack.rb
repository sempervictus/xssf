module Msf
class DBManager

class XssfWaitingAttack < ActiveRecord::Base
	include DBSave
	
	belongs_to :xssf_victims
end

end
end