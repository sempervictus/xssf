module Msf
class DBManager

class XssfLog < ActiveRecord::Base
	belongs_to :xssf_victim
end

end
end