module Msf
class DBManager

class XssfServer < ActiveRecord::Base
	has_many :xssf_victims
end

end
end