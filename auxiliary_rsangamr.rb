require 'msf/core'

class MetasploitModule < Msf::Auxiliary

include Msf::Exploit::Remote::Tcp
include Msf::Auxiliary::Scanner

def initialize
	super(
		'Name' => 'auxiliary_rsangamr.rb',
		'Verson' => '$Revision: 7243',
		'Description' => 'This module scans a given ip on the port 3285 to check for a vulnerable service',
		'Author' => 'Rishi Sangamreddy',
		'License' => MSF_LICENSE
	)

end


def run_host(ip)

	timeout = 1
	s = connect(false,{
		'RPORT' => 3285,
		'RHOST' => ip,
		'ConnectTimeout' => timeout 
		}
	)
