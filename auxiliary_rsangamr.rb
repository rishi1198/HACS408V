require 'msf/core'
require 'timeout'
require 'socket'

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

	sock = connect()

	rescue ::Rex::ConnectionRefused
		vprint_status("#{ip} - No BockServe 2.0A Vulnerability")
	
	info = sock.recv(1024)

	if(info != "Welcome to BockServe 2.0a! Please type 'yes' to agree to the terms and conditions, or 'view' to view the terms and conditions.\n") then
		vprint_status("#{ip} - No BockServe 2.0A Vulnerability")
	else
		sock.puts("view")
		info = sock.recv(1024)
		info = sock.recv(1024)
		sock.puts("yes")
		sock.gets()
		sock.puts("print(\"Vulnerable\")")
		timeout(5) do
        	info = sock.recv(1024)
        	if(info == "Vulnerable") then
        		vprint_status("#{ip} - BockServe 2.0A Vulnerability Exists")
        	else
        		vprint_status("#{ip} - No BockServe 2.0A Vulnerability")
        	end
    	end
		rescue Timeout::Error
    		vprint_status("#{ip} - No BockServe 2.0A Vulnerability")


	disconnect()







