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

		begin
			sock = connect()
		rescue ::Rex::ConnectionRefused
			print_bad("#{ip} - No BockServe 2.0A Vulnerability")
			return
		end

		info = sock.recv(1024)

		if(info != "Welcome to BockServe 2.0a! Please type 'yes' to agree to the terms and conditions, or 'view' to view the terms and conditions.\n") then
			print_bad("#{ip} - No BockServe 2.0A Vulnerability")
		else
			sock.puts("view")
			info = sock.recv(1200)
			info = sock.recv(1024)
			sock.puts("yes")
			info = sock.recv(1024)
			sock.puts("print('Vulnerable')")
		
			begin
				Timeout.timeout(3) do
			       	info = sock.recv(1024)
			    end
			rescue ::Timeout::Error
			    print_bad("#{ip} - No BockServe 2.0A Vulnerability")
			    disconnect()
			    return
			end

			if(info == "Vulnerable\n") then
				print_good("#{ip} - BockServe 2.0A Vulnerability Exists")
			else
				print_bad("#{ip} - No BockServe 2.0A Vulnerability")
			    disconnect()
			    return
			end

		end
	disconnect()

	end

end


