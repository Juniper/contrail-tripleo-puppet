require 'ipaddr'
module Puppet::Parser::Functions
  newfunction(:ip_to_nic, :type => :rvalue) do |args|
    cmd = "ip addr sh |grep " + args[0] + " |awk '{print $7}' '\n'"
    `#{cmd}`
  end
end
