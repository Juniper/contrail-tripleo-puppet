module Puppet::Parser::Functions
  newfunction(:get_gateway, :type => :rvalue) do |args|
    %x( ip route | grep default | awk '{print $3}' |tr -d '\n')
  end
end
