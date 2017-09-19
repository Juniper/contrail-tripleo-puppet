# Copyright 2016 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# == Class: tripleo::profile::base::neutron::opencontrail::vrouter
#
# Opencontrail profile to run the contrail vrouter
#
# === Parameters
#
# [*step*]
#   (Optional) The current step of the deployment
#   Defaults to hiera('step')
#
# [*admin_password*]
#  (optional) admin password
#  String value.
#  Defaults to hiera('contrail::admin_password')
#
# [*admin_tenant_name*]
#  (optional) admin tenant name.
#  String value.
#  Defaults to hiera('contrail::admin_tenant_name')
#
# [*admin_token*]
#  (optional) admin token
#  String value.
#  Defaults to hiera('contrail::admin_token')
#
# [*admin_user*]
#  (optional) admin user name.
#  String value.
#  Defaults to hiera('contrail::admin_user')
#
# [*analytics_server_list*]
#  (optional) list of analytics server
#  Array of String values.
#  Defaults to hiera('contrail_analytics_node_ips')
#
# [*api_server*]
#  (optional) IP address of api server
#  String value.
#  Defaults to hiera('contrail_config_vip',hiera('internal_api_virtual_ip'))
#
# [*api_port*]
#  (optional) port of api server
#  String value.
#  Defaults to hiera('contrail::api_port')
#
# [*auth_host*]
#  (optional) keystone server ip address
#  String (IPv4) value.
#  Defaults to hiera('contrail::auth_host')
#
# [*auth_port*]
#  (optional) keystone port.
#  Integer value.
#  Defaults to hiera('contrail::auth_port')
#
# [*auth_port_ssl*]
#  (optional) keystone ssl port.
#  Integer value.
#  Defaults to hiera('contrail::auth_port_ssl')
#
# [*auth_protocol*]
#  (optional) authentication protocol.
#  String value.
#  Defaults to hiera('contrail::auth_protocol')
#
# [*ca_file*]
#  (optional) ca file name
#  String value.
#  Defaults to hiera('contrail::service_certificate',false)
#
# [*cert_file*]
#  (optional) cert file name
#  String value.
#  Defaults to hiera('contrail::service_certificate',false)
#
# [*control_server*]
#  (optional) Contrail control server IP
#  Array of String (IPv4) value.
#  Defaults to hiera('contrail_control_node_ips')
#
# [*disc_server_ip*]
#  (optional) IPv4 address of discovery server.
#  String (IPv4) value.
#  Defaults to hiera('contrail::disc_server_ip')
#
# [*disc_server_port*]
#  (optional) port Discovery server listens on.
#  Integer value.
#  Defaults to hiera('contrail::disc_server_port')
#
# [*gateway*]
#  (optional) Default GW for vrouter
#  String (IPv4) value.
#  Defaults to hiera('contrail::vrouter::gateway')
#
# [*host_ip*]
#  (optional) host IP address of vrouter
#  String (IPv4) value.
#  Defaults to hiera('contrail::vrouter::host_ip')

# [*dpdk_driver*]
#  (optional) dpdk driver
#  String value.
#  Defaults to hiera('contrail::vrouter::dpdk_driver')
#
# [*insecure*]
#  (optional) insecure connections allowed
#  String value.
#  Defaults to hiera('contrail::insecure')
#
# [*memcached_servers*]
#  (optional) memcached server ip
#  String (IPv4) value.
#  Defaults to hiera('contrail::memcached_server')
#
# [*metadata_secret*]
#  (optional) secret for metadata
#  String value.
#  Defaults to hiera('contrail::vrouter::metadata_proxy_shared_secret')
#
# [*netmask*]
#  (optional) netmask for vrouter interface
#  String (IPv4) value.
#  Defaults to hiera('contrail::vrouter::netmask')
#
# [*physical_interface*]
#  (optional) vrouter interface
#  String value.
#  Defaults to hiera('contrail::vrouter::physical_interface')
#
# [*internal_vip*]
#  (optional) Public VIP to Keystone
#  String (IPv4) value.
#  Defaults to hiera('internal_api_virtual_ip')
#
# [*is_tsn*]
#  (optional) Turns vrouter into TSN
#  String value.
#  Defaults to hiera('contrail::vrouter::is_tsn',false)
#
# [*is_dpdk*]
#  (optional) Turns vrouter into DPDK Compute Node
#  String value.
#  Defaults to hiera('contrail::vrouter::is_dpdk',false)
#
class tripleo::network::contrail::vrouter (
  $step                  = hiera('step'),
  $admin_password        = hiera('contrail::admin_password'),
  $admin_tenant_name     = hiera('contrail::admin_tenant_name'),
  $admin_token           = hiera('contrail::admin_token'),
  $admin_user            = hiera('contrail::admin_user'),
  $analytics_server_list = hiera('contrail_analytics_node_ips',hiera('contrail::vrouter::analytics_node_ips')),
  $api_port              = hiera('contrail::api_port'),
  $api_server            = hiera('contrail_config_vip',hiera('internal_api_virtual_ip')),
  $auth_host             = hiera('contrail::auth_host'),
  $auth_port             = hiera('contrail::auth_port'),
  $auth_port_ssl         = hiera('contrail::auth_port_ssl'),
  $auth_protocol         = hiera('contrail::auth_protocol'),
  $ca_file               = hiera('contrail::service_certificate', undef),
  $cert_file             = hiera('contrail::service_certificate', undef),
  $contrail_version      = hiera('contrail::version',4),
  $control_server        = hiera('contrail_config_node_ips',hiera('contrail::vrouter::control_node_ips')),
  $disc_server_ip        = hiera('contrail_config_vip',hiera('internal_api_virtual_ip')),
  $disc_server_port      = hiera('contrail::disc_server_port'),
  $gateway               = hiera('contrail::vrouter::gateway'),
  $host_ip               = hiera('contrail::vrouter::host_ip'),
  $insecure              = hiera('contrail::insecure'),
  $memcached_servers     = hiera('contrail::memcached_server'),
  $metadata_secret       = hiera('contrail::vrouter::metadata_proxy_shared_secret'),
  $netmask               = hiera('contrail::vrouter::netmask'),
  $physical_interface    = hiera('contrail::vrouter::physical_interface'),
  $internal_vip          = hiera('internal_api_virtual_ip'),
  $is_tsn                = hiera('contrail::vrouter::is_tsn',false),
  $is_dpdk               = hiera('contrail::vrouter::is_dpdk',false),
  $dpdk_driver           = hiera('contrail::vrouter::dpdk_driver',false),
  $ssl_enabled           = hiera('contrail_ssl_enabled', false)
) {
  $cidr = netmask_to_cidr($netmask)
  $collector_server_list_8086 = join([join($analytics_server_list, ':8086 '),':8086'],'')
  if size($control_server) == 0 {
    $control_server_list = ''
    $control_server_list_53 = ''
    $control_server_list_5269 = ''
  } else {
    $control_server_list = join($control_server, ' ')
    $control_server_list_53 = join([join($control_server, ':53 '),':53'],'')
    $control_server_list_5269 = join([join($control_server, ':5269 '),':5269'],'')
  }

  $keystone_config_common = {
    'KEYSTONE' => {
      'admin_password'    => $admin_password,
      'admin_tenant_name' => $admin_tenant_name,
      'admin_user'        => $admin_user,
      'auth_host'         => $auth_host,
      'auth_protocol'     => $auth_protocol,
      'insecure'          => $insecure,
      'memcached_servers' => $memcached_servers,
    },
  }
  $vnc_api_lib_config_common = {
    'auth' => {
      'AUTHN_SERVER'   => $auth_host,
      'AUTHN_PROTOCOL' => $auth_protocol,
    },
  }
  if $auth_protocol == 'https' {
    $keystone_config_auth_specific = {
      'KEYSTONE' => {
        'auth_port'         => $auth_port_ssl,
        'certfile'          => $cert_file,
        'cafile'            => $ca_file,
      },
    }
    $vnc_api_lib_config_auth_specific = {
      'auth' => {
        'AUTHN_PORT'     => $auth_port_ssl,
        'certfile'       => $cert_file,
        'cafile'         => $ca_file,
      },
    }
  } else {
    $keystone_config_auth_specific = {
      'KEYSTONE' => {
        'auth_port'         => $auth_port,
      },
    }
    $vnc_api_lib_config_auth_specific = {
      'auth' => {
        'AUTHN_PORT'      => $auth_port,
      },
    }
  }

  if $contrail_version < 4 {
    $disco = {
      'port'   => $disc_server_port,
      'server' => $disc_server_ip,
    }
    $nodemgr_config = {
      'DISCOVERY' => $disco,
    }
    $vrouter_agent_config_ver_specific = {
      'DISCOVERY' => $disco,
      'DNS'  => {
        'server' => $control_server_list,
      },
      'CONTROL-NODE'  => {
        'server' => $control_server_list,
      },
    }
    $keystone_config = deep_merge($keystone_config_common, $keystone_config_auth_specific)
    $vnc_api_lib_config_ver_specific = {}
  } else {
    $nodemgr_config = {
      'COLLECTOR' => {
        'server_list'   => $collector_server_list_8086,
      },
    }
    $vrouter_agent_config_ver_specific = {
      'DEFAULT' => {
        'collectors'                      => $collector_server_list_8086,
        'xmpp_auth_enable'                => $ssl_enabled,
        'xmpp_dns_auth_enable'            => $ssl_enabled,
      },
      'SANDESH' => {
        'introspect_ssl_enable'           => $ssl_enabled,
        'sandesh_ssl_enable'              => $ssl_enabled,
      },
      'DNS'  => {
        'servers' => $control_server_list_53,
      },
      'CONTROL-NODE'  => {
        'servers' => $control_server_list_5269,
      },
    }
    $keystone_config = undef
    $vnc_api_cfg_global = {
      'global' => {
        'WEB_SERVER'  => $api_server,
        'WEB_PORT'    => $api_port,
      }
    }
    if $auth_host and $auth_host != '' {
      $vnc_api_lib_config_type = {
        'auth' => {
          'AUTHN_TYPE'      => 'keystone',
          'insecure'        => $insecure,
        },
      }
    } else {
      $vnc_api_lib_config_type = {
        'auth' => {
          'AUTHN_TYPE' => 'noauth',
        },
      }
    }
    $vnc_api_lib_config_ver_specific = deep_merge($vnc_api_cfg_global, $vnc_api_lib_config_type)
  }
  $vnc_api_lib_config = deep_merge(
    deep_merge($vnc_api_lib_config_common, $vnc_api_lib_config_auth_specific),
    $vnc_api_lib_config_ver_specific
  )
  $vrouter_agent_config_common = {
    'NETWORKS'  => {
      'control_network_ip' => $host_ip,
    },
    'VIRTUAL-HOST-INTERFACE'  => {
      'compute_node_address' => $host_ip,
      'gateway'              => $gateway,
      'ip'                   => "${host_ip}/${cidr}",
      'name'                 => 'vhost0',
      'physical_interface'   => $physical_interface,
    },
    'METADATA' => {
      'metadata_proxy_secret' => $metadata_secret,
    },
  }
  if !$is_dpdk {
    $macaddress = inline_template("<%= scope.lookupvar('::macaddress_${physical_interface}') -%>")
  } else {
    $macaddress = generate('/bin/cat','/etc/contrail/dpdk_mac')
  }
  if $is_tsn {
    $vrouter_agent_config_mode_specific = {
      'DEFAULT'  => {
        'agent_mode' => 'tsn',
      },
    }
  } elsif $is_dpdk {
    $pciaddress = generate('/bin/cat','/etc/contrail/dpdk_pci')
    $vrouter_agent_config_mode_specific = {
      'DEFAULT'  => {
        'platform'                   => 'dpdk',
        'physical_uio_driver'        => $dpdk_driver,
        'physical_interface_mac'     => $macaddress,
        'physical_interface_address' => $pciaddress,
        'log_file'                   => '/var/log/contrail/contrail-vrouter-agent.log',
        'log_level'                  => 'log_level',
        'log_local'                  => '1',
      },
      'SERVICE-INSTANCE' => {
        'netns_command' => '/usr/bin/opencontrail-vrouter-netns',
      },
    }
  } else {
    $vrouter_agent_config_mode_specific = {}
  }
  $vrouter_agent_config = deep_merge(
    deep_merge($vrouter_agent_config_common, $vrouter_agent_config_mode_specific),
    $vrouter_agent_config_ver_specific
  )

  if $step >= 4 {
    class {'::contrail::vrouter':
        contrail_version       => $contrail_version,
        discovery_ip           => $disc_server_ip,
        gateway                => $gateway,
        host_ip                => $host_ip,
        is_tsn                 => $is_tsn,
        is_dpdk                => $is_dpdk,
        macaddr                => $macaddress,
        mask                   => $cidr,
        netmask                => $netmask,
        physical_interface     => $physical_interface,
        vhost_ip               => $host_ip,
        keystone_config        => $keystone_config,
        vrouter_agent_config   => $vrouter_agent_config,
        vrouter_nodemgr_config => $nodemgr_config,
        vnc_api_lib_config     => $vnc_api_lib_config,
    }
  }
  if $step >= 5 {
    class {'::contrail::vrouter::provision_vrouter':
      api_address                => $api_server,
      api_port                   => $api_port,
      host_ip                    => $host_ip,
      node_name                  => $::hostname,
      keystone_admin_user        => $admin_user,
      keystone_admin_password    => $admin_password,
      keystone_admin_tenant_name => $admin_tenant_name,
      is_tsn                     => $is_tsn,
      is_dpdk                    => $is_dpdk,
    }
  }
}
